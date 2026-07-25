//! End-to-end scan tests: the compiled binary against real fixture trees,
//! with the recorded snapshot verified through the store's query layer.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_store::Store;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A ~40-token Rust function; long enough for the 20-token clone floor.
const CHECKSUM_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^ 0x5a5a
}
";

/// The same function under a consistent rename with changed literals.
const RENAMED_RS: &str = "pub fn digest_chunk(start: u64, items: &[u64]) -> u64 {
    let mut total = start;
    for item in items {
        total = total.wrapping_mul(37).wrapping_add(*item);
    }
    total ^ 0x1234
}
";

/// A verbatim C clone pair member.
const MIX_C: &str =
    "unsigned long mix_bytes(unsigned long seed, const unsigned long *data, int len) {
    unsigned long acc = seed;
    for (int i = 0; i < len; i++) {
        acc = acc * 31u + data[i];
    }
    return acc ^ 0x5a5aU;
}
";

/// A mixed Rust/C tree holding one verbatim Rust pair, one renamed Rust
/// copy and one verbatim C pair. The `.git` directory makes ignore rules
/// effective for the tests that add a `.gitignore`.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    std::fs::write(root.join("src/one.c"), MIX_C).unwrap();
    std::fs::write(root.join("src/two.c"), MIX_C).unwrap();
    dir
}

fn open_store(root: &Path) -> Store {
    Store::open(&root.join(".codehelion/audit.db")).expect("open audit db")
}

#[test]
fn scan_detects_clones_and_records_a_snapshot() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "files: 5 analysed (rust 3, c 2, cpp 0)",
        ))
        .stdout(predicate::str::contains("clone groups:"))
        .stdout(predicate::str::contains("type-1"))
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(run.analysis_mode, "fast");
    let groups = store.run_groups(run.id).unwrap();
    assert!(!groups.is_empty());

    // The verbatim Rust pair lands in a Type-1 group anchored to both files.
    let rust_type1 = groups
        .iter()
        .find(|group| {
            group.clone_type == "type-1" && group.members.iter().any(|m| m.file_path == "src/a.rs")
        })
        .expect("a Type-1 group for the Rust pair");
    assert!(rust_type1.members.iter().any(|m| m.file_path == "src/b.rs"));
    assert!(
        rust_type1
            .members
            .iter()
            .any(|m| m.unit_name.as_deref() == Some("checksum_block"))
    );

    // The C pair lands in its own Type-1 group.
    assert!(groups.iter().any(|group| {
        group.clone_type == "type-1"
            && group.members.iter().any(|m| m.file_path == "src/one.c")
            && group.members.iter().any(|m| m.file_path == "src/two.c")
    }));

    // The renamed copy is recovered as a Type-2 member.
    assert!(groups.iter().any(|group| {
        group.clone_type == "type-2" && group.members.iter().any(|m| m.file_path == "src/c.rs")
    }));

    // Every finding starts in the `new` audit state.
    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f.audit_state == "new"));
}

#[test]
fn rescans_reuse_stable_identifiers() {
    let dir = fixture();
    for _ in 0..2 {
        cmd()
            .current_dir(dir.path())
            .args(["scan", "."])
            .assert()
            .success();
    }
    let store = open_store(dir.path());
    let latest = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(latest.id, 2, "two runs recorded");

    let first = store.run_groups(1).unwrap();
    let second = store.run_groups(2).unwrap();
    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.fingerprint_hex, b.fingerprint_hex);
        let findings_a: Vec<_> = a.members.iter().map(|m| &m.finding_hex).collect();
        let findings_b: Vec<_> = b.members.iter().map(|m| &m.finding_hex).collect();
        assert_eq!(findings_a, findings_b);
    }
}

#[test]
fn fail_on_findings_gates_the_exit_code() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--fail-on-findings"])
        .assert()
        .code(3);
    // Without the flag, findings do not fail the scan.
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();
}

#[test]
fn no_ignore_scans_files_gitignore_hides() {
    let dir = fixture();
    std::fs::write(dir.path().join(".gitignore"), "src/b.rs\n").unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("files: 4 analysed"));
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-ignore"])
        .assert()
        .success()
        .stdout(predicate::str::contains("files: 5 analysed"));

    let store = open_store(dir.path());
    let ignored_run: usize = store
        .run_groups(1)
        .unwrap()
        .iter()
        .map(|group| group.members.len())
        .sum();
    let full_run: usize = store
        .run_groups(2)
        .unwrap()
        .iter()
        .map(|group| group.members.len())
        .sum();
    assert!(full_run > ignored_run, "{full_run} vs {ignored_run}");
}

#[test]
fn reports_show_the_priority_and_its_inputs() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("top groups by priority:"))
        .stdout(predicate::str::contains("priority"))
        .stdout(predicate::str::contains("similarity"));
}

#[test]
fn path_suppression_hides_but_records_findings() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/*.c\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/one.c").not());

    // Hidden, not deleted: the finding is recorded with its rule.
    {
        let store = open_store(dir.path());
        let run = store.latest_run().unwrap().expect("a recorded run");
        let findings = store.run_findings(run.id).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.suppression_scope.as_deref() == Some("path_glob"))
        );
    }

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains("suppressed groups:"))
        .stdout(predicate::str::contains("src/one.c"));
}

#[test]
fn an_inline_marker_suppresses_the_next_unit() {
    let dir = fixture();
    let marked = format!("// codehelion:ignore\n{CHECKSUM_RS}");
    std::fs::write(dir.path().join("src/a.rs"), &marked).unwrap();
    std::fs::write(dir.path().join("src/b.rs"), &marked).unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        // The verbatim Rust pair (both instances marked) is suppressed; the
        // Type-2 group still holds the unmarked src/c.rs and stays visible.
        .stdout(predicate::str::contains("1 by rule"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("inline_comment"))
    );
}

#[test]
fn a_symbol_glob_suppresses_by_unit_name_wherever_the_unit_lives() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"mix_*\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        // Both C instances are named mix_bytes, so their group is hidden;
        // the Rust groups are untouched.
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/one.c").not())
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("symbol_pattern"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbol glob \"mix_*\""));
}

#[test]
fn a_symbol_glob_matching_only_part_of_a_group_leaves_it_visible() {
    let dir = fixture();
    // checksum_block appears twice and digest_chunk once; naming only the
    // renamed copy leaves the duplication actionable, so nothing is hidden.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"digest_chunk\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"))
        .stdout(predicate::str::contains("src/c.rs"));
}

/// Run `scan --format json` in `root` and parse the produced document.
fn scan_json(root: &Path) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

#[test]
fn the_run_says_how_far_each_stage_of_the_pipeline_narrowed_it() {
    let dir = fixture();
    let value = scan_json(dir.path());
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    let passed = |name: &str| {
        funnel
            .iter()
            .find(|entry| entry["stage"] == name)
            .expect("the stage is reported")["passed"]
            .as_u64()
            .unwrap()
    };
    // The Fast pipeline's own stage names, not the structural ones: it
    // narrows a winnowed fingerprint index down to verified pairs.
    assert!(passed("tokens") > passed("fingerprints"));
    assert!(passed("fingerprints") >= passed("indexed values"));
    assert!(passed("verified pairs") >= 1, "the fixture holds a clone");

    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:").not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:"))
        .stdout(predicate::str::contains("fragment classes"));
}

#[test]
fn configured_file_size_ceiling_skips_oversized_files() {
    let dir = fixture();
    // 4 KiB of valid Rust, above the 1 KiB ceiling set below.
    let big = "// filler line to grow the file body\n".repeat(120);
    std::fs::write(dir.path().join("src/big.rs"), big).unwrap();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-file-bytes = 1024\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["files"]["total"], 5);
    assert_eq!(value["summary"]["excluded"]["skipped"], 1);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["members"].as_array().unwrap())
            .all(|member| member["file"] != "src/big.rs")
    );
}

#[test]
fn configured_pair_budget_exhaustion_is_reported() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\npair-budget = 0\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["pair_budget_exhausted"], true);
    assert_eq!(value["summary"]["groups"]["total"], 0);
}

#[test]
fn zero_parse_timeout_excludes_every_file_visibly() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nparse-timeout-ms = 0\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    // Every file blows a zero ceiling; all five are excluded and counted.
    assert_eq!(value["summary"]["files"]["total"], 0);
    assert_eq!(value["summary"]["excluded"]["skipped"], 5);
    assert_eq!(value["summary"]["groups"]["total"], 0);
}

#[test]
fn json_reports_follow_the_versioned_schema() {
    let dir = fixture();
    let value = scan_json(dir.path());

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["run"]["mode"], "fast");
    assert_eq!(value["run"]["build_variant"]["mode"], "fast");
    assert!(value["run"]["started_at"].as_str().unwrap().ends_with('Z'));
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "fp-schema")
    );
    assert_eq!(value["summary"]["files"]["total"], 5);
    assert!(value["summary"]["lines"].as_u64().unwrap() > 0);

    // Deterministic listing: priority descending across the whole document.
    let groups = value["groups"].as_array().unwrap();
    assert!(!groups.is_empty());
    let priorities: Vec<f64> = groups
        .iter()
        .map(|group| group["priority"]["value"].as_f64().unwrap())
        .collect();
    assert!(priorities.windows(2).all(|pair| pair[0] >= pair[1]));
    for group in groups {
        assert_eq!(group["suppressed"], serde_json::Value::Null);
        let members = group["members"].as_array().unwrap();
        assert!(members.len() >= 2);
        assert_eq!(members[0]["canonical"], true);
        assert_eq!(members[0]["finding_id"].as_str().unwrap().len(), 32);
    }

    // The JSON members carry exactly the finding ids the snapshot recorded.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored: std::collections::BTreeSet<String> = store
        .run_groups(run.id)
        .unwrap()
        .iter()
        .flat_map(|group| group.members.iter().map(|m| m.finding_hex.clone()))
        .collect();
    let reported: std::collections::BTreeSet<String> = groups
        .iter()
        .flat_map(|group| {
            group["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["finding_id"].as_str().unwrap().to_string())
        })
        .collect();
    assert_eq!(stored, reported);
}

#[test]
fn json_reports_are_deterministic_across_reruns() {
    let dir = fixture();
    let mut documents = Vec::new();
    for _ in 0..2 {
        let mut value = scan_json(dir.path());
        // Null out the only fields that legitimately differ between runs.
        let run = value["run"].as_object_mut().unwrap();
        for key in ["started_at", "finished_at", "run_id"] {
            run.insert(key.to_string(), serde_json::Value::Null);
        }
        documents.push(value);
    }
    assert_eq!(documents[0], documents[1]);
}

#[test]
fn json_suppression_status_names_the_matching_rule() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/*.c\"]\n",
    )
    .unwrap();
    let value = scan_json(dir.path());
    let suppressed: Vec<_> = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| !group["suppressed"].is_null())
        .collect();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(suppressed[0]["suppressed"]["kind"], "rule");
    assert_eq!(suppressed[0]["suppressed"]["scope"], "path_glob");
    assert_eq!(suppressed[0]["suppressed"]["pattern"], "src/*.c");
}

#[test]
fn default_reports_truncate_members_and_verbose_lists_them_all() {
    let dir = fixture();
    // Grow the verbatim Rust group to 9 members (a.rs, b.rs + 7 copies).
    for index in 0..7 {
        std::fs::write(dir.path().join(format!("src/copy{index}.rs")), CHECKSUM_RS).unwrap();
    }
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("... and 4 more occurrences"));
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("more occurrences").not())
        .stdout(predicate::str::contains("src/copy6.rs"));
}

#[test]
fn output_flag_writes_the_report_to_a_file() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote report.txt"));
    let report = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
    assert!(report.contains("codehelion scan (fast mode)"));
    assert!(report.contains("clone groups:"));
}

#[test]
fn db_flag_overrides_the_database_location() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--db", "custom/audit.db"])
        .assert()
        .success();
    assert!(dir.path().join("custom/audit.db").is_file());
    assert!(!dir.path().join(".codehelion/audit.db").exists());
}

#[test]
fn explain_looks_up_a_recorded_finding() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();

    let (finding_hex, file_path) = {
        let store = open_store(dir.path());
        let run = store.latest_run().unwrap().expect("a recorded run");
        let groups = store.run_groups(run.id).unwrap();
        let member = &groups[0].members[0];
        (member.finding_hex.clone(), member.file_path.clone())
    };

    cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex])
        .assert()
        .success()
        .stdout(predicate::str::contains(&finding_hex))
        .stdout(predicate::str::contains(&file_path));

    // The JSON detail view shares the same shape as a report member.
    let output = cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex, "--format", "json"])
        .output()
        .expect("run explain");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(value["finding_id"], finding_hex.as_str());
    assert_eq!(value["file"], file_path.as_str());
    assert_eq!(value["group"]["fingerprint"].as_str().unwrap().len(), 32);
    assert!(value["scan_run"].as_i64().unwrap() >= 1);

    // Well-formed but unknown id: a clear error, not silence.
    cmd()
        .current_dir(dir.path())
        .args(["explain", "00000000000000000000000000000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no occurrence"));
}

#[test]
fn explain_without_a_database_says_to_scan_first() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["explain", "00000000000000000000000000000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("run `codehelion scan` first"));
}

#[test]
fn doctor_hints_until_the_database_is_gitignored() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit database:"))
        .stdout(predicate::str::contains("hint:"));

    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("hint:").not());
}
