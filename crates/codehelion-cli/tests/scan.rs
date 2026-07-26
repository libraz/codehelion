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

/// A Rust function sharing nothing structural with the checksum family, so a
/// pair of these is its own group rather than a member of an existing one.
const FORMAT_RS: &str = "pub fn describe_entry(name: &str, size: usize) -> String {
    let mut text = String::new();
    text.push_str(name);
    text.push(':');
    text.push(' ');
    text.push_str(&size.to_string());
    text
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
    scan_json_with(root, &[])
}

/// The same, with extra arguments appended to the scan.
fn scan_json_with(root: &Path, extra: &[&str]) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--format", "json"])
        .args(extra)
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// A tree of `names`, each holding a small translation unit, plus a bare
/// header. The header's content is C++ that the C grammar cannot follow, so a
/// misread shows up as a language count rather than as a silent difference.
fn header_fixture(names: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    for name in names {
        std::fs::write(root.join(name), MIX_C).unwrap();
    }
    std::fs::write(
        root.join("shared.h"),
        "namespace demo {\nclass Widget {\n public:\n  int size() const { return n_; }\n\
         \n private:\n  int n_ = 0;\n};\n}\n",
    )
    .unwrap();
    dir
}

/// The `(c, cpp)` analysed-file counts and the reported header grammar.
fn header_reading(root: &Path, config: Option<&str>) -> (u64, u64, String) {
    if let Some(config) = config {
        std::fs::write(root.join("codehelion.toml"), config).unwrap();
    }
    let value = scan_json(root);
    let variant = &value["run"]["build_variant"];
    (
        value["summary"]["files"]["c"].as_u64().unwrap(),
        value["summary"]["files"]["cpp"].as_u64().unwrap(),
        variant["headers"].as_str().unwrap().to_string(),
    )
}

#[test]
fn a_bare_header_is_read_as_the_language_the_tree_is_written_in() {
    let cpp_tree = header_fixture(&["a.cpp", "b.cpp", "vendored.c"]);
    assert_eq!(
        header_reading(cpp_tree.path(), None),
        (1, 3, "cpp".to_string()),
        "two C++ sources outvote one C source, so shared.h is C++"
    );

    let c_tree = header_fixture(&["a.c", "b.c", "fuzz.cc"]);
    assert_eq!(
        header_reading(c_tree.path(), None),
        (3, 1, "c".to_string()),
        "one vendored C++ harness does not make a C project C++"
    );
}

#[test]
fn the_configured_header_grammar_overrides_the_tree_and_moves_the_variant() {
    let dir = header_fixture(&["a.cpp", "b.cpp"]);
    let (_, _, detected) = header_reading(dir.path(), None);
    assert_eq!(detected, "cpp");
    let detected_fingerprint = scan_json(dir.path())["run"]["build_variant"]["fingerprint"].clone();

    let (c_files, cpp_files, forced) =
        header_reading(dir.path(), Some("[languages]\nheaders = \"c\"\n"));
    assert_eq!(forced, "c", "the configured grammar decides");
    assert_eq!((c_files, cpp_files), (1, 2), "shared.h is now counted as C");

    // The two runs saw different code in the same header, so their results
    // must not land in one fingerprint space.
    assert_ne!(
        scan_json(dir.path())["run"]["build_variant"]["fingerprint"],
        detected_fingerprint
    );
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
        // The second run has a first run to compare itself with; what it
        // found in the sources is what has to agree, not what it knows about
        // its own history.
        let summary = value["summary"].as_object_mut().unwrap();
        for key in ["changes", "audit"] {
            summary.insert(key.to_string(), serde_json::Value::Null);
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

#[test]
fn a_scan_says_what_moved_since_the_previous_scan_of_the_tree() {
    let dir = fixture();
    let root = dir.path();

    // Nothing to compare a first scan with, and saying "5 added" would read
    // as a tree written from scratch rather than one never scanned before.
    let first = scan_json(root);
    assert!(
        first["summary"].get("changes").is_none(),
        "a first scan has no run to measure itself against"
    );
    let first_run = first["run"]["run_id"].as_i64().expect("a recorded run");

    // One file edited, one added, one deleted.
    std::fs::write(root.join("src/a.rs"), format!("{CHECKSUM_RS}\n// tail\n")).unwrap();
    std::fs::write(root.join("src/d.rs"), RENAMED_RS).unwrap();
    std::fs::remove_file(root.join("src/two.c")).unwrap();

    let second = scan_json(root);
    let changes = &second["summary"]["changes"];
    assert_eq!(changes["since_run_id"], first_run);
    assert_eq!(changes["modified"], 1);
    assert_eq!(changes["added"], 1);
    assert_eq!(changes["removed"], 1);
    assert_eq!(changes["unchanged"], 3, "the files nobody touched");

    // Scanning again without touching anything is the same tree, and says so.
    let third = scan_json(root);
    let changes = &third["summary"]["changes"];
    assert_eq!(changes["modified"], 0);
    assert_eq!(changes["added"], 0);
    assert_eq!(changes["removed"], 0);
    assert_eq!(changes["unchanged"], 5);
}

#[test]
fn a_scan_under_different_settings_has_nothing_to_compare_with() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);

    // A file whose bytes did not move still has to be re-read when the rules
    // for reading it did, so a run under another variant is not a run this
    // one can measure itself against.
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert!(
        value["summary"].get("changes").is_none(),
        "the Fast run is not a baseline for the Structural one"
    );
}

/// The fingerprints of every group a report lists, visible or not.
fn group_ids(report: &serde_json::Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|group| group["fingerprint"].as_str().expect("a hex id").to_string())
        .collect()
}

/// The fingerprints a report lists without a suppression.
fn visible_ids(report: &serde_json::Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|group| group["suppressed"].is_null())
        .map(|group| group["fingerprint"].as_str().expect("a hex id").to_string())
        .collect()
}

/// Record a baseline of `root`'s last scan into `root/baseline.json`.
fn record_baseline(root: &Path) {
    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .success();
}

#[test]
fn a_baseline_hides_what_came_before_it_and_nothing_else() {
    let dir = fixture();
    let root = dir.path();

    let before = scan_json(root);
    let frozen = visible_ids(&before);
    assert!(!frozen.is_empty(), "the fixture duplicates on purpose");
    record_baseline(root);

    // Everything the baseline froze is hidden, and hidden by the baseline.
    let baselined = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(visible_ids(&baselined).is_empty(), "all of it was frozen");
    let status = &baselined["summary"]["baseline"];
    assert_eq!(status["entries"], frozen.len());
    assert_eq!(status["matched"], frozen.len());
    assert_eq!(status["stale"], 0);
    assert!(status.get("mismatch").is_none(), "the same run's own ids");
    let hidden = baselined["groups"].as_array().expect("groups");
    assert!(
        hidden
            .iter()
            .all(|group| group["suppressed"]["scope"] == "baseline"),
        "suppressed, not deleted, and by the baseline: {hidden:?}"
    );

    // A duplication written after the baseline is the one thing left to see.
    // It has to be unlike anything already there: a near-copy of a frozen
    // group would join that group, and a group's id moves when its membership
    // gains content — which is a different behaviour from this one.
    std::fs::write(root.join("src/new_one.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/new_two.rs"), FORMAT_RS).unwrap();
    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    let visible = visible_ids(&after);
    assert_eq!(visible.len(), 1, "only what came after: {visible:?}");
    assert!(!frozen.contains(&visible[0]));
}

#[test]
fn a_baseline_survives_an_edit_that_changes_no_code() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Comments and blank lines do not survive tokenization, so an edit made
    // of nothing else cannot move a content fingerprint — however far it
    // shifts the line numbers the report prints.
    std::fs::write(
        root.join("src/a.rs"),
        format!("// A leading comment.\n//\n// And another.\n\n{CHECKSUM_RS}"),
    )
    .unwrap();

    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(
        visible_ids(&after).is_empty(),
        "reformatting is not new duplication"
    );
    assert_eq!(after["summary"]["baseline"]["stale"], 0);
}

#[test]
fn resolving_a_duplication_makes_its_entry_stale_and_update_drops_it() {
    let dir = fixture();
    let root = dir.path();
    let before = scan_json(root);
    let frozen = group_ids(&before).len();
    record_baseline(root);

    // The C pair is resolved the way it would be in practice: one copy goes.
    std::fs::remove_file(root.join("src/two.c")).unwrap();
    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    let stale = after["summary"]["baseline"]["stale"]
        .as_u64()
        .expect("a count");
    assert!(stale > 0, "the duplication the deleted file was half of");

    cmd()
        .current_dir(root)
        .args(["baseline", "update", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("resolved and dropped"));

    // Pruning drops exactly the stale entries and adopts nothing.
    let pruned = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert_eq!(pruned["summary"]["baseline"]["stale"], 0);
    assert_eq!(
        pruned["summary"]["baseline"]["entries"]
            .as_u64()
            .expect("a count"),
        u64::try_from(frozen).unwrap() - stale
    );
}

#[test]
fn a_baseline_from_other_settings_says_so_instead_of_hiding_nothing_quietly() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Every id is computed under a build variant. Handed to a run under
    // another one, a baseline matches nothing — which looks exactly like a
    // baseline that worked unless the report says otherwise.
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--baseline",
            "baseline.json",
        ])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        text.contains("this baseline hid nothing"),
        "the mismatch has to be stated: {text}"
    );
    assert!(text.contains("build variant"));
}

#[test]
fn a_baseline_that_cannot_be_read_stops_the_scan() {
    let dir = fixture();
    let root = dir.path();
    std::fs::write(root.join("broken.json"), "{ not json").unwrap();

    // Scanning on without the baseline would report the very findings the
    // user asked to have hidden, so a named file that cannot be applied is a
    // reason to stop.
    cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "broken.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("broken.json"));

    cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "absent.json"])
        .assert()
        .failure();
}

#[test]
fn recording_a_baseline_needs_a_scan_and_refuses_to_overwrite_silently() {
    let dir = fixture();
    let root = dir.path();

    cmd()
        .current_dir(root)
        .args(["baseline", "create", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("scan"));

    scan_json(root);
    record_baseline(root);
    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    cmd()
        .current_dir(root)
        .args([
            "baseline",
            "create",
            ".",
            "--file",
            "baseline.json",
            "--force",
        ])
        .assert()
        .success();
}
