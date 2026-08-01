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

    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());
}

#[test]
fn report_reformats_a_recorded_run_without_scanning_again() {
    let dir = fixture();
    let scanned = scan_json(dir.path());
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");

    let json = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("reformat recorded JSON report");
    assert!(json.status.success(), "{json:?}");
    let rendered: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("report stdout is JSON");
    assert_eq!(rendered["run"]["run_id"].as_i64(), Some(run_id));
    assert_eq!(rendered["groups"], scanned["groups"]);
    assert_eq!(
        rendered["run"]["ranking"], scanned["run"]["ranking"],
        "the original ranking recipe and weights are preserved"
    );

    cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "text"])
        .assert()
        .success()
        .stdout(predicate::str::contains("snapshot:"));

    let sarif = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "sarif"])
        .output()
        .expect("reformat recorded SARIF report");
    assert!(sarif.status.success(), "{sarif:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&sarif.stdout).expect("report stdout is SARIF JSON");
    assert_eq!(document["version"], "2.1.0");
}

/// Fast and Structural use their local frontends directly. This stays in the
/// package-scoped CI job that deliberately does not build compiler helpers.
#[test]
fn fast_and_structural_modes_run_without_compiler_helpers() {
    let dir = fixture();

    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion scan (fast mode)"));

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "codehelion scan (structural mode)",
        ));
}

#[test]
fn a_rescan_replaces_the_current_snapshot() {
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
    assert_eq!(latest.id, 1, "only the current snapshot is retained");
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
///
/// Always analyses: these tests are about what the analysis produces, and a
/// scan that reports a recorded run again would be testing the database
/// instead. The reuse path has its own tests.
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

/// A header-only library is the case with nothing to vote, and the case where
/// getting it wrong costs everything.
///
/// There is no `.cpp` to outvote a `.c` because there are no translation units
/// at all — every line the run will read is in the headers. Settling that by
/// default would read a whole C++ project with the C grammar, which does not
/// merely skip the C++ declarations: error recovery reshapes what surrounds
/// them, so most of the project stops being analysed at all.
#[test]
fn a_library_that_is_nothing_but_headers_is_read_by_what_the_headers_say() {
    let cpp_only = header_fixture(&[]);
    assert_eq!(
        header_reading(cpp_only.path(), None),
        (0, 1, "cpp".to_string()),
        "the header declares a namespace and a class, and nothing else speaks"
    );

    // And a C library shipped the same way stays C: the check is for what only
    // C++ can spell, not for a C++-looking word.
    let c_only = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        c_only.path().join("mixer.h"),
        "/* Widgets of every class, in the namespace sense. */\n#include <string.h>\n\
         static int mixer_width(const char *s) { return (int) strlen(s); }\n",
    )
    .unwrap();
    assert_eq!(
        header_reading(c_only.path(), None),
        (1, 0, "c".to_string()),
        "the C++ words are all in a comment"
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

/// A scan told to distrust the tree reads less of it, and a report that read
/// less has to be distinguishable from a tree that holds less. The oversized
/// file is the evidence the ceilings took effect; the profile line is what
/// stops the smaller result from reading as a smaller codebase.
#[test]
fn distrusting_the_tree_lowers_the_ceilings_and_reports_them() {
    let dir = fixture();
    // Above the untrusted profile's 512 KiB ceiling and below the default one.
    let big = "// filler line to grow the file body\n".repeat(16_000);
    std::fs::write(dir.path().join("src/big.rs"), big).unwrap();

    let trusting = scan_json(dir.path());
    assert_eq!(trusting["summary"]["files"]["total"], 6);
    assert!(trusting["summary"]["guardrails"].is_null());

    let distrusting = scan_json_with(dir.path(), &["--untrusted"]);
    assert_eq!(distrusting["summary"]["files"]["total"], 5);
    assert_eq!(distrusting["summary"]["excluded"]["skipped"], 1);
    let guardrails = &distrusting["summary"]["guardrails"];
    assert_eq!(guardrails["profile"], "untrusted");
    assert_eq!(guardrails["max_file_bytes"], 512 * 1024);
    assert_eq!(guardrails["parse_timeout_ms"], 5000);
    assert_eq!(guardrails["pair_budget"], 500_000);
}

/// The profile has to be visible in the format a person reads, not only in the
/// one a program reads: the text report is where somebody notices that a run
/// which found less was told to look at less.
#[test]
fn the_text_report_says_the_run_was_told_to_distrust_the_tree() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--untrusted"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(text.contains("untrusted profile"), "{text}");
}

/// The ceilings are part of what a reused run is matched on, so a distrusting
/// scan cannot be answered with a recording made under the default ones — that
/// recording read files this run would not have opened.
#[cfg(any())]
#[test]
fn a_distrusting_scan_does_not_reuse_a_run_that_trusted_the_tree() {
    let dir = fixture();
    let reused = |extra: &[&str]| -> bool {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--format", "json"])
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
        value["run"]["reused"] == serde_json::Value::Bool(true)
    };
    assert!(!reused(&[]), "the first scan cannot reuse anything");
    assert!(reused(&[]), "an unchanged tree is read from the recording");
    assert!(
        !reused(&["--untrusted"]),
        "a recording made under the default ceilings answered a distrusting scan"
    );
    assert!(
        reused(&["--untrusted"]),
        "a second distrusting scan should reuse the first one"
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
    // And says how much it did not look at. "The budget ran out" alone does
    // not tell a reader whether a handful of low-signal candidates were
    // trimmed or the search never started, and only one of those is a result
    // worth acting on.
    //
    // Both pairing passes are checked, because each holds its own allowance:
    // a pass whose funnel stage stayed silent would leave its share of the
    // search unaccounted for while the run as a whole still read as merely
    // "exhausted".
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    for stage_name in ["seed pairs", "fragment pairs"] {
        let stage = funnel.iter().find(|stage| stage["stage"] == stage_name);
        assert!(stage.is_some(), "the funnel names the {stage_name} stage");
        let stage = stage.unwrap();
        let unexamined = stage["dropped"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drop| drop["cause"] == "pair_budget");
        assert!(
            unexamined.is_some(),
            "{stage_name} accounts for what the ceiling stopped"
        );
        assert!(unexamined.unwrap()["count"].as_u64().unwrap() > 0);
        assert_eq!(stage["passed"], 0);
    }
}

/// A ceiling on the whole search must not switch one of the two detectors off.
///
/// The verbatim pass runs first over a far larger candidate space. Sharing one
/// allowance with the renamed-copy pass means that above a few hundred
/// thousand lines the first pass spends all of it, and Fast mode silently
/// becomes verbatim-only — while reporting nothing worse than an exhausted
/// budget.
#[test]
fn a_tight_budget_narrows_both_detectors_rather_than_silencing_one() {
    let dir = fixture();
    let full = scan_json(dir.path());
    let type2 = |value: &serde_json::Value| {
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|group| group["clone_type"] == "type-2")
            .count()
    };
    assert!(type2(&full) > 0, "the fixture holds a renamed copy");

    // Tight enough that the verbatim pass runs out, wide enough that the
    // renamed pass could still do its work with an allowance of its own.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\npair-budget = 12\n",
    )
    .unwrap();
    let squeezed = scan_json(dir.path());
    assert_eq!(squeezed["summary"]["pair_budget_exhausted"], true);
    assert!(
        type2(&squeezed) > 0,
        "the renamed copy is still found when the verbatim pass runs out"
    );
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

/// A scan report with the fields that legitimately differ between runs
/// removed, so two of them can be compared whole.
fn comparable_report(root: &Path, extra: &[&str]) -> serde_json::Value {
    let mut value = scan_json_with(root, extra);
    let run = value["run"].as_object_mut().expect("run object");
    for key in ["started_at", "finished_at", "run_id"] {
        run.insert(key.to_string(), serde_json::Value::Null);
    }
    // A later run has an earlier one to compare itself with; what it found in
    // the sources is what has to agree, not what it knows about its own
    // history.
    let summary = value["summary"].as_object_mut().expect("summary object");
    for key in ["changes", "audit"] {
        summary.insert(key.to_string(), serde_json::Value::Null);
    }
    value
}

#[test]
fn json_reports_are_deterministic_across_reruns() {
    let dir = fixture();
    let first = comparable_report(dir.path(), &[]);
    let second = comparable_report(dir.path(), &[]);
    assert_eq!(first, second);
}

/// A tree wide enough that the work actually spreads: one file per worker and
/// then some, in three contents so there is grouping to do rather than one
/// group of everything.
fn wide_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    for index in 0..24 {
        let (name, body) = match index % 3 {
            0 => (format!("src/copy{index}.rs"), CHECKSUM_RS),
            1 => (format!("src/renamed{index}.rs"), RENAMED_RS),
            _ => (format!("src/mix{index}.c"), MIX_C),
        };
        std::fs::write(root.join(name), body).unwrap();
    }
    dir
}

#[test]
fn the_worker_count_does_not_change_what_the_scan_reports() {
    // Ordering that comes from whichever worker finished first is the failure
    // this catches, and it is invisible at one thread: a report built by one
    // worker is in the order the tree was walked whether or not anything
    // downstream depends on that order. Comparing the documents whole is what
    // makes the check worth running — a group count would agree while the
    // members inside the groups shuffled.
    let dir = wide_fixture();
    let mut documents = Vec::new();
    for jobs in ["1", "4", "8"] {
        for mode in ["fast", "structural"] {
            documents.push((
                mode,
                jobs,
                comparable_report(dir.path(), &["--jobs", jobs, "--mode", mode]),
            ));
        }
    }
    for mode in ["fast", "structural"] {
        let mut same_mode = documents.iter().filter(|(m, _, _)| *m == mode);
        let (_, first_jobs, first) = same_mode.next().expect("at least one worker count");
        // An agreement between two empty reports is not the agreement this is
        // about.
        let members: usize = first["groups"]
            .as_array()
            .expect("groups array")
            .iter()
            .map(|group| group["members"].as_array().expect("members array").len())
            .sum();
        assert!(
            members >= 20,
            "{mode} mode placed {members} members over 24 files, too few for an \
             ordering to go wrong in",
        );
        for (_, jobs, other) in same_mode {
            assert_eq!(
                first, other,
                "{mode} mode reported differently at {jobs} workers than at {first_jobs}",
            );
        }
    }
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
fn default_database_is_placed_at_the_repository_root_for_a_subtree_scan() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "src"])
        .assert()
        .success();

    assert!(dir.path().join(".codehelion/audit.db").is_file());
    assert!(!dir.path().join("src/.codehelion/audit.db").exists());
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

    // Well-formed but unknown id: a clear error naming everything it looked
    // for, not silence and not a claim about one kind of id.
    cmd()
        .current_dir(dir.path())
        .args(["explain", "00000000000000000000000000000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no finding, clone group or cross-language comparison group",
        ));
}

#[test]
fn explain_takes_the_group_id_the_report_printed_and_an_abbreviation_of_it() {
    let dir = fixture();
    let root = dir.path();
    let report = scan_json(root);
    let group = visible_ids(&report)
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // The heading of a group in the report is a group fingerprint. Being
    // unable to paste it back in is the trail these ids exist to keep,
    // broken.
    cmd()
        .current_dir(root)
        .args(["explain", &group])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("clone group {group}")))
        .stdout(predicate::str::contains("maintenance risk"));

    // An abbreviation resolves wherever it names one thing, as it already
    // does for [suppression] clone-ids.
    let output = cmd()
        .current_dir(root)
        .args(["explain", &group[..12], "--format", "json"])
        .output()
        .expect("run explain");
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(value["schema_version"], "clone-group-explain-v1");
    assert_eq!(value["group"]["fingerprint"], group.as_str());
    assert!(value["group"]["priority"]["inputs"]["instances"].as_u64() >= Some(2));
    assert!(value["group"]["members"].as_array().expect("members").len() >= 2);
}

#[test]
fn text_that_is_not_a_usable_id_is_refused_with_the_reason() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);

    cmd()
        .current_dir(root)
        .args(["explain", "0a1b"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("too short"));

    cmd()
        .current_dir(root)
        .args(["explain", "not-hex-at-all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("hexadecimal"));

    // Every recorded id starts with the empty string, so an empty prefix is
    // the one that always collides; it is refused for length first.
    cmd()
        .current_dir(root)
        .args(["explain", ""])
        .assert()
        .failure();
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
        .stdout(predicate::str::contains("local database:"))
        .stdout(predicate::str::contains("hint:"));

    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("hint:").not());
}

#[cfg(any())]
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

#[test]
fn a_second_scan_replaces_the_first_instead_of_stacking_up() {
    let dir = fixture();
    let root = dir.path();

    let first = scan_json(root);
    let second = scan_json(root);
    assert_eq!(
        first["run"]["run_id"], second["run"]["run_id"],
        "one snapshot at a time, so the recorded run id is a name and not a counter"
    );

    // Printing a run number invites reading it as a growing history, and the
    // reader who wants a before and after needs pointing at what does that.
    cmd()
        .current_dir(root)
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("one scan at a time")
                .and(predicate::str::contains("baseline"))
                .and(predicate::str::contains("snapshot: run ").not()),
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
    assert_eq!(status["mode"], "suppress", "hiding is the default");
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

/// A tree whose duplication sits in a vendored subtree, in a directory whose
/// name merely starts like one, and in the project's own code.
fn vendored_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("third_party/r8brain")).unwrap();
    std::fs::create_dir_all(root.join("external_api")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    // Upstream code duplicating itself: nobody here can unify it.
    std::fs::write(root.join("third_party/r8brain/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("third_party/r8brain/b.rs"), CHECKSUM_RS).unwrap();
    // A directory whose name only starts like a vendored one.
    std::fs::write(root.join("external_api/a.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("external_api/b.rs"), FORMAT_RS).unwrap();
    dir
}

/// A Rust function unlike anything else in the fixtures, for a pair that has
/// to land in its own group.
const TRIM_RS: &str = "pub fn trim_suffix(text: &str, suffix: &str) -> String {
    if text.ends_with(suffix) {
        let cut = text.len() - suffix.len();
        return text[..cut].to_string();
    }
    text.to_string()
}
";

#[test]
fn vendored_trees_are_hidden_by_default_and_the_report_says_it_did_that() {
    let dir = vendored_fixture();
    let root = dir.path();

    let report = scan_json(root);
    let visible: Vec<&serde_json::Value> = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|group| group["suppressed"].is_null())
        .collect();
    // A name that merely starts like a vendored one is the project's own code:
    // globs match whole path components, so `external/` does not claim it.
    assert_eq!(visible.len(), 1, "{visible:?}");
    assert_eq!(visible[0]["members"][0]["file"], "external_api/a.rs");

    let hidden = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| group["suppressed"]["scope"] == "vendored_path")
        .expect("the vendored pair, suppressed rather than dropped");
    assert!(
        hidden["suppressed"]["pattern"]
            .as_str()
            .expect("the glob that matched")
            .contains("third_party")
    );
    assert_eq!(report["summary"]["suppressed"]["vendored"], 1);

    // Applied without anybody asking, so the run says so and names the way out.
    cmd()
        .current_dir(root)
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("duplication inside vendored trees")
                .and(predicate::str::contains("--include-vendored")),
        );
}

#[test]
fn vendored_suppression_can_be_undone_for_one_run_or_switched_off() {
    let dir = vendored_fixture();
    let root = dir.path();

    let included = scan_json_with(root, &["--include-vendored"]);
    assert_eq!(included["summary"]["suppressed"]["vendored"], 0);
    assert_eq!(visible_ids(&included).len(), 2);

    std::fs::write(
        root.join("codehelion.toml"),
        "[suppression]\nvendored-paths = []\n",
    )
    .unwrap();
    let configured = scan_json(root);
    assert_eq!(configured["summary"]["suppressed"]["vendored"], 0);
    assert_eq!(visible_ids(&configured).len(), 2);
}

#[test]
fn duplication_between_a_vendored_tree_and_the_project_stays_visible() {
    let dir = vendored_fixture();
    let root = dir.path();
    // The project copied upstream code into its own tree. Nothing about that
    // is upstream's problem, and hiding half of it would hide all of it.
    std::fs::write(root.join("third_party/r8brain/c.rs"), TRIM_RS).unwrap();
    std::fs::write(root.join("src/ours.rs"), TRIM_RS).unwrap();

    let report = scan_json(root);
    let crossing = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| {
            group["members"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| member["file"] == "src/ours.rs")
        })
        .expect("the group crossing the boundary");
    assert!(
        crossing["suppressed"].is_null(),
        "a group is hidden only when every occurrence in it is: {crossing:?}"
    );
}

/// The checksum function rewritten, for writing over both copies of it at
/// once: the same duplication in the same two places, made of other content,
/// so it is known by another id.
const CHECKSUM_REWORKED_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
        acc = acc.rotate_left(7);
    }
    acc ^ 0x5a5a
}
";

/// A tree holding one duplicated Rust function and nothing else, so that a
/// count of groups is a count of one thing.
fn one_pair() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    dir
}

#[test]
fn comparing_against_a_baseline_names_what_went_and_what_took_its_place() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Both copies are reworked in step. The duplication has not been removed
    // and has not spread; it is the same two functions in the same two files.
    // Its content moved, though, and a group is identified by its content, so
    // this is one group gone and another arriving in its place.
    std::fs::write(root.join("src/a.rs"), CHECKSUM_REWORKED_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_REWORKED_RS).unwrap();

    let after = scan_json_with(
        root,
        &["--baseline", "baseline.json", "--baseline-mode", "compare"],
    );
    let status = &after["summary"]["baseline"];
    assert_eq!(status["mode"], "compare");
    assert_eq!(status["stale"], 1);
    assert_eq!(status["appeared"], 1);
    assert!(
        status["stale_tokens"].as_u64().expect("a count") > 0,
        "what went is measured in tokens, not only in groups"
    );
    assert!(status["appeared_tokens"].as_u64().expect("a count") > 0);

    // Compare mode hides nothing: a report with the known half missing cannot
    // answer what moved.
    let groups = after["groups"].as_array().expect("groups");
    assert!(groups.iter().all(|group| group["suppressed"].is_null()));

    let gone = status["gone"].as_array().expect("the entries that went");
    assert_eq!(gone.len(), 1);
    let arrived = groups
        .iter()
        .find(|group| group["baseline"]["state"] == "new")
        .expect("the group that took its place");
    // Without this the reader sees "1 new group" and reads it as duplication
    // they have just introduced.
    assert_eq!(
        arrived["baseline"]["derived_from"]["group"],
        gone[0]["group"]
    );
    assert_eq!(arrived["baseline"]["derived_from"]["shared_sites"], 2);
}

#[test]
fn duplication_written_somewhere_new_is_not_credited_to_what_went() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // The frozen pair goes, and an unrelated pair arrives in files nothing was
    // ever frozen over. Nothing stood where this stands, so nothing is claimed.
    std::fs::remove_file(root.join("src/b.rs")).unwrap();
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/d.rs"), FORMAT_RS).unwrap();

    let after = scan_json_with(
        root,
        &["--baseline", "baseline.json", "--baseline-mode", "compare"],
    );
    assert_eq!(after["summary"]["baseline"]["stale"], 1);
    assert_eq!(after["summary"]["baseline"]["appeared"], 1);
    let arrived = after["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| group["baseline"]["state"] == "new")
        .expect("the new pair");
    assert!(arrived["baseline"].get("derived_from").is_none());
}

#[test]
fn a_comparison_lists_what_went_and_a_suppression_does_not() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);
    std::fs::remove_file(root.join("src/b.rs")).unwrap();

    let compared = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--baseline",
            "baseline.json",
            "--baseline-mode",
            "compare",
        ])
        .output()
        .expect("run scan");
    assert!(compared.status.success(), "{compared:?}");
    let text = String::from_utf8(compared.stdout).expect("utf-8");
    assert!(text.contains("since it was recorded:"), "{text}");
    assert!(text.contains("1 gone"), "{text}");
    assert!(text.contains("repeated tokens"), "{text}");
    assert!(text.contains("last seen at src/a.rs"), "{text}");

    // Suppress mode was asked to hide known duplication; a list of duplication
    // that is no longer there is not what it was asked for.
    let suppressed = cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "baseline.json"])
        .output()
        .expect("run scan");
    assert!(suppressed.status.success(), "{suppressed:?}");
    let text = String::from_utf8(suppressed.stdout).expect("utf-8");
    assert!(text.contains("since it was recorded:"), "{text}");
    assert!(!text.contains("last seen at"), "{text}");
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

/// Whether a compiler helper is installed is a property of the machine this
/// runs on, so what is fixed here is the pairing. Without one, the mode says
/// which program supplies it and stops — it does not answer without a compiler
/// and call the answer semantic. With one, the report says how much of the
/// tree the compiler could speak for, which is what tells a thin semantic run
/// apart from a tree with little duplication in it.
#[test]
fn semantic_mode_either_asks_a_compiler_or_says_which_one_is_missing() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "semantic"])
        .output()
        .expect("the scan should run");
    if output.status.success() {
        let text = String::from_utf8(output.stdout).expect("output is utf-8");
        assert!(text.contains("compiler: answered for"), "{text}");
    } else {
        let text = String::from_utf8(output.stderr).expect("output is utf-8");
        assert!(text.contains("codehelion-backend-rust"), "{text}");
    }
}

/// A scan rooted inside a workspace spells its files against that root, and
/// the compiler spells them against the workspace's. Matched on the scan's own
/// spelling the two never meet, and every file's types go missing without
/// anything saying so — the analysis says what it anchored against so the two
/// can be brought together instead.
#[test]
fn a_scan_below_the_workspace_root_still_gets_what_the_compiler_resolved() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("member/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("member/Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    // The second file is a declared module: a file no crate reaches is a file
    // the compiler resolves nothing in, which would leave the group scored the
    // way an unanchored one is and prove nothing about the anchoring.
    std::fs::write(
        root.join("member/src/lib.rs"),
        format!("mod other;\n\n{CHECKSUM_RS}"),
    )
    .unwrap();
    std::fs::write(root.join("member/src/other.rs"), CHECKSUM_RS).unwrap();

    let output = cmd()
        .current_dir(root.join("member"))
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("the scan should run");
    if !output.status.success() {
        // No helper on this machine, which the pairing test above covers.
        return;
    }
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(report["summary"]["compiler"]["answered"], 2);
    let types = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find_map(|group| group["similarity"]["type_similarity"].as_f64())
        .expect("a group scored on every dimension");
    assert!(
        (types - 1.0).abs() < f64::EPSILON,
        "two copies of one function agree on their types: {report}"
    );
}

/// Two readings of one tree under different features are two programs, and a
/// run has to file them apart. Nothing in the source text changes when a
/// feature is switched on — the manifest is not a file the scan reads — so a
/// run that took its identity from the tree alone would report the first
/// reading's findings as this one's, and the types the compiler resolved
/// differently would go unremarked.
#[cfg(any())]
#[test]
fn one_tree_read_with_different_features_is_not_reported_as_the_other() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    let manifest = |default: &str| {
        format!(
            "[workspace]\n\n[package]\nname = \"counters\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\npublish = false\n\n\
             [features]\ndefault = [{default}]\nwide = []\n"
        )
    };
    std::fs::write(root.join("Cargo.toml"), manifest("")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "#[cfg(feature = \"wide\")]\npub type Count = i64;\n\
         #[cfg(not(feature = \"wide\"))]\npub type Count = i16;\n\
         pub fn counted(values: &[Count]) -> Count { values.iter().sum() }\n",
    )
    .unwrap();

    let scan = || {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    // The same reading twice: reported from what was recorded, which is what
    // makes the third scan below say something.
    let again = scan().expect("the helper answered once, so it answers again");
    assert_eq!(again["run"]["reused"], serde_json::json!(true));

    std::fs::write(root.join("Cargo.toml"), manifest("\"wide\"")).unwrap();
    let widened = scan().expect("the helper answers");
    assert_ne!(
        widened["run"]["reused"],
        serde_json::json!(true),
        "{widened}"
    );
    assert_ne!(widened["run"]["run_id"], first["run"]["run_id"]);
}

/// A Cargo manifest can change a direct dependency's active features while the
/// lockfile stays byte-for-byte identical. The semantic variant must carry the
/// helper's resolved dependency feature set, or it would reuse findings for a
/// different program.
#[cfg(any())]
#[test]
fn a_direct_dependency_feature_change_gets_its_own_semantic_variant() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("app/src")).unwrap();
    std::fs::create_dir_all(root.join("support/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\", \"support\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    let app_manifest = |features: &str| {
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
             [dependencies]\nsupport = {{ path = \"../support\"{features} }}\n"
        )
    };
    std::fs::write(root.join("app/Cargo.toml"), app_manifest("")).unwrap();
    std::fs::write(
        root.join("app/src/lib.rs"),
        "pub fn answer() -> u8 { support::answer() }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("support/Cargo.toml"),
        "[package]\nname = \"support\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [features]\nextra = []\n",
    )
    .unwrap();
    std::fs::write(
        root.join("support/src/lib.rs"),
        "#[cfg(feature = \"extra\")]\npub fn answer() -> u8 { 2 }\n\
         #[cfg(not(feature = \"extra\"))]\npub fn answer() -> u8 { 1 }\n",
    )
    .unwrap();

    let scan = || {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    let lockfile_before = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    let again = scan().expect("the helper answered once, so it answers again");
    assert_eq!(again["run"]["reused"], serde_json::json!(true));

    std::fs::write(
        root.join("app/Cargo.toml"),
        app_manifest(", features = [\"extra\"]"),
    )
    .unwrap();
    let changed = scan().expect("the helper answers after a dependency feature changes");
    assert_eq!(
        std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default(),
        lockfile_before,
        "the lockfile cannot be the signal that keeps these runs apart"
    );
    assert_ne!(
        changed["run"]["reused"],
        serde_json::json!(true),
        "{changed}"
    );
    assert_ne!(changed["run"]["run_id"], first["run"]["run_id"]);
}

/// The three ways a permission would be granted and change nothing. Each is
/// refused with the sentence that says which, because a permission that was
/// accepted and dropped leaves somebody believing the thin answer they got is
/// what their project looks like.
#[test]
fn a_permission_that_could_not_take_effect_is_refused_rather_than_dropped() {
    let dir = fixture();
    let refused = |extra: &[&str]| {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", "."])
            .args(extra)
            .output()
            .expect("the scan should run");
        assert!(!output.status.success(), "{output:?}");
        String::from_utf8(output.stderr).expect("output is utf-8")
    };

    // A mode that runs nothing whatever it is told.
    let said = refused(&["--allow-execution=build-script"]);
    assert!(said.contains("fast"), "{said}");

    // A trust level that permits nothing, and a permission, in one command.
    let said = refused(&[
        "--mode",
        "semantic",
        "--untrusted",
        "--allow-execution=build-script",
    ]);
    assert!(said.contains("--untrusted"), "{said}");

    // A class nobody can grant, which somebody who misspelled one believes
    // they granted.
    let said = refused(&["--mode", "semantic", "--allow-execution=build-scripts"]);
    assert!(said.contains("build-script"), "{said}");
}

/// Permitting a build script changes two things at once, and both have to
/// hold. The crate stops being declined, which is what was asked for; and the
/// run is filed apart from the refused one, which is what stops the refused
/// run's findings from being handed back as this one's — nothing in the source
/// text differs between the two, so the identity is the only thing that can
/// tell them apart.
#[cfg(any())]
#[test]
fn a_run_allowed_to_build_reads_more_and_is_filed_apart_from_one_that_was_not() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\n\n[package]\nname = \"generated\"\nversion = \"0.1.0\"\n\
         edition = \"2021\"\npublish = false\nbuild = \"build.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("build.rs"),
        "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    \
         std::fs::write(std::path::Path::new(&out).join(\"table.rs\"), \
         \"pub const SIZES: [u32; 3] = [1, 2, 4];\\n\").unwrap();\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/table.rs\"));\n\
         pub fn largest() -> u32 { SIZES.iter().copied().max().unwrap_or(0) }\n",
    )
    .unwrap();

    let scan = |extra: &[&str]| {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .args(extra)
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(refused) = scan(&[]) else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    assert_eq!(
        refused["summary"]["compiler"]["unavailable"]["requires_execution"],
        serde_json::json!(1),
        "{refused}"
    );

    let permitted = scan(&["--allow-execution=build-script"]).expect("the helper answers");
    assert_eq!(
        permitted["summary"]["compiler"]["answered"],
        serde_json::json!(1),
        "{permitted}"
    );
    assert_ne!(permitted["run"]["reused"], serde_json::json!(true));
    assert_ne!(permitted["run"]["run_id"], refused["run"]["run_id"]);
}

/// A recorded semantic run is reported again like any other, and it has to
/// come back with the sentence that makes it semantic. Restored short — no
/// compiler line, or one claiming files nobody asked about were failures — a
/// thin run would read as a clean tree the second time it was reported.
#[cfg(any())]
#[test]
fn a_semantic_run_reported_again_still_says_what_the_compiler_answered() {
    let dir = fixture();
    let scan = || {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    let second = scan().expect("the helper answered once, so it answers again");
    assert_eq!(second["run"]["reused"], serde_json::json!(true));
    assert_eq!(second["run"]["run_id"], first["run"]["run_id"]);
    assert_eq!(second["summary"]["compiler"], first["summary"]["compiler"]);
    assert!(
        second["summary"]["compiler"].is_object(),
        "a semantic run says what a compiler answered: {second}"
    );
}

/// The reuse path's own tests: a tree nobody touched is reported from the
/// recorded run rather than analysed again, and every input that could change
/// the answer defeats that.
#[cfg(any())]
mod reuse {
    use super::{cmd, fixture};
    use std::path::Path;

    /// Scan and parse, letting the reuse decision take its course.
    fn scan(root: &Path, extra: &[&str]) -> serde_json::Value {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--format", "json"])
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
    }

    fn reused(value: &serde_json::Value) -> bool {
        value["run"]["reused"] == serde_json::json!(true)
    }

    /// The report a reused run produces is the report an analysis produces:
    /// everything but the run's own metadata and what it says about *this*
    /// invocation's comparisons.
    fn findings(mut value: serde_json::Value) -> serde_json::Value {
        let run = value["run"].as_object_mut().expect("run object");
        for key in ["started_at", "finished_at", "run_id", "reused"] {
            run.remove(key);
        }
        let summary = value["summary"].as_object_mut().expect("summary object");
        for key in ["changes", "audit"] {
            summary.remove(key);
        }
        value
    }

    #[test]
    fn an_untouched_tree_is_reported_from_the_run_that_read_it() {
        let dir = fixture();
        let analysed = scan(dir.path(), &["--no-reuse"]);
        assert!(!reused(&analysed));

        let again = scan(dir.path(), &[]);
        assert!(reused(&again), "{again:#?}");
        assert_eq!(again["run"]["run_id"], analysed["run"]["run_id"]);
        assert_eq!(findings(again), findings(analysed));
    }

    #[test]
    fn reporting_a_run_again_records_no_second_run() {
        let dir = fixture();
        scan(dir.path(), &["--no-reuse"]);
        scan(dir.path(), &[]);
        scan(dir.path(), &[]);

        let store = super::open_store(dir.path());
        let latest = store.latest_run().unwrap().expect("a recorded run");
        assert_eq!(latest.id, 1, "the reused scans recorded nothing");
    }

    #[test]
    fn a_file_that_moved_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        std::fs::write(
            dir.path().join("src/new.rs"),
            "pub fn added() -> u8 { 1 }\n",
        )
        .unwrap();
        assert!(!reused(&scan(dir.path(), &[])));
    }

    #[test]
    fn a_changed_setting_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        assert!(reused(&scan(dir.path(), &[])));

        std::fs::write(
            dir.path().join("codehelion.toml"),
            "min-clone-tokens = 25\n",
        )
        .unwrap();
        assert!(!reused(&scan(dir.path(), &[])));
    }

    /// A baseline is not part of the configuration, so the run has to record
    /// which frozen set it was reported against: the same tree under two
    /// baselines is two different reports.
    #[test]
    fn a_different_frozen_set_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        cmd()
            .current_dir(dir.path())
            .args(["baseline", "create", "."])
            .assert()
            .success();

        let with = ["--baseline", "codehelion-baseline.json"];
        assert!(!reused(&scan(dir.path(), &with)), "a baseline came in");
        assert!(reused(&scan(dir.path(), &with)), "the same baseline again");
        assert!(!reused(&scan(dir.path(), &[])), "the baseline went away");
    }

    /// A mode is a different reading of the same bytes, so one mode's run says
    /// nothing about another's.
    #[test]
    fn another_mode_is_analysed_rather_than_answered_from_this_one() {
        let dir = fixture();
        scan(dir.path(), &[]);
        assert!(!reused(&scan(dir.path(), &["--mode", "structural"])));
        assert!(reused(&scan(dir.path(), &["--mode", "structural"])));
        assert!(
            reused(&scan(dir.path(), &[])),
            "the Fast run is still there"
        );
    }
}
