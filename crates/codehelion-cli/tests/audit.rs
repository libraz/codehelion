//! End-to-end audit tests: the compiled binary over a tree that is edited
//! between scans, checking that each of the eight states is reached by the
//! edit that should reach it.
//!
//! The edits are the ones a reviewer would recognise — rename a file, add a
//! copy, delete a copy, change one copy, extract a shared helper — and each
//! test asserts the state and the evidence, not the wording.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

const CHECKSUM_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^ 0x5a5a
}
";

/// A function with distinct control flow, and a gapped copy of it: two
/// members with two different contents, which is what divergence needs to be
/// visible at all.
const ALPHA_RS: &str = "pub fn alpha(data: &[u32]) -> u32 {
    let mut acc = 0u32;
    let mut count = 0u32;
    for value in data {
        if *value > 10 {
            acc = acc.wrapping_add(*value);
        } else {
            acc = acc.wrapping_sub(1);
        }
        count += 1;
    }
    acc = acc.wrapping_mul(3);
    return acc + count;
}
";

const GAPPED_RS: &str = "pub fn beta(feed: &[u32]) -> u32 {
    let mut state = 3u32;
    let mut seen = 7u32;
    for item in feed {
        if *item > 99 {
            state = state.wrapping_add(*item);
        } else {
            state = state.wrapping_sub(2);
        }
        seen += 4;
    }
    state = state.wrapping_mul(8);
    let extra = state ^ seen;
    return state + seen + extra;
}
";

/// The gapped copy edited once more: still the same shape, no longer the same
/// content.
const DRIFTED_RS: &str = "pub fn beta(feed: &[u32]) -> u32 {
    let mut state = 5u32;
    let mut seen = 11u32;
    for item in feed {
        if *item > 77 {
            state = state.wrapping_add(*item);
        } else {
            state = state.wrapping_sub(6);
        }
        seen += 9;
    }
    state = state.wrapping_mul(2);
    let extra = state ^ seen;
    return state + seen + extra;
}
";

/// A function sharing nothing structural with the checksum family, so a pair
/// of these forms its own group rather than joining an existing one.
const FORMAT_RS: &str = "pub fn describe_entry(name: &str, size: usize) -> String {
    let mut text = String::new();
    text.push_str(name);
    text.push(':');
    text.push(' ');
    text.push_str(&size.to_string());
    text
}
";

/// A tree holding exactly one clone pair.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    dir
}

fn scan(root: &Path) {
    cmd()
        .current_dir(root)
        .args(["scan", "."])
        .assert()
        .success();
}

fn scan_structural(root: &Path) {
    cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success();
}

/// Scan, then audit the latest run against the one before it.
fn audit_json(root: &Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["audit", ".", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("audit report is json")
}

/// The states the report holds, in the order it lists them.
fn states(report: &Value) -> Vec<String> {
    report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["state"].as_str().unwrap().to_string())
        .collect()
}

fn entry<'a>(report: &'a Value, state: &str) -> &'a Value {
    report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["state"] == state)
        .unwrap_or_else(|| panic!("no {state} entry in {report:#}"))
}

#[test]
fn a_tree_nobody_touched_reports_nothing_and_says_so() {
    let dir = fixture();
    scan(dir.path());
    scan(dir.path());

    let report = audit_json(dir.path());
    // Unchanged groups are counted but not listed: an audit is about what
    // moved, and the tree that did not move is the ordinary case.
    assert!(states(&report).is_empty());
    assert_eq!(report["summary"][0]["state"], "unchanged");
    assert_eq!(report["summary"][0]["count"], 1);

    let listed = cmd()
        .current_dir(dir.path())
        .args(["audit", ".", "--format", "json", "--show-unchanged"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: Value = serde_json::from_slice(&listed).unwrap();
    assert_eq!(states(&listed), vec!["unchanged"]);
}

#[test]
fn moving_a_file_moves_the_finding_rather_than_replacing_it() {
    let dir = fixture();
    scan(dir.path());
    std::fs::rename(dir.path().join("src/b.rs"), dir.path().join("src/moved.rs")).unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert_eq!(states(&report), vec!["moved"]);
    let moved = entry(&report, "moved");
    // The same duplication at a new address: same group, same members.
    assert_eq!(moved["group"], moved["previous_group"]);
    assert_eq!(moved["members"], 2);
    let relocation = &moved["relocations"][0];
    assert_eq!(relocation["from"]["file"], "src/b.rs");
    assert_eq!(relocation["to"]["file"], "src/moved.rs");
}

#[test]
fn a_comment_added_above_a_clone_moves_no_line_that_matters() {
    let dir = fixture();
    scan(dir.path());
    // Every line of the clone shifts down. Nothing about the duplication
    // changed, and a comparison that read line numbers would say otherwise.
    std::fs::write(
        dir.path().join("src/b.rs"),
        format!("// one\n// two\n// three\n{CHECKSUM_RS}"),
    )
    .unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert!(states(&report).is_empty(), "{report:#}");
}

#[test]
fn a_third_copy_expands_the_group_it_joined() {
    let dir = fixture();
    scan(dir.path());
    std::fs::write(dir.path().join("src/c.rs"), CHECKSUM_RS).unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert_eq!(states(&report), vec!["expanded"]);
    let expanded = entry(&report, "expanded");
    assert_eq!(expanded["members"], 3);
    assert_eq!(expanded["previous_members"], 2);
    assert_eq!(expanded["occurrences"].as_array().unwrap().len(), 3);
}

#[test]
fn deleting_one_copy_of_three_reduces_the_group() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/c.rs"), CHECKSUM_RS).unwrap();
    scan(dir.path());
    std::fs::remove_file(dir.path().join("src/c.rs")).unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert_eq!(states(&report), vec!["reduced"]);
    assert_eq!(entry(&report, "reduced")["members"], 2);
    assert_eq!(entry(&report, "reduced")["previous_members"], 3);
}

#[test]
fn editing_one_copy_of_a_gapped_pair_reports_the_copies_drifting_apart() {
    // Divergence needs members that were never byte-identical to begin with:
    // an exact clone group holds one content between all its members, so
    // editing one takes it out of the group rather than changing what the
    // group holds. A gapped pair holds two contents, and this is what happens
    // when one of them is edited further.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), GAPPED_RS).unwrap();
    scan_structural(root);
    std::fs::write(root.join("src/b.rs"), DRIFTED_RS).unwrap();
    scan_structural(root);

    let report = audit_json(root);
    assert!(
        states(&report).contains(&"diverged".to_string()),
        "{report:#}"
    );
    let diverged = entry(&report, "diverged");
    assert_eq!(diverged["members"], diverged["previous_members"]);
    assert_ne!(diverged["group"], diverged["previous_group"]);
    // It kept its history rather than starting one: one of the two contents
    // is still there, which is the whole connection.
    assert_eq!(diverged["shared_content"], 1);
    assert!((diverged["overlap"].as_f64().unwrap() - 0.5).abs() < 1e-9);
}

#[test]
fn extracting_the_duplication_away_resolves_it() {
    let dir = fixture();
    scan(dir.path());
    std::fs::remove_file(dir.path().join("src/b.rs")).unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert_eq!(states(&report), vec!["resolved"]);
    let resolved = entry(&report, "resolved");
    assert!(resolved["group"].is_null());
    assert_eq!(resolved["previous_members"], 2);
}

#[test]
fn duplication_written_after_the_last_audit_is_the_only_thing_reported_new() {
    let dir = fixture();
    scan(dir.path());
    std::fs::write(dir.path().join("src/x.rs"), FORMAT_RS).unwrap();
    std::fs::write(dir.path().join("src/y.rs"), FORMAT_RS).unwrap();
    scan(dir.path());

    let report = audit_json(dir.path());
    assert_eq!(states(&report), vec!["new"]);
    let fresh = entry(&report, "new");
    assert!(fresh["previous_group"].is_null());
    assert_eq!(fresh["members"], 2);
    let files: Vec<&str> = fresh["occurrences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|place| place["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["src/x.rs", "src/y.rs"]);
}

#[test]
fn a_scan_says_what_became_of_the_duplication_without_being_asked() {
    let dir = fixture();
    scan(dir.path());
    std::fs::write(dir.path().join("src/x.rs"), FORMAT_RS).unwrap();
    std::fs::write(dir.path().join("src/y.rs"), FORMAT_RS).unwrap();

    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("audit since run 1: 1 new"))
        .stdout(predicate::str::contains("1 unchanged"));
}

#[test]
fn the_recorded_state_is_what_the_comparison_settled_on() {
    let dir = fixture();
    scan(dir.path());
    std::fs::write(dir.path().join("src/c.rs"), CHECKSUM_RS).unwrap();
    scan(dir.path());

    let store =
        codehelion_store::Store::open(&dir.path().join(".codehelion/audit.db")).expect("open db");
    let root = dir.path().canonicalize().unwrap();
    let runs = store
        .completed_runs(&root.to_string_lossy(), 2)
        .expect("runs");
    let findings = store.run_findings(runs[0].id).expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].audit_state, "expanded");
    // The first run had nothing behind it, and says so.
    let first = store.run_findings(runs[1].id).expect("findings");
    assert_eq!(first[0].audit_state, "new");
}

#[test]
fn an_exported_report_stands_in_for_the_run_it_came_from() {
    let dir = fixture();
    let export = dir.path().join("before.json");
    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--output",
            export.to_str().unwrap(),
        ])
        .assert()
        .success();
    std::fs::write(dir.path().join("src/c.rs"), CHECKSUM_RS).unwrap();
    scan(dir.path());

    let output = cmd()
        .current_dir(dir.path())
        .args([
            "audit",
            ".",
            "--previous",
            export.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(states(&report), vec!["expanded"]);
    assert_eq!(report["previous"]["source"], export.display().to_string());
}

#[test]
fn results_from_different_settings_are_refused_rather_than_compared() {
    let dir = fixture();
    let export = dir.path().join("fast.json");
    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--output",
            export.to_str().unwrap(),
        ])
        .assert()
        .success();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args(["audit", ".", "--previous", export.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not comparable"))
        .stderr(predicate::str::contains("build variant"));
}

#[test]
fn one_scan_is_not_a_history_and_the_message_says_which() {
    let dir = fixture();
    scan(dir.path());

    cmd()
        .current_dir(dir.path())
        .arg("audit")
        .assert()
        .failure()
        .stderr(predicate::str::contains("only one scan"))
        .stderr(predicate::str::contains("nothing to compare"));
}

#[test]
fn gating_on_new_duplication_ignores_duplication_that_only_moved() {
    let dir = fixture();
    scan(dir.path());
    std::fs::rename(dir.path().join("src/b.rs"), dir.path().join("src/moved.rs")).unwrap();
    scan(dir.path());
    cmd()
        .current_dir(dir.path())
        .args(["audit", ".", "--fail-on-new"])
        .assert()
        .success();

    std::fs::write(dir.path().join("src/x.rs"), FORMAT_RS).unwrap();
    std::fs::write(dir.path().join("src/y.rs"), FORMAT_RS).unwrap();
    scan(dir.path());
    cmd()
        .current_dir(dir.path())
        .args(["audit", ".", "--fail-on-new"])
        .assert()
        .code(3);
}

#[test]
fn the_text_view_leads_with_what_needs_attention() {
    let dir = fixture();
    scan(dir.path());
    std::fs::write(dir.path().join("src/x.rs"), FORMAT_RS).unwrap();
    std::fs::write(dir.path().join("src/y.rs"), FORMAT_RS).unwrap();
    scan(dir.path());

    cmd()
        .current_dir(dir.path())
        .args(["audit", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 new, 1 unchanged"))
        .stdout(predicate::str::contains("new:"))
        .stdout(predicate::str::contains("src/x.rs describe_entry"));
}
