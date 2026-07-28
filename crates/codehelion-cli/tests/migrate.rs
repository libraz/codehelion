//! End-to-end result-compatibility tests: what happens to a frozen judgement
//! and a recorded history when the rules that make identifiers change under
//! them.
//!
//! The rule change is a real one rather than a simulated version bump. The
//! literal-folding strategy is part of what a normalized content id *is*, so
//! switching it moves every Type-2 identifier in the tree while leaving the
//! build variant, the source and the duplication exactly as they were — which
//! is precisely the situation a migration exists for, reachable from
//! configuration.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_core::compat::Churn;
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A pair of functions that are copies once identifiers are renamed away.
///
/// Their literals are equal, so both strategies read them as one duplication;
/// what differs between the two runs is only the strategy label folded into
/// the content hash. That is the case the whole mechanism is for — the same
/// finding in the same place under a name nothing recorded before it can
/// spell.
const ALPHA_RS: &str = "pub fn alpha(data: &[u64], seed: u64) -> u64 {
    let mut acc = seed;
    let mut count = 0u64;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
        count += 1;
    }
    acc = acc ^ 0x5a5a;
    acc.wrapping_add(count)
}
";

const BETA_RS: &str = "pub fn beta(feed: &[u64], start: u64) -> u64 {
    let mut state = start;
    let mut seen = 0u64;
    for item in feed {
        state = state.wrapping_mul(31).wrapping_add(*item);
        seen += 1;
    }
    state = state ^ 0x5a5a;
    state.wrapping_add(seen)
}
";

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), BETA_RS).unwrap();
    dir
}

/// Write the configuration that decides how literals are folded, which is what
/// this file changes to move identifiers without touching the source.
fn set_literals(root: &Path, strategy: &str) {
    std::fs::write(
        root.join("codehelion.toml"),
        format!("literal-normalization = \"{strategy}\"\n"),
    )
    .unwrap();
}

/// Scan and record, whether or not the tree moved: a migration rewrites one
/// run's identifiers onto another's, so both have to exist as runs.
fn scan(root: &Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--format", "json", "--no-reuse"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("scan report is json")
}

fn scan_with_baseline(root: &Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--baseline",
            "codehelion-baseline.json",
            "--no-reuse",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("scan report is json")
}

fn create_baseline(root: &Path) {
    cmd()
        .current_dir(root)
        .args(["baseline", "create", "."])
        .assert()
        .success();
}

fn baseline_file(root: &Path) -> Value {
    let text = std::fs::read_to_string(root.join("codehelion-baseline.json")).unwrap();
    serde_json::from_str(&text).expect("baseline is json")
}

/// The group ids one scan report holds.
fn group_ids(report: &Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["fingerprint"].as_str().unwrap().to_string())
        .collect()
}

/// The finding ids one scan report holds — one per occurrence, which is what
/// a user's suppressions and history are written in terms of.
fn finding_ids(report: &Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["members"].as_array().unwrap())
        .map(|member| member["finding_id"].as_str().unwrap().to_string())
        .collect()
}

/// Audit the two newest runs, listing the groups that did not move too.
fn audit_json(root: &Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["audit", ".", "--format", "json", "--show-unchanged"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("audit report is json")
}

#[test]
fn changing_how_literals_fold_moves_every_identifier_and_says_so() {
    let dir = fixture();
    let root = dir.path();
    set_literals(root, "preserve");
    let before = scan(root);
    create_baseline(root);
    assert!(!group_ids(&before).is_empty(), "the fixture has a clone");

    set_literals(root, "full");
    let after = scan_with_baseline(root);

    // Same source, same duplication, no id in common.
    assert_ne!(group_ids(&before), group_ids(&after));
    let baseline = &after["summary"]["baseline"];
    assert_eq!(baseline["matched"], 0);
    let mismatch = baseline["mismatch"].as_str().expect("a stated mismatch");
    assert!(mismatch.contains("literals"), "{mismatch}");
    // A suppression that silently covers nothing looks exactly like one that
    // worked, so the report has to name the way out.
    assert!(mismatch.contains("baseline migrate"), "{mismatch}");
}

#[test]
fn migrating_a_baseline_carries_the_judgement_onto_the_new_identifiers() {
    let dir = fixture();
    let root = dir.path();
    set_literals(root, "preserve");
    scan(root);
    create_baseline(root);
    let frozen = baseline_file(root);
    let frozen_ids: Vec<&str> = frozen["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["group"].as_str().unwrap())
        .collect();

    set_literals(root, "full");
    let after = scan_with_baseline(root);
    assert_eq!(after["summary"]["baseline"]["matched"], 0);

    let output = cmd()
        .current_dir(root)
        .args(["baseline", "migrate", "."])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("version drift: literals"), "{text}");
    assert!(text.contains("entries carried"), "{text}");

    let migrated = baseline_file(root);
    let migrated_ids: Vec<&str> = migrated["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["group"].as_str().unwrap())
        .collect();
    assert_eq!(migrated_ids.len(), frozen_ids.len());
    assert_ne!(migrated_ids, frozen_ids, "the ids moved");
    assert_eq!(migrated["schema_version"], 2);
    // The file now describes the run it was rewritten onto; a file claiming to
    // describe the run whose language it no longer speaks would fail the very
    // check this exists to satisfy.
    let recorded = migrated["migrations"].as_array().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(
        recorded[0]["drift"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("literals"))
    );

    // And the judgement suppresses again.
    let again = scan_with_baseline(root);
    assert_eq!(
        again["summary"]["baseline"]["matched"],
        u64::try_from(migrated_ids.len()).unwrap()
    );
    assert!(again["summary"]["baseline"]["mismatch"].is_null());
}

#[test]
fn a_migration_says_what_it_would_do_before_it_does_it() {
    let dir = fixture();
    let root = dir.path();
    set_literals(root, "preserve");
    scan(root);
    create_baseline(root);
    let before = baseline_file(root);

    set_literals(root, "full");
    scan(root);

    let output = cmd()
        .current_dir(root)
        .args(["baseline", "migrate", ".", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("would rewrite"), "{text}");
    assert_eq!(baseline_file(root), before, "a dry run wrote nothing");
}

#[test]
fn a_history_reaches_back_past_the_change_after_a_migration() {
    let dir = fixture();
    let root = dir.path();
    set_literals(root, "preserve");
    scan(root);
    scan(root);
    let established = audit_json(root);
    let entries = established["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{established:#}");
    assert_eq!(entries[0]["state"], "unchanged");
    let history = entries[0]["lineage"].as_str().unwrap().to_string();

    set_literals(root, "full");
    scan(root);
    // No baseline: a project that froze nothing still has a history worth
    // carrying, and the command says which two runs it read.
    cmd()
        .current_dir(root)
        .args(["baseline", "migrate", "."])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "carrying the recorded history only",
        ))
        .stdout(predicates::str::contains(
            "1 of 1 groups in run 3 now continue a history from before the change",
        ));

    // The run after the migration compares against a migrated result. The
    // duplication reads as the long-standing finding it is rather than as
    // something that arrived with the release, and it says so by belonging to
    // the history it belonged to before the rules moved.
    scan(root);
    let after = audit_json(root);
    let entries = after["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{after:#}");
    assert_eq!(entries[0]["state"], "unchanged");
    assert_eq!(entries[0]["lineage"].as_str().unwrap(), history);
}

#[test]
fn two_results_that_name_findings_differently_are_not_compared() {
    let dir = fixture();
    let root = dir.path();
    set_literals(root, "preserve");
    scan(root);
    set_literals(root, "full");
    scan(root);

    // Every group of one side would read as gone and every group of the other
    // as new. That is not a comparison with a caveat, it is two vocabularies,
    // and reporting it as churn would be the tool lying about the code.
    cmd()
        .current_dir(root)
        .args(["audit", "."])
        .assert()
        .failure()
        .stderr(predicates::str::contains("name their findings differently"))
        .stderr(predicates::str::contains("baseline migrate"));
}

#[test]
fn changing_only_the_order_findings_are_read_in_moves_no_identifier() {
    let dir = fixture();
    let root = dir.path();
    let before = scan(root);

    // The ranking recipe is recorded beside every run, and it is the one
    // recorded component that decides nothing about what a finding is. A build
    // that treated any version difference alike would throw away the whole
    // baseline over this.
    std::fs::write(
        root.join("codehelion.toml"),
        "[priority]\nmaintenance-risk = 5\nrefactoring-ease = 0\n",
    )
    .unwrap();
    let after = scan(root);

    // Churn, as the compatibility rules define it: a change declared to move
    // no identifier that moves one is a mistake in the declaration, and this
    // is what makes the declaration checkable rather than a promise.
    let churn = Churn::between(
        finding_ids(&before).iter().map(String::as_str),
        finding_ids(&after).iter().map(String::as_str),
    );
    assert!(churn.before > 0, "the fixture reports findings at all");
    assert!(
        churn.is_stable(),
        "a reporting change moved {} of {} finding ids",
        churn.lost(),
        churn.before
    );
    assert!(churn.rate().abs() < f64::EPSILON);
    assert_eq!(group_ids(&before), group_ids(&after));

    let drift = audit_json(root);
    let listed: Vec<&str> = drift["version_drift"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap())
        .collect();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert!(listed[0].starts_with("ranking "), "{listed:?}");
    assert!(listed[0].ends_with("(reporting)"), "{listed:?}");
    // Nothing moved, so the comparison across the change has nothing to report
    // beyond the group still being there.
    assert_eq!(drift["entries"][0]["state"], "unchanged");
}
