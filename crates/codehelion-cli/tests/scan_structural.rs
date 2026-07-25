//! End-to-end Structural-mode scan tests: the compiled binary against real
//! fixture trees, with the recorded snapshot verified through the store's
//! query layer.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_store::Store;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// The original function.
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

/// A consistently renamed copy carrying one extra statement: a gapped
/// (Type-3) clone that Fast mode cannot recover.
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

/// An unrelated function, which must stay out of the group.
const OTHER_RS: &str = "pub fn label(name: &str) -> usize {
    let trimmed = name.trim();
    let width = trimmed.chars().count();
    for _ in 0..width {
        if width > 3 {
            return width;
        }
    }
    return width.saturating_mul(2);
}
";

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), GAPPED_RS).unwrap();
    std::fs::write(root.join("src/other.rs"), OTHER_RS).unwrap();
    dir
}

fn open_store(root: &Path) -> Store {
    Store::open(&root.join(".codehelion/audit.db")).expect("open audit db")
}

/// Run `scan --mode structural --format json` in `root` and parse the
/// produced document.
fn scan_json(root: &Path) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

#[test]
fn a_gapped_clone_is_detected_and_recorded_with_its_evidence() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "codehelion scan (structural mode)",
        ))
        .stdout(predicate::str::contains("type-3 1"))
        .stdout(predicate::str::contains("similarity: composite"))
        // The dimension the mode cannot measure is named, not guessed.
        .stdout(predicate::str::contains("type n/a"))
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(run.analysis_mode, "structural");

    let groups = store.run_groups(run.id).unwrap();
    assert_eq!(groups.len(), 1, "one gapped group");
    let group = &groups[0];
    assert_eq!(group.clone_type, "type-3");
    assert!(group.members.iter().any(|m| m.file_path == "src/a.rs"));
    assert!(group.members.iter().any(|m| m.file_path == "src/b.rs"));
    assert!(
        group.members.iter().all(|m| m.file_path != "src/other.rs"),
        "the unrelated function stays out"
    );
    // Content entropy is measured, not defaulted.
    assert!(group.entropy_bits > 1.0);

    let similarity = group
        .similarity
        .as_ref()
        .expect("a structural group carries its breakdown");
    assert_eq!(similarity.weight_version, "structural-verify-v0");
    assert!(similarity.composite > 0.6);
    assert!(similarity.min_pairwise > 0.6);
    assert!(
        similarity.type_similarity.is_none(),
        "types are unavailable in this mode and stay absent"
    );

    // Every finding starts in the `new` audit state, as in Fast mode.
    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f.audit_state == "new"));
}

#[test]
fn json_reports_carry_the_breakdown_and_stay_deterministic() {
    let dir = fixture();
    let mut documents = Vec::new();
    for _ in 0..2 {
        let mut value = scan_json(dir.path());
        let run = value["run"].as_object_mut().unwrap();
        for key in ["started_at", "finished_at", "run_id"] {
            run.insert(key.to_string(), serde_json::Value::Null);
        }
        documents.push(value);
    }
    assert_eq!(documents[0], documents[1], "reruns agree token for token");

    let value = &documents[0];
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["run"]["mode"], "structural");
    assert_eq!(value["run"]["build_variant"]["mode"], "structural");
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "verify-weights")
    );
    assert_eq!(value["summary"]["groups"]["type_3"], 1);

    let group = &value["groups"][0];
    assert_eq!(group["clone_type"], "type-3");
    assert_eq!(group["members"][0]["canonical"], true);
    assert_eq!(
        group["similarity"]["type_similarity"],
        serde_json::Value::Null
    );
    assert!(group["similarity"]["composite"].as_f64().unwrap() > 0.6);
    assert!(
        ["high", "medium", "low"]
            .contains(&group["similarity"]["confidence_band"].as_str().unwrap())
    );
}

#[test]
fn structural_results_are_a_distinct_build_variant_from_fast() {
    let dir = fixture();
    for mode in ["fast", "structural"] {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode])
            .assert()
            .success();
    }
    let store = open_store(dir.path());
    let fast = store.run_groups(1).unwrap();
    let structural = store.run_groups(2).unwrap();

    // Fast recovers only the identical statement run the two functions
    // share, as a partial Type-2 fragment; it reports no gapped clone and
    // measures no breakdown.
    assert!(fast.iter().all(|group| group.clone_type == "type-2"));
    assert!(fast.iter().all(|group| group.similarity.is_none()));

    // Structural judges the whole units and reports the gapped clone, with
    // larger members than the fragment Fast matched.
    assert_eq!(structural.len(), 1);
    assert_eq!(structural[0].clone_type, "type-3");
    let fast_tokens = fast[0].members[0].token_count;
    assert!(
        structural[0].members[0].token_count > fast_tokens,
        "whole units, not the shared fragment"
    );

    // Two variants, two identities: the results never share a fingerprint.
    let fast_ids: Vec<&String> = fast.iter().map(|g| &g.fingerprint_hex).collect();
    assert!(
        structural
            .iter()
            .all(|group| !fast_ids.contains(&&group.fingerprint_hex))
    );
    let latest = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(latest.analysis_mode, "structural");
}

#[test]
fn rescans_reuse_stable_identifiers() {
    let dir = fixture();
    for _ in 0..2 {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", "structural"])
            .assert()
            .success();
    }
    let store = open_store(dir.path());
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
fn explain_resolves_a_structural_finding() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
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
        .stdout(predicate::str::contains(&file_path))
        .stdout(predicate::str::contains("type-3"));
}

#[test]
fn path_suppression_hides_but_records_structural_findings() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/**\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/a.rs").not());

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("path_glob")),
        "the finding is hidden, not deleted"
    );
}

#[test]
fn the_scan_needs_no_executables_and_no_network() {
    let dir = fixture();
    // With an empty PATH nothing can be spawned, and no proxy is reachable:
    // a scan that still succeeds ran entirely in process, reading files only.
    cmd()
        .current_dir(dir.path())
        .env("PATH", "")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("type-3 1"));
}
