//! End-to-end Structural-mode scan tests: the compiled binary against real
//! fixture trees, with the recorded snapshot verified through the store's
//! query layer.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

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
    assert_eq!(similarity.weight_version, "structural-verify-v2");
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
        .stdout(predicate::str::contains("type-3"))
        // The evidence the scan reported is reachable from the occurrence.
        .stdout(predicate::str::contains("2 instances"))
        .stdout(predicate::str::contains("similarity: composite"))
        .stdout(predicate::str::contains("type n/a"))
        .stdout(predicate::str::contains("confidence "));

    let output = cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex, "--format", "json"])
        .output()
        .expect("run explain");
    let detail: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    let similarity = &detail["group"]["similarity"];
    assert_eq!(similarity["weight_version"], "structural-verify-v2");
    assert!(similarity["type_similarity"].is_null());
    assert!(similarity["confidence_band"].is_string());
    assert_eq!(detail["group"]["members"], 2);
}

#[test]
fn explain_reports_a_fast_finding_without_inventing_dimensions() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();

    let finding_hex = {
        let store = open_store(dir.path());
        let run = store.latest_run().unwrap().expect("a recorded run");
        let groups = store.run_groups(run.id).unwrap();
        groups[0].members[0].finding_hex.clone()
    };
    let output = cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex, "--format", "json"])
        .output()
        .expect("run explain");
    let detail: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    // Fast mode scores no dimensions, so the breakdown is absent rather than
    // filled in.
    assert!(detail["group"]["similarity"].is_null());
    assert!(detail["group"]["suppressed"].is_null());
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

/// Two routines that are nothing but macro invocations: a duplicate a reader
/// would not act on, and larger than the real clone above so ranking, not
/// size, decides where it lands.
const DUMP_A: &str = "pub fn dump_config(config: &Config) {
    println!(\"a: {}\", config.a);
    println!(\"b: {}\", config.b);
    println!(\"c: {}\", config.c);
    println!(\"d: {}\", config.d);
    println!(\"e: {}\", config.e);
    println!(\"f: {}\", config.f);
    println!(\"g: {}\", config.g);
    println!(\"h: {}\", config.h);
}
";

const DUMP_B: &str = "pub fn dump_limits(limits: &Limits) {
    println!(\"a: {}\", limits.a);
    println!(\"b: {}\", limits.b);
    println!(\"c: {}\", limits.c);
    println!(\"d: {}\", limits.d);
    println!(\"e: {}\", limits.e);
    println!(\"f: {}\", limits.f);
    println!(\"g: {}\", limits.g);
    println!(\"h: {}\", limits.h);
}
";

fn fixture_with_boilerplate() -> tempfile::TempDir {
    let dir = fixture();
    std::fs::write(dir.path().join("src/dump_a.rs"), DUMP_A).unwrap();
    std::fs::write(dir.path().join("src/dump_b.rs"), DUMP_B).unwrap();
    dir
}

#[test]
fn boilerplate_is_named_and_ranked_below_code_that_carries_behaviour() {
    let dir = fixture_with_boilerplate();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let position = |category: serde_json::Value| {
        groups
            .iter()
            .position(|group| group["boilerplate"] == category)
            .unwrap_or_else(|| panic!("a group with boilerplate {category}"))
    };
    let boilerplate = position(serde_json::json!("macro-repetition"));
    let behaviour = position(serde_json::Value::Null);
    assert!(
        behaviour < boilerplate,
        "the gapped clone outranks the larger run of macro invocations"
    );
    // Ranked down, not hidden, and its size is reported unchanged: the
    // ranking moved, the measurements did not.
    assert_eq!(groups[boilerplate]["suppressed"], serde_json::Value::Null);
    assert!(
        groups[boilerplate]["priority"]["value"].as_f64().unwrap()
            > groups[behaviour]["priority"]["value"].as_f64().unwrap()
    );

    // The classifier's rules are versioned like every other detector.
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "boilerplate")
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("macro-repetition")),
        "the classification is recorded, not just displayed"
    );
}

#[test]
fn a_hidden_boilerplate_category_is_recorded_with_the_rule_that_hid_it() {
    let dir = fixture_with_boilerplate();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression.boilerplate]\nmacro-repetition = \"hide\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("dump_config").not());

    // Hidden, not deleted: the finding names the rule that hid it.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("ast_pattern")),
    );
    assert!(
        store
            .run_groups(run.id)
            .unwrap()
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("macro-repetition"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[suppressed: boilerplate: macro-repetition]",
        ));
}

#[test]
fn a_symbol_glob_hides_a_group_only_when_it_names_every_member() {
    let dir = fixture();
    // beta is the gapped copy of alpha; naming one of the two leaves the
    // duplication actionable.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"beta\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"))
        .stdout(predicate::str::contains("src/a.rs"));

    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"alpha\", \"beta\"]\n",
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
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("symbol_pattern"))
    );
}

#[test]
fn a_clone_id_hides_exactly_the_group_it_names() {
    let dir = fixture();
    let report = scan_json(dir.path());
    let fingerprint = report["groups"][0]["fingerprint"]
        .as_str()
        .expect("a detected group")
        .to_string();

    // An id that identifies no group changes nothing.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nclone-ids = [\"deadbeefdeadbeef\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"));

    // A prefix of the reported id hides that group, and says so.
    let prefix = &fingerprint[..12];
    std::fs::write(
        dir.path().join("codehelion.toml"),
        format!("[suppression]\nclone-ids = [\"{prefix}\"]\n"),
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains(fingerprint.as_str()).not());

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("stable_clone_id"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "[suppressed: clone id {prefix}]"
        )));
}

#[test]
fn a_clone_id_that_could_not_identify_a_group_fails_the_scan() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nclone-ids = [\"abc\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shorter than"));
}
