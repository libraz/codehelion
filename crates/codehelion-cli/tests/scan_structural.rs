//! End-to-end Structural-mode scan tests: the compiled binary against real
//! fixture trees, with the recorded snapshot verified through the store's
//! query layer.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
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
///
/// Always analyses: these tests are about what the analysis produces, and a
/// scan that reports a recorded run again would be testing the database
/// instead. The reuse path has its own tests.
fn scan_json(root: &Path) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--format",
            "json",
            "--no-reuse",
        ])
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
    assert_eq!(similarity.weight_version, "structural-verify-v4");
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
        // The second run knows a first run happened. That is the comparison
        // working, not the findings moving.
        let summary = value["summary"].as_object_mut().unwrap();
        for key in ["changes", "audit"] {
            summary.insert(key.to_string(), serde_json::Value::Null);
        }
        documents.push(value);
    }
    assert_eq!(documents[0], documents[1], "reruns agree token for token");

    let value = &documents[0];
    assert_eq!(value["schema_version"], 2);
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
fn a_source_the_parser_could_not_follow_is_reported_as_such() {
    // An error-tolerant parser keeps going, so a file it could not read still
    // reaches detection and still contributes units. Without this count a
    // scan that understood a fraction of a project is indistinguishable from
    // one that understood all of it and found little.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::write(root.join("good.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("broken.rs"), "pub fn wrecked( { let x = ;;; \n").unwrap();

    let value = scan_json(root);
    let unparsed = &value["summary"]["unparsed"];
    assert_eq!(unparsed["files"], 1, "only the broken file is counted");
    assert!(unparsed["tokens"].as_u64().unwrap() > 0);
    let share = unparsed["share"].as_f64().unwrap();
    assert!((0.0..1.0).contains(&share), "a share of the scan: {share}");

    cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("the parser could not follow"));
}

#[test]
fn a_scan_the_parser_followed_says_nothing_about_coverage() {
    let dir = fixture();
    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["unparsed"]["files"], 0);
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("the parser could not follow").not());
}

#[test]
fn both_modes_read_a_bare_header_the_same_way() {
    // The header grammar is settled once, during discovery, and Structural
    // rebuilds its own variant afterwards. If it rebuilt that variant from
    // configuration alone it would lose the setting and hand `.h` files to a
    // different frontend than the one that decided the counts.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::write(root.join("a.cpp"), "int a() { return 1; }\n").unwrap();
    std::fs::write(root.join("b.cpp"), "int b() { return 2; }\n").unwrap();
    std::fs::write(root.join("shared.h"), "class Widget { int n_ = 0; };\n").unwrap();

    for mode in ["fast", "structural"] {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", mode, "--format", "json"])
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
        assert_eq!(
            value["run"]["build_variant"]["headers"], "cpp",
            "{mode} mode read the header as something else"
        );
        assert_eq!(value["summary"]["files"]["c"], 0, "in {mode} mode");
        assert_eq!(value["summary"]["files"]["cpp"], 3, "in {mode} mode");
    }
}

#[test]
fn rescans_reuse_stable_identifiers() {
    let dir = fixture();
    for _ in 0..2 {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", "structural", "--no-reuse"])
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
    assert_eq!(similarity["weight_version"], "structural-verify-v4");
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

/// Two folds of the same shape, one per integer width — what a language
/// without a way to write the family once forces an author to type twice.
/// Every name that differs does so by the width, and no constant moves.
const FOLD_32: &str = "pub fn fold_u32(bytes: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    for byte in bytes {
        acc = acc.rotate_left(5);
        acc ^= u32::from(*byte);
        acc = acc.wrapping_mul(31);
    }
    acc
}
";

const FOLD_64: &str = "pub fn fold_u64(bytes: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    for byte in bytes {
        acc = acc.rotate_left(5);
        acc ^= u64::from(*byte);
        acc = acc.wrapping_mul(31);
    }
    acc
}
";

#[test]
fn a_family_written_once_per_width_is_named_and_withheld() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/fold32.rs"), FOLD_32).unwrap();
    std::fs::write(dir.path().join("src/fold64.rs"), FOLD_64).unwrap();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let family = groups
        .iter()
        .find(|group| group["width_family"] == serde_json::json!(true))
        .expect("the two folds are one family");
    // Hidden, and the rule that hid it says which judgement it was rather
    // than leaving the reader to guess from the shape of the members.
    assert_eq!(family["suppressed"]["pattern"], "width-family");
    // Nothing else in the fixture reads as one: the claim is about these two
    // bodies, not about anything that merely looks alike.
    assert_eq!(
        groups
            .iter()
            .filter(|group| group["width_family"] == serde_json::json!(true))
            .count(),
        1
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored.iter().any(|group| group.width_family),
        "what the group is was recorded, not only what the report did with it"
    );
}

#[test]
fn one_member_that_is_a_plain_copy_stops_the_group_being_a_family() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/fold32.rs"), FOLD_32).unwrap();
    std::fs::write(dir.path().join("src/fold64.rs"), FOLD_64).unwrap();
    // The same routine again under a name that has nothing to do with a width.
    // Two of the three members are still a width apart; the group is not, and
    // hiding it would hide a copy somebody made by hand.
    std::fs::write(
        dir.path().join("src/digest.rs"),
        FOLD_32.replace("fold_u32", "digest_bytes"),
    )
    .unwrap();
    let value = scan_json(dir.path());

    let family = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["width_family"] == serde_json::json!(true));
    assert!(
        family.is_none(),
        "a group holding a hand-made copy is not one routine written per width"
    );
}

/// Two units whose answer a feature flag picks. Nothing in either body chooses
/// between the two returns, because the attribute that does never reaches the
/// IR — which is what makes them alike, and what makes the likeness worthless.
const FLAGGED_A: &str = "pub fn entries(map: &Map) -> usize {
    #[cfg(feature = \"ordered\")]
    return map.ordered_len();
    #[cfg(not(feature = \"ordered\"))]
    return map.plain_len();
}
";

const FLAGGED_B: &str = "pub fn slots(map: &Map) -> usize {
    #[cfg(feature = \"ordered\")]
    return map.ordered_slots();
    #[cfg(not(feature = \"ordered\"))]
    return map.plain_slots();
}
";

#[test]
fn a_body_the_build_configuration_answers_for_is_named_and_withheld() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/entries.rs"), FLAGGED_A).unwrap();
    std::fs::write(dir.path().join("src/slots.rs"), FLAGGED_B).unwrap();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let configured = groups
        .iter()
        .find(|group| group["boilerplate"] == serde_json::json!("configured-answer"))
        .expect("two bodies a feature flag answers for");
    assert!(
        configured["suppressed"].is_object(),
        "hidden by default, and the suppressed section still lists it"
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("configured-answer")),
        "what the group is was recorded, not only what the report did with it"
    );
}

#[test]
fn an_arm_that_does_work_is_not_the_configuration_answering() {
    let dir = fixture();
    // The same pair of arms, with one of them computing its answer. That work
    // is written once per configuration, which is duplication worth reading.
    let working = FLAGGED_A.replace(
        "    #[cfg(feature = \"ordered\")]",
        "    let scale = map.scale();\n    #[cfg(feature = \"ordered\")]",
    );
    std::fs::write(dir.path().join("src/entries.rs"), &working).unwrap();
    std::fs::write(
        dir.path().join("src/slots.rs"),
        working
            .replace("entries", "slots")
            .replace("_len", "_slots"),
    )
    .unwrap();
    let value = scan_json(dir.path());

    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["boilerplate"] != serde_json::json!("configured-answer")),
        "an arm that computes is not an answer the build picked"
    );
}

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

/// A rendering routine carrying a measurement loop.
const RENDER_RS: &str = "pub fn render_rows(rows: &[String], width: usize) -> String {
    let mut out = String::new();
    let mut index = 0usize;
    while index < rows.len() {
        out.push_str(&rows[index]);
        out.push('\\n');
        index += 1;
    }
    if out.is_empty() {
        return String::from(\"(empty)\");
    }
    out.push_str(\"---\");
    out.push('\\n');
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    out.push_str(&format!(\"{total} {widest} {width}\"));
    out.push('\\n');
    out.push_str(\"===\");
    out
}
";

/// An auditing routine that computes something else entirely, and carries a
/// verbatim copy of the measurement loop's body. The two functions are not
/// clones of each other; only that stretch is duplicated.
const AUDIT_RS: &str = "pub fn audit_entries(entries: &[String], limit: u64) -> u64 {
    let mut flagged = 0u64;
    match entries.first() {
        Some(first) if first.is_empty() => return 0,
        Some(_) => flagged += 1,
        None => return 0,
    }
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in entries {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    loop {
        if total <= widest {
            break;
        }
        total -= widest.max(1);
        flagged += 1;
    }
    if flagged > limit {
        flagged = limit;
    }
    flagged
}
";

/// A tree whose only duplication is a run shared by two unrelated functions.
fn run_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/render.rs"), RENDER_RS).unwrap();
    std::fs::write(root.join("src/audit.rs"), AUDIT_RS).unwrap();
    dir
}

#[test]
fn a_run_shared_by_unrelated_units_is_reported_as_a_run() {
    let dir = run_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        // The extent is stated: without it the entry reads as a duplicated
        // function, which neither occurrence is.
        .stdout(predicate::str::contains("type-1 run of 4 statements"))
        .stdout(predicate::str::contains(
            "src/audit.rs:11-14 (audit_entries)",
        ))
        .stdout(predicate::str::contains(
            "src/render.rs:17-20 (render_rows)",
        ))
        .stdout(predicate::str::contains(
            "1 of them are runs duplicated inside units that are not clones of each other",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["total"], 1);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 1);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 0);
    // Nothing longer covers this run, so nothing is left out on that account.
    assert_eq!(value["summary"]["groups"]["subsumed_runs"], 0);
    let group = &value["groups"][0];
    assert_eq!(group["scope"], "fragment");
    assert_eq!(group["statements"], 4);
    assert_eq!(group["clone_type"], "type-1");
    // Confirmed by content equality rather than scored across dimensions.
    assert_eq!(group["similarity"], serde_json::Value::Null);
    assert_eq!(group["confidence"], 1.0);
    let units: Vec<&str> = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["unit"].as_str().unwrap())
        .collect();
    assert_eq!(units, vec!["audit_entries", "render_rows"]);
}

#[test]
fn a_reported_run_is_recorded_against_the_units_that_host_it() {
    let dir = run_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success();

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let groups = store.run_groups(run.id).unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.member_scope, "fragment");
    assert_eq!(group.clone_type, "type-1");
    // Entropy is measured over the run's own tokens, not its host unit's.
    assert!(group.entropy_bits > 1.0);
    for member in &group.members {
        let host = member.unit_name.as_deref().expect("a host unit");
        assert!(host == "audit_entries" || host == "render_rows");
        // The anchor is the run, so it is a fraction of the unit it sits in.
        assert!(member.token_count < 60);
    }

    let finding = &group.members[0].finding_hex;
    cmd()
        .current_dir(dir.path())
        .args(["explain", finding])
        .assert()
        .success()
        // What the occurrence is, not just where: the unit is the host, and
        // the group is about the run inside it.
        .stdout(predicate::str::contains("duplicated run, type-1"))
        .stdout(predicate::str::contains("2 instances"));
}

#[test]
fn a_run_a_group_already_covers_is_folded_into_it_and_counted() {
    // The gapped fixture's two functions are clones of each other, so every
    // run they share is implied by the group that already reports them.
    // Listing both would describe one duplication twice.
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "were folded into the groups that already cover them",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 0);
    assert!(
        value["summary"]["groups"]["folded_runs"].as_u64().unwrap() > 0,
        "the fold has to have happened, or this proves nothing"
    );
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["scope"] == "unit")
    );
}

#[test]
fn a_path_rule_hides_a_run_as_it_hides_a_group() {
    let dir = run_fixture();
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
        .stdout(predicate::str::contains("run of 4 statements").not());

    // Hidden, not deleted: the run is still recorded with the rule that hid it.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|finding| finding.suppression_scope.as_deref() == Some("path_glob"))
    );
}

#[test]
fn a_suppression_rule_that_matched_nothing_is_named() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        // The path glob names a directory this tree does not have, and the
        // clone id names a group this run did not produce.
        "[suppression]\npaths = [\"third_party/**\"]\nclone-ids = [\"0123456789abcdef\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "note: 2 suppression rule(s) matched nothing",
        ))
        .stdout(predicate::str::contains("path glob \"third_party/**\""))
        .stdout(predicate::str::contains("clone id 0123456789abcdef"));

    let value = scan_json(dir.path());
    let unused = value["summary"]["unused_suppressions"].as_array().unwrap();
    assert_eq!(unused.len(), 2);
    assert_eq!(unused[0]["scope"], "path_glob");
    assert_eq!(unused[1]["scope"], "stable_clone_id");
}

#[test]
fn a_set_of_related_units_too_large_to_compare_whole_is_cut_and_said_so() {
    let dir = fixture();
    // A third copy, so the three functions form one set of related units.
    std::fs::write(
        dir.path().join("src/c.rs"),
        GAPPED_RS
            .replace("beta", "gamma")
            .replace("state", "total")
            .replace("seen", "hits"),
    )
    .unwrap();
    // A ceiling of two forces the cut on a set this small.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-component = 2\n",
    )
    .unwrap();

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "note: 1 set(s) of related units were too large to compare as one",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["split_components"], 1);
    // The cut costs recall, not soundness: the pieces are still cohesive
    // groups, each with its own canonical instance.
    let groups = value["groups"].as_array().unwrap();
    assert!(groups.len() >= 2, "the set is reported as several groups");
    for group in groups {
        assert!(group["confidence"].as_f64().unwrap() >= 0.6);
        assert_eq!(group["members"][0]["canonical"], true);
    }
}

#[test]
fn the_run_says_how_far_each_stage_of_the_pipeline_narrowed_it() {
    let dir = fixture();
    let value = scan_json(dir.path());
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    let stage = |name: &str| {
        funnel
            .iter()
            .find(|entry| entry["stage"] == name)
            .unwrap_or_else(|| panic!("stage {name} is reported"))
    };
    let passed = |name: &str| stage(name)["passed"].as_u64().unwrap();

    // Both branches of the run are accounted for: units narrow to verified
    // pairs, and the window seeds narrow to confirmed runs.
    assert!(passed("units") >= 3, "one unit per fixture function");
    assert!(passed("indexed fragments") > passed("unit pairs"));
    assert!(passed("verified pairs") <= passed("unit pairs"));
    assert!(passed("confirmed runs") <= passed("duplicated runs"));

    // Each stage's drops are named rather than folded into the passed count.
    for entry in funnel {
        for drop in entry["dropped"].as_array().unwrap() {
            assert!(
                drop["count"].as_u64().unwrap() > 0,
                "{drop} dropped nothing"
            );
            assert!(drop["cause"].as_str().unwrap().is_ascii());
        }
    }

    // The counts are detail, so they stay out of the default text view.
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:").not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:"))
        .stdout(predicate::str::contains("verified pairs"));
}

#[test]
fn a_suppression_rule_that_hid_something_is_not_called_unused() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/**\", \"third_party/**\"]\n",
    )
    .unwrap();
    let value = scan_json(dir.path());
    let unused = value["summary"]["unused_suppressions"].as_array().unwrap();
    assert_eq!(unused.len(), 1, "only the glob that matched nothing");
    assert_eq!(unused[0]["pattern"], "third_party/**");
}

/// A module compiled only for tests, holding two cases that differ in nothing
/// but their names and values.
const SUITE_RS: &str = "pub fn width_of(text: &str) -> usize {
    text.trim().chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_measures_a_short_string() {
        let input = String::from(\"  hi  \");
        let measured = width_of(&input);
        let doubled = measured * 2;
        assert_eq!(measured, 2);
        assert_eq!(doubled, 4);
    }

    #[test]
    fn it_measures_a_longer_string() {
        let input = String::from(\"  hello  \");
        let measured = width_of(&input);
        let doubled = measured * 2;
        assert_eq!(measured, 5);
        assert_eq!(doubled, 10);
    }
}
";

fn suite_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/measure.rs"), SUITE_RS).unwrap();
    dir
}

#[test]
fn duplication_inside_a_test_suite_is_reported_and_marked() {
    let dir = suite_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        // Ranked down, not hidden: the count is stated and the entry says why
        // it sits where it does.
        .stdout(predicate::str::contains("[test code]"))
        .stdout(predicate::str::contains(
            "1 of them are duplication inside test code",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
    assert_eq!(value["summary"]["suppressed"]["by_rule"], 0);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["test_code"] == true)
    );
}

#[test]
fn a_policy_that_hides_test_code_records_the_marker_that_hid_it() {
    let dir = suite_fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\ntest-code = \"hide\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"));

    // Hidden, not deleted: the rule that hid it names the marker it read.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.suppression_scope.as_deref() == Some("attribute"))
    );
}

/// The crate root, which declares the suite and holds the routine it covers.
/// `{}` is where the declaration's attribute goes, or does not.
const SPLIT_ROOT_RS: &str = "pub fn width_of(text: &str) -> usize {
    text.trim().chars().count()
}

{}
mod tests;
";

/// The suite's own root: nothing but the file it hands on to.
const SPLIT_SUITE_RS: &str = "mod width;\n";

/// Two helpers of the suite, identical and neither marked: the duplication is
/// recognisable as test code only through the declaration two files above.
const SPLIT_CASES_RS: &str = "use super::super::width_of;

#[track_caller]
fn short_case(input: &str, expected: usize) {
    let measured = width_of(input);
    let doubled = measured * 2;
    assert_eq!(measured, expected);
    assert_eq!(doubled, expected * 2);
}

#[track_caller]
fn long_case(input: &str, expected: usize) {
    let measured = width_of(input);
    let doubled = measured * 2;
    assert_eq!(measured, expected);
    assert_eq!(doubled, expected * 2);
}
";

/// A suite declared in one file and written in two others, optionally marked
/// as test-only where it is declared.
fn split_suite_fixture(declared_for_tests: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src/tests")).unwrap();
    let attribute = if declared_for_tests {
        "#[cfg(test)]"
    } else {
        ""
    };
    std::fs::write(
        root.join("src/lib.rs"),
        SPLIT_ROOT_RS.replace("{}", attribute),
    )
    .unwrap();
    std::fs::write(root.join("src/tests.rs"), SPLIT_SUITE_RS).unwrap();
    std::fs::write(root.join("src/tests/width.rs"), SPLIT_CASES_RS).unwrap();
    dir
}

#[test]
fn a_suite_declared_in_one_file_and_written_in_another_is_still_a_suite() {
    let value = scan_json(split_suite_fixture(true).path());
    let groups = value["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    // Neither helper carries a marker; the only one in the tree is on the
    // declaration in the crate root, two files above them.
    assert_eq!(groups[0]["test_code"], true);
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
}

#[test]
fn a_suite_is_recognised_from_its_declaration_and_not_from_its_directory() {
    // The same three files, with the attribute taken off the declaration. A
    // directory called `tests` is not on its own evidence of anything.
    let value = scan_json(split_suite_fixture(false).path());
    let groups = value["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    assert_eq!(groups[0]["test_code"], false);
    assert_eq!(value["summary"]["groups"]["test_code"], 0);
}

/// A measuring routine whose loop is a small part of it.
const LOCAL_LEFT_RS: &str = "pub fn summarize_left(rows: &[String], width: usize) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    if width > 0 {
        total /= width;
    }
    total + widest
}
";

/// A routine that shares that loop verbatim and diverges everywhere else, so
/// the two units are alike only overall while the loop matches exactly.
const LOCAL_RIGHT_RS: &str = "pub fn summarize_right(rows: &[String], limit: usize) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    match limit {
        0 => widest = 1,
        other => total = total.min(other),
    }
    while total > widest {
        total -= widest.max(1);
    }
    total + widest
}
";

#[test]
fn a_run_naming_a_place_inside_its_hosts_survives_the_fold() {
    // The group says these two functions are alike overall, and says nothing
    // about where they agree exactly. The run does: this stretch is identical
    // and can be lifted out as it stands. Folding it would lose that, and it
    // is small enough in both hosts that the group is not already pointing
    // the reader at it.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/left.rs"), LOCAL_LEFT_RS).unwrap();
    std::fs::write(root.join("src/right.rs"), LOCAL_RIGHT_RS).unwrap();

    let value = scan_json(root);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 0);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 1);

    let groups = value["groups"].as_array().unwrap();
    let unit = groups.iter().find(|g| g["scope"] == "unit").unwrap();
    assert_eq!(unit["clone_type"], "type-3");
    let run = groups.iter().find(|g| g["scope"] == "fragment").unwrap();
    assert_eq!(run["clone_type"], "type-1");
    assert_eq!(run["statements"], 4);
    // Both hosts are members of the group that nonetheless failed to absorb it.
    let hosts: Vec<&str> = run["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["file"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, vec!["src/left.rs", "src/right.rs"]);
    // Each occurrence is well under half of the unit that hosts it; that is
    // what keeps it out of the fold.
    for member in run["members"].as_array().unwrap() {
        let host = unit["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["file"] == member["file"])
            .unwrap();
        assert!(member["tokens"].as_u64().unwrap() * 2 <= host["tokens"].as_u64().unwrap());
    }
}

/// A function that measures its input twice over, so a run is duplicated
/// inside it.
const SELF_A_RS: &str = "pub fn collect_alpha(rows: &[String]) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    let mut second = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    total + widest + second
}
";

/// A consistently renamed copy of it, so the two functions are a clone group.
const SELF_B_RS: &str = "pub fn collect_beta(items: &[String]) -> usize {
    let mut sum = 0usize;
    let mut peak = 0usize;
    for row in items {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        sum = sum.saturating_add(size);
        peak = peak.max(size);
    }
    let mut spare = 0usize;
    for row in items {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        sum = sum.saturating_add(size);
        peak = peak.max(size);
    }
    sum + peak + spare
}
";

#[test]
fn a_run_duplicated_inside_one_unit_survives_the_fold() {
    // Both cases at once. The run the two functions share is folded away:
    // the group that reports them as clones already implies it. The run each
    // function duplicates inside *itself* is not implied by anything, so it
    // stays — folding it would lose a finding no group states.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), SELF_A_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), SELF_B_RS).unwrap();

    let value = scan_json(root);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 1);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 2);

    for group in value["groups"].as_array().unwrap() {
        if group["scope"] != "fragment" {
            continue;
        }
        let members = group["members"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(
            members[0]["unit"], members[1]["unit"],
            "the surviving runs are the ones a unit duplicates inside itself"
        );
        assert_ne!(members[0]["start_line"], members[1]["start_line"]);
    }
}

/// A routine whose copy elsewhere is exact.
const TRIO_A_RS: &str = "pub fn measure_alpha(rows: &[String]) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    total
}
";

/// The verbatim copy of it.
const TRIO_B_RS: &str = "pub fn measure_beta(rows: &[String]) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    total
}
";

/// A variant close to the first two but carrying an extra loop, so it is a
/// clone of one of them and further from the rest.
const TRIO_C_RS: &str = "pub fn measure_gamma(rows: &[String], width: usize) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    let mut pad = 0usize;
    while pad < width {
        pad += 2;
        total = total.saturating_add(pad);
    }
    total
}
";

#[test]
fn a_pair_no_group_holds_is_reported_and_says_so() {
    // Being a clone is not transitive, so a scan can verify a pair that no
    // group can hold. Dropping it would throw away a verdict the tool reached;
    // reporting it without saying what it is would read as a second, competing
    // account of code already covered elsewhere.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), TRIO_A_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), TRIO_B_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), TRIO_C_RS).unwrap();

    let value = scan_json(root);
    let groups = value["groups"].as_array().unwrap();
    for group in groups {
        assert!(
            group["split_pair"].is_boolean(),
            "every group states whether it is a pair no group holds"
        );
    }
    assert!(
        groups.iter().any(|group| group["split_pair"] == false),
        "the verbatim copies group"
    );
    // Whatever the corpus produces, a pair reported on its own has exactly two
    // members and is a clone class the judge accepted.
    for pair in groups.iter().filter(|group| group["split_pair"] == true) {
        assert_eq!(pair["members"].as_array().unwrap().len(), 2);
        assert_eq!(pair["priority"]["inputs"]["instances"], 2);
        assert!(
            pair["clone_type"].as_str().unwrap().starts_with("type-"),
            "a pair carries the class the judge gave it"
        );
    }
}

#[test]
fn every_entry_carries_the_measures_its_place_was_argued_from() {
    let dir = fixture();
    let value = scan_json(dir.path());

    // The run says how it weighed the measures, because two reports composed
    // under different weights are different orderings of the same findings.
    assert_eq!(value["run"]["ranking"]["maintenance_risk"], 2);
    assert_eq!(value["run"]["ranking"]["refactoring_ease"], 1);

    let groups = value["groups"].as_array().unwrap();
    assert!(!groups.is_empty());
    for group in groups {
        let priority = &group["priority"];
        for measure in [
            "value",
            "clone_confidence",
            "maintenance_risk",
            "refactoring_difficulty",
        ] {
            let value = priority[measure].as_f64().unwrap_or_else(|| {
                panic!("{measure} is a number");
            });
            assert!(
                (0.0..=1.0).contains(&value),
                "{measure} left its range at {value}"
            );
        }
        // Reserved until a backend measures them. Absent, never zero: zero is
        // a measurement, and none of these has been taken.
        for reserved in [
            "semantic_confidence",
            "source_artifact_confidence",
            "savings_confidence",
        ] {
            assert!(priority[reserved].is_null(), "{reserved} is not measured");
        }
        // The facts, so a reader who disagrees with the placement can see
        // which input produced it, and reproduce the ranking from the report.
        let inputs = &priority["inputs"];
        assert_eq!(inputs["min_clone_tokens"], 20);
        assert!(inputs["smallest_member_tokens"].as_u64().unwrap() > 0);
        assert!(
            inputs["smallest_member_tokens"].as_u64().unwrap()
                <= inputs["largest_member_tokens"].as_u64().unwrap()
        );
        assert!(inputs["instances"].as_u64().unwrap() >= 2);
        assert_eq!(inputs["languages"], 1);
        assert!(inputs["churn"].is_null());
        assert!(inputs["ownership_spread"].is_null());
    }
}

#[test]
fn the_weights_change_the_order_and_nothing_else() {
    let dir = fixture();
    let root = dir.path();
    std::fs::write(root.join("src/c.rs"), OTHER_RS.replace("label", "caption")).unwrap();

    let before = scan_json(root);
    // Ranking on confidence alone: the maintenance argument stops being heard.
    std::fs::write(
        root.join("codehelion.toml"),
        "[priority]\nmaintenance-risk = 0\nrefactoring-ease = 0\n",
    )
    .unwrap();
    let after = scan_json(root);

    assert_eq!(after["run"]["ranking"]["maintenance_risk"], 0);
    assert_ne!(
        before["run"]["ranking"]["recipe"], after["run"]["ranking"]["recipe"],
        "the recorded recipe names the weights it was composed under"
    );
    // The same findings, said the same way: weights decide the order a report
    // is read in and nothing about what is in it.
    let names = |value: &serde_json::Value| {
        let mut ids: Vec<String> = value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["fingerprint"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(names(&before), names(&after));
    for (a, b) in before["groups"]
        .as_array()
        .unwrap()
        .iter()
        .zip(after["groups"].as_array().unwrap())
    {
        assert_eq!(
            a["priority"]["clone_confidence"],
            b["priority"]["clone_confidence"]
        );
        assert_eq!(
            a["priority"]["maintenance_risk"],
            b["priority"]["maintenance_risk"]
        );
    }
}

#[test]
fn two_runs_of_one_tree_rank_it_identically() {
    let dir = fixture();
    let first = scan_json(dir.path());
    let second = scan_json(dir.path());
    assert_eq!(first["groups"], second["groups"]);
}

#[test]
fn a_ranking_does_not_move_because_something_else_was_found() {
    // What makes a priority comparable between two runs, and what a
    // rank-based composition would give up: a finding's place is computed from
    // its own facts, so it cannot move because the scan found one more group.
    let dir = fixture();
    let root = dir.path();
    let alone = scan_json(root);
    let before: Vec<(String, f64)> = alone["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["fingerprint"].as_str().unwrap().to_string(),
                group["priority"]["value"].as_f64().unwrap(),
            )
        })
        .collect();

    std::fs::write(root.join("src/c.rs"), TRIO_A_RS).unwrap();
    std::fs::write(root.join("src/d.rs"), TRIO_B_RS).unwrap();
    let crowded = scan_json(root);
    let after: std::collections::BTreeMap<String, f64> = crowded["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["fingerprint"].as_str().unwrap().to_string(),
                group["priority"]["value"].as_f64().unwrap(),
            )
        })
        .collect();
    assert!(after.len() > before.len(), "the second scan found more");
    for (fingerprint, value) in before {
        assert_eq!(
            after.get(&fingerprint),
            Some(&value),
            "group {fingerprint} was re-ranked by the arrival of another group"
        );
    }
}

#[test]
fn explain_says_which_fact_put_the_finding_where_it_is() {
    let dir = fixture();
    let root = dir.path();
    let value = scan_json(root);
    let finding = value["groups"][0]["members"][0]["finding_id"]
        .as_str()
        .unwrap()
        .to_string();

    let text = cmd()
        .current_dir(root)
        .args(["explain", &finding])
        .output()
        .expect("run explain");
    assert!(text.status.success(), "{text:?}");
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("priority:"), "{text}");
    // Each measure names the facts behind it rather than only its value.
    assert!(
        text.contains("tokens in the smallest occurrence against a 20-token floor"),
        "{text}"
    );
    assert!(text.contains("maintenance risk"), "{text}");
    assert!(text.contains("refactoring difficulty"), "{text}");
    // And says which inputs nobody has measured, so a zero is never inferred
    // from their absence.
    assert!(
        text.contains("not measured by this run, and so not weighed"),
        "{text}"
    );
}

/// A tree holding several copies of a family of functions that are clones of
/// one another, but not transitively so.
///
/// This is what a dependency directory looks like when it carries a library at
/// more than one version, or a project that keeps one algorithm per target
/// architecture: the same handful of shapes, over and over. Similarity is not
/// transitive, so no one group can hold the whole family, and the verdicts
/// left over recur once per crossing of the copies — the same fact, with many
/// places to say it about.
fn fixture_with_repeated_copies(copies: usize) -> tempfile::TempDir {
    const FAMILY: [&str; 6] = [
        "seed",
        "calls_swapped",
        "rewritten",
        "guard_added",
        "loop_nested",
        "exits_removed",
    ];
    let corpus = Path::new("../../corpus/synthetic/rust-divergent");
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    for copy in 0..copies {
        for member in FAMILY {
            let text = std::fs::read_to_string(corpus.join(format!("{member}.rs")))
                .unwrap_or_else(|e| panic!("reading the divergence corpus: {e}"));
            std::fs::write(root.join(format!("src/{member}_{copy}.rs")), text).unwrap();
        }
    }
    dir
}

/// Every identifier a report hands out has to name one thing.
///
/// A reader freezes a finding by its clone id and follows it by its finding
/// id. Two rows under one clone id means freezing either hides both; two
/// occurrences under one finding id means neither can be suppressed or
/// followed on its own. Neither failure announces itself — a baseline that
/// hides more than it was pointed at looks exactly like one that worked.
#[test]
fn every_identifier_a_report_hands_out_names_one_thing() {
    let dir = fixture_with_repeated_copies(6);
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();
    assert!(groups.len() > 1, "the fixture reports several findings");

    let clone_ids: Vec<&str> = groups
        .iter()
        .map(|group| group["fingerprint"].as_str().unwrap())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = clone_ids.iter().copied().collect();
    assert_eq!(
        clone_ids.len(),
        distinct.len(),
        "{} of {} rows share a clone id with another row",
        clone_ids.len() - distinct.len(),
        clone_ids.len()
    );

    let finding_ids: Vec<&str> = groups
        .iter()
        .flat_map(|group| group["members"].as_array().unwrap())
        .map(|member| member["finding_id"].as_str().unwrap())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = finding_ids.iter().copied().collect();
    assert_eq!(
        finding_ids.len(),
        distinct.len(),
        "{} of {} occurrences share a finding id with another occurrence",
        finding_ids.len() - distinct.len(),
        finding_ids.len()
    );
}

/// The same relation observed in many places is one finding, not many.
///
/// Six copies of one shape against six of another is thirty-six crossings and
/// one fact. Reported one crossing at a time it fills the report with rows
/// that differ in nothing a reader can act on — and, since a clone id is
/// composed from member content, all thirty-six carry the same id anyway.
#[test]
fn one_relation_seen_in_many_places_is_reported_once() {
    let copies = 6;
    let dir = fixture_with_repeated_copies(copies);
    let value = scan_json(dir.path());
    let split: Vec<&serde_json::Value> = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| group["split_pair"] == true)
        .collect();
    assert_eq!(
        split.len(),
        1,
        "the relation between the two shapes is stated {} times",
        split.len()
    );
    // And it carries every place it was seen rather than one representative
    // pair, so a reader who acts on it knows the whole extent of the work.
    let members = split[0]["members"].as_array().unwrap();
    assert_eq!(members.len(), copies * 2);
    assert_eq!(
        members
            .iter()
            .filter(|member| member["canonical"] == true)
            .count(),
        1
    );
}

/// Two functions copied whole, each holding a nested helper.
///
/// The shape that produces a crossing nothing can act on: the helpers are
/// copies of each other and so are their parents, which leaves each helper
/// agreeing with the *other* parent as well — not because it was copied there
/// but because its own twin lives inside it.
const NESTED_TWINS_RS: &str = "\
fn build_index(rows: &[u64]) -> (u64, usize) {
    fn fold(rows: &[u64], seed: u64) -> u64 {
        let mut acc = seed;
        for row in rows {
            acc = acc.wrapping_mul(31).wrapping_add(*row);
            if *row == 0 {
                acc = acc.rotate_left(7);
            }
            acc ^= acc >> 13;
        }
        return acc;
    }
    return (fold(rows, 17), rows.len());
}

fn build_table(rows: &[u64]) -> (u64, usize) {
    fn fold(rows: &[u64], seed: u64) -> u64 {
        let mut acc = seed;
        for row in rows {
            acc = acc.wrapping_mul(31).wrapping_add(*row);
            if *row == 0 {
                acc = acc.rotate_left(7);
            }
            acc ^= acc >> 13;
        }
        return acc;
    }
    return (fold(rows, 17), rows.len());
}
";

/// A crossing two reported groups already account for is not a third finding.
///
/// A helper nested in one function and copied into another agrees with that
/// other function too, over the stretch its own twin occupies there. The
/// verdict is not wrong — the tokens do line up — but the report has already
/// said it twice, once for the pair of helpers and once for the pair of
/// parents, and stating it a third time at a two-to-one size ratio points a
/// reader at work that does not exist. Both real groups have to survive:
/// dropping the crossing must not cost the facts it was derived from.
#[test]
fn a_crossing_two_groups_already_account_for_is_not_reported_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/nested.rs"), NESTED_TWINS_RS).unwrap();

    let value = scan_json(root);
    let groups = value["groups"].as_array().unwrap();
    let units: Vec<&str> = groups
        .iter()
        .filter(|group| group["split_pair"] == false)
        .map(|group| group["members"][0]["unit"].as_str().unwrap())
        .collect();
    assert!(
        units.contains(&"fold"),
        "the two nested helpers are no longer grouped: {units:?}"
    );
    assert!(
        units.iter().any(|unit| unit.starts_with("build_")),
        "the two parents are no longer grouped: {units:?}"
    );
    let crossings: Vec<&serde_json::Value> = groups
        .iter()
        .filter(|group| group["split_pair"] == true)
        .collect();
    assert!(
        crossings.is_empty(),
        "a helper is still reported against the parent that holds its twin: {crossings:#?}"
    );
    // And the run says how many it left out, so the drop is a number in the
    // funnel rather than findings that quietly went missing.
    let verified = value["summary"]["funnel"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == "verified pairs")
        .expect("the funnel reports the verified-pair stage");
    assert_eq!(
        verified["dropped"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drop| drop["cause"] == "a_group_says_it_already")
            .map(|drop| drop["count"].as_u64().unwrap()),
        Some(2),
        "expected both crossings counted: {verified:#?}"
    );
}

/// Two copies of one function have the same content and therefore the same
/// unit fingerprint, so what tells their occurrences apart is the rank the
/// identifier carries. A report that prints one id and a database that holds
/// another leave `explain` unable to answer about a finding the report named.
#[test]
fn every_occurrence_the_report_names_can_be_explained() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    // Three verbatim copies: one group whose members share a fingerprint.
    for name in ["a.rs", "b.rs", "c.rs"] {
        std::fs::write(src.join(name), ALPHA_RS).expect("write source");
    }

    let value = scan_json(dir.path());
    let members = value["groups"][0]["members"]
        .as_array()
        .expect("the group lists its occurrences");
    assert_eq!(members.len(), 3, "{value:#?}");

    for member in members {
        let id = member["finding_id"].as_str().expect("a finding id");
        cmd()
            .current_dir(dir.path())
            .args(["explain", id])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                member["file"].as_str().expect("a file path"),
            ));
    }
}

/// One member of a renamed family, spelled with names of its own.
///
/// Eight of these share every window and subtree hash, so one posting list
/// holds twenty-eight pairs — more than the ceilings below allow, which is the
/// point.
fn family_member(index: usize) -> String {
    format!(
        "pub fn member{index}(input{index}: &[u32]) -> u32 {{
    let mut total{index} = 0u32;
    let mut seen{index} = 0u32;
    for value{index} in input{index} {{
        if *value{index} > 10 {{
            total{index} = total{index}.wrapping_add(*value{index});
        }} else {{
            total{index} = total{index}.wrapping_sub(1);
        }}
        seen{index} += 1;
    }}
    total{index} = total{index}.wrapping_mul(3);
    return total{index} + seen{index};
}}
"
    )
}

/// Raising the candidate ceiling must never shorten the report.
///
/// Grouping reads a pair nothing proposed as a pair that is not similar, which
/// is sound while the stage above it finished and is not once a ceiling cut a
/// posting list in half. A family compared to itself only in part arrives there
/// looking like a family that disagrees: it is broken up, and the comparisons
/// that did survive come back out one at a time as pairs no group holds both
/// halves of. The report then *grows* as the allowance shrinks — the reader is
/// handed more rows, saying less, exactly when the tool is under pressure.
///
/// So the property worth holding is not how much a squeezed run finds but that
/// squeezing it cannot inflate it. Ceilings are spent a posting list at a time,
/// and this is what says so from outside.
#[test]
fn a_tighter_ceiling_never_makes_the_report_longer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    for index in 0..8 {
        std::fs::write(src.join(format!("m{index}.rs")), family_member(index))
            .expect("write source");
    }

    let mut previous = usize::MAX;
    let mut ceilings = String::new();
    for budget in [100_000usize, 400, 200, 100, 60, 40, 20, 10] {
        std::fs::write(
            dir.path().join("codehelion.toml"),
            format!("[limits]\npair-budget = {budget}\n"),
        )
        .expect("write the ceiling");
        let value = scan_json(dir.path());
        let groups = value["groups"]
            .as_array()
            .expect("the report lists its groups")
            .len();
        let _ = writeln!(ceilings, "  ceiling {budget}: {groups} groups");
        assert!(
            groups <= previous,
            "a tighter ceiling reported more groups\n{ceilings}"
        );
        previous = groups;
    }
    // And the family is found at all when the allowance is there, so the run
    // above is not monotone merely by finding nothing throughout.
    assert!(previous < 8, "{ceilings}");
}

/// A ceiling that cuts a set apart must not then report the cut as findings.
///
/// Refinement runs on sets, and comparing a set costs time quadratic in its
/// size, so a set past the ceiling is cut into pieces and each piece refined on
/// its own. Two members in different pieces are then never weighed against each
/// other — and the relation between them, which verification had already
/// accepted, comes back out as a pair no group holds both halves of. The
/// ceiling exists so that a repository of thousands of interchangeable units
/// cannot make a scan expensive; reporting what it severed would move that
/// expense onto the reader, one pair at a time, at the size of the set squared.
///
/// So the severed relations are counted under a cause of their own instead of
/// being listed. What the ceiling costs is a coarser partition, which is the
/// price it was always documented to charge; what it must not cost is a report
/// made of the same duplication restated.
#[test]
fn a_set_the_ceiling_cut_is_not_reported_as_the_pairs_it_severed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    for index in 0..8 {
        std::fs::write(src.join(format!("m{index}.rs")), family_member(index))
            .expect("write source");
    }

    let whole = scan_json(dir.path());
    // Whole-unit findings only: the statement run the eight share is a
    // sub-unit view of the same code, and the ceiling is about sets of units.
    let units = |value: &serde_json::Value| {
        value["groups"]
            .as_array()
            .expect("the report lists its groups")
            .iter()
            .filter(|group| group["scope"] == "unit")
            .count()
    };
    assert_eq!(
        units(&whole),
        1,
        "the family is one group when nothing cuts"
    );

    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-component = 3\n",
    )
    .expect("write the ceiling");
    let cut = scan_json(dir.path());
    assert_eq!(cut["summary"]["split_components"], 1, "{cut:#?}");

    // Three pieces, so three groups: the coarser partition is what the ceiling
    // charges. Anything beyond that would be the severed relations coming back
    // as rows, and twenty-one of the twenty-eight verified pairs are severed.
    assert_eq!(units(&cut), 3, "{cut:#?}");
    assert!(
        cut["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .all(|group| group["split_pair"] == false),
        "{cut:#?}"
    );

    // And the count is stated rather than left to be noticed.
    let verified = cut["summary"]["funnel"]
        .as_array()
        .expect("a funnel")
        .iter()
        .find(|stage| stage["stage"] == "verified pairs")
        .expect("the funnel names the verification stage");
    let severed = verified["dropped"]
        .as_array()
        .expect("the stage accounts for what it dropped")
        .iter()
        .find(|drop| drop["cause"] == "the_ceiling_cut_the_set")
        .expect("the cut is named as a cause");
    assert!(severed["count"].as_u64().expect("a count") > 0, "{cut:#?}");
}
