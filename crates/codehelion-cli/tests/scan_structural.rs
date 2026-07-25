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
        assert_eq!(pair["priority"]["extra_instances"], 1);
        assert!(
            pair["clone_type"].as_str().unwrap().starts_with("type-"),
            "a pair carries the class the judge gave it"
        );
    }
}
