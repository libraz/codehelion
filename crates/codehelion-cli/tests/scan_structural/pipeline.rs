//! The Structural pipeline end to end: parse limits, gapped-clone
//! detection, the shape of every report, reuse and lookup.

use super::*;

/// Structural and Semantic both copy the shared guardrail model through their
/// partition result, so this real Structural run fixes the serialized shape
/// at that boundary as well as Fast mode's direct one.
#[test]
fn untrusted_structural_scan_reports_all_effective_ceilings() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-file-bytes = 2097152\nparse-timeout-ms = 10000\nhelper-timeout-ms = 300000\nposting-cap = 256\npair-budget = 1000000\nmax-component = 1024\n",
    )
    .unwrap();
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--untrusted",
            "--format",
            "json",
        ])
        .output()
        .expect("run structural scan");
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(
        report["summary"]["guardrails"],
        serde_json::json!({
            "profile": "untrusted",
            "max_file_bytes": 512 * 1024,
            "parse_timeout_ms": 5_000,
            "helper_timeout_ms": 30_000,
            "posting_cap": 32,
            "pair_budget": 500_000,
            "verification_budget": 100_000,
            "max_alignment_cells": 250_000,
            "near_miss_delta": 0.05,
            "near_miss_cap": 1_000,
            "sibling_candidate_budget": 50_000,
            "sibling_per_group_cap": 8,
            "sibling_total_cap": 1_000,
            "signature_sibling_candidate_budget": 50_000,
            "signature_sibling_per_group_cap": 8,
            "signature_sibling_total_cap": 1_000,
            "signature_sibling_max_units_per_signature": 8,
            "max_component": 128,
        })
    );
}

/// A depth ceiling is an intentional loss of coverage, not an ordinary parse
/// recovery. It must reach the persisted funnel and the normal text report.
#[test]
fn depth_limited_structural_parse_is_visible_in_json_and_text_reports() {
    let dir = fixture();
    let mut deep = String::from("pub fn deeply_nested() ");
    deep.push_str(&"{".repeat(10_000));
    deep.push_str("()");
    deep.push_str(&"}".repeat(10_000));
    std::fs::write(dir.path().join("src/deep.rs"), deep).unwrap();

    let report = scan_json(dir.path());
    let stage = report["summary"]["funnel"]
        .as_array()
        .expect("funnel is an array")
        .iter()
        .find(|stage| stage["stage"] == "structural files")
        .expect("structural parse stage is recorded");
    assert_eq!(stage["passed"], 3);
    assert_eq!(
        stage["dropped"],
        serde_json::json!([{"cause": "depth_limit", "count": 1}])
    );

    let run = report["run"]["run_id"].as_i64().expect("recorded run id");
    cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run.to_string()])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "structural parsing reached its depth limit in 1 file(s)",
        ));
}

#[test]
fn a_gapped_clone_is_detected_and_recorded_with_its_evidence() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "-v",
            "--decoration",
            "unicode",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "codehelion scan · structural mode ·",
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
    let identifier_jaccard = group
        .identifier_jaccard
        .expect("raw identifier agreement is stored as triage evidence");
    assert!(
        (identifier_jaccard - 4.0 / 15.0).abs() < f64::EPSILON,
        "the established whole-unit measurement must not change"
    );
    assert!(group.has_loop.is_some());
    assert!(group.has_dynamic_allocation.is_some());
    assert!(group.call_count.is_some());

    let similarity = group
        .similarity
        .as_ref()
        .expect("a structural group carries its breakdown");
    assert_eq!(similarity.weight_version, "structural-verify-v1");
    assert!(similarity.composite > 0.6);
    assert!(similarity.min_pairwise > 0.6);
    assert!(
        similarity.type_similarity.is_none(),
        "types are unavailable in this mode and stay absent"
    );

    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());

    let rendered = scan_json(dir.path());
    assert!(
        rendered["groups"][0]["identifier_jaccard"].is_number(),
        "the JSON report exposes raw identifier agreement without changing classification"
    );
    assert!(rendered["groups"][0]["body_materiality"].is_object());
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
        run.remove("reused");
        // The second run knows a first run happened. That is the comparison
        // working, not the findings moving.
        let summary = value["summary"].as_object_mut().unwrap();
        for key in ["changes", "audit", "top_churn"] {
            summary.insert(key.to_string(), serde_json::Value::Null);
        }
        // Likewise per group: how a group stands relative to an earlier run is
        // a statement about the pair of runs, not about the finding.
        for group in value["groups"].as_array_mut().unwrap() {
            group.as_object_mut().unwrap().remove("identity");
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
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "maximal" && entry["version"] == "maximal-v1")
    );
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["component"] == "substitution" && entry["version"] == "substitution-v1"
            })
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
    let fast_run = store.run_summary(1).unwrap().expect("a Fast run");
    let structural_run = store.run_summary(2).unwrap().expect("a Structural run");
    assert_eq!(fast_run.analysis_mode, "fast");
    assert_eq!(structural_run.analysis_mode, "structural");
    let fast = store.run_groups(fast_run.id).unwrap();
    let structural = store.run_groups(structural_run.id).unwrap();

    // Fast may recover a local common fragment, but it cannot make the
    // whole-unit Structural judgment below.

    // Structural judges the whole units and reports the gapped clone.
    assert_eq!(structural.len(), 1);
    assert_eq!(structural[0].clone_type, "type-3");

    // Two variants, two identities: the Structural result cannot be a Fast
    // finding reinterpreted under another mode.
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
        .stderr(predicate::str::contains("the parser could not follow"));
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
fn a_structural_rescan_reuses_an_unchanged_snapshot() {
    let dir = fixture();
    for _ in 0..2 {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", "structural"])
            .assert()
            .success();
    }
    let store = open_store(dir.path());
    let latest = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(latest.id, 1, "an unchanged tree reuses its completed run");
    assert_eq!(store.table_count("scan_run").unwrap(), 1);
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
    assert_eq!(similarity["weight_version"], "structural-verify-v1");
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
        .args(["scan", ".", "--mode", "structural", "-v"])
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
