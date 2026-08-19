use super::*;

const SIGNATURE_PRIMARY_RS: &str = "pub fn alpha(values: &[u32]) -> u32 {
    let mut total = 0u32;
    for value in values {
        if *value > 10 {
            total = total.wrapping_add(*value);
        } else {
            total = total.wrapping_sub(1);
        }
    }
    total = total.wrapping_mul(3);
    total
}
";

const SIGNATURE_CANDIDATE_RS: &str = "pub fn beta(input: &[u32]) -> u32 {
    let first = input.first().copied().unwrap_or(0);
    let second = input.get(1).copied().unwrap_or(0);
    let third = first ^ second;
    let fourth = third.rotate_left(3);
    fourth.wrapping_add(11)
}
";

const SIGNATURE_OTHER_RS: &str = "pub fn gamma(input: &[u32]) -> u32 {
    let mut output = 0u32;
    for chunk in input.chunks(2) {
        output = output.wrapping_add(chunk.len() as u32);
    }
    if output == 0 {
        7
    } else {
        output
    }
}
";

fn signature_context_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src/primary")).unwrap();
    std::fs::create_dir_all(root.join("src/other")).unwrap();
    std::fs::write(root.join("src/primary/a.rs"), SIGNATURE_PRIMARY_RS).unwrap();
    std::fs::write(
        root.join("src/primary/b.rs"),
        SIGNATURE_PRIMARY_RS.replace("alpha", "renamed"),
    )
    .unwrap();
    std::fs::write(
        root.join("src/primary/candidate.rs"),
        SIGNATURE_CANDIDATE_RS,
    )
    .unwrap();
    std::fs::write(root.join("src/other/outside.rs"), SIGNATURE_OTHER_RS).unwrap();
    dir
}

/// The signature fixture plus enough same-signature units to let a configured
/// rarity limit sit between "rare enough to be evidence" and "shared by too
/// much of the tree". Every added body differs, so the extra units are
/// signature company rather than clones.
fn crowded_signature_fixture(extra_units: usize) -> tempfile::TempDir {
    let dir = signature_context_fixture();
    for index in 0..extra_units {
        let source = format!(
            "pub fn crowded_{index}(input: &[u32]) -> u32 {{
    let seed = input.first().copied().unwrap_or({index});
    let mixed = seed.rotate_left({}) ^ {};
    mixed.wrapping_add({})
}}
",
            index % 7 + 1,
            index * 13 + 3,
            index * 29 + 5
        );
        std::fs::write(
            dir.path().join(format!("src/primary/crowded_{index}.rs")),
            source,
        )
        .unwrap();
    }
    dir
}

#[test]
fn actual_frontend_signature_context_is_same_directory_scoped() {
    let dir = signature_context_fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--no-reuse",
            "--siblings-by-signature",
            "--format",
            "json",
        ])
        .output()
        .expect("run opt-in signature scan");
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    let siblings = report["siblings"].as_array().expect("siblings array");
    let sibling_files = siblings
        .iter()
        .flat_map(|group| group["siblings"].as_array().into_iter().flatten())
        .filter_map(|sibling| sibling["member"]["file"].as_str())
        .collect::<Vec<_>>();
    assert!(
        sibling_files.contains(&"src/primary/candidate.rs"),
        "same-directory frontend signature candidate is retained: {sibling_files:?}"
    );
    assert!(
        sibling_files
            .iter()
            .all(|file| *file != "src/other/outside.rs"),
        "different-directory candidate is excluded: {sibling_files:?}"
    );
}

#[test]
fn signature_sibling_generation_is_opt_in_and_reuse_profiles_are_isolated() {
    let dir = signature_context_fixture();
    let root = dir.path();
    let database = root.join(".codehelion/opt-in.db");
    let database_text = database.to_str().expect("database path is utf-8");
    let run_scan = |extra: &[&str]| -> serde_json::Value {
        let output = cmd()
            .current_dir(root)
            .args([
                "scan",
                ".",
                "--mode",
                "structural",
                "--untrusted",
                "--format",
                "json",
                "--db",
                database_text,
            ])
            .args(extra)
            .output()
            .expect("run structural opt-in fixture");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("scan output is JSON")
    };
    let signature_siblings = |report: &serde_json::Value| {
        report["siblings"]
            .as_array()
            .expect("sibling groups")
            .iter()
            .flat_map(|group| group["siblings"].as_array().into_iter().flatten())
            .filter(|sibling| sibling["basis"] == "signature")
            .count()
    };
    let has_signature_stage = |report: &serde_json::Value| {
        report["summary"]["funnel"]
            .as_array()
            .expect("funnel")
            .iter()
            .any(|stage| stage["stage"] == "signature sibling entries")
    };

    let off_fresh = run_scan(&["--no-reuse"]);
    assert_ne!(off_fresh["run"]["reused"], true);
    assert_eq!(signature_siblings(&off_fresh), 0);
    assert!(!has_signature_stage(&off_fresh));

    let display_only = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--untrusted",
            "--show-siblings",
            "-vv",
            "--db",
            database_text,
        ])
        .output()
        .expect("run display-only sibling scan");
    assert!(display_only.status.success(), "{display_only:?}");
    let display_text = String::from_utf8(display_only.stdout).expect("display output is UTF-8");
    assert!(!display_text.contains("[same signature]"), "{display_text}");

    let on_fresh = run_scan(&["--siblings-by-signature"]);
    assert_ne!(on_fresh["run"]["reused"], true);
    assert!(signature_siblings(&on_fresh) > 0);
    assert!(has_signature_stage(&on_fresh));
    assert_eq!(off_fresh["groups"], on_fresh["groups"]);

    let on_reused = run_scan(&["--siblings-by-signature"]);
    assert_eq!(on_reused["run"]["reused"], true);
    assert_eq!(on_reused["groups"], on_fresh["groups"]);

    let off_reused = run_scan(&[]);
    assert_eq!(off_reused["run"]["reused"], true);
    assert_eq!(off_reused["groups"], off_fresh["groups"]);
    assert_eq!(signature_siblings(&off_reused), 0);
    assert!(!has_signature_stage(&off_reused));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test covers JSON, SARIF and text replay"
)]
fn signature_siblings_keep_exact_json_funnel_guardrail_and_sarif_parity_across_reuse_and_replay() {
    let dir = signature_context_fixture();
    let root = dir.path();
    let run_scan = |format: &str, extra: &[&str]| -> serde_json::Value {
        let mut args = vec![
            "scan",
            ".",
            "--mode",
            "structural",
            "--untrusted",
            "--siblings-by-signature",
            "--format",
            format,
        ];
        args.extend(extra);
        let output = cmd()
            .current_dir(root)
            .args(args)
            .output()
            .expect("run structural signature fixture");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("scan output is JSON")
    };

    let fresh = run_scan("json", &["--no-reuse"]);
    let run_id = fresh["run"]["run_id"].as_i64().expect("fresh run id");
    let siblings = fresh["siblings"].as_array().expect("fresh sibling groups");
    let signature_sibling = siblings
        .iter()
        .flat_map(|group| group["siblings"].as_array().into_iter().flatten())
        .find(|sibling| sibling["basis"] == "signature")
        .expect("fresh report contains a signature sibling");
    assert!(signature_sibling["signature"].is_string());
    assert_eq!(signature_sibling["clone_type"], "type-3");
    assert_eq!(signature_sibling["confidence_band"], "low");
    let signature_stage = fresh["summary"]["funnel"]
        .as_array()
        .expect("fresh funnel")
        .iter()
        .find(|stage| stage["stage"] == "signature sibling entries")
        .expect("independent signature sibling funnel stage");
    assert_eq!(signature_stage["passed"], fresh["summary"]["siblings"]);
    assert!(
        fresh["summary"]["guardrails"]
            .get("signature_sibling_candidate_budget")
            .is_some()
    );
    assert!(
        fresh["summary"]["guardrails"]
            .get("signature_sibling_per_group_cap")
            .is_some()
    );
    assert!(
        fresh["summary"]["guardrails"]
            .get("signature_sibling_total_cap")
            .is_some()
    );

    let reused = run_scan("json", &[]);
    assert_eq!(reused["run"]["reused"], true);
    assert_eq!(reused["siblings"], fresh["siblings"]);
    assert_eq!(reused["summary"]["funnel"], fresh["summary"]["funnel"]);
    assert_eq!(
        reused["summary"]["guardrails"],
        fresh["summary"]["guardrails"]
    );

    let replay_output = cmd()
        .current_dir(root)
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("replay signature report");
    assert!(replay_output.status.success(), "{replay_output:?}");
    let replay: serde_json::Value =
        serde_json::from_slice(&replay_output.stdout).expect("replay output is JSON");
    assert_eq!(replay["siblings"], fresh["siblings"]);
    assert_eq!(replay["summary"]["siblings"], fresh["summary"]["siblings"]);
    assert_eq!(replay["summary"]["funnel"], fresh["summary"]["funnel"]);
    assert_eq!(
        replay["summary"]["guardrails"],
        fresh["summary"]["guardrails"]
    );

    let fresh_sarif = run_scan("sarif", &["--no-reuse"]);
    let sarif_run_id = fresh_sarif["runs"][0]["properties"]["run_id"]
        .as_i64()
        .expect("fresh SARIF run id");
    let reused_sarif = run_scan("sarif", &[]);
    assert_eq!(
        reused_sarif["runs"][0]["properties"]["run_id"],
        fresh_sarif["runs"][0]["properties"]["run_id"]
    );
    let replay_sarif_output = cmd()
        .current_dir(root)
        .args([
            "report",
            "--run",
            &sarif_run_id.to_string(),
            "--format",
            "sarif",
        ])
        .output()
        .expect("replay signature SARIF");
    assert!(
        replay_sarif_output.status.success(),
        "{replay_sarif_output:?}"
    );
    let replay_sarif: serde_json::Value =
        serde_json::from_slice(&replay_sarif_output.stdout).expect("replay SARIF is JSON");
    let sibling_properties = |document: &serde_json::Value| {
        document["runs"][0]["results"]
            .as_array()
            .expect("SARIF results")
            .iter()
            .find_map(|result| {
                let siblings = result["properties"]["siblings"].as_array()?;
                (!siblings.is_empty()).then_some(result["properties"]["siblings"].clone())
            })
            .expect("SARIF signature sibling properties")
    };
    assert_eq!(
        sibling_properties(&fresh_sarif),
        sibling_properties(&replay_sarif)
    );
    assert_eq!(
        fresh_sarif["runs"][0]["properties"]["summary"]["funnel"],
        replay_sarif["runs"][0]["properties"]["summary"]["funnel"]
    );
    assert_eq!(
        fresh_sarif["runs"][0]["properties"]["summary"]["guardrails"],
        replay_sarif["runs"][0]["properties"]["summary"]["guardrails"]
    );
    assert_eq!(
        reused_sarif["runs"][0]["results"],
        fresh_sarif["runs"][0]["results"]
    );
    assert_eq!(
        reused_sarif["runs"][0]["properties"]["summary"]["funnel"],
        fresh_sarif["runs"][0]["properties"]["summary"]["funnel"]
    );
    assert_eq!(
        reused_sarif["runs"][0]["properties"]["summary"]["guardrails"],
        fresh_sarif["runs"][0]["properties"]["summary"]["guardrails"]
    );

    let text_scan = |extra: &[&str]| -> String {
        let mut args = vec![
            "scan",
            ".",
            "--mode",
            "structural",
            "--untrusted",
            "--siblings-by-signature",
            "--show-siblings",
            "-vv",
        ];
        args.extend(extra);
        let output = cmd()
            .current_dir(root)
            .args(args)
            .output()
            .expect("run signature text report");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).expect("text output is UTF-8")
    };
    let fresh_text = text_scan(&["--no-reuse"]);
    let text_run_id = open_store(root)
        .latest_run()
        .unwrap()
        .expect("fresh text run")
        .id;
    let reused_text = text_scan(&[]);
    let replay_text_output = cmd()
        .current_dir(root)
        .args([
            "report",
            "--run",
            &text_run_id.to_string(),
            "--show-siblings",
            "-vv",
        ])
        .output()
        .expect("replay signature text report");
    assert!(
        replay_text_output.status.success(),
        "{replay_text_output:?}"
    );
    let sibling_lines = |text: &str| {
        text.lines()
            .filter(|line| line.trim_start().starts_with("sibling "))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    let supplemental_lines = |text: &str| {
        text.lines()
            .filter(|line| line.trim_start().starts_with("supplemental:"))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    let diagnostics_lines = |text: &str| {
        text.lines()
            .filter(|line| line.trim_start().starts_with("diagnostics:"))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    let replay_text = String::from_utf8(replay_text_output.stdout).expect("replay text UTF-8");
    for (name, text) in [
        ("fresh", fresh_text.as_str()),
        ("reused", reused_text.as_str()),
        ("replay", replay_text.as_str()),
    ] {
        assert_eq!(
            sibling_lines(&fresh_text),
            sibling_lines(text),
            "{name} sibling lines differ"
        );
        assert_eq!(
            supplemental_lines(&fresh_text),
            supplemental_lines(text),
            "{name} supplemental lines differ"
        );
        assert_eq!(
            diagnostics_lines(&fresh_text),
            diagnostics_lines(text),
            "{name} diagnostics lines differ"
        );
    }
    let shared_units = signature_sibling["signature_units"]
        .as_u64()
        .expect("signature sibling records how many units share its signature");
    let signature_marker = format!("[same signature, {shared_units} units share it]");
    assert!(fresh_text.contains(&signature_marker), "{fresh_text}");
    let composite = signature_sibling["similarity"]["composite"]
        .as_f64()
        .expect("signature sibling composite score");
    let composite_marker = format!("({composite:.2}) {signature_marker}");
    assert!(
        fresh_text.contains(&composite_marker),
        "signature sibling keeps composite score marker {composite_marker}: {fresh_text}"
    );
}

/// A signature is evidence only while it is rare, and how rare is a project
/// decision: the same tree keeps or loses its signature siblings depending on
/// the configured sharing limit, and the run records the limit it worked under.
#[test]
fn the_configured_sharing_limit_decides_whether_a_signature_is_still_evidence() {
    let dir = crowded_signature_fixture(2);
    let root = dir.path();
    let scan_json = || -> serde_json::Value {
        let output = cmd()
            .current_dir(root)
            .args([
                "scan",
                ".",
                "--mode",
                "structural",
                "--untrusted",
                "--siblings-by-signature",
                "--no-reuse",
                "--format",
                "json",
            ])
            .output()
            .expect("run crowded signature scan");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("scan output is JSON")
    };

    let admitted = scan_json();
    assert_eq!(admitted["summary"]["common_signatures_skipped"], 0);
    assert_eq!(admitted["summary"]["largest_skipped_signature_units"], 0);
    assert!(
        admitted["summary"]["siblings"].as_u64().unwrap_or(0) > 0,
        "the default limit leaves the crowded signature usable: {admitted:#?}"
    );

    std::fs::write(
        root.join("codehelion.toml"),
        "[limits]\nsignature-sibling-max-units-per-signature = 4\n",
    )
    .unwrap();
    let excluded = scan_json();
    assert_eq!(excluded["summary"]["common_signatures_skipped"], 1);
    assert_eq!(excluded["summary"]["largest_skipped_signature_units"], 6);
    assert_eq!(excluded["summary"]["siblings"], 0);
    assert_eq!(
        excluded["summary"]["guardrails"]["signature_sibling_max_units_per_signature"], 4,
        "the limit the run worked under is recorded beside the channel's caps"
    );
    assert_eq!(admitted["groups"], excluded["groups"], "{excluded:#?}");
}

/// The gate silences the whole channel on a tree whose signatures are common,
/// which is the report that hides its own explanation unless the run says what
/// it left out — in the original text and in every replay of it.
#[test]
fn a_signature_skipped_for_being_common_is_named_in_text_and_repeated_by_replay() {
    let dir = crowded_signature_fixture(2);
    let root = dir.path();
    std::fs::write(
        root.join("codehelion.toml"),
        "[limits]\nsignature-sibling-max-units-per-signature = 4\n",
    )
    .unwrap();
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--untrusted",
            "--siblings-by-signature",
            "--no-reuse",
            "--show-siblings",
        ])
        .output()
        .expect("run crowded signature text scan");
    assert!(output.status.success(), "{output:?}");
    let scan_text = String::from_utf8(output.stdout).expect("text output is UTF-8");
    let expected =
        "signature siblings: 1 signatures skipped as too common (the most common covers 6 units)";
    assert!(scan_text.contains(expected), "{scan_text}");
    assert!(
        !scan_text.contains("supplemental:"),
        "the gate left no supplemental evidence to total: {scan_text}"
    );

    let run_id = open_store(root)
        .latest_run()
        .unwrap()
        .expect("the scan recorded a run")
        .id;
    let replay = cmd()
        .current_dir(root)
        .args(["report", "--run", &run_id.to_string(), "--show-siblings"])
        .output()
        .expect("replay crowded signature report");
    assert!(replay.status.success(), "{replay:?}");
    let replay_text = String::from_utf8(replay.stdout).expect("replay text is UTF-8");
    assert!(replay_text.contains(expected), "{replay_text}");
}

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
