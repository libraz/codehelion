use super::*;

/// Both helpers must answer a real Semantic CLI scan and persist their IR.
#[test]
fn semantic_helpers_store_compiler_ir_for_rust_and_cpp() {
    let rust_dir = rust_fixture();
    let rust_root = rust_dir.path();
    let rust_report = scan(rust_root);
    let rust_run = rust_report["run"]["run_id"].as_i64().expect("Rust run id");
    assert_eq!(rust_report["summary"]["compiler"]["answered"], 1);
    assert!(stored_ir(rust_root, rust_run), "Rust helper stored no IR");

    let cpp_dir = tempfile::tempdir().expect("temporary C++ project");
    let cpp_root = codehelion_fixtures::copy_cpp("header-only", cpp_dir.path())
        .expect("copy C++ fixture with its compilation database");
    let cpp_report = scan(&cpp_root);
    let partitions = cpp_report["partitions"]
        .as_array()
        .expect("C++ definitions produce independent reports");
    assert_eq!(partitions.len(), 2);
    assert!(partitions.iter().all(|partition| {
        let run_id = partition["run"]["run_id"].as_i64().expect("C++ run id");
        partition["summary"]["compiler"]["answered"] == 2 && stored_ir(&cpp_root, run_id)
    }));
}

/// An opt-in comparison keeps the Rust and C++ normal scans independent while
/// recording a separately justified correspondence with both source graphs.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the end-to-end assertion fixes output, evidence, persistence, and measurement together"
)]
fn semantic_cross_language_comparison_records_closed_api_evidence() {
    let fixture = cross_language_pipeline_fixture();
    let root = fixture.path().to_path_buf();

    let ordinary = scan(&root);
    assert!(
        ordinary.get("cross_language_comparison").is_none(),
        "ordinary semantic scans do not join language partitions: {ordinary}"
    );
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .table_count("cross_language_comparison")
            .expect("count comparisons"),
        0
    );

    let compared = scan_comparing_languages(&root);
    let comparison = &compared["cross_language_comparison"];
    assert_eq!(
        comparison["comparison_kind"], "restricted-semantic-rust-cpp-pipelines",
        "cross-language comparison was not emitted: {compared}"
    );
    assert_eq!(
        comparison["origin_variants"].as_array().map(Vec::len),
        Some(2),
        "the comparison domain holds one Rust and one C++ variant: {compared}"
    );
    let group = comparison["groups"]
        .as_array()
        .expect("cross-language groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-sequence-pipeline-v1"
                && group["correspondence_ids"].as_array().is_some_and(|ids| {
                    ids.iter()
                        .map(Value::as_str)
                        .eq([Some("sequence-source-v1"), Some("sequence-collect-v1")])
                })
        })
        .unwrap_or_else(|| panic!("closed Rust/C++ pipeline correspondence: {comparison}"));
    assert!(
        group["semantic_confidence"]
            .as_f64()
            .is_some_and(|confidence| (0.0..=0.55).contains(&confidence)),
        "cross-language confidence must stay at or below its lower policy base: {group}"
    );
    let members = group["members"].as_array().expect("comparison members");
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|member| member["language"] == "rust"));
    assert!(members.iter().any(|member| member["language"] == "cpp"));
    assert!(members.iter().all(|member| {
        member["graph"]["nodes"].as_array().is_some_and(|nodes| {
            nodes
                .iter()
                .map(|node| node["kind"].as_str())
                .eq([Some("source"), Some("collect")])
        })
    }));
    let optional = comparison["groups"]
        .as_array()
        .expect("cross-language groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-optional-validation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["optional-presence-validation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Rust/C++ optional correspondence: {comparison}"));
    assert!(optional["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "validate"
                    && nodes[0]["attributes"]["fallible_kind"] == "option"
            })
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(root.join("labels.json")).expect("read corpus labels"),
    )
    .expect("parse cross-language corpus labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&compared).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = evaluate(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    assert!(metrics.recall_overall == Some(1.0), "{metrics:?}");
    assert!(metrics.precision_overall == Some(1.0), "{metrics:?}");
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    for rule_id in [
        "cross-language-sequence-pipeline-v1",
        "cross-language-optional-validation-v1",
    ] {
        let rule_metrics = &by_rule[rule_id];
        assert!(
            rule_metrics.recall_overall == Some(1.0),
            "{rule_id}: {rule_metrics:?}"
        );
        assert!(
            rule_metrics.precision_overall == Some(1.0),
            "{rule_id}: {rule_metrics:?}"
        );
    }

    let store = Store::open(&root.join(".codehelion/audit.db")).expect("reopen audit database");
    assert_eq!(
        store
            .table_count("cross_language_comparison")
            .expect("count comparisons"),
        1
    );
    assert_eq!(
        store
            .table_count("cross_language_semantic_group")
            .expect("count groups"),
        2
    );
    assert_eq!(
        store
            .table_count("cross_language_semantic_member")
            .expect("count members"),
        4
    );
}

/// Direct loop correspondence stays cross-language only when both compiler
/// helpers establish the narrow, untransformed construct form.
#[test]
fn semantic_cross_language_direct_loops_have_closed_construct_evidence() {
    let fixture = cross_language_direct_loop_fixture();
    let root = fixture.path();
    let compared = scan_comparing_languages(root);
    let groups = compared["cross_language_comparison"]["groups"]
        .as_array()
        .expect("cross-language groups");
    let direct_groups: Vec<_> = groups
        .iter()
        .filter(|group| {
            group["rule_id"] == "cross-language-sequence-pipeline-v1"
                && group["correspondence_ids"] == serde_json::json!(["direct-loop-sequence-v1"])
        })
        .collect();
    assert_eq!(direct_groups.len(), 2, "{groups:?}");
    assert!(direct_groups.iter().all(|group| {
        group["members"].as_array().is_some_and(|members| {
            members.iter().all(|member| {
                member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                    nodes.len() == 2
                        && nodes[0]["kind"] == "source"
                        && matches!(nodes[1]["kind"].as_str(), Some("collect" | "reduce"))
                        && nodes
                            .iter()
                            .all(|node| node["attributes"]["api_names"] == serde_json::json!([]))
                })
            })
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(root.join("labels.json")).expect("read corpus labels"),
    )
    .expect("parse cross-language loop labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&compared).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["cross-language-sequence-pipeline-v1"];
    assert!(metrics.recall_overall == Some(1.0), "{metrics:?}");
    assert!(metrics.precision_overall == Some(1.0), "{metrics:?}");
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// A helper re-run, rather than a reused snapshot, must return the same IR
/// under an unchanged build variant.
#[test]
fn semantic_rust_ir_is_deterministic_across_fresh_scans() {
    let fixture = rust_fixture();
    let root = fixture.path();
    let first = scan(root);
    let second = scan(root);
    let first_run = first["run"]["run_id"].as_i64().expect("first run id");
    let second_run = second["run"]["run_id"].as_i64().expect("second run id");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .run_compiler_units(first_run)
            .expect("read first compiler IR"),
        store
            .run_compiler_units(second_run)
            .expect("read second compiler IR")
    );
    assert_eq!(
        first["run"]["build_variant"],
        second["run"]["build_variant"]
    );
    assert_eq!(first["summary"]["compiler"], second["summary"]["compiler"]);
}

/// The compiler-backed pipeline must preserve the committed corpus's full
/// Type-1/2/3 coverage. In particular, the Type-3 mutation has a valid edge
/// that complete linkage reports as a split pair rather than silently losing
/// it while the neighbouring exact copies form a group.
#[test]
fn semantic_rust_corpus_keeps_structural_coverage_and_reports_the_split_type3_pair() {
    let (corpus, labels) = semantic_rust_corpus();
    let structural = scan_mode(corpus.path(), "structural");
    let semantic = scan(corpus.path());

    for (mode, report) in [("structural", &structural), ("semantic", &semantic)] {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (result, lines) = detected::from_report_json(&report_json)
            .unwrap_or_else(|error| panic!("read {mode} corpus report: {error}"));
        let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        assert!(
            metrics.recall_overall == Some(1.0),
            "{mode} recall: {:?}",
            metrics.recall_overall
        );
        assert!(
            metrics.precision_overall == Some(1.0),
            "{mode} precision: {:?}",
            metrics.precision_overall
        );
        assert_eq!(metrics.non_clone_hits, 0, "{mode} non-clone hits");
    }

    assert_eq!(semantic["summary"]["compiler"]["answered"], 4);
    let split_type3 = semantic["groups"]
        .as_array()
        .expect("Semantic report groups")
        .iter()
        .find(|group| group["clone_type"] == "type-3" && group["split_pair"] == true)
        .expect("Semantic report retains the Type-3 split pair");
    let members = split_type3["members"]
        .as_array()
        .expect("split pair members");
    assert!(members.iter().any(|member| {
        member["file"] == "src/lib.rs" && member["start_line"] == 4 && member["end_line"] == 12
    }));
    assert!(members.iter().any(|member| {
        member["file"] == "src/type3.rs" && member["start_line"] == 4 && member["end_line"] == 15
    }));
}

/// C++ compilation-database partitions are independently re-asked and keep
/// both their selected build variant and their compiler IR across fresh runs.
#[test]
fn semantic_cpp_ir_is_deterministic_across_fresh_scans() {
    let directory = tempfile::tempdir().expect("temporary C++ project");
    let root = codehelion_fixtures::copy_cpp("header-only", directory.path())
        .expect("copy C++ fixture with its compilation database");
    let first = scan(&root);
    let second = scan(&root);
    let first_partitions = first["partitions"].as_array().expect("first partitions");
    let second_partitions = second["partitions"].as_array().expect("second partitions");
    assert_eq!(first_partitions.len(), second_partitions.len());
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    for (first, second) in first_partitions.iter().zip(second_partitions) {
        let first_run = first["run"]["run_id"].as_i64().expect("first run id");
        let second_run = second["run"]["run_id"].as_i64().expect("second run id");
        assert_eq!(
            first["run"]["build_variant"],
            second["run"]["build_variant"]
        );
        assert_eq!(first["summary"]["compiler"], second["summary"]["compiler"]);
        assert_eq!(
            store
                .run_compiler_units(first_run)
                .expect("read first compiler IR"),
            store
                .run_compiler_units(second_run)
                .expect("read second compiler IR")
        );
    }
}
