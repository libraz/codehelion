use super::*;

#[test]
fn semantic_scan_records_registered_pipeline_evidence() {
    let fixture = rust_pipeline_fixture();
    let root = fixture.path();
    let report = scan(root);
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
        })
        .expect("registered pipeline finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(group["split_pair"], false);
    assert_eq!(
        group["semantic"]["graphs"][0]["nodes"]
            .as_array()
            .expect("canonical graph nodes")
            .iter()
            .map(|node| node["kind"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("source"), Some("filter"), Some("map"), Some("collect")],
        "the nested iterator calls lost their written order: {group:#}"
    );
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(4),
        "registered graph did not retain the iterator operations: {group:#}"
    );
    let confidence = group["semantic"]["rules"][0]["confidence"]
        .as_f64()
        .expect("semantic confidence");
    assert!(
        (confidence - 0.7).abs() < f64::EPSILON,
        "semantic evidence names the registered rule confidence: {confidence}"
    );
    assert!(
        group["confidence"]
            .as_f64()
            .is_some_and(|confidence| (confidence - 0.735).abs() < f64::EPSILON),
        "the group separately retains its corroborated composite confidence: {group:#}"
    );

    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let stored = store.run_groups(run_id).expect("read groups");
    let semantic = stored
        .iter()
        .find_map(|group| group.semantic.as_ref())
        .expect("stored semantic evidence");
    assert_eq!(semantic.rule_id, "sequence-pipeline-v1");
    assert!((semantic.rule_confidence - confidence).abs() < f64::EPSILON);
    assert_eq!(semantic.graphs.len(), 2);
    assert_eq!(semantic.node_mappings.len(), 4);
    let stored_ir = store.run_compiler_units(run_id).expect("read compiler IR");
    let data_flow = stored_ir
        .iter()
        .find_map(|unit| match &unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(&ir.data_flow),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("stored Rust compiler IR");
    assert!(data_flow.computed);
    assert_eq!(data_flow.flows.len(), 2, "{data_flow:?}");
}

/// C++ serialization is admitted only as its exact resolved conversion pair.
#[test]
fn semantic_scan_matches_only_closed_cpp_serialization_round_trips() {
    let fixture = cpp_serialization_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "cpp-serialization-round-trip-v1"
        })
        .expect("closed C++ serialization pair");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        group["semantic"]["graphs"][0]["nodes"]
            .as_array()
            .expect("serialization graph nodes")
            .iter()
            .map(|node| node["kind"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("map"), Some("map")]
    );
}

/// Every same-language rule starts enabled only because a labelled corpus
/// exercises its positive and deliberately close negative forms through the
/// real helper process. The assertion is a regression check, not a CI score
/// gate or a claim that this compact corpus estimates field precision.
#[test]
fn semantic_rules_have_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_rust_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);

    for rule_id in [
        "sequence-pipeline-v1",
        "result-direct-propagation-v1",
        "option-direct-propagation-v1",
        "optional-validation-v1",
        "result-validation-v1",
        "resource-lifecycle-v1",
        "rust-serialization-round-trip-v1",
    ] {
        let metrics = &by_rule[rule_id];
        assert!(
            metrics.recall_overall == Some(1.0),
            "{rule_id}: {metrics:?}"
        );
        assert!(
            metrics.precision_overall == Some(1.0),
            "{rule_id}: {metrics:?}"
        );
        assert_eq!(metrics.non_clone_hits, 0, "{rule_id}: {metrics:?}");
    }
}

/// The C++ serialization rule is enabled only after the Clang helper resolves
/// both conversion calls in its labelled positive and negative corpus forms.
#[test]
fn cpp_serialization_rule_has_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_cpp_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["cpp-serialization-round-trip-v1"];
    assert!(metrics.recall_overall == Some(1.0), "{metrics:?}");
    assert!(metrics.precision_overall == Some(1.0), "{metrics:?}");
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// The C++ direct range-for collection and reduction forms are enabled only
/// after their real-helper corpus accepts both registered pairs and rejects
/// transformed near misses.
#[test]
fn cpp_plain_range_loop_forms_have_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_cpp_loop_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["sequence-pipeline-v1"];
    assert!(metrics.recall_overall == Some(1.0), "{metrics:?}");
    assert!(metrics.precision_overall == Some(1.0), "{metrics:?}");
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// Repeating a real-helper scan preserves the direct range-for findings and
/// their rule-specific measurement.
#[test]
fn cpp_plain_range_loop_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_cpp_loop_corpus();
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    assert_eq!(measure(&first), measure(&second));
}

/// Fresh C++ scans retain the same closed-rule findings and measurements.
#[test]
fn cpp_serialization_rule_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_cpp_corpus();
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    assert_eq!(measure(&first), measure(&second));
}

/// Repeating a real-helper scan of the same labelled semantic corpus must
/// preserve both the reported findings and every per-rule metric. This keeps
/// result stability and the per-kLOC rates in the same regression contract as
/// the closed positive and negative examples.
#[test]
fn semantic_rule_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_rust_corpus();
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let (first_detected, first_metrics) = measure(&first);
    let (second_detected, second_metrics) = measure(&second);
    assert_eq!(first_detected, second_detected);
    assert_eq!(first_metrics, second_metrics);
    assert!(first_metrics.values().all(|metrics| {
        metrics.findings_per_kloc.is_some_and(|rate| rate > 0.0)
            && metrics.false_positives_per_kloc == Some(0.0)
            && metrics.non_clone_hits == 0
    }));
}

/// A registered sequence embedded beside unrelated registered constructs is a
/// fragment finding. Its source lines must name the iterator expression, not
/// the enclosing function, while its graph retains only the sequence nodes.
#[test]
fn semantic_scan_reports_partial_pipeline_source_ranges() {
    let fixture = rust_partial_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
        })
        .unwrap_or_else(|| panic!("partial pipelines form a semantic finding: {report}"));
    assert_eq!(group["scope"], "fragment");
    for member in group["members"].as_array().expect("group members") {
        assert!(
            matches!(member["start_line"].as_u64(), Some(2 | 7)),
            "the finding must start at its iterator expression: {member:#}"
        );
        assert_eq!(member["start_line"], member["end_line"]);
    }
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("source"), Some("filter"), Some("map"), Some("collect")]
        );
    }
}

/// A plain explicit collection loop is comparable to the registered iterator
/// collection pipeline when both represent only source and collection.
#[test]
fn semantic_scan_matches_a_plain_collection_loop_to_an_iterator_pipeline() {
    let fixture = rust_loop_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["members"].as_array().map(Vec::len) == Some(2)
        })
        .unwrap_or_else(|| {
            panic!("plain loop and iterator pipeline form a semantic finding: {report}")
        });
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("source"), Some("collect")],
            "the loop normalizer admitted an unregistered operation: {graph:#}"
        );
    }
}

/// The resource rule is available only when the Rust helper proved the direct
/// standard acquisition and the lexical scope supplied its `Drop` boundary.
#[test]
fn semantic_scan_matches_direct_standard_file_lifetimes() {
    let fixture = rust_resource_lifetime_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "resource-lifecycle-v1"
        })
        .unwrap_or_else(|| panic!("direct standard file lifetimes form a finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(3));
    assert_eq!(group["split_pair"], false);
    assert!(
        group["semantic"]["rules"][0]["confidence"]
            .as_f64()
            .is_some_and(|confidence| (confidence - 0.9).abs() < f64::EPSILON),
        "{group:#}"
    );
    assert!(
        group["confidence"]
            .as_f64()
            .is_some_and(|confidence| (confidence - 0.4725).abs() < f64::EPSILON),
        "the group separately retains its corroborated composite confidence: {group:#}"
    );
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(4),
        "each non-canonical graph must retain both resource-node mappings: {group:#}"
    );
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("acquire_resource"), Some("release_resource")],
            "the resource graph admitted an unrelated operation: {graph:#}"
        );
        assert_eq!(
            graph["edges"]
                .as_array()
                .expect("graph edges")
                .iter()
                .filter(|edge| edge["kind"] == "resource_lifetime")
                .count(),
            1,
            "the resource graph lost its lifecycle edge: {graph:#}"
        );
    }
}

/// `Iterator::fold` is a closed reduce operation, not an API-name suffix
/// guess: the helper must resolve both the source and fold calls before the
/// same sequence rule may compare the two functions.
#[test]
fn semantic_scan_matches_registered_iterator_reductions() {
    let fixture = rust_reduce_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("reduce")])
                            })
                        })
                    })
        })
        .unwrap_or_else(|| {
            panic!("two registered iterator reductions form a semantic finding: {report}")
        });
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(2)
    );
}

/// A direct arithmetic loop is admitted only as SOURCE/REDUCE and therefore
/// pairs with the same closed iterator reduction. Its guarded sibling is not
/// reconstructed as a reduction of every element.
#[test]
fn semantic_scan_matches_a_plain_reduce_loop_to_an_iterator_reduction() {
    let fixture = rust_loop_reduce_fixture();
    let report = scan(fixture.path());
    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let compiler_units = Store::open(&fixture.path().join(".codehelion/audit.db"))
        .expect("open audit database")
        .run_compiler_units(run_id)
        .expect("read compiler analyses");
    let compiler_ir = compiler_units
        .iter()
        .find_map(|analysis| match &analysis.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("Rust helper analysis");
    let constructs = &compiler_ir.semantic_constructs;
    assert_eq!(
        constructs
            .iter()
            .filter(|construct| construct.kind.name() == "reduce")
            .count(),
        1,
        "the guarded loop must not enter the reduction vocabulary: {constructs:?}"
    );
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("reduce")])
                            })
                        })
                    })
        })
        .unwrap_or_else(|| {
            panic!(
                "plain loop and iterator reduction form a finding; constructs: {constructs:?}; calls: {:?}; report: {report}",
                compiler_ir.calls
            )
        });
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
}

/// The direct `Result` rule needs the helper-confirmed form on both sides;
/// a naked propagation expression is insufficient evidence for a finding.
#[test]
fn semantic_scan_matches_only_direct_result_propagation_forms() {
    let fixture = rust_direct_propagation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "result-direct-propagation-v1"
        })
        .expect("direct Result adapters form a semantic finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("propagate_error")]
        );
        assert_eq!(
            graph["nodes"][0]["attributes"]["direct_propagation"],
            "result_adapter"
        );
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "result-direct-propagation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// Direct `Option` adapters need compiler confirmation of an identity form;
/// a transformation after `?` and a project constructor named `Some` remain
/// non-matches even though both functions have the same standard fallible type.
#[test]
fn semantic_scan_matches_only_direct_option_propagation_forms() {
    let fixture = rust_direct_propagation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "option-direct-propagation-v1"
        })
        .unwrap_or_else(|| panic!("direct Option adapters form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "option");
        assert_eq!(
            graph["nodes"][0]["attributes"]["direct_propagation"],
            "option_adapter"
        );
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "option-direct-propagation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// Direct standard `Option::is_some`, a standard `Option` match, and the
/// narrow early unit-return guard have the same closed validation evidence.
/// Compound and other inverted conditions remain outside the vocabulary.
#[test]
fn semantic_scan_matches_only_direct_option_presence_checks() {
    let fixture = rust_optional_validation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "optional-validation-v1"
        })
        .unwrap_or_else(|| panic!("direct optional checks form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(5));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("validate")]
        );
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "option");
        assert!(graph["nodes"][0]["attributes"]["direct_propagation"].is_null());
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "optional-validation-v1"
            || group["members"].as_array().map(Vec::len) != Some(6)
    }));
}

/// A direct standard `Result::is_ok` condition is independently comparable.
/// Compound and project-defined `is_ok` conditions stay outside the closed
/// vocabulary, despite sharing the same source-level method spelling.
#[test]
fn semantic_scan_matches_only_direct_result_presence_checks() {
    let fixture = rust_result_validation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "result-validation-v1"
        })
        .unwrap_or_else(|| panic!("direct result checks form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("validate")]
        );
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "result");
        assert!(graph["nodes"][0]["attributes"]["direct_propagation"].is_null());
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "result-validation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// The Rust `Ok(value?)` and C++23 `return expected_value;` forms meet only
/// through the explicit result/expected propagation rule. Transformed forms
/// are not candidates for the direct-adapter correspondence.
#[test]
fn semantic_cross_language_result_expected_uses_closed_propagation_evidence() {
    let fixture = cross_language_result_expected_fixture();
    let report = scan_comparing_languages(fixture.path());
    let comparison = report["cross_language_comparison"]
        .as_object()
        .expect("cross-language comparison");
    let group = comparison["groups"]
        .as_array()
        .expect("comparison groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-result-direct-propagation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["result-expected-direct-propagation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Result/expected correspondence: {comparison:?}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert!(group["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "propagate_error"
                    && nodes[0]["attributes"]["fallible_kind"] == "result"
                    && nodes[0]["attributes"]["direct_propagation"] == "result_adapter"
            })
        })
    }));
    assert!(comparison["groups"].as_array().is_some_and(|groups| {
        groups.iter().all(|other| {
            other["rule_id"] != "cross-language-result-direct-propagation-v1"
                || other["members"].as_array().map(Vec::len) != Some(3)
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(fixture.path().join("labels.json"))
            .expect("read result/expected corpus labels"),
    )
    .expect("parse result/expected corpus labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&report).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = evaluate(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    assert!(
        metrics.recall_overall == Some(1.0),
        "{metrics:?}\nlabels: {labels:?}\ndetected: {detected:?}"
    );
    assert!(metrics.precision_overall == Some(1.0), "{metrics:?}");
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    for rule_id in [
        "cross-language-result-direct-propagation-v1",
        "cross-language-result-validation-v1",
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
}

/// A presence branch is compared independently from propagation: the helpers
/// must resolve `Result::is_ok()` and `expected::has_value()` to their standard
/// families, while the compound forms remain outside the closed rule.
#[test]
fn semantic_cross_language_result_expected_uses_closed_validation_evidence() {
    let fixture = cross_language_result_expected_fixture();
    let report = scan_comparing_languages(fixture.path());
    let comparison = report["cross_language_comparison"]
        .as_object()
        .expect("cross-language comparison");
    let group = comparison["groups"]
        .as_array()
        .expect("comparison groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-result-validation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["result-expected-validation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Result/expected validation: {comparison:?}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert!(group["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "validate"
                    && nodes[0]["attributes"]["fallible_kind"] == "result"
                    && nodes[0]["attributes"]["direct_propagation"].is_null()
            })
        })
    }));
    assert!(comparison["groups"].as_array().is_some_and(|groups| {
        groups.iter().all(|other| {
            other["rule_id"] != "cross-language-result-validation-v1"
                || other["members"].as_array().map(Vec::len) != Some(3)
        })
    }));
}

/// Disabling a stable rule ID removes only that registered semantic verdict;
/// the compiler-backed scan still completes and retains its ordinary
/// structural findings.
#[test]
fn semantic_rule_registry_can_disable_a_registered_pipeline() {
    let fixture = rust_pipeline_fixture();
    std::fs::write(
        fixture.path().join("codehelion.toml"),
        "[semantic]\ndisabled = [\"sequence-pipeline-v1\"]\n",
    )
    .expect("write semantic configuration");
    let report = scan(fixture.path());
    assert!(
        report["groups"]
            .as_array()
            .expect("groups array")
            .iter()
            .all(|group| group["clone_type"] != "restricted-semantic"),
        "a disabled rule emitted a restricted-semantic finding"
    );
    let disabled = report["summary"]["funnel"]
        .as_array()
        .expect("funnel array")
        .iter()
        .find(|stage| stage["stage"] == "semantic verified pairs")
        .and_then(|stage| stage["dropped"].as_array())
        .expect("semantic verifier accounted for the disabled rule");
    assert!(disabled.iter().any(|drop| {
        drop["cause"] == "rule_disabled" && drop["count"].as_u64().unwrap_or(0) > 0
    }));
}
