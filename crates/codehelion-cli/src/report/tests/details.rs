use super::*;

#[test]
fn semantic_finding_detail_keeps_graphs_and_mappings_readable() {
    let detail = FindingDetail {
        member: fragment_group().members.remove(0),
        group: GroupRef {
            fingerprint: "0e".repeat(16),
            clone_type: "restricted-semantic".to_string(),
            scope: CloneScope::Unit.name().to_string(),
            confidence: 0.7,
            entropy_bits: 4.5,
            priority: None,
            members: 2,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            split_pair: true,
            similarity: None,
            semantic: Some(SemanticEvidence {
                schema_version: "sog-v1".to_string(),
                rules: vec![SemanticRuleEvidence {
                    id: "sequence-pipeline-v1".to_string(),
                    version: 1,
                    confidence: 0.7,
                }],
                graphs: vec![semantic_graph(), semantic_graph()],
                node_mappings: vec![SemanticNodeMapping {
                    corresponding_member: 1,
                    canonical: 0,
                    corresponding: 0,
                }],
            }),
            suppressed: None,
        },
        scan_run: 3,
        source_artifact_mappings: Vec::new(),
        clone_group_savings: Vec::new(),
    };
    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(
        json["group"]["semantic"]["graphs"].as_array().map(Vec::len),
        Some(2)
    );

    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("semantic evidence: sog-v1"));
    assert!(text.contains("rule sequence-pipeline-v1@1"));
    assert!(text.contains("graph 1: source -> collect"));
    assert!(text.contains("node mapping: 0→0"));
}

#[test]
fn cross_language_group_detail_keeps_closed_evidence_and_origins_readable() {
    let detail = CrossLanguageGroupDetail {
        group_id: "ab".repeat(16),
        comparison_id: "cd".repeat(16),
        policy_version: "cross-language-semantic-v1".to_string(),
        root_path: "/work/project".to_string(),
        origin_variants: vec!["cpp-variant".to_string(), "rust-variant".to_string()],
        rule_id: "cross-language-sequence-pipeline-v1".to_string(),
        rule_version: 1,
        semantic_confidence: 0.55,
        correspondence_ids: vec!["sequence-map-v1".to_string()],
        members: vec![CrossLanguageGroupMemberDetail {
            origin_variant: "rust-variant".to_string(),
            language: "rust".to_string(),
            file: "rust/src/lib.rs".to_string(),
            start_line: 3,
            end_line: 6,
            unit: Some("map_values".to_string()),
            graph: semantic_graph(),
        }],
    };

    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(json["schema_version"], FINDING_DETAIL_SCHEMA_VERSION);
    assert_eq!(json["response_kind"], EXPLAIN_RESPONSE_CROSS_LANGUAGE_GROUP);
    assert_valid_finding_detail_schema(&json);
    assert_eq!(json["correspondence_ids"][0], "sequence-map-v1");
    assert_eq!(json["members"][0]["graph"]["schema_version"], "sog-v1");
    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("cross-language semantic group"));
    assert!(text.contains("sequence-map-v1"));
    assert!(text.contains("rust rust/src/lib.rs:3-6 (rust-variant)"));
    assert!(text.contains("graph sog-v1: source -> collect"));
}

#[test]
fn a_scored_group_reports_every_dimension_and_marks_the_absent_one() {
    let mut report = sample_report();
    report.summary.groups.type_3 = 1;
    report.groups.push(structural_group());
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();

    let similarity = &value["groups"][2]["similarity"];
    assert_eq!(similarity["composite"], 0.82);
    assert_eq!(similarity["min_pairwise"], 0.79);
    assert_eq!(similarity["weight_version"], "structural-verify-v1");
    assert_eq!(similarity["confidence_band"], "medium");
    assert_eq!(value["groups"][2]["entropy_bits"], 5.4);
    assert_eq!(value["groups"][2]["identifier_jaccard"], 0.5);
    assert_eq!(
        value["groups"][2]["priority"]["inputs"]["identifier_jaccard"],
        0.5
    );
    assert_eq!(
        value["groups"][2]["priority"]["inputs"]["api_similarity"],
        0.75
    );
    assert_eq!(value["groups"][2]["body_materiality"]["call_count"], 3);
    // Unavailable, not guessed: the dimension is reported as absent.
    assert_eq!(similarity["type_similarity"], serde_json::Value::Null);
    // A mode that scores no dimensions says so rather than omitting the key.
    assert_eq!(value["groups"][0]["similarity"], serde_json::Value::Null);
    assert_eq!(value["summary"]["groups"]["type_3"], 1);

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("type-1 2, type-2 0, type-3 1"));
    assert!(text.contains(
        "similarity: composite 0.82 (lexical 0.71, structural 0.88, \
         control-flow 0.90, type n/a, api 0.75); cohesion 0.79; \
         confidence medium [structural-verify-v1]"
    ));
    // On the heading, beside the value the default order reads, because a
    // reader following identifier agreement needs it where the ordering
    // can be checked against it.
    assert!(text.contains("identifiers 0.50"));
    assert!(text.contains("body evidence: loop yes"));
    assert!(text.contains("content entropy: 5.40 bits"));
}

#[test]
fn unmeasured_control_flow_is_json_null_and_text_na() {
    let mut report = sample_report();
    report.groups.push(structural_group());
    let similarity = report.groups[2]
        .similarity
        .as_mut()
        .expect("the structural sample has a similarity breakdown");
    similarity.control_flow = None;

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["groups"][2]["similarity"]["control_flow"],
        serde_json::Value::Null
    );

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("control-flow n/a"));
}

#[test]
fn a_group_standing_where_a_gone_one_stood_says_so_and_the_rest_stay_quiet() {
    let mut report = sample_report();
    report.groups[0].baseline = Some(GroupBaseline {
        state: GROUP_NEW.to_string(),
        added_instances: None,
        derived_from: Some(Derivation {
            group: "aa11".to_string(),
            shared_sites: 2,
        }),
    });
    report.groups[1].baseline = Some(GroupBaseline {
        state: GROUP_CONTINUING.to_string(),
        added_instances: None,
        derived_from: None,
    });

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("new since the baseline, standing where aa11 stood (2 occurrence(s)"),
        "{text}"
    );
    // Continuing is the unremarkable case, and marking every one of them
    // would bury the one that matters.
    assert_eq!(text.matches("since the baseline").count(), 1, "{text}");
}

#[test]
fn an_expanded_group_names_the_uncovered_occurrences() {
    let mut report = sample_report();
    report.groups[0].baseline = Some(GroupBaseline {
        state: GROUP_EXPANDED.to_string(),
        added_instances: Some(1),
        derived_from: None,
    });

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("expanded since the baseline: 1 new occurrence(s)"),
        "{text}"
    );
}

#[test]
fn a_comparison_says_how_much_went_as_well_as_how_many() {
    let mut report = sample_report();
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_COMPARE.to_string(),
        matched: 8,
        stale: 4,
        appeared: 21,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 3400,
        appeared_tokens: 900,
        expanded_tokens: 0,
        gone: vec![GoneGroup {
            group: "aa11".to_string(),
            clone_type: "type-2".to_string(),
            duplicated_tokens: 3400,
            anchor: Some(GoneAnchor {
                file: "src/gone.rs".to_string(),
                start_line: 10,
                end_line: 40,
                unit: Some("validate".to_string()),
            }),
        }],
        mismatch: None,
    });

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // 21 new against 4 gone reads as a regression until the sizes are on
    // the same line: the four that went were most of the duplication.
    assert!(
        text.contains(
            "since it was recorded: 4 gone (-3400 repeated tokens), 21 new (+900), 0 expanded (+0 occurrence(s), +0 repeated tokens), 8 unchanged"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "gone aa11 type-2 (3400 repeated tokens), last seen at src/gone.rs:10 in validate"
        ),
        "{text}"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the test walks every public JSON object against its schema declaration"
)]
fn json_field_names_appear_in_the_shipped_schema() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        i64::from(SCHEMA_VERSION)
    );
    assert_eq!(schema["properties"]["summary"]["$ref"], "#/$defs/summary");
    assert!(schema["$defs"]["run"]["properties"]["configuration"].is_object());
    assert!(
        schema["$defs"]["summary"]["properties"]["compiler"]["properties"]["execution_refusals"]
            .is_object()
    );
    let mut report = sample_report();
    report.groups.push(structural_group());
    report.groups.push(fragment_group());
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_SUPPRESS.to_string(),
        matched: 11,
        stale: 1,
        appeared: 3,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 320,
        appeared_tokens: 90,
        expanded_tokens: 0,
        gone: vec![GoneGroup {
            group: "aa11".to_string(),
            clone_type: "type-2".to_string(),
            duplicated_tokens: 320,
            anchor: Some(GoneAnchor {
                file: "src/gone.rs".to_string(),
                start_line: 10,
                end_line: 40,
                unit: Some("validate".to_string()),
            }),
        }],
        mismatch: Some("recorded under another build variant".to_string()),
    });
    report.groups[0].baseline = Some(GroupBaseline {
        state: GROUP_NEW.to_string(),
        added_instances: None,
        derived_from: Some(Derivation {
            group: "aa11".to_string(),
            shared_sites: 2,
        }),
    });
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert!(value["groups"][0]["artifact_savings"].is_array());
    assert!(value["summary"]["search_truncated"].is_boolean());
    let baseline_schema = &schema["$defs"]["summary"]["properties"]["baseline"]["properties"];
    let group_baseline_schema = &schema["$defs"]["group"]["properties"]["baseline"]["properties"];
    let run_schema = &schema["$defs"]["run"]["properties"];
    let run_configuration_schema =
        &schema["$defs"]["run"]["properties"]["configuration"]["properties"];
    let checks = [
        (&value["groups"][3], &schema["$defs"]["group"]["properties"]),
        (&value["summary"]["baseline"], baseline_schema),
        (
            &value["summary"]["baseline"]["gone"][0],
            &baseline_schema["gone"]["items"]["properties"],
        ),
        (
            &value["summary"]["baseline"]["gone"][0]["anchor"],
            &baseline_schema["gone"]["items"]["properties"]["anchor"]["properties"],
        ),
        (&value["groups"][0]["baseline"], group_baseline_schema),
        (
            &value["groups"][0]["baseline"]["derived_from"],
            &group_baseline_schema["derived_from"]["properties"],
        ),
        (&value, &schema["properties"]),
        (&value["run"], run_schema),
        (&value["run"]["configuration"], run_configuration_schema),
        (&value["summary"], &schema["$defs"]["summary"]["properties"]),
        (
            &value["summary"]["groups"],
            &schema["$defs"]["summary"]["properties"]["groups"]["properties"],
        ),
        (&value["groups"][0], &schema["$defs"]["group"]["properties"]),
        (
            &value["groups"][0]["members"][0],
            &schema["$defs"]["member"]["properties"],
        ),
        (
            &value["groups"][1]["suppressed"],
            &schema["$defs"]["suppression"]["properties"],
        ),
        (
            &value["groups"][2]["similarity"],
            &schema["$defs"]["similarity"]["properties"],
        ),
        (
            &value["run"]["ranking"],
            &schema["$defs"]["ranking"]["properties"],
        ),
        (
            &value["groups"][0]["priority"],
            &schema["$defs"]["priority"]["properties"],
        ),
        (
            &value["groups"][0]["priority"]["inputs"],
            &schema["$defs"]["priority_inputs"]["properties"],
        ),
    ];
    for (object, properties) in checks {
        for key in object.as_object().unwrap().keys() {
            assert!(
                properties.get(key).is_some(),
                "field {key:?} missing from the shipped schema"
            );
        }
    }
}

#[test]
fn a_baseline_with_only_stale_entries_reports_its_actual_counts() {
    let mut report = sample_report();
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_SUPPRESS.to_string(),
        matched: 0,
        stale: 12,
        appeared: 0,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 0,
        appeared_tokens: 0,
        expanded_tokens: 0,
        gone: Vec::new(),
        mismatch: None,
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("baseline codehelion-baseline.json: 0 of 12 entries matched"));
    assert!(!text.contains("warning:"));

    // A baseline that applies says only what it did.
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_SUPPRESS.to_string(),
        matched: 11,
        stale: 1,
        appeared: 0,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 0,
        appeared_tokens: 0,
        expanded_tokens: 0,
        gone: Vec::new(),
        mismatch: None,
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("11 of 12 entries matched, 1 no longer found"));
    assert!(!text.contains("warning:"));
}

#[test]
fn text_view_truncates_with_an_explicit_count() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("lines: 40; tokens: 200"));
    assert!(text.contains("... and 2 more occurrences"));
    assert!(!text.contains("src/file6.rs"));
    assert!(!text.contains("vendor/a.rs")); // suppressed and not requested
    assert!(!text.contains('\x1b'));
}

#[test]
fn a_candidate_search_cut_is_stated_without_verbose_output() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("candidate search was truncated by high frequency"));
    assert!(text.contains("may be missing from this report"));
}

#[test]
fn text_view_states_each_groups_file_spread() {
    let mut report = sample_report();
    report.groups[0].priority.inputs.files = 1;
    report.groups[1].priority.inputs.files = 2;
    report.groups[1].priority.inputs.directories = 1;
    report.groups[1].suppressed = None;
    let mut third = fragment_group();
    third.priority.inputs.files = 2;
    third.priority.inputs.directories = 2;
    report.groups.push(third);

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("[within one file]"));
    assert!(text.contains("[within one directory]"));
    assert!(text.contains("[across directories]"));
}

#[test]
fn verbose_text_lists_every_member_and_suppressed_section_is_opt_in() {
    let opts = TextOptions {
        verbose: true,
        show_suppressed: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("src/file6.rs"));
    assert!(!text.contains("more occurrences"));
    assert!(text.contains("suppressed groups:"));
    assert!(text.contains("[suppressed: path glob \"vendor/**\"]"));
}

#[test]
fn suppressed_text_listing_has_the_same_default_cap_as_visible_groups() {
    let mut report = sample_report();
    for index in 0..TEXT_GROUP_LIMIT {
        let mut group = suppressed_group();
        group.fingerprint = format!("{index:032x}");
        report.groups.push(group);
    }

    let render = |verbose| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    verbose,
                    show_suppressed: true,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert!(render(false).contains("... and 1 more suppressed groups"));
    assert!(!render(true).contains("more suppressed groups"));
}

#[test]
fn the_pipeline_counts_are_detail_the_verbose_view_asks_for() {
    let render = |verbose| {
        let opts = TextOptions {
            verbose,
            ..TextOptions::default()
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    };
    let verbose = render(true);
    assert!(verbose.contains("candidate pipeline:"));
    assert!(verbose.contains("tokens"));
    assert!(verbose.contains("(dropped: high frequency 3)"));
    // A cause that dropped nothing says nothing.
    assert!(!verbose.contains("hash collision"));
    assert!(!render(false).contains("candidate pipeline:"));
}

#[test]
fn a_depth_limited_parse_is_stated_in_the_default_text_view() {
    let mut report = sample_report();
    report
        .summary
        .funnel
        .push(FunnelStage::new("structural files", 2).dropping("depth_limit", 1));
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("structural parsing reached its depth limit in 1 file(s)"),
        "{text}"
    );
}

#[test]
fn colored_text_uses_ansi_codes_only_when_enabled() {
    let opts = TextOptions {
        color: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("\x1b[1mcodehelion scan (fast mode)\x1b[0m"));
    assert!(text.contains("\x1b[36m"));
}

#[test]
fn finding_detail_shares_the_member_shape_across_views() {
    let detail = FindingDetail {
        member: Member {
            language: "rust".to_string(),
            finding_id: "ab".repeat(16),
            content: "c0".repeat(16),
            file: "src/lib.rs".to_string(),
            start_line: 3,
            end_line: 12,
            unit: Some("checksum".to_string()),
            boilerplate: None,
            tokens: 64,
            canonical: true,
        },
        group: GroupRef {
            fingerprint: "cd".repeat(16),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            confidence: 1.0,
            entropy_bits: 5.2,
            priority: None,
            members: 2,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            split_pair: false,
            similarity: None,
            semantic: None,
            suppressed: None,
        },
        scan_run: 7,
        source_artifact_mappings: Vec::new(),
        clone_group_savings: Vec::new(),
    };
    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(value["schema_version"], FINDING_DETAIL_SCHEMA_VERSION);
    assert_eq!(value["response_kind"], EXPLAIN_RESPONSE_OCCURRENCE);
    assert_valid_finding_detail_schema(&value);
    assert_eq!(value["finding_id"], "ab".repeat(16));
    assert_eq!(value["group"]["clone_type"], "type-1");
    assert_eq!(value["group"]["entropy_bits"], 5.2);
    assert_eq!(value["scan_run"], 7);
    // A Fast-mode occurrence measured no dimensions; the field is present
    // and null rather than filled with a guess.
    assert!(value["group"]["similarity"].is_null());

    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains(&format!("finding {}", "ab".repeat(16))));
    assert!(text.contains("location: src/lib.rs:3-12"));
    assert!(text.contains("canonical: yes"));
    assert!(text.contains("2 instances"));
    assert!(text.contains("content entropy: 5.20 bits"));
}

#[test]
fn clone_group_detail_has_a_discriminated_schema_envelope() {
    let detail = CloneGroupDetail {
        database: ".codehelion/audit.db".to_string(),
        group: visible_group(),
    };
    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(value["schema_version"], CloneGroupDetail::SCHEMA_VERSION);
    assert_eq!(value["response_kind"], EXPLAIN_RESPONSE_CLONE_GROUP);
    assert_valid_finding_detail_schema(&value);
}

#[test]
fn finding_detail_exposes_mapping_evidence_and_separate_estimate_confidences() {
    let detail = FindingDetail {
        member: fragment_group().members.remove(0),
        group: GroupRef {
            fingerprint: "0e".repeat(16),
            clone_type: "type-1".to_string(),
            scope: SCOPE_FRAGMENT.to_string(),
            confidence: 1.0,
            entropy_bits: 4.0,
            priority: None,
            members: 2,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            split_pair: false,
            similarity: None,
            semantic: None,
            suppressed: None,
        },
        scan_run: 3,
        source_artifact_mappings: vec![SourceArtifactMappingDetail {
            artifact_analysis_id: 12,
            artifact_symbol_fingerprint: "ab".repeat(16),
            source_build_variant_fingerprint: "cd".repeat(16),
            artifact_build_variant_fingerprint: "ef".repeat(16),
            confidence: "ambiguous".to_string(),
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::Dwarf {
                    source_path: "src/lib.rs".to_string(),
                }],
                1,
                true,
            ),
            attributed_bytes: Some(8),
        }],
        clone_group_savings: vec![CloneGroupSavingsDetail {
            artifact_analysis_id: 12,
            source_build_variant_fingerprint: "cd".repeat(16),
            artifact_build_variant_fingerprint: "ef".repeat(16),
            duplicated_bytes: 8,
            estimated_refactor_savings_bytes: -2,
            mapping_confidence: "high".to_string(),
            clone_confidence: 1.0,
            model_confidence: "low".to_string(),
            savings_confidence: "low".to_string(),
            model_schema_version: "refactor-savings-model-v1".to_string(),
            assumptions: serde_json::json!([{
                "kind": "shared_implementation_retains_copies",
                "copies": 1,
            }]),
        }],
    };

    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(
        value["source_artifact_mappings"][0]["evidence"]["facts"][0]["kind"],
        "dwarf"
    );
    assert_eq!(
        value["source_artifact_mappings"][0]["evidence"]["has_conflict"],
        true
    );
    assert_eq!(
        value["clone_group_savings"][0]["estimated_refactor_savings_bytes"],
        -2
    );
    assert_eq!(value["clone_group_savings"][0]["model_confidence"], "low");
    assert_eq!(
        value["clone_group_savings"][0]["source_build_variant_fingerprint"],
        "cd".repeat(16)
    );
    assert_eq!(
        value["clone_group_savings"][0]["assumptions"][0]["kind"],
        "shared_implementation_retains_copies"
    );

    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("source-artifact mappings:"));
    assert!(text.contains("conflicting evidence retained"));
    assert!(text.contains("refactoring estimates (not guaranteed):"));
    assert!(text.contains("-2 estimated bytes"));
    assert!(text.contains(&format!("source build variant: {}", "cd".repeat(16))));
    assert!(text.contains(&format!("artifact build variant: {}", "ef".repeat(16))));
    assert!(text.contains("model schema: refactor-savings-model-v1"));
    assert!(text.contains("shared_implementation_retains_copies"));
}

#[test]
fn a_structural_occurrence_explains_itself_with_the_recorded_evidence() {
    let detail = FindingDetail {
        member: Member {
            language: "rust".to_string(),
            finding_id: "ef".repeat(16),
            content: "c0".repeat(16),
            file: "src/b.rs".to_string(),
            start_line: 1,
            end_line: 20,
            unit: Some("beta".to_string()),
            boilerplate: None,
            tokens: 90,
            canonical: false,
        },
        group: GroupRef {
            fingerprint: "cd".repeat(16),
            clone_type: "type-3".to_string(),
            scope: "unit".to_string(),
            confidence: 0.87,
            entropy_bits: 5.4,
            priority: None,
            members: 2,
            boilerplate: Some("macro-repetition".to_string()),
            test_code: false,
            test_code_evidence: None,
            split_pair: false,
            similarity: Some(Similarity {
                weight_version: "structural-verify-v1".to_string(),
                lexical: 0.71,
                structural: 0.92,
                control_flow: Some(1.0),
                type_similarity: None,
                api: Some(0.8),
                composite: 0.87,
                min_pairwise: 0.87,
                confidence_band: Some("medium".to_string()),
            }),
            semantic: None,
            suppressed: Some(Suppression {
                kind: SuppressionKind::Rule,
                reason: None,
                scope: Some("symbol_pattern".to_string()),
                pattern: Some("beta".to_string()),
                active: Some(true),
            }),
        },
        scan_run: 9,
        source_artifact_mappings: Vec::new(),
        clone_group_savings: Vec::new(),
    };
    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("similarity: composite 0.87"));
    // The unmeasured dimension is named, never guessed.
    assert!(text.contains("type n/a"));
    assert!(text.contains("confidence medium"));
    assert!(text.contains("boilerplate: macro-repetition"));
    // A suppressed finding is still recorded and still explainable.
    assert!(text.contains("suppressed: symbol glob \"beta\""));
}

#[test]
fn an_unrecorded_confidence_band_prints_as_absent() {
    let similarity = Similarity {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 0.5,
        structural: 0.5,
        control_flow: Some(0.5),
        type_similarity: None,
        api: Some(0.5),
        composite: 0.5,
        min_pairwise: 0.5,
        confidence_band: None,
    };
    assert!(similarity.line().contains("confidence n/a"));
}

/// Absent is not low. A mode that measures identifier agreement on some
/// entries and not others would otherwise report the unmeasured ones as
/// the least alike, which is a claim nothing was made about.
#[test]
fn an_entry_with_no_measurement_on_the_axis_is_listed_after_the_measured() {
    let mut measured = visible_group();
    measured.identifier_jaccard = Some(0.1);
    let mut unmeasured = suppressed_group();
    unmeasured.identifier_jaccard = None;

    assert_eq!(
        compare_on(&measured, &unmeasured, Sort::IdentifierJaccard),
        Ordering::Less,
    );
    assert_eq!(
        compare_on(&unmeasured, &measured, Sort::IdentifierJaccard),
        Ordering::Greater,
    );
}

/// Two entries that tie on the axis still have to come out in one order,
/// or a reader citing a position cites a coin toss.
#[test]
fn entries_that_tie_on_the_axis_fall_back_to_the_stable_id() {
    let left = visible_group();
    let mut right = suppressed_group();
    right.priority = left.priority.clone();

    assert!(left.fingerprint < right.fingerprint);
    assert_eq!(compare_on(&left, &right, Sort::Priority), Ordering::Less);
}

#[test]
fn repeated_tokens_count_everything_past_the_copy_that_would_be_kept() {
    let group = visible_group();
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let canonical = group
        .members
        .iter()
        .find(|member| member.canonical)
        .expect("a canonical member")
        .tokens;
    assert_eq!(duplicated_tokens(&group), total - canonical);
}
