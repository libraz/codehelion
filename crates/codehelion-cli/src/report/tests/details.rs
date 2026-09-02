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
fn cross_variant_group_detail_keeps_origins_and_members_readable() {
    let detail = CrossVariantGroupDetail {
        group_id: "50".repeat(16),
        comparison_id: "4f".repeat(16),
        policy_version: "cross-variant-exact-v1".to_string(),
        root_path: "/work/project".to_string(),
        origin_variants: vec!["debug".to_string(), "release".to_string()],
        clone_type: "type-1".to_string(),
        members: vec![CrossVariantGroupMemberDetail {
            origin_variant: "release".to_string(),
            language: "cpp".to_string(),
            file: "src/shared.cpp".to_string(),
            start_line: 3,
            end_line: 8,
            unit: Some("shared".to_string()),
            token_count: 24,
        }],
    };

    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(json["response_kind"], EXPLAIN_RESPONSE_CROSS_VARIANT_GROUP);
    assert_valid_finding_detail_schema(&json);
    assert_eq!(json["members"][0]["origin_variant"], "release");
    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("cross-build-variant clone group"));
    assert!(text.contains("cpp src/shared.cpp:3-8 (release, 24 tokens)"));
}

#[test]
fn sibling_detail_preserves_its_separate_finding_namespace() {
    let sibling = sample_siblings().siblings.remove(0);
    let finding_id = sibling.member.finding_id.clone();
    let detail = SiblingDetail {
        scan_run: 17,
        group_fingerprint: "19".repeat(16),
        sibling,
    };

    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(json["response_kind"], EXPLAIN_RESPONSE_SIBLING);
    assert_eq!(json["sibling"]["member"]["finding_id"], finding_id);
    assert_valid_finding_detail_schema(&json);
    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("sibling finding"));
    assert!(text.contains("primary group"));
}

#[test]
fn signature_sibling_detail_keeps_the_basis_and_exact_signature_marker() {
    let mut sibling = sample_siblings().siblings.remove(0);
    sibling.basis = "signature".to_string();
    sibling.signature = Some("detail-signature-sentinel".to_string());
    let detail = SiblingDetail {
        scan_run: 17,
        group_fingerprint: "19".repeat(16),
        sibling,
    };

    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(json["sibling"]["basis"], "signature");
    assert_eq!(json["sibling"]["signature"], "detail-signature-sentinel");
    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("[same signature]"));
    assert!(text.contains("basis: signature"));
    assert!(text.contains("signature: detail-signature-sentinel"));
}

#[test]
fn a_signature_sibling_detail_states_how_rare_the_signature_is() {
    let mut sibling = sample_siblings().siblings.remove(0);
    sibling.basis = "signature".to_string();
    sibling.signature = Some("detail-signature-sentinel".to_string());
    sibling.signature_units = Some(900);
    let detail = SiblingDetail {
        scan_run: 17,
        group_fingerprint: "19".repeat(16),
        sibling,
    };

    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    // A signature nine hundred units share is not the evidence a signature
    // three units share, and the two render differently wherever either does.
    assert!(
        text.contains("[same signature, 900 units share it]"),
        "{text}"
    );
}

#[test]
fn a_suppressed_sibling_detail_names_the_rule_that_hid_it() {
    let mut sibling = sample_siblings().siblings.remove(0);
    sibling.suppressed = Some(Suppression {
        kind: SuppressionKind::Rule,
        reason: None,
        scope: Some("path_glob".to_string()),
        pattern: Some("vendor/**".to_string()),
        active: Some(true),
    });
    let detail = SiblingDetail {
        scan_run: 17,
        group_fingerprint: "19".repeat(16),
        sibling,
    };

    let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(json["sibling"]["suppressed"]["scope"], "path_glob");
    let mut text = Vec::new();
    detail.render_text(&mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("suppressed: path glob \"vendor/**\""),
        "{text}"
    );
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
        scan_run: 17,
        analysis_mode: "structural".to_string(),
        build_variant: "ab".repeat(32),
        latest_scan_run: None,
        present_in_latest_run: None,
        group: visible_group(),
    };
    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(value["schema_version"], CloneGroupDetail::SCHEMA_VERSION);
    assert_eq!(value["response_kind"], EXPLAIN_RESPONSE_CLONE_GROUP);
    assert_eq!(value["scan_run"], 17);
    assert_eq!(value["analysis_mode"], "structural");
    assert_eq!(value["build_variant"], "ab".repeat(32));
    assert_valid_finding_detail_schema(&value);
    let mut text = Vec::new();
    detail
        .render_text(Decoration::Ascii, false, &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("run: 17 (structural; build variant digest"));
    // Nothing to compare the run with, so the run line makes no claim about
    // what a later scan found.
    assert!(!text.contains("latest"), "{text}");
}

#[test]
fn clone_group_detail_says_whether_the_newest_comparable_run_still_holds_the_group() {
    let mut detail = CloneGroupDetail {
        database: ".codehelion/audit.db".to_string(),
        scan_run: 1,
        analysis_mode: "structural".to_string(),
        build_variant: "ab".repeat(32),
        latest_scan_run: Some(4),
        present_in_latest_run: Some(false),
        group: visible_group(),
    };
    let mut text = Vec::new();
    detail
        .render_text(Decoration::Ascii, false, &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("not present in the latest run 4"), "{text}");
    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(value["latest_scan_run"], 4);
    assert_eq!(value["present_in_latest_run"], false);
    assert_valid_finding_detail_schema(&value);

    detail.scan_run = 4;
    detail.present_in_latest_run = Some(true);
    let mut text = Vec::new();
    detail
        .render_text(Decoration::Ascii, false, &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains(&format!(
            "run: 4 (structural; build variant digest {}) — latest",
            "ab".repeat(32)
        )),
        "{text}"
    );
    let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
    assert_eq!(value["present_in_latest_run"], true);
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
    assert!(text.contains(&format!("source build variant digest: {}", "cd".repeat(16))));
    assert!(text.contains(&format!(
        "artifact build variant digest: {}",
        "ef".repeat(16)
    )));
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
fn an_occurrence_inside_the_suite_explains_why() {
    let mut group = fragment_group();
    group.test_code = true;
    let detail = FindingDetail {
        member: group.members.remove(0),
        group: GroupRef {
            fingerprint: "0e".repeat(16),
            clone_type: "type-1".to_string(),
            scope: SCOPE_FRAGMENT.to_string(),
            confidence: 1.0,
            entropy_bits: 4.0,
            priority: None,
            members: 2,
            boilerplate: None,
            test_code: true,
            test_code_evidence: Some(TestCodeEvidence::Marker),
            split_pair: false,
            similarity: None,
            semantic: None,
            suppressed: None,
        },
        scan_run: 3,
        source_artifact_mappings: Vec::new(),
        clone_group_savings: Vec::new(),
    };
    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    assert!(
        String::from_utf8(buffer)
            .unwrap()
            .contains("test code: every occurrence is inside a test")
    );
}

#[test]
fn an_occurrence_of_a_run_explains_itself_as_a_run() {
    let mut detail = FindingDetail {
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
        source_artifact_mappings: Vec::new(),
        clone_group_savings: Vec::new(),
    };
    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("duplicated run, type-1"));

    // The same occurrence in a whole-unit group reads the other way.
    detail.group.scope = "unit".to_string();
    let mut buffer = Vec::new();
    detail.render_text(&mut buffer).unwrap();
    assert!(
        String::from_utf8(buffer)
            .unwrap()
            .contains("duplicated unit")
    );
}
