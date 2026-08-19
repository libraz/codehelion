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
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // A type this mode reported none of is left out rather than printed
    // as a zero the eye has to dismiss.
    assert!(text.contains("type-1 2, type-3 1"), "{text}");
    assert!(!text.contains("type-2 0"), "{text}");
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
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
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
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
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
    // The listing marks it; the sentence is one of the details behind it.
    assert!(text.contains("[expanded +1]"), "{text}");

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
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
    });

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
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
    assert!(baseline_schema.get("mismatch").is_none());
    assert!(baseline_schema.get("caveat").is_none());
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
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("baseline codehelion-baseline.json: 0 of 12 matched, 12 gone"),
        "{text}"
    );
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
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("11 of 12 matched, 1 gone"), "{text}");
    assert!(!text.contains("warning:"));
}

#[test]
fn text_view_truncates_with_an_explicit_count() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("2 files, 40 lines, 200 tokens"), "{text}");
    // Every occurrence is listed under the group, canonical included, so the
    // seven stop at five and the count says what is missing.
    assert!(text.contains("... and 2 more occurrences"), "{text}");
    assert!(!text.contains("src/file6.rs"));
    assert!(!text.contains("vendor/a.rs")); // suppressed and not requested
    assert!(!text.contains('\x1b'));
}

#[test]
fn a_candidate_search_cut_is_stated_as_a_note() {
    let mut buffer = Vec::new();
    sample_report()
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("candidate search was truncated by high frequency"));
    assert!(text.contains("may be missing from this report"));
}

/// The listing renders as text, with the options a caller passes.
fn rendered(report: &Report, opts: TextOptions) -> String {
    let mut buffer = Vec::new();
    report.render_text(opts, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[test]
fn each_group_is_numbered_and_its_occurrences_hang_from_it() {
    let text = rendered(&sample_report(), TextOptions::default());
    assert!(text.contains(" #1  "), "{text}");
    assert!(text.contains("├─ "), "{text}");
    assert!(text.contains("└─ "), "{text}");
    // The number is what `explain` is offered against, so it exists for the
    // reader to name one entry among the others.
    let numbered = text.lines().filter(|line| line.contains('#')).count();
    assert!(numbered >= 1, "{text}");
}

#[test]
fn the_canonical_occurrence_leads_its_group_and_is_marked() {
    let text = rendered(&sample_report(), TextOptions::default());
    let occurrences: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("src/file"))
        .collect();
    let first = occurrences.first().copied().unwrap_or_default();
    // file0 is the canonical member of the sample group.
    assert!(first.contains("src/file0.rs"), "{text}");
    assert!(first.contains('◆'), "{text}");
    // Exactly one occurrence carries the mark.
    assert_eq!(
        occurrences.iter().filter(|line| line.contains('◆')).count(),
        1,
        "{text}"
    );
}

#[test]
fn an_ascii_listing_carries_nothing_outside_ascii() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            decoration: Decoration::Ascii,
            ..TextOptions::default()
        },
    );
    // The whole point of asking for it: a console that draws no box-drawing
    // character gets a report with none in it, heading and summary included.
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("|- "), "{text}");
    assert!(text.contains("`- "), "{text}");
}

#[test]
fn an_undecorated_listing_draws_no_glyphs_but_keeps_its_columns() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            decoration: Decoration::None,
            ..TextOptions::default()
        },
    );
    // No tree, no marks: the occurrences are a plain indented list, which is
    // what something reading this report line by line wants.
    for glyph in ['├', '└', '◆', '×', '·'] {
        assert!(!text.contains(glyph), "{glyph} in {text}");
    }
    assert!(text.is_ascii(), "{text}");
    // The structure indentation and the columns still carry.
    assert!(text.contains(" #1  "), "{text}");
    assert!(text.contains("src/file0.rs"), "{text}");
}

#[test]
fn one_listings_headings_share_their_columns() {
    let mut report = sample_report();
    // A second group whose kind is wider than the first's, which is what
    // pushes every column right if the widths are measured per row.
    report.groups[1].suppressed = None;
    report.groups[1].scope = SCOPE_FRAGMENT.to_string();
    let text = rendered(&report, TextOptions::default());
    let headings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains(" tokens  "))
        .collect();
    assert_eq!(headings.len(), 2, "{text}");
    let columns: Vec<Option<usize>> = headings.iter().map(|line| line.find(" tokens")).collect();
    assert_eq!(columns[0], columns[1], "{text}");
}

#[test]
fn what_unsettles_the_report_is_written_as_a_warning_before_the_notes() {
    let mut report = sample_report();
    report.summary.unused_suppressions = vec![UnusedRule {
        scope: "path".to_string(),
        pattern: "vendor/**".to_string(),
    }];
    let mut buffer = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    let warning = text.find("⚠ warning: candidate search was truncated");
    let note = text.find("note: 1 suppression rule(s) matched nothing");
    assert!(warning.is_some() && note.is_some(), "{text}");
    // A reader who stops after one line should have stopped after the line
    // that changes what the rest of the report means.
    assert!(warning < note, "{text}");
}

#[test]
fn the_report_closes_with_the_marks_it_used_and_what_to_type_next() {
    let text = rendered(&sample_report(), TextOptions::default());
    assert!(
        text.contains("◆ the occurrence a group is measured against"),
        "{text}"
    );
    assert!(text.contains("codehelion explain 0b0b0b0b"), "{text}");
    assert!(text.contains("--limit 0"), "{text}");
    // "run" is not a word this report used, so it is not a word this report
    // explains.
    assert!(!text.contains("\"run\""), "{text}");
}

#[test]
fn a_listing_of_runs_says_what_a_run_is() {
    let mut report = sample_report();
    report.groups[0].scope = SCOPE_FRAGMENT.to_string();
    let text = rendered(&report, TextOptions::default());
    assert!(text.contains("type-1 run ×"), "{text}");
    assert!(text.contains("\"run\" a repeated stretch"), "{text}");
}

#[test]
fn a_listing_says_what_the_count_after_the_heading_counts() {
    let text = rendered(&sample_report(), TextOptions::default());
    // The mark is on every heading, and reads as a multiple of the code until
    // the legend says it counts occurrences.
    assert!(text.contains("×N the number of occurrences"), "{text}");
}

#[test]
fn a_listing_of_nothing_explains_no_marks() {
    let mut report = sample_report();
    report.groups.clear();
    let text = rendered(&report, TextOptions::default());
    assert!(!text.contains("the number of occurrences"), "{text}");
    assert!(
        !text.contains("the occurrence a group is measured against"),
        "{text}"
    );
    assert!(!text.contains("codehelion explain"), "{text}");
}

/// The depth at which the composition of the group total is written.
fn composition_detail() -> TextOptions {
    TextOptions {
        verbosity: 1,
        ..TextOptions::default()
    }
}

#[test]
fn each_part_of_the_group_total_names_the_total_it_is_part_of() {
    let mut report = sample_report();
    report.summary.groups.total = 3;
    report.summary.groups.fragment_scope = 1;
    report.summary.groups.folded_runs = 4;
    report.summary.groups.subsumed_runs = 2;
    report.summary.groups.test_code = 1;
    let text = rendered(&report, composition_detail());

    // Three of these counts are read against a different total, so no line
    // stands in for its total with a pronoun.
    assert!(!text.contains("of them"), "{text}");
    let line = |needle: &str| {
        text.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_default()
            .to_string()
    };
    let runs = line("describe a repeated run");
    assert!(
        runs.contains("of the 3 listed groups, 1 describe"),
        "{text}"
    );
    let left_out = line("folded into groups that already cover them");
    assert!(
        left_out.contains("runs not among the 3 listed groups: 4 folded"),
        "{text}"
    );
    assert!(left_out.contains("2 covered by a longer run"), "{text}");
    let suite = line("duplication inside test code");
    assert!(suite.contains("of the 3 listed groups, 1 are"), "{text}");

    // The breakdown shares no total with the suppression split, which stands
    // after it rather than reading as its heading.
    let suppressed = text
        .lines()
        .position(|line| line.contains("suppressed: "))
        .expect("the suppression split is written at this depth");
    let last_part = text
        .lines()
        .position(|line| line.contains("duplication inside test code"))
        .expect("the test-code part is written at this depth");
    assert!(suppressed > last_part, "{text}");
}

#[test]
fn runs_left_out_of_the_listing_are_named_only_when_there_were_some() {
    let mut report = sample_report();
    report.summary.groups.fragment_scope = 1;
    let text = rendered(&report, composition_detail());
    assert!(!text.contains("runs not among the"), "{text}");

    report.summary.groups.folded_runs = 4;
    let folded = rendered(&report, composition_detail());
    assert!(
        folded.contains(
            "runs not among the 2 listed groups: 4 folded into groups that already \
             cover them\n"
        ),
        "{folded}"
    );

    report.summary.groups.folded_runs = 0;
    report.summary.groups.subsumed_runs = 2;
    let subsumed = rendered(&report, composition_detail());
    assert!(
        subsumed.contains("runs not among the 2 listed groups: 2 covered by a longer run\n"),
        "{subsumed}"
    );
}

#[test]
fn the_parts_of_the_group_total_are_written_with_thousands_separators() {
    let mut report = sample_report();
    report.summary.groups.total = 10_853;
    report.summary.groups.fragment_scope = 1_036;
    report.summary.groups.folded_runs = 3_070;
    report.summary.groups.subsumed_runs = 1_423;
    report.summary.groups.test_code = 8_087;
    report.summary.suppressed.noise = 1_811;
    report.summary.suppressed.by_rule = 1_640;
    let text = rendered(&report, composition_detail());
    // A count written one way in the headline and another in the breakdown
    // reads as a count of something else.
    for written in [
        "10,853", "1,036", "3,070", "1,423", "8,087", "1,811", "1,640",
    ] {
        assert!(text.contains(written), "{written} in {text}");
    }
}

#[test]
fn a_quiet_listing_is_the_groups_alone() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            quiet: true,
            ..TextOptions::default()
        },
    );
    assert!(!text.contains("codehelion scan"), "{text}");
    assert!(
        !text.contains("the occurrence a group is measured against"),
        "{text}"
    );
    assert!(!text.contains("codehelion explain"), "{text}");
    assert!(text.contains("src/file0.rs"), "{text}");
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
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("within one file,"), "{text}");
    assert!(text.contains("within one directory,"), "{text}");
    assert!(text.contains("across directories,"), "{text}");
}

#[test]
fn verbose_text_lists_every_member_and_suppressed_section_is_opt_in() {
    let opts = TextOptions {
        limit: Some(0),
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

    let render = |limit| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    limit,
                    show_suppressed: true,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert!(render(None).contains("... and 1 more suppressed group"));
    assert!(!render(Some(0)).contains("more suppressed groups"));
}

#[test]
fn the_pipeline_counts_are_detail_the_verbose_view_asks_for() {
    let render = |verbosity| {
        let opts = TextOptions {
            verbosity,
            ..TextOptions::default()
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    };
    let verbose = render(2);
    assert!(verbose.contains("candidate pipeline:"));
    assert!(verbose.contains("tokens"));
    assert!(verbose.contains("(dropped: high frequency 3)"));
    // A cause that dropped nothing says nothing.
    assert!(!verbose.contains("hash collision"));
    assert!(!render(1).contains("candidate pipeline:"));
    assert!(!render(0).contains("candidate pipeline:"));
}

#[test]
fn a_depth_limited_parse_is_stated_as_a_note() {
    let mut report = sample_report();
    report
        .summary
        .funnel
        .push(FunnelStage::new("structural files", 2).dropping("depth_limit", 1));
    let mut buffer = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut buffer)
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
    assert!(text.contains("\x1b[1mcodehelion scan · fast mode · /work/project\x1b[0m"));
    assert!(text.contains("\x1b[36m"));
}

#[test]
fn the_quiet_view_prints_the_groups_and_nothing_around_them() {
    let opts = TextOptions {
        quiet: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("src/file0.rs:1-9"), "{text}");
    assert!(!text.contains("codehelion scan"), "{text}");
    assert!(!text.contains("sorted by"), "{text}");
    assert!(!text.contains("replay"), "{text}");
}

#[test]
fn a_quiet_run_says_nothing_about_what_qualifies_it() {
    let mut buffer = Vec::new();
    sample_report()
        .render_notes(
            TextOptions {
                quiet: true,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    assert!(buffer.is_empty(), "{:?}", String::from_utf8(buffer));
}

/// An id a report prints has to be one the lookup accepts, so the listing
/// abbreviates to exactly the prefix `codehelion explain` takes and no less.
#[test]
fn the_listing_abbreviates_identifiers_and_the_diagnostic_view_spells_them_out() {
    let report = sample_report();
    let fingerprint = report.groups[0].fingerprint.clone();

    let render = |verbosity| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    verbosity,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    let listed = render(0);
    assert!(listed.contains(&fingerprint[..crate::suppress::MIN_CLONE_ID_CHARS]));
    assert!(!listed.contains(&fingerprint), "{listed}");
    assert!(render(2).contains(&fingerprint));
}

#[test]
fn the_group_limit_is_separate_from_how_much_each_group_says() {
    let mut report = sample_report();
    for index in 0..TEXT_GROUP_LIMIT {
        let mut group = visible_group();
        group.fingerprint = format!("{index:032x}");
        report.groups.push(group);
    }

    let render = |limit| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    limit,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert!(
        render(None).contains("... and 1 more group (--limit 0 lists every one)"),
        "{}",
        render(None)
    );
    assert!(
        render(Some(2)).contains("... and 9 more groups"),
        "{}",
        render(Some(2))
    );
    assert!(
        !render(Some(0)).contains("more group"),
        "{}",
        render(Some(0))
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

/// A tie on the axis is the ordinary case rather than the corner: raw
/// identifier agreement pins whole cohorts at exactly 1.00. Leaving those to
/// the fingerprint would hand the reader the tier in hash order, so the
/// composed ranking decides inside a tie.
#[test]
fn entries_that_tie_on_the_axis_are_ordered_by_the_composed_ranking() {
    let mut stronger = visible_group();
    let mut weaker = suppressed_group();
    stronger.identifier_jaccard = Some(1.0);
    weaker.identifier_jaccard = Some(1.0);
    // The weaker entry takes the smaller fingerprint, so hash order and
    // ranking order disagree and only one of the two can be deciding.
    std::mem::swap(&mut stronger.fingerprint, &mut weaker.fingerprint);

    assert!(weaker.fingerprint < stronger.fingerprint);
    assert!(stronger.priority.value > weaker.priority.value);
    assert_eq!(
        compare_on(&stronger, &weaker, Sort::IdentifierJaccard),
        Ordering::Less,
    );
}

/// Two entries that tie on the axis and on the ranking still have to come out
/// in one order, or a reader citing a position cites a coin toss.
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
