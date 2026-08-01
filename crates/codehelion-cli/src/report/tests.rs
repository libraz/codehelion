use super::*;
use boon::{Compiler, Schemas};
use codehelion_core::discovery::Language;
use codehelion_core::semantic::{
    OperationAttributes, OperationEdge, OperationEdgeKind, OperationKind, OperationNode,
    SemanticOperationGraph,
};
use codehelion_store::artifact::MappingEvidenceFact;

fn assert_valid_finding_detail_schema(value: &serde_json::Value) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler
        .add_resource(
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v1.schema.json",
            serde_json::from_str(JSON_SCHEMA).expect("valid scan schema"),
        )
        .expect("scan schema resource");
    compiler
        .add_resource(
            FINDING_DETAIL_SCHEMA_URI,
            serde_json::from_str(FINDING_DETAIL_JSON_SCHEMA).expect("valid finding detail schema"),
        )
        .expect("finding detail schema resource");
    let index = compiler
        .compile(FINDING_DETAIL_SCHEMA_URI, &mut schemas)
        .expect("compile finding detail schema");
    schemas
        .validate(value, index)
        .expect("validate finding detail");
}

pub(super) fn semantic_graph() -> SemanticOperationGraph {
    SemanticOperationGraph::new(
        Language::Rust,
        [1; 32],
        vec![
            OperationNode {
                kind: OperationKind::Source,
                attributes: OperationAttributes::default(),
            },
            OperationNode {
                kind: OperationKind::Collect,
                attributes: OperationAttributes::default(),
            },
        ],
        vec![OperationEdge {
            from: 0,
            to: 1,
            kind: OperationEdgeKind::Data,
        }],
    )
    .expect("test graph")
}

/// A two-group report whose second group is hidden by a path rule; shared
/// with the sibling reporter tests.
pub(super) fn sample_report() -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        run: RunInfo {
            tool_version: "0.1.0".to_string(),
            mode: "fast".to_string(),
            root: "/work/project".to_string(),
            configuration: ConfigurationInfo {
                source: "root".to_string(),
                path: Some("/work/project/codehelion.toml".to_string()),
                min_clone_tokens: 20,
            },
            started_at: "2026-01-01T00:00:00.000000Z".to_string(),
            finished_at: "2026-01-01T00:00:01.000000Z".to_string(),
            build_variant: BuildVariantInfo {
                mode: "fast".to_string(),
                languages: vec!["rust".to_string()],
                headers: Some("c".to_string()),
                normalization_version: 1,
                fingerprint: "aa".repeat(32),
            },
            detector_versions: vec![DetectorVersion {
                component: "fp-schema".to_string(),
                version: "1".to_string(),
            }],
            ranking: RankingInfo {
                recipe: Weights::default().recipe(),
                maintenance_risk: 2,
                refactoring_ease: 1,
            },
            database: ".codehelion/audit.db".to_string(),
            run_id: 1,
        },
        summary: Summary {
            files: FileCounts {
                total: 2,
                rust: 2,
                c: 0,
                cpp: 0,
            },
            lines: 40,
            tokens: 200,
            lexer_diagnostics: 0,
            unparsed: None,
            excluded: ExcludedCounts {
                generated: 0,
                by_glob: 0,
                skipped: 0,
                too_large: 0,
                binary: 0,
                unreadable: 0,
                symlinks: 0,
                walk_errors: 0,
                timed_out: 0,
            },
            baseline: None,
            groups: GroupCounts {
                total: 2,
                type_1: 2,
                type_2: 0,
                type_3: 0,
                restricted_semantic: 0,
                fragment_scope: 0,
                folded_runs: 0,
                subsumed_runs: 0,
                test_code: 0,
            },
            suppressed: SuppressedCounts {
                noise: 0,
                by_rule: 1,
                vendored: 0,
            },
            unused_suppressions: Vec::new(),
            unapplied_suppression_policies: Vec::new(),
            funnel: vec![
                FunnelStage::new("tokens", 200),
                FunnelStage::new("fingerprints", 64)
                    .dropping("high_frequency", 3)
                    .dropping("hash_collision", 0),
                FunnelStage::new("verified pairs", 2),
            ],
            split_components: 0,
            pair_budget_exhausted: false,
            search_truncated: true,
            guardrails: None,
            compiler: None,
        },
        groups: vec![visible_group(), suppressed_group()],
    }
}

/// A plain visible group: the highest-priority entry of the sample report.
fn visible_group() -> Group {
    ranked(
        Group {
            fingerprint: "0b".repeat(16),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            entropy_bits: 5.2,
            priority: Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            suppressed: None,
            baseline: None,
            split_pair: false,
            semantic: None,
            artifact_savings: Vec::new(),
            members: (0..7)
                .map(|index| Member {
                    finding_id: format!("{index:032x}"),
                    content: "c0".repeat(16),
                    file: format!("src/file{index}.rs"),
                    language: "rust".to_string(),
                    start_line: 1,
                    end_line: 9,
                    unit: Some("checksum".to_string()),
                    boilerplate: None,
                    tokens: 80,
                    canonical: index == 0,
                })
                .collect(),
        },
        &Weights::default(),
        20,
    )
}

/// A group a path rule hid, kept in the report rather than dropped.
fn suppressed_group() -> Group {
    ranked(
        Group {
            fingerprint: "0c".repeat(16),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            entropy_bits: 4.1,
            priority: Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            suppressed: Some(Suppression {
                kind: SuppressionKind::Rule,
                reason: None,
                scope: Some("path_glob".to_string()),
                pattern: Some("vendor/**".to_string()),
                active: Some(true),
            }),
            baseline: None,
            split_pair: false,
            semantic: None,
            artifact_savings: Vec::new(),
            members: vec![
                Member {
                    finding_id: "1".repeat(32),
                    content: "c0".repeat(16),
                    file: "vendor/a.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 1,
                    end_line: 5,
                    unit: None,
                    boilerplate: None,
                    tokens: 30,
                    canonical: true,
                },
                Member {
                    finding_id: "2".repeat(32),
                    content: "c0".repeat(16),
                    file: "vendor/b.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 1,
                    end_line: 5,
                    unit: None,
                    boilerplate: None,
                    tokens: 30,
                    canonical: false,
                },
            ],
        },
        &Weights::default(),
        20,
    )
}

/// A gapped group as a mode that scores dimensions reports it: a
/// similarity breakdown whose type dimension was never measured.
pub(super) fn structural_group() -> Group {
    ranked(
        Group {
            fingerprint: "0d".repeat(16),
            clone_type: "type-3".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 0.79,
            entropy_bits: 5.4,
            priority: Priority::unranked(),
            similarity: Some(Similarity {
                weight_version: "structural-verify-v1".to_string(),
                lexical: 0.71,
                structural: 0.88,
                control_flow: Some(0.90),
                type_similarity: None,
                api: Some(0.75),
                composite: 0.82,
                min_pairwise: 0.79,
                confidence_band: Some("medium".to_string()),
            }),
            identifier_jaccard: Some(0.5),
            body_materiality: Some(BodyMateriality {
                has_loop: true,
                has_dynamic_allocation: false,
                call_count: 3,
            }),
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            suppressed: None,
            baseline: None,
            split_pair: false,
            semantic: None,
            artifact_savings: Vec::new(),
            members: vec![
                Member {
                    finding_id: "3".repeat(32),
                    content: "c0".repeat(16),
                    file: "src/parse.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 10,
                    end_line: 30,
                    unit: Some("parse_header".to_string()),
                    boilerplate: None,
                    tokens: 60,
                    canonical: true,
                },
                Member {
                    finding_id: "4".repeat(32),
                    content: "c0".repeat(16),
                    file: "src/parse.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 40,
                    end_line: 62,
                    unit: Some("parse_trailer".to_string()),
                    boilerplate: None,
                    tokens: 58,
                    canonical: false,
                },
            ],
        },
        &Weights::default(),
        20,
    )
}

/// A run duplicated inside two units that are not clones of each other:
/// the members are stretches of their hosts, not the hosts.
pub(super) fn fragment_group() -> Group {
    ranked(
        Group {
            fingerprint: "0e".repeat(16),
            clone_type: "type-1".to_string(),
            scope: SCOPE_FRAGMENT.to_string(),
            statements: Some(5),
            confidence: 1.0,
            entropy_bits: 4.0,
            priority: Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            suppressed: None,
            baseline: None,
            split_pair: false,
            semantic: None,
            artifact_savings: Vec::new(),
            members: vec![
                Member {
                    finding_id: "5".repeat(32),
                    content: "c0".repeat(16),
                    file: "src/render.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 17,
                    end_line: 21,
                    unit: Some("render_rows".to_string()),
                    boilerplate: None,
                    tokens: 39,
                    canonical: true,
                },
                Member {
                    finding_id: "6".repeat(32),
                    content: "c0".repeat(16),
                    file: "src/audit.rs".to_string(),
                    language: "rust".to_string(),
                    start_line: 11,
                    end_line: 15,
                    unit: Some("audit_entries".to_string()),
                    boilerplate: None,
                    tokens: 39,
                    canonical: false,
                },
            ],
        },
        &Weights::default(),
        20,
    )
}

#[test]
fn a_duplicated_run_states_its_extent_in_every_view() {
    let mut report = sample_report();
    report.summary.groups.total = 3;
    report.summary.groups.fragment_scope = 1;
    report.summary.groups.folded_runs = 4;
    report.summary.groups.subsumed_runs = 2;
    report.groups.insert(0, fragment_group());

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let group = &value["groups"][0];
    assert_eq!(group["scope"], "fragment");
    assert_eq!(group["statements"], 5);
    // A whole-unit group says so, and says it has no such extent.
    assert_eq!(value["groups"][1]["scope"], "unit");
    assert_eq!(value["groups"][1]["statements"], serde_json::Value::Null);

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("type-1 run of 5 statements priority 0."));
    // What was folded away is stated rather than silently dropped.
    assert!(text.contains(
        "1 of them are runs duplicated inside units that are not clones of each other; \
         4 more were folded into the groups that already cover them and 2 into longer runs"
    ));
}

#[test]
fn a_rule_that_matched_nothing_is_named_not_left_to_be_noticed() {
    let mut report = sample_report();
    report.summary.unused_suppressions = vec![
        UnusedRule {
            scope: "path_glob".to_string(),
            pattern: "third_party/**".to_string(),
        },
        UnusedRule {
            scope: "stable_clone_id".to_string(),
            pattern: "abcd1234".to_string(),
        },
    ];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unused_suppressions"][0]["scope"],
        "path_glob"
    );
    assert_eq!(
        value["summary"]["unused_suppressions"][1]["pattern"],
        "abcd1234"
    );

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // Named the way a rule that did match is named, so the two read alike.
    assert!(text.contains(
        "note: 2 suppression rule(s) matched nothing: path glob \"third_party/**\", \
         clone id abcd1234"
    ));
}

#[test]
fn a_run_with_every_rule_matching_says_nothing_about_them() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    assert!(
        !String::from_utf8(buffer)
            .unwrap()
            .contains("matched nothing")
    );
}

#[test]
fn a_group_inside_the_suite_says_so_in_every_view() {
    let mut report = sample_report();
    report.summary.groups.test_code = 1;
    let mut group = fragment_group();
    group.test_code = true;
    group.test_code_evidence = Some(TestCodeEvidence::Marker);
    report.groups.insert(0, group);

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["groups"][0]["test_code"], true);
    assert_eq!(value["groups"][0]["test_code_evidence"], "marker");
    // A group reaching outside the suite is the interesting case, and says
    // as much rather than leaving the field out.
    assert_eq!(value["groups"][1]["test_code"], false);

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // Shown, not hidden, and its place in the ranking is explained.
    assert!(text.contains("[test code]"));
    assert!(text.contains("1 of them are duplication inside test code"));
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

#[test]
fn the_unparsed_share_counts_files_and_tokens_against_the_whole_scan() {
    let counts = UnparsedCounts::new([0, 250, 0, 750], 4000);
    assert_eq!(counts.files, 2, "only the files that lost something count");
    assert_eq!(counts.tokens, 1000);
    assert!((counts.share - 0.25).abs() < f64::EPSILON);
}

#[test]
fn a_scan_the_parser_followed_reports_a_share_of_nothing() {
    let clean = UnparsedCounts::new([0, 0], 4000);
    assert_eq!((clean.files, clean.tokens), (0, 0));
    assert!(clean.share.abs() < f64::EPSILON);
    // An empty scan divides by nothing rather than producing a NaN that
    // would serialize as `null` and read as "not measured".
    let empty = UnparsedCounts::new([], 0);
    assert!(empty.share.abs() < f64::EPSILON);
}

#[test]
fn a_lexing_mode_reports_no_parse_coverage_rather_than_a_clean_one() {
    // Fast mode has no parser, so `unparsed` is absent from its JSON. A
    // zero there would claim the parser followed everything.
    let value: serde_json::Value =
        serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
    assert!(value["summary"].get("unparsed").is_none());
}

#[test]
fn json_view_serializes_the_documented_shape() {
    let value: serde_json::Value =
        serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(value["run"]["mode"], "fast");
    assert_eq!(value["run"]["configuration"]["source"], "root");
    assert_eq!(value["run"]["configuration"]["min_clone_tokens"], 20);
    assert_eq!(value["run"]["build_variant"]["normalization_version"], 1);
    assert_eq!(value["summary"]["files"]["total"], 2);
    assert_eq!(value["summary"]["pair_budget_exhausted"], false);
    assert_eq!(value["summary"]["search_truncated"], true);
    let group = &value["groups"][0];
    assert_eq!(group["clone_type"], "type-1");
    assert_eq!(group["priority"]["inputs"]["largest_member_tokens"], 80);
    assert_eq!(group["width_family"], false);
    assert_eq!(group["suppressed"], serde_json::Value::Null);
    assert_eq!(group["members"][0]["canonical"], true);
    let suppressed = &value["groups"][1]["suppressed"];
    assert_eq!(suppressed["kind"], "rule");
    assert_eq!(suppressed["scope"], "path_glob");
    assert!(suppressed.get("reason").is_none());
    assert_eq!(suppressed["active"], true);
}

#[test]
fn text_json_and_sarif_keep_group_order_and_suppression_state() {
    let report = sample_report();
    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let expected = json["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["fingerprint"].as_str().unwrap(),
                !group["suppressed"].is_null(),
            )
        })
        .collect::<Vec<_>>();

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let sarif_groups = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            (
                result["partialFingerprints"][sarif::FINGERPRINT_KEY]
                    .as_str()
                    .unwrap(),
                !result["suppressions"].as_array().unwrap().is_empty(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(sarif_groups, expected);

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                verbose: true,
                show_suppressed: true,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    let positions = expected
        .iter()
        .map(|(fingerprint, suppressed)| {
            let line = text
                .lines()
                .find(|line| line.contains(fingerprint))
                .expect("text lists every group");
            assert_eq!(line.contains("[suppressed:"), *suppressed);
            text.find(line).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn structural_shape_label_keeps_the_rule_judgement() {
    let suppression = Suppression {
        kind: SuppressionKind::Rule,
        reason: Some("one routine per integer width".to_string()),
        scope: Some("ast_pattern".to_string()),
        pattern: Some("width-family".to_string()),
        active: Some(true),
    };

    assert_eq!(
        suppression.label(),
        "one routine per integer width: width-family"
    );
}

#[test]
fn current_json_report_validates_against_the_shipped_v1_schema() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let uri = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v1.schema.json";
    compiler.add_resource(uri, schema).unwrap();
    let index = compiler.compile(uri, &mut schemas).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
    schemas.validate(&value, index).unwrap();

    let mut with_execution_refusal = sample_report();
    with_execution_refusal.summary.compiler = Some(CompilerCoverage {
        answered: 0,
        not_asked: 0,
        unavailable: BTreeMap::from([("requires_execution".to_string(), 1)]),
        execution_refusals: vec![ExecutionRefusal {
            execution: "build-script".to_string(),
            files: 1,
            cost: "types generated by a build script".to_string(),
            permission_argument: "--allow-execution=build-script".to_string(),
            message: "Pass --allow-execution=build-script to allow it.".to_string(),
        }],
        restarts: 0,
    });
    let with_execution_refusal: serde_json::Value =
        serde_json::from_str(&with_execution_refusal.to_json().unwrap()).unwrap();
    schemas.validate(&with_execution_refusal, index).unwrap();

    let mut report = sample_report();
    report.groups.push(structural_group());
    report.groups[2]
        .similarity
        .as_mut()
        .expect("sample structural group has similarity evidence")
        .confidence_band = None;
    let without_a_recorded_band: serde_json::Value =
        serde_json::from_str(&report.to_json().unwrap()).unwrap();
    schemas.validate(&without_a_recorded_band, index).unwrap();

    let mut unsupported = value;
    unsupported["schema_version"] = serde_json::json!(2);
    assert!(schemas.validate(&unsupported, index).is_err());
}

#[test]
fn denied_execution_is_actionable_in_json_and_text() {
    let mut report = sample_report();
    report.summary.compiler = Some(CompilerCoverage {
        answered: 0,
        not_asked: 0,
        unavailable: BTreeMap::from([("requires_execution".to_string(), 2)]),
        execution_refusals: vec![ExecutionRefusal {
            execution: "build-script".to_string(),
            files: 2,
            cost: "types and items that only exist after a build script has generated them"
                .to_string(),
            permission_argument: "--allow-execution=build-script".to_string(),
            message: "skipped build-script: not permitted, so this run has no types and items that only exist after a build script has generated them. Pass --allow-execution=build-script to allow it."
                .to_string(),
        }],
        restarts: 0,
    });

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let refusal = &json["summary"]["compiler"]["execution_refusals"][0];
    assert_eq!(refusal["execution"], "build-script");
    assert_eq!(refusal["files"], 2);
    assert!(refusal["cost"].as_str().unwrap().contains("build script"));
    assert_eq!(
        refusal["permission_argument"],
        "--allow-execution=build-script"
    );

    let mut text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("build script has generated them"), "{text}");
    assert!(text.contains("--allow-execution=build-script"), "{text}");
}

#[test]
fn artifact_savings_use_the_same_group_value_in_every_report_format() {
    let mut report = sample_report();
    report.groups[0].artifact_savings = vec![ArtifactSavings {
        artifact_analysis_id: 17,
        source_build_variant_fingerprint: "01".repeat(16),
        artifact_build_variant_fingerprint: "02".repeat(16),
        duplicated_bytes: 24,
        estimated_refactor_savings_bytes: 9,
        mapping_confidence: "high".to_string(),
        clone_confidence: 1.0,
        model_confidence: "low".to_string(),
        savings_confidence: "low".to_string(),
        model_schema_version: "refactor-savings-model-v1".to_string(),
        assumptions: serde_json::json!([{ "kind": "inlining_outcome_unknown" }]),
    }];

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let expected = &json["groups"][0]["artifact_savings"];
    assert_eq!(expected[0]["estimated_refactor_savings_bytes"], 9);
    assert_eq!(
        expected[0]["assumptions"][0]["kind"],
        "inlining_outcome_unknown"
    );

    let mut text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("artifact refactoring estimates (not guaranteed):"));
    assert!(text.contains("analysis 17: 9 estimated bytes from 24 attributed duplicate bytes"));
    assert!(text.contains("inlining_outcome_unknown"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["artifact_savings"],
        *expected
    );
    assert_eq!(
        sarif["runs"][0]["results"][1]["properties"]["artifact_savings"],
        serde_json::json!([])
    );
}

#[test]
fn group_boilerplate_schema_tracks_the_classifier_categories() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let values = schema["$defs"]["group"]["properties"]["boilerplate"]["enum"]
        .as_array()
        .expect("group boilerplate enum");
    let categories: Vec<_> = values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let expected: Vec<_> = Boilerplate::all()
        .iter()
        .map(|category| category.name())
        .collect();
    assert_eq!(categories, expected);
    assert!(
        values.iter().any(serde_json::Value::is_null),
        "a group without a dominant shape remains representable"
    );
}

#[test]
fn restricted_semantic_evidence_is_explicit_in_json() {
    let mut report = sample_report();
    let group = &mut report.groups[0];
    group.clone_type = "restricted-semantic".to_string();
    group.semantic = Some(SemanticEvidence {
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
    });
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["groups"][0]["semantic"]["rules"][0]["id"],
        "sequence-pipeline-v1"
    );
    assert_eq!(
        value["groups"][0]["semantic"]["graphs"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    assert!(schema["$defs"]["group"]["properties"]["semantic"].is_object());
    assert!(schema["$defs"]["semantic_evidence"].is_object());
}

mod details;
