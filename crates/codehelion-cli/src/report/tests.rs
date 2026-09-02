use super::*;
use std::collections::BTreeMap;

use boon::{Compiler, Schemas};
use codehelion_core::discovery::Language;
use codehelion_core::semantic::{
    OperationAttributes, OperationEdge, OperationEdgeKind, OperationKind, OperationNode,
    SemanticOperationGraph,
};
use codehelion_store::artifact::MappingEvidenceFact;
use codehelion_store::snapshot::SummaryRow;

fn assert_valid_finding_detail_schema(value: &serde_json::Value) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler
        .add_resource(
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v2.schema.json",
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
#[allow(clippy::too_many_lines)] // Keep this shared fixture's complete report shape visible.
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
                settings: BTreeMap::new(),
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
            timings: None,
            replay_database: None,
            run_id: Some(1),
            reused: false,
        },
        summary: Summary {
            top_churn: None,
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
                oversized_metadata: 0,
                binary: 0,
                unreadable: 0,
                symlinks: 0,
                walk_errors: 0,
                timed_out: 0,
                language_excluded: 0,
                symlink_files: 0,
                symlink_directories: 0,
            },
            baseline: None,
            changes: None,
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
            siblings: 0,
            near_misses: 0,
            identity_collapsed: 0,
            unmeasured_in_this_mode: vec![
                "identifier agreement".to_string(),
                "similarity breakdown".to_string(),
                "siblings".to_string(),
                "near misses".to_string(),
            ],
            unused_suppressions: Vec::new(),
            unapplied_suppression_policies: Vec::new(),
            funnel: vec![
                FunnelStage::new("tokens", 200),
                FunnelStage::new("fingerprints", 64)
                    .dropping(FunnelCause::OversharedValues, 3)
                    .dropping(FunnelCause::HashCollision, 0),
                FunnelStage::new("verified pairs", 2),
            ],
            split_components: 0,
            common_signatures_skipped: 0,
            largest_skipped_signature_units: 0,
            pair_budget_exhausted: false,
            search_truncated: true,
            guardrails: None,
            compiler: None,
        },
        groups: vec![visible_group(), suppressed_group()],
        siblings: Vec::new(),
        near_misses: Vec::new(),
        seam: None,
    }
}

/// A recorded seam run holding two seams, the first of which has a previous
/// generation to be compared with.
pub(super) fn sample_seam_report() -> SeamReport {
    SeamReport {
        seam_run_id: 3,
        settings_digest: "7f".repeat(32),
        first_commit: Some("a0".repeat(20)),
        last_commit: Some("b1".repeat(20)),
        commits: 434,
        since_seam_run_id: Some(2),
        seams: vec![
            ReportedSeam {
                id: "frontend-c-cpp".to_string(),
                note: Some("one grammar written twice".to_string()),
                asymmetric_changes: 12,
                breaches: 7,
                last_breach: Some("8f1c2ab0".to_string() + &"0".repeat(32)),
                findings: 4,
                asymmetric_changes_since: Some(1),
                breaches_since: Some(1),
                findings_since: Some(0),
            },
            ReportedSeam {
                id: "readme-en-ja".to_string(),
                note: None,
                asymmetric_changes: 2,
                breaches: 0,
                last_breach: None,
                findings: 0,
                asymmetric_changes_since: None,
                breaches_since: None,
                findings_since: None,
            },
        ],
    }
}

/// One supplemental local mirror for the sample report's first primary group.
pub(super) fn sample_siblings() -> GroupSiblings {
    GroupSiblings {
        group_fingerprint: "0b".repeat(16),
        siblings: vec![Sibling {
            clone_type: "type-3".to_string(),
            confidence_band: "low".to_string(),
            basis: "similarity".to_string(),
            signature: None,
            signature_units: None,
            similarity: SiblingSimilarity {
                weight_version: "structural-verify-v1".to_string(),
                lexical: 0.72,
                structural: 0.91,
                control_flow: Some(0.8),
                type_similarity: None,
                api: Some(0.7),
                composite: 0.76,
            },
            member: Member {
                finding_id: "f0".repeat(16),
                content: "f1".repeat(16),
                file: "src/incomplete.rs".to_string(),
                language: "rust".to_string(),
                start_line: 30,
                end_line: 36,
                unit: Some("incomplete_checksum".to_string()),
                boilerplate: None,
                tokens: 31,
                canonical: false,
            },
            suppressed: None,
        }],
    }
}

/// One run-scoped LSH diagnostic shared by the JSON, text, and SARIF tests.
pub(super) fn sample_near_miss() -> NearMiss {
    NearMiss {
        estimated_jaccard: 0.28,
        left: NearMissUnit {
            unit_fingerprint: "a1".repeat(16),
            language: "rust".to_string(),
            file: "src/left.rs".to_string(),
            start_line: 10,
            end_line: 24,
            unit: Some("left_candidate".to_string()),
            tokens: 48,
        },
        right: NearMissUnit {
            unit_fingerprint: "b2".repeat(16),
            language: "rust".to_string(),
            file: "src/right.rs".to_string(),
            start_line: 31,
            end_line: 46,
            unit: Some("right_candidate".to_string()),
            tokens: 51,
        },
        suppressed: None,
    }
}

/// A plain visible group: the highest-priority entry of the sample report.
fn visible_group() -> Group {
    ranked(
        Group {
            identity: None,
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
            narrower_cut_of: None,
            ranked_down: false,
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
            identity: None,
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
            narrower_cut_of: None,
            ranked_down: false,
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
            identity: None,
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
            narrower_cut_of: None,
            ranked_down: false,
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
            identity: None,
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
            narrower_cut_of: None,
            ranked_down: false,
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
    // The listing states the extent as a kind; the count of statements is
    // one of the numbers behind it.
    assert!(text.contains("type-1 run ×"), "{text}");

    let mut detailed = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut detailed,
        )
        .unwrap();
    let detailed = String::from_utf8(detailed).unwrap();
    assert!(detailed.contains("run of 5 statements"), "{detailed}");
    // What was folded away is stated rather than silently dropped, and each
    // count says which total it belongs to.
    assert!(
        detailed.contains(
            "of the 3 reported groups, 1 describe a repeated run inside units that are not clones \
             of each other"
        ),
        "{detailed}"
    );
    assert!(
        detailed.contains(
            "findings not among the 3 reported groups: 4 folded into groups that already cover \
             them; 2 covered by a longer finding"
        ),
        "{detailed}"
    );
}

#[test]
fn an_unrecorded_report_does_not_offer_replay_or_artifact_guidance() {
    let mut report = sample_report();
    report.run.run_id = None;

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert!(json["run"].get("run_id").is_none(), "{json}");

    let mut text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("run unrecorded"), "{text}");
    assert!(!text.contains("codehelion report --run"), "{text}");
    assert!(!text.contains("codehelion explain"), "{text}");
    assert!(text.contains("list every group: --limit 0"), "{text}");
    assert!(!text.contains("artifact savings"), "{text}");

    let mut detailed = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut detailed,
        )
        .unwrap();
    let detailed = String::from_utf8(detailed).unwrap();
    assert!(
        detailed
            .lines()
            .any(|line| line == "database: .codehelion/audit.db (run not recorded)"),
        "{detailed}"
    );
    assert!(!detailed.contains("snapshot:"), "{detailed}");
    assert!(!detailed.contains("codehelion explain"), "{detailed}");
    assert!(
        detailed.contains("list every group: --limit 0"),
        "{detailed}"
    );

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let run = &sarif["runs"][0];
    assert!(run.get("automationDetails").is_none(), "{sarif}");
    assert_eq!(run["invocations"][0]["executionSuccessful"], false);
    assert!(run["properties"].get("run_id").is_none(), "{sarif}");
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

    let mut detailed = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut detailed,
        )
        .unwrap();
    let detailed = String::from_utf8(detailed).unwrap();
    assert!(
        detailed.contains(
            "of the 2 reported groups, 1 are duplication inside test code, which repeats itself by \
             design"
        ),
        "{detailed}"
    );
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
    assert!(value["run"]["build_variant"].get("settings").is_none());
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
                verbosity: 2,
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
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut text,
        )
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

mod baseline;
mod details;
mod groups;
mod identity;
mod notes;
mod ordering;
mod schema;
mod seams;
mod summary;
mod supplemental;
