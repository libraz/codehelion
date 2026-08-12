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
            run_id: Some(1),
            reused: false,
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
        siblings: Vec::new(),
        near_misses: Vec::new(),
    }
}

#[test]
fn text_exclusion_total_counts_each_cause_once() {
    let mut report = sample_report();
    report.summary.excluded = ExcludedCounts {
        generated: 1,
        by_glob: 2,
        skipped: 42,
        too_large: 3,
        binary: 4,
        unreadable: 5,
        symlinks: 7,
        walk_errors: 8,
        timed_out: 9,
        language_excluded: 6,
        symlink_files: 3,
        symlink_directories: 4,
    };
    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .expect("render report with exclusions");
    let text = String::from_utf8(rendered).expect("UTF-8 report");
    assert!(
        text.contains("7 symlinks, 8 walk errors, 9 timed out (45 total)"),
        "{text}"
    );
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

#[test]
fn identity_normalization_counts_a_duplicate_group_once_without_member_double_counting() {
    let normalized = normalize_identities(vec![visible_group(), visible_group()])
        .expect("exact duplicate groups are safe to collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_counts_duplicate_findings_within_one_group() {
    let mut group = visible_group();
    group.members.push(group.members[0].clone());
    let normalized = normalize_identities(vec![group])
        .expect("equal finding payloads inside one group are safe to collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.groups[0].members.len(), 7);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_rejects_a_finding_id_reused_by_another_group() {
    let mut second = visible_group();
    second.fingerprint = "0c".repeat(16);
    let error = normalize_identities(vec![visible_group(), second])
        .expect_err("one finding id cannot identify two groups");
    assert!(error.to_string().contains("stable finding identity"));
}

#[test]
fn identity_normalization_rejects_an_equal_group_id_with_an_unequal_payload() {
    let mut second = visible_group();
    second.members[0].file = "src/changed.rs".to_string();
    let error = normalize_identities(vec![visible_group(), second])
        .expect_err("an unequal payload cannot be selected by a stable id");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_does_not_collapse_distinct_non_finite_payloads() {
    let mut nan = visible_group();
    nan.confidence = f64::NAN;
    let mut infinity = visible_group();
    infinity.confidence = f64::INFINITY;
    let error = normalize_identities(vec![nan, infinity])
        .expect_err("NaN and infinity must remain unequal identity payloads");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_does_not_collapse_signed_zero_payloads() {
    let mut positive = visible_group();
    positive.entropy_bits = 0.0;
    let mut negative = visible_group();
    negative.entropy_bits = -0.0;
    let error = normalize_identities(vec![positive, negative])
        .expect_err("signed zero must remain unequal identity payloads");
    assert!(error.to_string().contains("stable clone-group identity"));
}

fn artifact_savings_with_assumptions(assumptions: serde_json::Value) -> ArtifactSavings {
    ArtifactSavings {
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
        assumptions,
    }
}

#[test]
fn identity_normalization_collapses_exact_nested_json_assumptions() {
    let assumptions = serde_json::json!({
        "nested": [null, true, "text", 7, { "inner": [1.5, false] }]
    });
    let mut first = visible_group();
    first
        .artifact_savings
        .push(artifact_savings_with_assumptions(assumptions.clone()));
    let mut second = visible_group();
    second
        .artifact_savings
        .push(artifact_savings_with_assumptions(assumptions));
    let normalized = normalize_identities(vec![first, second])
        .expect("exact nested JSON assumptions should collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_rejects_signed_zero_in_nested_json_assumptions() {
    let positive = serde_json::Value::Number(
        serde_json::Number::from_f64(0.0).expect("finite zero is a JSON number"),
    );
    let negative = serde_json::Value::Number(
        serde_json::Number::from_f64(-0.0).expect("finite zero is a JSON number"),
    );
    let mut first = visible_group();
    first
        .artifact_savings
        .push(artifact_savings_with_assumptions(serde_json::json!({
            "nested": [positive]
        })));
    let mut second = visible_group();
    second
        .artifact_savings
        .push(artifact_savings_with_assumptions(serde_json::json!({
            "nested": [negative]
        })));
    let error = normalize_identities(vec![first, second])
        .expect_err("signed zero in nested JSON must remain unequal");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_stage_round_trips_through_stored_summary() {
    let mut funnel = Vec::new();
    append_stored_identity_stage(&mut funnel, 3, 2);
    assert_eq!(stored_identity_collapsed(&funnel), 2);

    let stored = SummaryRow {
        funnel,
        ..SummaryRow::default()
    };
    let restored = restored(&stored, &[], "fast");
    assert_eq!(restored.identity_collapsed, 2);
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
    // What was folded away is stated rather than silently dropped.
    assert!(detailed.contains(
        "1 of them are runs duplicated inside units that are not clones of each other; \
         4 more were folded into the groups that already cover them and 2 into longer runs"
    ));
}

#[test]
fn text_names_the_run_required_for_replay() {
    let report = sample_report();
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();

    assert!(
        text.contains("run 1 (replay: codehelion report --run 1)"),
        "{text}"
    );

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
        detailed.contains("snapshot: .codehelion/audit.db"),
        "{detailed}"
    );
}

#[test]
fn text_run_status_names_reuse_and_the_exact_tree_delta() {
    let mut reused = sample_report();
    reused.run.reused = true;
    let mut rendered = Vec::new();
    reused
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("run 1 (reused: tree unchanged; replay: codehelion report --run 1)"),
        "{rendered}"
    );

    let mut changed = sample_report();
    changed.summary.changes = Some(TreeChanges {
        since_run_id: 7,
        modified: 1,
        added: 1,
        removed: 1,
        unchanged: 4,
    });
    let mut rendered = Vec::new();
    changed
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("run 1 (3 file(s) changed; replay: codehelion report --run 1)"),
        "{rendered}"
    );
    assert!(!rendered.contains("reused: tree unchanged"), "{rendered}");
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
fn replay_order_uses_the_recorded_rank_down_verdict() {
    let ordinary = visible_group();
    let delayed = suppressed_group();
    let ordinary_id = ordinary.fingerprint.clone();
    let delayed_id = delayed.fingerprint.clone();
    let recorded = BTreeMap::from([(delayed_id.clone(), true), (ordinary_id.clone(), false)]);
    let mut groups = vec![delayed, ordinary];

    order_recorded(&mut groups, &recorded, Sort::Priority);

    assert_eq!(groups[0].fingerprint, ordinary_id);
    assert_eq!(groups[1].fingerprint, delayed_id);
}

#[test]
fn a_sibling_is_exported_but_text_hides_it_until_requested() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["siblings"][0]["group_fingerprint"], "0b".repeat(16));
    assert_eq!(
        value["siblings"][0]["siblings"][0]["member"]["file"],
        "src/incomplete.rs"
    );
    assert_eq!(
        value["siblings"][0]["siblings"][0]["similarity"]["composite"],
        0.76
    );
    assert_eq!(value["siblings"][0]["siblings"][0]["basis"], "similarity");
    assert_eq!(
        value["siblings"][0]["siblings"][0]["signature"],
        serde_json::Value::Null
    );

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    assert!(
        !String::from_utf8(default_text)
            .unwrap()
            .contains("sibling type-3")
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("sibling type-3 low (0.76): src/incomplete.rs:30"));
    assert!(shown_text.contains("incomplete_checksum"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let sibling = &sarif["runs"][0]["results"][0]["properties"]["siblings"][0];
    assert_eq!(sibling["basis"], "similarity");
    assert_eq!(sibling["signature"], serde_json::Value::Null);
}

#[test]
fn signature_siblings_keep_their_identity_and_render_as_exact_matches() {
    let mut report = sample_report();
    let mut siblings = sample_siblings();
    let sibling = siblings
        .siblings
        .first_mut()
        .expect("sample has one sibling");
    sibling.basis = "signature".to_string();
    sibling.signature = Some("normalized-signature-sentinel".to_string());
    report.siblings = vec![siblings];
    report.summary.guardrails = Some(Guardrails {
        profile: "untrusted".to_string(),
        max_file_bytes: 1,
        parse_timeout_ms: 2,
        helper_timeout_ms: 3,
        posting_cap: 4,
        pair_budget: 5,
        verification_budget: 6,
        max_alignment_cells: 7,
        near_miss_delta: 0.1,
        near_miss_cap: 8,
        sibling_candidate_budget: 9,
        sibling_per_group_cap: 10,
        sibling_total_cap: 11,
        signature_sibling_candidate_budget: 12,
        signature_sibling_per_group_cap: 13,
        signature_sibling_total_cap: 14,
        max_component: 15,
    });

    let mut disabled_diagnostics = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 2,
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut disabled_diagnostics,
        )
        .unwrap();
    assert!(
        !String::from_utf8(disabled_diagnostics)
            .unwrap()
            .contains("signature sibling sweep"),
        "the opt-in channel's ceilings must not look active when its stage is absent"
    );
    report
        .summary
        .funnel
        .push(FunnelStage::new("signature sibling entries", 1));

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let sibling = &value["siblings"][0]["siblings"][0];
    assert_eq!(sibling["basis"], "signature");
    assert_eq!(sibling["signature"], "normalized-signature-sentinel");
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_candidate_budget"],
        12
    );
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_per_group_cap"],
        13
    );
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_total_cap"],
        14
    );

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("sibling type-3 low (0.76) [same signature]: src/incomplete.rs:30"));

    let mut diagnostics = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 2,
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut diagnostics,
        )
        .unwrap();
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(diagnostics.contains("signature sibling sweep 12 candidates, 13 per group, 14 total"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let sibling = &sarif["runs"][0]["results"][0]["properties"]["siblings"][0];
    assert_eq!(sibling["basis"], "signature");
    assert_eq!(sibling["signature"], "normalized-signature-sentinel");
}

#[test]
fn supplemental_totals_count_serialized_hidden_entries_and_name_the_flags() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    report.near_misses = vec![sample_near_miss()];
    report.refresh_supplemental_summary();

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["summary"]["siblings"], 1);
    assert_eq!(value["summary"]["near_misses"], 1);

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    let default_text = String::from_utf8(default_text).unwrap();
    assert!(
        default_text.contains(
            "supplemental: 1 siblings (--show-siblings), 1 near misses (--show-near-misses)"
        ),
        "{default_text}"
    );
    assert!(!default_text.contains("sibling type-3"), "{default_text}");
    assert!(
        !default_text.contains("near-match near misses:"),
        "{default_text}"
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("sibling type-3 low (0.76): src/incomplete.rs:30"));
    assert!(shown_text.contains("near-match near misses:"));
}

#[test]
fn supplemental_totals_omit_the_summary_line_when_empty() {
    let report = sample_report();
    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(!rendered.contains("supplemental:"), "{rendered}");
}

#[test]
fn supplemental_cap_note_requires_actual_dropped_entries() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    report.summary.funnel.push(
        FunnelStage::new("sibling entries", 1)
            .dropping("sibling_total_cap", 2)
            .dropping("sibling_candidate_budget", 0),
    );
    report.refresh_supplemental_summary();

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered
            .contains("supplemental: 1 siblings (--show-siblings; 2 dropped by search ceilings)"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("near miss(es) were dropped"),
        "{rendered}"
    );

    let mut no_drop = sample_report();
    no_drop.siblings = vec![sample_siblings()];
    no_drop
        .summary
        .funnel
        .push(FunnelStage::new("sibling entries", 1));
    no_drop.refresh_supplemental_summary();
    let mut rendered = Vec::new();
    no_drop
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        !rendered.contains("dropped by search ceilings"),
        "{rendered}"
    );
}

#[test]
fn signature_sibling_caps_are_supplemental_but_not_primary_search_truncation() {
    let mut report = sample_report();
    report.summary.funnel = vec![
        FunnelStage::new("signature sibling entries", 0)
            .dropping("signature_sibling_candidate_budget", 2)
            .dropping("signature_sibling_per_group_cap", 3)
            .dropping("signature_sibling_total_cap", 4),
    ];
    assert!(!search_truncated(&report.summary.funnel));

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("supplemental: 9 sibling candidate(s) dropped by search ceilings"),
        "{rendered}"
    );
    assert!(!rendered.contains("search was truncated"), "{rendered}");
}

#[test]
fn identifier_floor_reports_the_exact_unmeasured_count() {
    let mut report = sample_report();
    let mut measured = structural_group();
    measured.identifier_jaccard = Some(0.5);
    report.groups.push(measured);

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains(
            "2 group(s) are not listed: raw identifier agreement below 0.90 (1 of them were not measured in this mode)"
        ),
        "{rendered}"
    );
}

#[test]
fn identifier_floor_omits_unmeasured_clause_when_every_group_has_a_measure() {
    let mut report = sample_report();
    report.groups[0].identifier_jaccard = Some(0.5);
    let mut measured = structural_group();
    measured.identifier_jaccard = Some(0.6);
    report.groups.push(measured);

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("2 group(s) are not listed: raw identifier agreement below 0.90\n"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("not measured in this mode"),
        "{rendered}"
    );
}

#[test]
fn a_near_miss_is_exported_but_text_hides_it_until_requested() {
    let mut report = sample_report();
    report.near_misses = vec![sample_near_miss()];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["near_misses"][0]["estimated_jaccard"], 0.28);
    assert_eq!(value["near_misses"][0]["left"]["file"], "src/left.rs");
    assert!(value["near_misses"][0].get("finding_id").is_none());
    assert!(value["near_misses"][0].get("group_fingerprint").is_none());

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    assert!(
        !String::from_utf8(default_text)
            .unwrap()
            .contains("near-match near misses:")
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("near-match near misses:"));
    assert!(shown_text.contains("estimated Jaccard 0.28: src/left.rs:10"));
    assert!(shown_text.contains("src/right.rs:31"));
}

#[test]
fn supplemental_diagnostics_respect_show_suppressed_in_text() {
    let suppression = Suppression {
        kind: SuppressionKind::Rule,
        reason: Some("vendored sources".to_string()),
        scope: Some("path_glob".to_string()),
        pattern: Some("vendor/**".to_string()),
        active: Some(true),
    };
    let mut report = sample_report();
    let mut siblings = sample_siblings();
    siblings.siblings[0].suppressed = Some(suppression.clone());
    report.siblings = vec![siblings];
    let mut near_miss = sample_near_miss();
    near_miss.suppressed = Some(suppression);
    report.near_misses = vec![near_miss];

    let mut hidden = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut hidden,
        )
        .unwrap();
    let hidden = String::from_utf8(hidden).unwrap();
    assert!(!hidden.contains("src/incomplete.rs"));
    assert!(!hidden.contains("near-match near misses:"));

    let mut shown = Vec::new();
    report
        .render_text(
            TextOptions {
                show_suppressed: true,
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown,
        )
        .unwrap();
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("src/incomplete.rs"));
    assert!(shown.contains("near-match near misses:"));
}

#[test]
fn the_near_miss_text_flag_is_rejected_for_machine_formats() {
    let error = crate::scan::write_report_options(
        crate::scan::ReportOutput {
            format: crate::cli::Format::Json,
            output: None,
            force: false,
            view: crate::cli::ViewArgs::default(),
            show_suppressed: false,
            show_siblings: false,
            show_near_misses: true,
            sort: Sort::Priority,
            min_identifier_jaccard: None,
        },
        &mut Vec::new(),
        &sample_report(),
    )
    .expect_err("machine formats retain near misses without a display flag");
    assert!(format!("{error:#}").contains("--show-near-misses applies only to text reports"));
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
        .render_notes(TextOptions::default(), &mut buffer)
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
    assert!(
        String::from_utf8(detailed)
            .unwrap()
            .contains("1 of them are duplication inside test code")
    );
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
fn fast_summary_names_overlapping_totals_and_unmeasured_evidence() {
    let report = sample_report();
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses"
        ])
    );

    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        notes.contains(
            "Fast duplicated-token totals may overlap because one source location can appear in multiple groups"
        ),
        "{notes}"
    );
    for feature in [
        "identifier agreement",
        "similarity breakdown",
        "siblings",
        "near misses",
    ] {
        assert!(notes.contains(feature), "{feature}: {notes}");
    }
}

#[test]
fn unmeasured_measurements_are_scoped_to_fast_mode() {
    assert_eq!(
        unmeasured_in_this_mode("fast"),
        [
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    );
    assert!(unmeasured_in_this_mode("structural").is_empty());
    assert!(unmeasured_in_this_mode("semantic").is_empty());
}

#[test]
fn structural_summary_serializes_an_empty_fast_only_unmeasured_list() {
    let mut report = sample_report();
    report.run.mode = "structural".to_string();
    report.summary.unmeasured_in_this_mode.clear();

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([])
    );

    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("duplicated-token totals may overlap"),
        "{notes}"
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
#[allow(
    clippy::too_many_lines,
    reason = "one schema test keeps the complete current, legacy-additive, and invalid sibling contracts together"
)]
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

    let mut unrecorded = sample_report();
    unrecorded.run.run_id = None;
    unrecorded.run.reused = false;
    unrecorded.summary.changes = None;
    let unrecorded: serde_json::Value =
        serde_json::from_str(&unrecorded.to_json().unwrap()).unwrap();
    schemas.validate(&unrecorded, index).unwrap();

    let mut with_execution_refusal = sample_report();
    with_execution_refusal.summary.compiler = Some(CompilerCoverage {
        answered: 0,
        not_asked: 0,
        unavailable: BTreeMap::from([("requires_execution".to_string(), 1)]),
        diagnostics: BTreeMap::new(),
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
    report.near_misses = vec![sample_near_miss()];
    report.groups.push(structural_group());
    report.groups[2]
        .similarity
        .as_mut()
        .expect("sample structural group has similarity evidence")
        .confidence_band = None;
    let without_a_recorded_band: serde_json::Value =
        serde_json::from_str(&report.to_json().unwrap()).unwrap();
    schemas.validate(&without_a_recorded_band, index).unwrap();

    // The additive fields remain optional for reports emitted before sibling
    // provenance was persisted.
    let mut old_v1_report = sample_report();
    old_v1_report.siblings = vec![sample_siblings()];
    old_v1_report.summary.guardrails = Some(Guardrails {
        profile: "untrusted".to_string(),
        max_file_bytes: 1,
        parse_timeout_ms: 2,
        helper_timeout_ms: 3,
        posting_cap: 4,
        pair_budget: 5,
        verification_budget: 6,
        max_alignment_cells: 7,
        near_miss_delta: 0.1,
        near_miss_cap: 8,
        sibling_candidate_budget: 9,
        sibling_per_group_cap: 10,
        sibling_total_cap: 11,
        signature_sibling_candidate_budget: 12,
        signature_sibling_per_group_cap: 13,
        signature_sibling_total_cap: 14,
        max_component: 15,
    });
    let mut old_v1: serde_json::Value =
        serde_json::from_str(&old_v1_report.to_json().unwrap()).unwrap();
    let old_sibling = old_v1["siblings"][0]["siblings"][0]
        .as_object_mut()
        .expect("sibling object");
    old_sibling.remove("basis");
    old_sibling.remove("signature");
    let old_guardrails = old_v1["summary"]["guardrails"]
        .as_object_mut()
        .expect("guardrails object");
    old_guardrails.remove("signature_sibling_candidate_budget");
    old_guardrails.remove("signature_sibling_per_group_cap");
    old_guardrails.remove("signature_sibling_total_cap");
    schemas.validate(&old_v1, index).unwrap();

    let mut signature_report = sample_report();
    let mut signature_group = sample_siblings();
    signature_group.siblings[0].basis = "signature".to_string();
    signature_group.siblings[0].signature = Some("schema-signature".to_string());
    signature_report.siblings = vec![signature_group];
    let signature_value: serde_json::Value =
        serde_json::from_str(&signature_report.to_json().unwrap()).unwrap();
    schemas.validate(&signature_value, index).unwrap();

    let mut missing_signature = signature_value;
    missing_signature["siblings"][0]["siblings"][0]
        .as_object_mut()
        .expect("sibling object")
        .remove("signature");
    assert!(schemas.validate(&missing_signature, index).is_err());

    let null_signature: serde_json::Value =
        serde_json::from_str(&signature_report.to_json().unwrap()).unwrap();
    let mut null_signature = null_signature;
    null_signature["siblings"][0]["siblings"][0]["signature"] = serde_json::Value::Null;
    assert!(schemas.validate(&null_signature, index).is_err());

    let mut orphan_signature = value.clone();
    orphan_signature["siblings"] = serde_json::json!([{
        "group_fingerprint": "0b".repeat(16),
        "siblings": [{
            "clone_type": "type-3",
            "confidence_band": "low",
            "signature": "orphan-signature",
            "similarity": {
                "weight_version": "structural-verify-v1",
                "lexical": 0.72,
                "structural": 0.91,
                "control_flow": 0.8,
                "type_similarity": null,
                "api": 0.7,
                "composite": 0.76
            },
            "member": {
                "finding_id": "f0".repeat(16),
                "content": "f1".repeat(16),
                "file": "src/incomplete.rs",
                "language": "rust",
                "start_line": 30,
                "end_line": 36,
                "unit": "incomplete_checksum",
                "tokens": 31,
                "canonical": false
            },
            "suppressed": null
        }]
    }]);
    assert!(schemas.validate(&orphan_signature, index).is_err());

    let mut similarity_with_signature = value.clone();
    similarity_with_signature["siblings"] = serde_json::json!([{
        "group_fingerprint": "0b".repeat(16),
        "siblings": [{
            "clone_type": "type-3",
            "confidence_band": "low",
            "basis": "similarity",
            "signature": "must-not-be-present",
            "similarity": {
                "weight_version": "structural-verify-v1",
                "lexical": 0.72,
                "structural": 0.91,
                "control_flow": 0.8,
                "type_similarity": null,
                "api": 0.7,
                "composite": 0.76
            },
            "member": {
                "finding_id": "f0".repeat(16),
                "content": "f1".repeat(16),
                "file": "src/incomplete.rs",
                "language": "rust",
                "start_line": 30,
                "end_line": 36,
                "unit": "incomplete_checksum",
                "tokens": 31,
                "canonical": false
            },
            "suppressed": null
        }]
    }]);
    assert!(schemas.validate(&similarity_with_signature, index).is_err());

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
        diagnostics: BTreeMap::from([("compiler library unavailable".to_string(), 2)]),
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
    assert_eq!(
        json["summary"]["compiler"]["diagnostics"]["compiler library unavailable"],
        2
    );
    assert!(refusal["cost"].as_str().unwrap().contains("build script"));
    assert_eq!(
        refusal["permission_argument"],
        "--allow-execution=build-script"
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
    assert!(text.contains("2 helper diagnostic: compiler library unavailable"));
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

#[test]
fn artifact_guidance_appears_only_when_every_group_lacks_savings() {
    let mut report = sample_report();
    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        notes.contains(
            "note: no artifact savings are recorded; provide an artifact at <PATH> retaining symbols/debug info, or a matching companion via --debug-file <PATH>, then run artifact analyze <PATH> --source-run <id> --build-variant <manifest>\n"
        ),
        "{notes}"
    );

    report.groups[0].artifact_savings.push(ArtifactSavings {
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
        assumptions: serde_json::json!([]),
    });
    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("no artifact savings are recorded"),
        "{notes}"
    );

    let mut empty = sample_report();
    empty.groups.clear();
    let mut notes = Vec::new();
    empty
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("no artifact savings are recorded"),
        "{notes}"
    );
}

#[test]
fn partition_artifact_guidance_is_aggregated_over_all_models() {
    const GUIDANCE: &str = "note: no artifact savings are recorded; provide an artifact at <PATH> retaining symbols/debug info, or a matching companion via --debug-file <PATH>, then run artifact analyze <PATH> --source-run <id> --build-variant <manifest>";

    let reports = [sample_report(), sample_report()];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 1, "{notes}");

    let mut with_savings = sample_report();
    with_savings.groups[0]
        .artifact_savings
        .push(ArtifactSavings {
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
            assumptions: serde_json::json!([]),
        });
    let reports = [sample_report(), with_savings];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 0, "{notes}");

    let mut empty = sample_report();
    empty.groups.clear();
    let reports = [empty, sample_report()];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 1, "{notes}");

    let reports = [empty_report(), empty_report()];
    let mut notes = Vec::new();
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 0, "{notes}");
}

fn empty_report() -> Report {
    let mut report = sample_report();
    report.groups.clear();
    report
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
