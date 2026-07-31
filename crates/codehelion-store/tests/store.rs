//! Store integration: snapshot round-trips, crash atomicity, fingerprint
//! dedup across scans and unsupported-layout rejection — all against real `SQLite`
//! databases (in-memory and on-disk), never mocks.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{
    BuildConfiguration, BuildVariant, CppBuild, Language, LanguageSelection, RustBuild,
};
use codehelion_core::features::{
    ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, FeatureKind, SubtreeFeature,
    UnitFeatures, WindowFeature,
};
use codehelion_core::frontend::UnitKind;
use codehelion_core::ir::ByteRange;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, CrossLanguageComparisonId, CrossLanguageGroupId, FindingId,
    FragmentFingerprint, UnitFingerprint,
};
use codehelion_core::verify::Confidence;
use codehelion_store::query::StoredVariant;
use codehelion_store::snapshot::{
    CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow, CrossLanguageSemanticMemberRow,
    FeatureRow, FileRow, FunnelDropRow, FunnelStageRow, GroupRow, MemberRow, PriorityRow,
    SemanticEvidenceRow, SemanticNodeMappingRow, SemanticOperationGraphRow, SimilarityBreakdownRow,
    Snapshot, SummaryRow, SuppressionRuleRow, UnitRow, UnparsedRow, UnusedRuleRow,
};
use codehelion_store::{Store, StoreError};

const fn unit_fp(seed: u8) -> UnitFingerprint {
    UnitFingerprint::from_bytes([seed; 16])
}

const fn frag_fp(seed: u8) -> FragmentFingerprint {
    FragmentFingerprint::from_bytes([seed; 16])
}

const fn group_fp(seed: u8) -> CloneGroupFingerprint {
    CloneGroupFingerprint::from_bytes([seed; 16])
}

const fn finding(seed: u8) -> FindingId {
    FindingId::from_bytes([seed; 16])
}

fn semantic_graph_json(kind: &str) -> String {
    serde_json::json!({
        "schema_version": "sog-v1",
        "language": "c",
        "build_variant_fingerprint": vec![0_u8; 32],
        "nodes": [{
            "kind": kind,
            "attributes": {
                "type_tag": null,
                "structure_fingerprint": null,
                "api_names": [],
                "resource_kind": null,
                "fallible_kind": null,
                "direct_propagation": null
            }
        }],
        "edges": []
    })
    .to_string()
}

fn cross_language_graph_json(language: &str, kind: &str, api_name: &str, variant: u8) -> String {
    serde_json::json!({
        "schema_version": "sog-v1",
        "language": language,
        "build_variant_fingerprint": vec![variant; 32],
        "nodes": [{
            "kind": kind,
            "attributes": {
                "type_tag": null,
                "structure_fingerprint": null,
                "api_names": [api_name],
                "resource_kind": null,
                "fallible_kind": null,
                "direct_propagation": null
            }
        }],
        "edges": []
    })
    .to_string()
}

fn detector_versions() -> Vec<(String, String)> {
    vec![
        ("normalization".to_string(), "2".to_string()),
        ("frontend.rust".to_string(), "rust-lexer-v1".to_string()),
        ("fp-schema".to_string(), "fp-schema-v1".to_string()),
    ]
}

fn member_with_finding(
    content_seed: u8,
    finding_seed: u8,
    path: &str,
    host: Option<usize>,
) -> MemberRow {
    MemberRow {
        content: frag_fp(content_seed),
        finding: finding(finding_seed.wrapping_add(100)),
        language: Language::Rust,
        host_unit: host,
        boilerplate: None,
        file_path: path.to_string(),
        start_line: 10,
        end_line: 20,
        token_count: 42,
    }
}

fn sample_snapshot<'a>(
    variant: &'a BuildVariant,
    detectors: &'a [(String, String)],
) -> Snapshot<'a> {
    Snapshot {
        root_path: "/repo",
        tool_version: "0.1.0",
        config_hash: "cfg-hash",
        started_at: "2026-07-24T00:00:00Z",
        finished_at: "2026-07-24T00:00:05Z",
        variant,
        min_clone_tokens: 20,
        detector_versions: detectors,
        units: vec![
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/a.rs".to_string(),
                start_line: 1,
                end_line: 9,
                token_count: 50,
            },
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/b.rs".to_string(),
                start_line: 3,
                end_line: 11,
                token_count: 50,
            },
        ],
        suppressions: Vec::new(),
        groups: vec![GroupRow {
            fingerprint: group_fp(9),
            clone_type: CloneClass::Type1,
            split_pair: false,
            member_scope: CloneScope::Unit,
            statements: None,
            identifier_jaccard: None,
            has_loop: None,
            has_dynamic_allocation: None,
            call_count: None,
            test_code: false,
            score: 1.0,
            entropy_bits: 4.2,
            suppress_reason: None,
            boilerplate: None,
            width_family: false,
            suppressed_by: None,
            priority: PriorityRow {
                clone_confidence: 0.81,
                maintenance_risk: 0.44,
                refactoring_difficulty: 0.27,
                final_priority: 0.52,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            similarity: None,
            semantic: None,
            members: vec![
                member_with_finding(1, 1, "src/a.rs", Some(0)),
                member_with_finding(1, 2, "src/b.rs", Some(1)),
            ],
        }],
        features: Vec::new(),
        files: vec![
            FileRow {
                relative_path: "src/a.rs".to_string(),
                content_hash: "aa".repeat(32),
                language: Language::Rust,
                byte_len: 120,
            },
            FileRow {
                relative_path: "src/b.rs".to_string(),
                content_hash: "bb".repeat(32),
                language: Language::Rust,
                byte_len: 240,
            },
        ],
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: sample_summary(),
    }
}

/// A summary with every field distinguishable from every other, so a
/// round-trip that swaps two of them fails instead of passing.
fn sample_summary() -> SummaryRow {
    SummaryRow {
        lines: 310,
        tokens: 1_400,
        lexer_diagnostics: 2,
        unparsed: Some(UnparsedRow {
            files: 1,
            tokens: 35,
        }),
        excluded_generated: 3,
        excluded_by_glob: 4,
        excluded_skipped: 5,
        folded_runs: 6,
        subsumed_runs: 7,
        split_components: 8,
        pair_budget_exhausted: true,
        baseline_digest: Some("cc".repeat(32)),
        funnel: vec![
            FunnelStageRow {
                name: "tokens".to_string(),
                passed: 1_400,
                dropped: Vec::new(),
            },
            FunnelStageRow {
                name: "seed pairs".to_string(),
                passed: 12,
                dropped: vec![
                    FunnelDropRow {
                        cause: "pair_budget".to_string(),
                        count: 9,
                    },
                    FunnelDropRow {
                        cause: "high_frequency".to_string(),
                        count: 4,
                    },
                ],
            },
        ],
        unused_suppressions: vec![UnusedRuleRow {
            scope: "path_glob".to_string(),
            pattern: "vendor/**".to_string(),
        }],
    }
}

#[test]
fn a_snapshot_round_trips_through_queries() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let run = store.latest_run().unwrap().expect("a run");
    assert_eq!(run.id, run_id);
    assert_eq!(run.root_path, "/repo");
    assert_eq!(run.analysis_mode, "fast");
    assert_eq!(run.finished_at.as_deref(), Some("2026-07-24T00:00:05Z"));
    assert_eq!(run.group_count, 1);

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.fingerprint_hex, group_fp(9).to_hex());
    assert_eq!(group.clone_type, "type-1");
    assert!(
        group.similarity.is_none(),
        "Fast mode measures no breakdown"
    );
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.members[0].file_path, "src/a.rs");
    assert_eq!(group.members[0].unit_name.as_deref(), Some("checksum"));
    assert!(group.members[0].is_canonical);
    assert!(!group.members[1].is_canonical);

    // `explain` path: look one occurrence up by its finding id.
    let hex = finding(101).to_hex();
    let occurrence = store.occurrence(&hex).unwrap().expect("occurrence");
    assert_eq!(occurrence.member.finding_hex, hex);
    assert_eq!(occurrence.group_fingerprint_hex, group_fp(9).to_hex());
    assert_eq!(occurrence.scan_run_id, run_id);

    // Unknown but well-formed id: not found, not an error.
    assert!(store.occurrence(&finding(250).to_hex()).unwrap().is_none());
    // Malformed id: an explicit error.
    assert!(matches!(
        store.occurrence("not-hex"),
        Err(StoreError::MalformedId { .. })
    ));
}

/// What a run reported about itself has to come back the way it went in,
/// stage order and drop order included: a report rebuilt from these rows is
/// compared byte for byte against the one the scan printed.
#[test]
fn what_a_run_reported_about_itself_comes_back_as_it_went_in() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let read = store.run_summary_row(run_id).unwrap().expect("a summary");
    assert_eq!(read, sample_summary());
}

#[test]
fn source_units_keep_the_variant_that_minted_their_fingerprints() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let units = store.source_units(run_id).unwrap();
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].file_path, "src/a.rs");
    assert_eq!(units[0].fingerprint, [1; 16]);
    assert_eq!(units[0].start_line, Some(1));
    assert_eq!(units[0].end_line, Some(9));
    assert_eq!(
        units[0].build_variant_fingerprint,
        units[1].build_variant_fingerprint
    );
}

#[test]
fn clone_fragments_keep_the_variant_that_minted_their_fingerprints() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let fragments = store.source_clone_fragments(run_id).unwrap();
    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[0].fingerprint, [1; 16]);
    assert_eq!(fragments[0].finding_id, [101; 16]);
    assert_eq!(fragments[0].clone_group_fingerprint, [9; 16]);
    assert!(fragments[0].is_canonical);
    assert!((fragments[0].clone_confidence - 1.0).abs() < f64::EPSILON);
    assert_eq!(fragments[0].file_path, "src/a.rs");
    assert_eq!(fragments[0].start_line, Some(10));
    assert_eq!(fragments[0].end_line, Some(20));
    assert_eq!(fragments[1].fingerprint, [1; 16]);
    assert_eq!(fragments[1].finding_id, [102; 16]);
    assert_eq!(fragments[1].clone_group_fingerprint, [9; 16]);
    assert!(!fragments[1].is_canonical);
    assert_eq!(fragments[1].file_path, "src/b.rs");
}

/// Any layout marker other than the v1 baseline is rejected.
#[test]
fn a_development_database_before_summaries_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE schema_meta SET version = 2", [])
            .unwrap();
    }

    assert!(matches!(
        Store::open(&path),
        Err(StoreError::UnsupportedSchema { found: 2 })
    ));
}

#[test]
fn a_structural_group_persists_its_similarity_breakdown() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].clone_type = CloneClass::Type2;
    snapshot.groups[0].similarity = Some(SimilarityBreakdownRow {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 0.8,
        structural: 0.95,
        control_flow: 0.9,
        // Structural mode resolves no types.
        type_similarity: None,
        api: Some(0.5),
        composite: 0.87,
        min_pairwise: 0.72,
        confidence_band: Confidence::Medium,
    });
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let breakdown = groups[0]
        .similarity
        .as_ref()
        .expect("the structural group carries a breakdown");
    assert_eq!(breakdown.weight_version, "structural-verify-v1");
    assert!((breakdown.structural - 0.95).abs() < 1e-9);
    assert!((breakdown.composite - 0.87).abs() < 1e-9);
    assert!((breakdown.min_pairwise - 0.72).abs() < 1e-9);
    // The unmeasured type dimension survives the round-trip as absent.
    assert!(breakdown.type_similarity.is_none());
    assert_eq!(breakdown.api, Some(0.5));
    // The band is not derivable from the numbers, so it is stored alongside
    // them rather than recomputed on read.
    assert_eq!(breakdown.confidence_band.as_deref(), Some("medium"));

    // The same evidence is reachable from a single occurrence, which is what
    // `explain` looks up.
    let finding_hex = groups[0].members[0].finding_hex.clone();
    let occurrence = store
        .occurrence(&finding_hex)
        .unwrap()
        .expect("the occurrence is stored");
    assert_eq!(occurrence.clone_type, "type-2");
    assert_eq!(
        occurrence.member_count,
        i64::try_from(groups[0].members.len()).unwrap()
    );
    let breakdown = occurrence
        .similarity
        .expect("the occurrence carries its group's breakdown");
    assert!((breakdown.composite - 0.87).abs() < 1e-9);
    assert_eq!(breakdown.confidence_band.as_deref(), Some("medium"));
}

#[test]
fn an_unmeasured_api_dimension_round_trips_as_absent() {
    // Two units that call nothing have no call surfaces to compare. The column
    // has to distinguish that from perfect agreement, or reading the row back
    // would invent evidence the run never had.
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].similarity = Some(SimilarityBreakdownRow {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 1.0,
        structural: 1.0,
        control_flow: 1.0,
        type_similarity: None,
        api: None,
        composite: 1.0,
        min_pairwise: 1.0,
        confidence_band: Confidence::High,
    });
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let breakdown = groups[0]
        .similarity
        .as_ref()
        .expect("the group carries a breakdown");
    assert!(breakdown.api.is_none());
    assert!((breakdown.composite - 1.0).abs() < 1e-9);
}

#[test]
fn a_suppressed_occurrence_explains_the_rule_that_hid_it() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "symbol_pattern".to_string(),
        pattern: "checksum_*".to_string(),
        reason: None,
    }];
    snapshot.groups[0].suppressed_by = Some(0);
    snapshot.groups[0].boilerplate = Some(Boilerplate::Forwarding);
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let occurrence = store
        .occurrence(&groups[0].members[0].finding_hex)
        .unwrap()
        .expect("a suppressed occurrence is still stored");
    let rule = occurrence
        .suppression
        .expect("the occurrence names the rule that hid it");
    assert_eq!(rule.scope, "symbol_pattern");
    assert_eq!(rule.pattern, "checksum_*");
    assert_eq!(occurrence.boilerplate.as_deref(), Some("forwarding"));
}

#[test]
fn a_boilerplate_group_records_what_it_is_independently_of_policy() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].boilerplate = Some(Boilerplate::MacroRepetition);
    // Nothing was suppressed: the classification is a fact about the code,
    // not a record of what the report did with it.
    snapshot.groups[0].suppress_reason = None;
    snapshot.groups[0].suppressed_by = None;
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups[0].boilerplate.as_deref(), Some("macro-repetition"));
    assert!(groups[0].suppress_reason.is_none());

    // A group that matches no shape stores none.
    let mut plain = sample_snapshot(&variant, &detectors);
    plain.groups[0].boilerplate = None;
    let run_id = store.record_snapshot(&plain).unwrap();
    assert!(store.run_groups(run_id).unwrap()[0].boilerplate.is_none());
}

#[test]
fn a_failing_snapshot_leaves_no_partial_rows() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    // A member referencing a unit index that does not exist fails the write
    // midway, after the run and unit rows were already inserted.
    snapshot.groups[0].members[1].host_unit = Some(99);
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownUnitIndex { index: 99, .. }
    ));

    assert!(store.latest_run().unwrap().is_none(), "no partial run");
    for table in [
        "scan_run",
        "source_unit",
        "fragment",
        "clone_group",
        "finding",
        "fingerprint",
    ] {
        let count = store.table_count(table).unwrap();
        assert_eq!(count, 0, "table {table} must be empty after rollback");
    }
}

#[test]
fn semantic_evidence_persists_one_graph_per_member_and_rolls_back_on_mismatch() {
    let variant = BuildVariant::semantic(LanguageSelection::default(), Language::C, Vec::new());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].clone_type = CloneClass::RestrictedSemantic;
    snapshot.groups[0].semantic = Some(SemanticEvidenceRow {
        schema_version: "sog-v1".to_string(),
        rule_id: "sequence-pipeline-v1".to_string(),
        rule_version: 1,
        rule_confidence: 0.7,
        graphs: vec![
            SemanticOperationGraphRow {
                schema_version: "sog-v1".to_string(),
                graph_json: semantic_graph_json("filter"),
            },
            SemanticOperationGraphRow {
                schema_version: "sog-v1".to_string(),
                graph_json: semantic_graph_json("collect"),
            },
        ],
        node_mappings: vec![SemanticNodeMappingRow {
            corresponding_member: 1,
            canonical: 0,
            corresponding: 0,
        }],
    });
    store.record_snapshot(&snapshot).unwrap();
    assert_eq!(store.table_count("semantic_operation_graph").unwrap(), 2);
    assert_eq!(store.table_count("semantic_group_evidence").unwrap(), 1);
    assert_eq!(store.table_count("semantic_node_mapping").unwrap(), 1);
    let stored = store
        .run_groups(store.latest_run().unwrap().unwrap().id)
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].semantic.as_ref().map(|evidence| {
            (
                evidence.rule_id.as_str(),
                evidence.graphs.len(),
                evidence.node_mappings.len(),
            )
        }),
        Some(("sequence-pipeline-v1", 2, 1))
    );
    assert_eq!(
        stored[0]
            .semantic
            .as_ref()
            .map(|evidence| evidence.node_mappings.as_slice()),
        Some(
            [codehelion_store::query::StoredSemanticNodeMapping {
                corresponding_member: 1,
                canonical: 0,
                corresponding: 0,
            }]
            .as_slice()
        )
    );

    let mut malformed = sample_snapshot(&variant, &detectors);
    malformed.groups[0].clone_type = CloneClass::RestrictedSemantic;
    malformed.groups[0].semantic = Some(SemanticEvidenceRow {
        schema_version: "sog-v1".to_string(),
        rule_id: "sequence-pipeline-v1".to_string(),
        rule_version: 1,
        rule_confidence: 0.7,
        graphs: Vec::new(),
        node_mappings: Vec::new(),
    });
    let error = store.record_snapshot(&malformed).unwrap_err();
    assert!(matches!(error, StoreError::InvalidSemanticEvidence { .. }));
    assert_eq!(store.table_count("scan_run").unwrap(), 1);
}

#[test]
fn cross_language_semantic_comparison_is_separate_and_keeps_its_evidence() {
    let mut store = Store::open_in_memory().unwrap();
    let origins = vec!["cpp-variant".to_string(), "rust-variant".to_string()];
    let groups = vec![CrossLanguageSemanticGroupRow {
        group_id: CrossLanguageGroupId::from_bytes([72; 16]),
        rule_id: "cross-language-sequence-pipeline-v1".to_string(),
        rule_version: 1,
        semantic_confidence: 0.55,
        correspondence_ids: vec!["sequence-map-v1".to_string()],
        members: vec![
            CrossLanguageSemanticMemberRow {
                origin_variant: "rust-variant".to_string(),
                language: Language::Rust,
                file_path: "rust/src/lib.rs".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v1".to_string(),
                graph_json: cross_language_graph_json("rust", "map", "rust::Iterator::map", 1),
            },
            CrossLanguageSemanticMemberRow {
                origin_variant: "cpp-variant".to_string(),
                language: Language::Cpp,
                file_path: "cpp/src/map.cpp".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v1".to_string(),
                graph_json: cross_language_graph_json("cpp", "map", "std::transform", 2),
            },
        ],
    }];
    let comparison = CrossLanguageComparisonSnapshot {
        root_path: "/repo",
        comparison_id: CrossLanguageComparisonId::from_bytes([71; 16]),
        policy_version: "cross-language-semantic-v1",
        started_at: "2026-07-31T00:00:00Z",
        finished_at: "2026-07-31T00:00:01Z",
        origins: &origins,
        groups: &groups,
    };
    store.record_cross_language_comparison(&comparison).unwrap();
    assert_eq!(store.table_count("cross_language_comparison").unwrap(), 1);
    assert_eq!(
        store.table_count("cross_language_semantic_group").unwrap(),
        1
    );
    assert_eq!(
        store.table_count("cross_language_semantic_member").unwrap(),
        2
    );
    assert_eq!(store.table_count("scan_run").unwrap(), 0);
    let detail = store
        .cross_language_group(&"48".repeat(16))
        .unwrap()
        .expect("the comparison group is queryable by its stable id");
    assert_eq!(detail.comparison_id_hex, "47".repeat(16));
    assert_eq!(detail.policy_version, "cross-language-semantic-v1");
    assert_eq!(detail.root_path, "/repo");
    assert_eq!(detail.origin_variants, origins);
    assert_eq!(detail.rule_id, "cross-language-sequence-pipeline-v1");
    assert_eq!(detail.correspondence_ids, vec!["sequence-map-v1"]);
    assert_eq!(detail.members.len(), 2);
    assert_eq!(detail.members[0].language, "cpp");
    assert_eq!(detail.members[0].graph.schema_version, "sog-v1");
    assert!(
        store
            .cross_language_group(&"ff".repeat(16))
            .unwrap()
            .is_none()
    );

    let mut malformed_groups = groups.clone();
    malformed_groups[0].members[1].language = Language::C;
    let malformed = CrossLanguageComparisonSnapshot {
        groups: &malformed_groups,
        ..comparison
    };
    let error = store
        .record_cross_language_comparison(&malformed)
        .unwrap_err();
    assert!(matches!(error, StoreError::InvalidSemanticEvidence { .. }));
    assert_eq!(store.table_count("cross_language_comparison").unwrap(), 1);
}

#[test]
fn a_new_snapshot_replaces_the_previous_scan() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut second = sample_snapshot(&variant, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    let second_id = store.record_snapshot(&second).unwrap();

    assert_eq!(store.table_count("scan_run").unwrap(), 1);
    // Identical content under an identical context: one fingerprint row per
    // identity (1 unit + 1 member content + 1 group), not per scan.
    assert_eq!(store.table_count("fingerprint").unwrap(), 3);
    assert_eq!(store.table_count("build_variant").unwrap(), 1);

    // Only the later run remains queryable.
    assert_eq!(store.latest_run().unwrap().unwrap().id, second_id);
}

/// A unit-features fixture with one window, one subtree, a cfg profile and
/// the two api hashes — five distinct feature hashes in total.
fn sample_unit_features() -> UnitFeatures {
    let mut counts = [0u32; 23];
    counts[1] = 3;
    counts[11] = 2;
    UnitFeatures {
        name: None,
        shape_tag: 1,
        range: ByteRange { start: 0, end: 100 },
        windows: vec![WindowFeature {
            hash: FeatureHash::from_bytes([7; 16]),
            length: 4,
            range: ByteRange { start: 0, end: 40 },
            block: 0,
            offset: 0,
        }],
        subtrees: vec![SubtreeFeature {
            hash: FeatureHash::from_bytes([8; 16]),
            node_count: 6,
            range: ByteRange { start: 0, end: 50 },
        }],
        vector: CharacteristicVector {
            counts,
            max_depth: 4,
            node_count: 12,
        },
        cfg: CfgFeature {
            hash: FeatureHash::from_bytes([9; 16]),
            skeleton_hash: FeatureHash::from_bytes([11; 16]),
            op_count: 5,
            skeleton_ops: 4,
            max_loop_depth: 2,
            branch_count: 1,
        },
        api: ApiCallFeature {
            names: Vec::new(),
            sequence_hash: FeatureHash::from_bytes([10; 16]),
            multiset_hash: FeatureHash::from_bytes([11; 16]),
        },
    }
}

#[test]
fn feature_fingerprints_persist_and_deduplicate_across_scans() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let unit = sample_unit_features();
    let mut first = sample_snapshot(&variant, &detectors);
    first.features = vec![FeatureRow::from_unit(0, &unit)];
    let run_id = store.record_snapshot(&first).unwrap();

    // One window + one subtree + one cfg + two api hashes = five occurrences,
    // each a distinct fingerprint; one scalar unit_feature row.
    assert_eq!(store.table_count("feature_occurrence").unwrap(), 5);
    assert_eq!(store.table_count("feature_fingerprint").unwrap(), 5);
    assert_eq!(store.table_count("unit_feature").unwrap(), 1);

    // The subtree hash resolves to its single occurrence with the right anchor
    // and extent.
    let posting = store
        .feature_posting_list(FeatureKind::Subtree, &[8; 16])
        .unwrap();
    assert_eq!(posting.len(), 1);
    assert_eq!(posting[0].scan_run_id, run_id);
    assert_eq!(posting[0].start_byte, 0);
    assert_eq!(posting[0].end_byte, 50);
    assert_eq!(posting[0].extent, 6);
    assert!(posting[0].source_unit_id.is_some());
    assert!(
        store
            .feature_posting_list(FeatureKind::Subtree, &[99; 16])
            .unwrap()
            .is_empty()
    );

    // A second, identical scan replaces its occurrence rows with the current
    // snapshot while retaining content-addressed feature fingerprints.
    let mut second = sample_snapshot(&variant, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    second.features = vec![FeatureRow::from_unit(0, &unit)];
    store.record_snapshot(&second).unwrap();
    assert_eq!(store.table_count("feature_fingerprint").unwrap(), 5);
    assert_eq!(store.table_count("feature_occurrence").unwrap(), 5);
    assert_eq!(store.table_count("unit_feature").unwrap(), 1);
    assert_eq!(
        store
            .feature_posting_list(FeatureKind::Subtree, &[8; 16])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_feature_referencing_an_unknown_unit_rolls_the_snapshot_back() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let unit = sample_unit_features();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.features = vec![FeatureRow::from_unit(99, &unit)];
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownUnitIndex { index: 99, .. }
    ));

    assert!(store.latest_run().unwrap().is_none(), "no partial run");
    for table in ["feature_fingerprint", "feature_occurrence", "unit_feature"] {
        assert_eq!(store.table_count(table).unwrap(), 0, "{table} not empty");
    }
}

#[test]
fn artifact_tables_exist_and_stay_empty() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    for table in ["artifact", "artifact_symbol", "source_artifact_mapping"] {
        assert_eq!(
            store.table_count(table).unwrap(),
            0,
            "{table} must stay empty"
        );
    }
    // The diagnostic rejects unknown tables instead of interpolating them.
    assert!(matches!(
        store.table_count("no_such_table"),
        Err(StoreError::UnknownTable { .. })
    ));
}

#[test]
fn a_finding_records_the_state_the_run_settled_on() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let findings = store.run_findings(run_id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].group_fingerprint_hex, group_fp(9).to_hex());
    // The measures the run settled on, not the raw similarity: a finding row
    // records where the run put it, and why.
    assert!((findings[0].clone_confidence - 0.81).abs() < f64::EPSILON);
    assert!((findings[0].final_priority - 0.52).abs() < f64::EPSILON);
    assert!(findings[0].suppression_scope.is_none());
}

#[test]
fn suppressed_findings_reference_a_deduplicated_rule_row() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("vendored sources".to_string()),
    }];
    snapshot.groups[0].suppressed_by = Some(0);
    store.record_snapshot(&snapshot).unwrap();
    let second_run = store.record_snapshot(&snapshot).unwrap();

    // The current snapshot keeps its suppression evidence.
    assert_eq!(store.table_count("suppression").unwrap(), 1);
    let findings = store.run_findings(second_run).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].suppression_scope.as_deref(), Some("path_glob"));
    let hidden = &store.run_groups(second_run).unwrap()[0];
    let rule = hidden.suppressed_by.as_ref().expect("the rule that hid it");
    assert_eq!(rule.scope, "path_glob");
    assert_eq!(rule.pattern, "vendor/**");
}

#[test]
fn a_run_read_back_carries_the_conditions_its_ids_were_computed_under() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    assert!(
        store.latest_completed_run("/repo").unwrap().is_none(),
        "nothing scanned yet"
    );

    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let origin = store.latest_completed_run("/repo").unwrap().expect("a run");
    assert_eq!(origin.id, run_id);
    assert_eq!(origin.analysis_mode, "structural");
    assert_eq!(origin.tool_version, "0.1.0");
    assert_eq!(origin.finished_at, "2026-07-24T00:00:05Z");
    assert_eq!(origin.variant_fingerprint, variant.fingerprint());
    assert_eq!(
        origin.normalization_version,
        i64::from(variant.normalization_version)
    );
    assert_eq!(origin.detector_versions, sorted(detectors.clone()));

    // Another root is another history; this one has none.
    assert!(store.latest_completed_run("/elsewhere").unwrap().is_none());
}

/// The detector versions as the query orders them: by component, then version.
fn sorted(mut versions: Vec<(String, String)>) -> Vec<(String, String)> {
    versions.sort();
    versions
}

#[test]
fn an_unknown_suppression_index_rolls_the_snapshot_back() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].suppressed_by = Some(5);
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownSuppressionIndex { index: 5, rules: 0 }
    ));
    assert!(store.latest_run().unwrap().is_none(), "no partial run");
}

#[test]
fn on_disk_databases_reopen_and_a_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");

    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    {
        // Reopen: the v1 baseline remains readable and the data is still there.
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            codehelion_store::schema::SCHEMA_VERSION
        );
        assert!(store.latest_run().unwrap().is_some());
    }

    // Pretend a newer tool wrote the database.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE schema_meta SET version = 999", [])
            .unwrap();
    }
    let err = Store::open(&path).unwrap_err();
    assert!(matches!(err, StoreError::UnsupportedSchema { found: 999 }));
}

#[test]
fn a_run_duplicated_inside_its_hosts_is_recorded_as_a_fragment_group() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    // The same two units, but what is duplicated is a stretch inside each of
    // them rather than the units themselves.
    snapshot.groups[0].member_scope = CloneScope::Fragment;
    for member in &mut snapshot.groups[0].members {
        member.start_line = 4;
        member.end_line = 7;
        member.token_count = 18;
    }
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let group = &groups[0];
    assert_eq!(group.member_scope, "fragment");
    // Recorded, not inferred from how the anchors compare: each occurrence
    // still names the unit that hosts it.
    assert_eq!(group.members[0].unit_name.as_deref(), Some("checksum"));
    assert!(group.members[0].token_count < 50);

    let occurrence = store
        .occurrence(&finding(101).to_hex())
        .unwrap()
        .expect("occurrence");
    assert_eq!(occurrence.member_scope, "fragment");
}

#[test]
fn a_whole_unit_group_records_the_scope_it_was_written_with() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    assert_eq!(store.run_groups(run_id).unwrap()[0].member_scope, "unit");
}

#[test]
fn a_pair_no_group_could_hold_records_that_it_is_one() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].split_pair = true;
    let run_id = store.record_snapshot(&snapshot).unwrap();

    assert!(store.run_groups(run_id).unwrap()[0].split_pair);
}

#[test]
fn a_group_wholly_inside_the_suite_records_that_it_is() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].test_code = true;
    let run_id = store.record_snapshot(&snapshot).unwrap();

    assert!(store.run_groups(run_id).unwrap()[0].test_code);
    let occurrence = store
        .occurrence(&finding(101).to_hex())
        .unwrap()
        .expect("occurrence");
    assert!(occurrence.test_code);
}

#[test]
fn a_group_reaching_outside_the_suite_records_that_it_does() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    assert!(!store.run_groups(run_id).unwrap()[0].test_code);
}

/// A variant resolved from a compilation database entry.
fn compiled_variant(macros: &[&str]) -> BuildVariant {
    let mut command = vec!["clang++".to_string(), "-std=c++17".to_string()];
    command.extend(macros.iter().map(|setting| (*setting).to_string()));
    command.extend(
        [
            "-I/w/vendor",
            "-I/w/local",
            "-c",
            "-o",
            "wide.o",
            "/w/src/wide.cpp",
        ]
        .iter()
        .map(|argument| (*argument).to_string()),
    );
    BuildVariant::semantic(
        LanguageSelection::default(),
        Language::Cpp,
        vec![BuildConfiguration::Cpp(Box::new(CppBuild::from_command(
            &command,
            Path::new("/w/src/wide.cpp"),
        )))],
    )
}

fn values_of<'a>(variant: &'a StoredVariant, name: &str) -> Vec<&'a str> {
    variant
        .settings
        .iter()
        .filter(|setting| setting.name == name)
        .map(|setting| setting.value.as_str())
        .collect()
}

/// A stored variant that can only be compared with another is a stored variant
/// nobody can act on: two runs are shown to be incomparable and nothing says
/// what the difference was.
#[test]
fn what_a_compiler_was_told_is_recorded_beside_the_variant_it_identifies() {
    let variant = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .expect("the variant the run was recorded under");
    assert_eq!(stored.analysis_mode, "semantic");
    assert_eq!(stored.languages.as_deref(), Some("rust,c,cpp"));
    assert_eq!(stored.header_language.as_deref(), Some("cpp"));
    assert_eq!(stored.build_language.as_deref(), Some("cpp"));
    assert_eq!(values_of(&stored, "compiler"), vec!["clang++"]);
    assert_eq!(values_of(&stored, "macros"), vec!["-DACCUM_WIDTH=64"]);
    assert_eq!(values_of(&stored, "flags"), vec!["-std=c++17"]);
    // The search order is the meaning of an include path, so it comes back in
    // the order it was given rather than in any order the database found handy.
    assert_eq!(
        values_of(&stored, "includes"),
        vec!["/w/vendor", "/w/local"]
    );
    // Nobody ran the compiler to ask its version, and a setting nobody
    // resolved is absent rather than empty.
    assert!(values_of(&stored, "compiler_version").is_empty());
    assert!(values_of(&stored, "linker").is_empty());
}

/// A tree holding both languages is answered by a compiler for each, and both
/// have a `compiler_version`. Recorded under the setting name alone, one would
/// stand for the other — and a reader comparing two runs would be shown a
/// compiler that never touched half the tree.
#[test]
fn what_two_compilers_were_told_is_kept_apart_by_the_language_each_answered_for() {
    let variant = BuildVariant::semantic(
        LanguageSelection::default(),
        Language::Cpp,
        vec![
            BuildConfiguration::Cpp(Box::new(CppBuild {
                compiler: "clang++".into(),
                compiler_version: Some("Apple clang version 21.0.0".into()),
                ..CppBuild::default()
            })),
            BuildConfiguration::Rust(Box::new(RustBuild {
                compiler_version: "rust-analyzer 0.0.344".into(),
                ..RustBuild::default()
            })),
        ],
    );
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .expect("the variant the run was recorded under");
    assert_eq!(stored.build_language.as_deref(), Some("cpp,rust"));
    let version = |language: &str| {
        stored
            .settings
            .iter()
            .filter(|setting| setting.language == language && setting.name == "compiler_version")
            .map(|setting| setting.value.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(version("cpp"), vec!["Apple clang version 21.0.0"]);
    assert_eq!(version("rust"), vec!["rust-analyzer 0.0.344"]);
}

/// Two builds of one source tree are two variants, and what tells them apart
/// has to be readable, not just hashable.
#[test]
fn two_builds_of_one_tree_are_told_apart_by_what_they_were_told() {
    let narrow = compiled_variant(&[]);
    let wide = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&narrow, &detectors))
        .unwrap();
    store
        .record_snapshot(&sample_snapshot(&wide, &detectors))
        .unwrap();

    let stored_narrow = store.build_variant(&narrow.fingerprint()).unwrap().unwrap();
    let stored_wide = store.build_variant(&wide.fingerprint()).unwrap().unwrap();
    assert_ne!(stored_narrow.id, stored_wide.id);
    assert!(values_of(&stored_narrow, "macros").is_empty());
    assert_eq!(values_of(&stored_wide, "macros"), vec!["-DACCUM_WIDTH=64"]);
}

/// The same variant seen again is the same variant: its settings are rewritten
/// rather than added to, or a tree scanned twice would report every define
/// twice.
#[test]
fn recording_one_variant_twice_records_its_settings_once() {
    let variant = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    for _ in 0..2 {
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .unwrap();
    assert_eq!(values_of(&stored, "macros"), vec!["-DACCUM_WIDTH=64"]);
    assert_eq!(
        values_of(&stored, "includes"),
        vec!["/w/vendor", "/w/local"]
    );
}

/// A run of the same tree under rules that named every group differently.
#[cfg(any())]
fn renamed_snapshot<'a>(
    variant: &'a BuildVariant,
    detectors: &'a [(String, String)],
) -> Snapshot<'a> {
    let mut snapshot = sample_snapshot(variant, detectors);
    snapshot.started_at = "2026-07-25T00:00:00Z";
    snapshot.finished_at = "2026-07-25T00:00:05Z";
    snapshot.groups[0].fingerprint = group_fp(77);
    snapshot.groups[0].history = GroupOrigin::unconnected(&group_fp(77));
    for (index, member) in snapshot.groups[0].members.iter_mut().enumerate() {
        // Content ids moved with the rule change, exactly as group ids did;
        // placement is all the two runs still have in common.
        member.content = frag_fp(70 + u8::try_from(index).unwrap());
        member.finding = finding(170 + u8::try_from(index).unwrap());
    }
    snapshot
}

#[test]
#[cfg(any())]
fn a_history_carries_across_a_change_that_moved_every_identifier() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let history = group_lineage_id(&group_fp(9));
    // The comparison could connect nothing: the two runs share no identifier.
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(77)))
    );

    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: history.to_hex(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap();

    assert_eq!(adopted.taken, vec![group_fp(77).to_hex()]);
    assert!(adopted.already_connected.is_empty());
    assert!(adopted.unknown.is_empty());
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(history),
        "the newer run now belongs to the history the older one started"
    );
}

#[test]
#[cfg(any())]
fn a_group_the_comparison_already_connected_is_left_as_it_was() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let evidence = group_lineage_id(&group_fp(9));
    let mut snapshot = renamed_snapshot(&variant, &detectors);
    snapshot.groups[0].history = GroupOrigin {
        state: AuditState::Expanded,
        lineage: evidence,
        parents: vec![LineageParent {
            fingerprint: group_fp(9),
            lineage: evidence,
            primary: true,
            shared_content: 2,
            overlap: 1.0,
        }],
    };
    let after = store.record_snapshot(&snapshot).unwrap();

    // Matched on content, so the rule change did not touch it. A conversion
    // must not replace an answer the evidence supported with one from
    // placement.
    let invented = group_lineage_id(&group_fp(123));
    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: invented.to_hex(),
                shared: 1,
                overlap: 0.5,
            }],
        )
        .unwrap();

    assert!(adopted.taken.is_empty());
    assert_eq!(adopted.already_connected, vec![group_fp(77).to_hex()]);
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(evidence)
    );
}

#[test]
#[cfg(any())]
fn a_group_a_run_does_not_hold_is_named_rather_than_passed_over() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(200).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: group_lineage_id(&group_fp(9)).to_hex(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap();

    assert!(adopted.taken.is_empty());
    assert_eq!(adopted.unknown, vec![group_fp(200).to_hex()]);
}

#[test]
#[cfg(any())]
fn a_malformed_identifier_stops_the_rewrite_rather_than_half_applying_it() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let error = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: "not-a-lineage".to_string(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap_err();

    assert!(matches!(error, StoreError::MalformedId { .. }));
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(77))),
        "a rewrite that could not finish left nothing behind"
    );
}
