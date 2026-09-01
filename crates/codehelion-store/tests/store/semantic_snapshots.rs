use super::*;

#[test]
fn semantic_evidence_persists_one_graph_per_member_and_rolls_back_on_mismatch() {
    let variant = BuildVariant::semantic(LanguageSelection::default(), Language::C, Vec::new());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].clone_type = CloneClass::RestrictedSemantic;
    // The last two fingerprints sort opposite to their member positions.
    // A read path that reorders by fingerprint would return their graphs as
    // `collect`, then `map`, rather than the order recorded below.
    snapshot.groups[0].members[1] = member_with_finding(3, 2, "src/b.rs", Some(1));
    snapshot.groups[0]
        .members
        .push(member_with_finding(2, 3, "src/c.rs", None));
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
                graph_json: semantic_graph_json("map"),
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
    assert_eq!(store.table_count("semantic_operation_graph").unwrap(), 3);
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
        Some(("sequence-pipeline-v1", 3, 1))
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
    assert_eq!(
        stored[0]
            .semantic
            .as_ref()
            .expect("semantic evidence")
            .graphs
            .iter()
            .map(|graph| graph.nodes[0].kind.name())
            .collect::<Vec<_>>(),
        vec!["filter", "map", "collect"],
        "semantic graphs must retain the recorded member order"
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
                member_id: CrossLanguageMemberId::from_bytes([73; 16]),
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
                member_id: CrossLanguageMemberId::from_bytes([74; 16]),
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
fn cross_variant_members_use_stable_ids_instead_of_source_anchors_as_the_key() {
    let mut store = Store::open_in_memory().unwrap();
    let origins = vec!["a".to_string(), "b".to_string()];
    let members = vec![
        CrossVariantMemberRow {
            member_id: CrossVariantMemberId::from_bytes([81; 16]),
            origin_variant: "a".to_string(),
            language: Language::Cpp,
            file_path: "generated.cpp".to_string(),
            start_line: 1,
            end_line: 1,
            unit_name: Some("generated".to_string()),
            token_count: 4,
        },
        CrossVariantMemberRow {
            member_id: CrossVariantMemberId::from_bytes([82; 16]),
            origin_variant: "a".to_string(),
            language: Language::Cpp,
            file_path: "generated.cpp".to_string(),
            start_line: 1,
            end_line: 1,
            unit_name: Some("generated".to_string()),
            token_count: 4,
        },
        CrossVariantMemberRow {
            member_id: CrossVariantMemberId::from_bytes([83; 16]),
            origin_variant: "b".to_string(),
            language: Language::Cpp,
            file_path: "generated.cpp".to_string(),
            start_line: 1,
            end_line: 1,
            unit_name: Some("generated".to_string()),
            token_count: 4,
        },
    ];
    let groups = vec![CrossVariantGroupRow {
        group_id: CrossVariantGroupId::from_bytes([80; 16]),
        clone_type: CloneClass::Type1,
        members,
    }];
    let snapshot = CrossVariantComparisonSnapshot {
        root_path: "/repo",
        comparison_id: CrossVariantComparisonId::from_bytes([79; 16]),
        policy_version: "test",
        started_at: "2026-08-03T00:00:00Z",
        finished_at: "2026-08-03T00:00:01Z",
        origins: &origins,
        groups: &groups,
    };

    store.record_cross_variant_comparison(&snapshot).unwrap();
    assert_eq!(store.table_count("cross_variant_clone_member").unwrap(), 3);
}

#[test]
fn a_new_snapshot_retains_the_previous_scan_as_history() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let first_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut second = sample_snapshot(&variant, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    let second_id = store.record_snapshot(&second).unwrap();

    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    // Identical content under an identical context: one fingerprint row per
    // identity (1 unit + 1 member content + 1 group), not per scan.
    assert_eq!(store.table_count("fingerprint").unwrap(), 3);
    assert_eq!(store.table_count("build_variant").unwrap(), 1);

    // The later run is current, while the predecessor stays readable for
    // fingerprint changes that need continuity evidence.
    assert!(
        second_id > first_id,
        "a later snapshot must receive a new history row"
    );
    assert_eq!(store.latest_run().unwrap().unwrap().id, second_id);
}

#[test]
fn snapshots_for_distinct_roots_and_prior_runs_coexist() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut first_package = sample_snapshot(&variant, &detectors);
    first_package.root_path = "/repo/packages/first";
    first_package.started_at = "2026-07-24T00:00:00Z";
    let first_id = store.record_snapshot(&first_package).unwrap();

    let mut second_package = sample_snapshot(&variant, &detectors);
    second_package.root_path = "/repo/packages/second";
    second_package.started_at = "2026-07-25T00:00:00Z";
    let second_id = store.record_snapshot(&second_package).unwrap();
    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    assert_eq!(
        store
            .latest_completed_run("/repo/packages/first")
            .unwrap()
            .map(|run| run.id),
        Some(first_id)
    );
    assert_eq!(
        store
            .latest_completed_run("/repo/packages/second")
            .unwrap()
            .map(|run| run.id),
        Some(second_id)
    );

    let mut replacement = sample_snapshot(&variant, &detectors);
    replacement.root_path = "/repo/packages/first";
    replacement.started_at = "2026-07-26T00:00:00Z";
    let replacement_id = store.record_snapshot(&replacement).unwrap();
    assert_eq!(store.table_count("scan_run").unwrap(), 3);
    assert_eq!(
        store
            .latest_completed_run("/repo/packages/first")
            .unwrap()
            .map(|run| run.id),
        Some(replacement_id)
    );
    assert_eq!(
        store
            .latest_completed_run("/repo/packages/second")
            .unwrap()
            .map(|run| run.id),
        Some(second_id)
    );
}

#[test]
fn an_artifact_referenced_source_scan_survives_a_later_source_scan() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let source_run = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let analysis_id = store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: "artifact-ir-v1",
            path: "fixture.wasm",
            format: "wasm",
            content_fingerprint: [7; 16],
            observed_bytes: 0,
            ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
            build_variant_manifest_path: None,
            build_variant_fingerprint: None,
            started_at: "2026-07-24T00:00:06Z",
            finished_at: "2026-07-24T00:00:07Z",
            symbols: &[],
            mappings: &[],
            unmapped_symbols: &[],
            unmapped_sources: &[],
            correlation: Some(ArtifactAnalysisCorrelation {
                schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
                source_scan_run_id: source_run,
                mapping_count: 0,
                artifact_symbol_count: 0,
                mapped_symbol_count: 0,
                artifact_symbol_bytes: 0,
                mapped_symbol_bytes: 0,
            }),
            clone_group_savings: &[],
        })
        .unwrap();

    let mut later = sample_snapshot(&variant, &detectors);
    later.started_at = "2026-07-25T00:00:00Z";
    later.finished_at = "2026-07-25T00:00:04Z";
    let later_run = store.record_snapshot(&later).unwrap();

    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    assert_eq!(store.latest_run().unwrap().unwrap().id, later_run);
    assert_eq!(store.run_origin(source_run).unwrap().root_path, "/repo");
    assert_eq!(
        store
            .artifact_correlation(analysis_id)
            .unwrap()
            .expect("the recorded source-artifact correlation")
            .source_scan_run_id,
        source_run
    );
}

#[test]
fn an_incomplete_partition_keeps_the_prior_snapshot_readable() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let prior_run = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let mut partition = sample_snapshot(&variant, &detectors);
    partition.started_at = "2026-07-25T00:00:00Z";
    partition.finished_at = "2026-07-25T00:00:04Z";
    partition.groups[0].fingerprint = group_fp(77);
    let group_fingerprint = partition.groups[0].fingerprint.to_hex();
    let incomplete_run = store.record_snapshot_part(&partition).unwrap();

    assert!(matches!(
        store.ensure_completed_run(incomplete_run),
        Err(StoreError::RunNotCompleted { run_id }) if run_id == incomplete_run
    ));
    assert!(matches!(
        store.ensure_completed_run(999),
        Err(StoreError::RunNotFound { run_id }) if run_id == 999
    ));
    assert_eq!(
        store
            .latest_completed_run("/repo")
            .unwrap()
            .expect("the prior completed snapshot")
            .id,
        prior_run
    );
    assert_eq!(
        store
            .occurrence(&finding(101).to_hex())
            .unwrap()
            .expect("a completed occurrence")
            .scan_run_id,
        prior_run
    );
    assert!(store.group(&group_fingerprint).unwrap().is_none());
    assert!(
        store
            .ids_starting_with(&group_fingerprint[..12])
            .unwrap()
            .is_empty()
    );

    store.complete_snapshot_parts(&[incomplete_run]).unwrap();
    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    assert_eq!(
        store
            .latest_completed_run("/repo")
            .unwrap()
            .expect("the completed partition")
            .id,
        incomplete_run
    );
    assert_eq!(
        store
            .occurrence(&finding(101).to_hex())
            .unwrap()
            .expect("the completed partition occurrence")
            .scan_run_id,
        incomplete_run
    );
}

/// A partition whose staging invocation is gone is what the grace period is
/// about: nothing will ever finalize it, and the content identities it minted
/// belong to nobody.
#[test]
fn writer_open_reaps_expired_partitions_left_by_another_invocation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    let inherited = directory.path().join("inherited.db");
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();

    {
        let mut store = Store::open(&database).unwrap();
        let mut partition = sample_snapshot(&variant, &detectors);
        partition.started_at = "2020-01-01T00:00:00Z";
        partition.finished_at = "2020-01-01T00:00:04Z";
        let run_id = store.record_snapshot_part(&partition).unwrap();

        assert_eq!(store.abandoned_runs().unwrap()[0].id, run_id);
        assert!(store.table_count("fingerprint").unwrap() > 0);
    }
    // A copy is a database no live invocation staged anything into, which is
    // what an interrupted earlier scan leaves behind.
    std::fs::copy(&database, &inherited).unwrap();

    let store = Store::open(&inherited).unwrap();
    assert!(store.abandoned_runs().unwrap().is_empty());
    assert_eq!(store.table_count("scan_run").unwrap(), 0);
    assert_eq!(store.table_count("fingerprint").unwrap(), 0);
}

/// An invocation that outlives the grace period between staging its first
/// partition and finalizing its last must not meet its own work as abandoned.
/// The writer is opened once per step, so the reaper runs several times inside
/// one scan, and a reaped partition would fail finalization and discard every
/// other partition with it.
#[test]
fn a_long_invocation_still_finalizes_the_partition_it_staged() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();

    let staged = {
        let mut store = Store::open(&database).unwrap();
        let mut partition = sample_snapshot(&variant, &detectors);
        // This partition finished long before the grace period expired; the
        // invocation that staged it is still running.
        partition.started_at = "2020-01-01T00:00:00Z";
        partition.finished_at = "2020-01-01T00:00:04Z";
        store.record_snapshot_part_staged(&partition).unwrap()
    };

    let mut store = Store::open(&database).unwrap();
    assert_eq!(store.abandoned_runs().unwrap()[0].id, staged.run_id());
    store
        .finalize_snapshot_parts(
            std::slice::from_ref(&staged),
            codehelion_store::snapshot::SnapshotComparisons::default(),
        )
        .unwrap();

    assert!(store.abandoned_runs().unwrap().is_empty());
    assert_eq!(store.table_count("scan_run").unwrap(), 1);
    assert_eq!(
        store
            .latest_completed_run("/repo")
            .unwrap()
            .expect("the finalized partition")
            .id,
        staged.run_id()
    );
}

#[test]
fn discard_run_refuses_completed_history() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let completed = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    assert!(matches!(
        store.discard_run(completed),
        Err(StoreError::RunNotRunning { run_id }) if run_id == completed
    ));
}

#[test]
fn the_latest_completed_invocation_returns_every_partition() {
    let fast = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let structural = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut first = sample_snapshot(&fast, &detectors);
    first.started_at = "2026-07-25T00:00:00Z";
    first.finished_at = "2026-07-25T00:00:04Z";
    let first_id = store.record_snapshot_part(&first).unwrap();

    let mut second = sample_snapshot(&structural, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    let second_id = store.record_snapshot_part(&second).unwrap();
    store
        .complete_snapshot_parts(&[first_id, second_id])
        .unwrap();

    let invocation = store.latest_completed_invocation("/repo").unwrap();
    assert_eq!(invocation.len(), 2);
    assert_eq!(
        invocation
            .iter()
            .map(|origin| origin.id)
            .collect::<Vec<_>>(),
        vec![first_id, second_id]
    );
    assert!(
        invocation
            .iter()
            .all(|origin| origin.started_at == "2026-07-25T00:00:00Z")
    );
    let fingerprints: std::collections::BTreeSet<_> = invocation
        .iter()
        .map(|origin| origin.variant_fingerprint.clone())
        .collect();
    assert_eq!(
        fingerprints,
        std::collections::BTreeSet::from([fast.fingerprint(), structural.fingerprint()])
    );
}
