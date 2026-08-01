use super::*;

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
    assert_eq!(rule.reason.as_deref(), Some("vendored sources"));
    assert_eq!(rule.active, Some(true));
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
    assert_eq!(origin.config_source, "root");
    assert_eq!(origin.config_path.as_deref(), Some("/repo/codehelion.toml"));
    assert_eq!(origin.min_clone_tokens, 20);
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
    snapshot.groups[0].test_code_evidence =
        Some(codehelion_core::test_code::TestCodeEvidence::Marker);
    let run_id = store.record_snapshot(&snapshot).unwrap();

    assert!(store.run_groups(run_id).unwrap()[0].test_code);
    assert_eq!(
        store.run_groups(run_id).unwrap()[0].test_code_evidence,
        Some(codehelion_core::test_code::TestCodeEvidence::Marker)
    );
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
