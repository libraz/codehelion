use super::*;

#[test]
fn a_snapshot_with_duplicate_group_fingerprints_is_rejected_before_writing() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups.push(snapshot.groups[0].clone());

    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(err, StoreError::DuplicateGroupFingerprint { .. }));
    assert!(store.latest_run().unwrap().is_none(), "no partial run");
}

#[test]
fn a_snapshot_with_duplicate_finding_ids_is_rejected_before_writing() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    let mut second = snapshot.groups[0].clone();
    second.fingerprint = group_fp(99);
    second.members[0].content = frag_fp(99);
    snapshot.groups.push(second);

    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(err, StoreError::DuplicateFindingId { .. }));
    assert!(store.latest_run().unwrap().is_none(), "no partial run");
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
fn suppression_rules_refresh_their_reason_and_current_active_state() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut first = sample_snapshot(&variant, &detectors);
    first.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("initial reason".to_string()),
    }];
    first.groups[0].suppressed_by = Some(0);
    let first_run = store.record_snapshot_part(&first).unwrap();

    // Two partitions are one invocation. The second has no such rule, so the
    // first partition's still-readable evidence must say that the rule is no
    // longer active rather than preserving its initial active state.
    let mut without_rule = sample_snapshot(&variant, &detectors);
    without_rule.root_path = "/other-repository";
    let second_run = store.record_snapshot_part(&without_rule).unwrap();
    store
        .complete_snapshot_parts(&[first_run, second_run])
        .unwrap();
    let inactive = store.run_groups(first_run).unwrap();
    let rule = inactive[0]
        .suppressed_by
        .as_ref()
        .expect("the finding retains its suppression provenance");
    assert_eq!(rule.reason.as_deref(), Some("initial reason"));
    assert_eq!(rule.active, Some(false));

    let mut revised = sample_snapshot(&variant, &detectors);
    revised.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("revised reason".to_string()),
    }];
    revised.groups[0].suppressed_by = Some(0);
    let revised_run = store.record_snapshot(&revised).unwrap();
    assert_eq!(store.table_count("suppression").unwrap(), 1);
    let active = store.run_groups(revised_run).unwrap();
    let rule = active[0]
        .suppressed_by
        .as_ref()
        .expect("the active finding names its rule");
    assert_eq!(rule.reason.as_deref(), Some("revised reason"));
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
