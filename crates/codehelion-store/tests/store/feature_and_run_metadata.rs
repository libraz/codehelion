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
        // Reopen: the current baseline remains readable and the data is still there.
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
fn incompatible_schema_rejection_leaves_the_database_and_wal_sidecars_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [(1_i64, "v1"), (999_i64, "unknown"), (0_i64, "markerless")];
    for (version, label) in cases {
        let path = dir.path().join(format!("{label}.db"));
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            if version != 0 {
                conn.execute_batch(
                    "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1),
                                                  version INTEGER NOT NULL) STRICT;
                     INSERT INTO schema_meta (id, version) VALUES (1, 1);
                     CREATE TABLE sentinel (value TEXT NOT NULL);
                     INSERT INTO sentinel (value) VALUES ('keep-me');",
                )
                .unwrap();
                conn.execute("UPDATE schema_meta SET version = ?1", [version])
                    .unwrap();
            } else {
                conn.execute_batch(
                    "CREATE TABLE sentinel (value TEXT NOT NULL);
                     INSERT INTO sentinel (value) VALUES ('keep-me');",
                )
                .unwrap();
            }
        }
        // The write-ahead log carries database content and must come through
        // a rejection exactly as it was. Shared memory is not content: it is
        // the index every reader rebuilds from the log it finds, so a reader
        // that rebuilds it has read the database rather than altered it.
        let sidecars = [(
            format!("{}-wal", path.display()),
            b"wal-sentinel".as_slice(),
        )];
        for (sidecar, bytes) in &sidecars {
            std::fs::write(sidecar, bytes).unwrap();
        }
        let before_main = std::fs::read(&path).unwrap();
        let before_sidecars = sidecars
            .iter()
            .map(|(path, _)| std::fs::read(path).unwrap())
            .collect::<Vec<_>>();

        let error = Store::open(&path).unwrap_err();
        assert!(matches!(
            error,
            StoreError::UnsupportedSchema { found } if found == version
        ));
        let text = error.to_string();
        assert!(text.contains("automatic migration is not supported"));
        assert!(text.contains("existing database was left unchanged"));
        assert!(text.contains("--db path"));
        assert!(text.contains("fresh scan"));
        assert_eq!(std::fs::read(&path).unwrap(), before_main);
        for ((sidecar, _), before) in sidecars.iter().zip(before_sidecars) {
            assert_eq!(std::fs::read(sidecar).unwrap(), before);
        }
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    sidecar.into()
}

fn file_state(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[test]
#[allow(
    clippy::disallowed_types,
    reason = "a child process is required to leave a genuine crash-stale SQLite WAL without running destructors"
)]
fn stale_wal_schema_rejection_preserves_the_real_database_and_sidecars() {
    if let Some(raw_path) = std::env::var_os("CODEHELION_STALE_WAL_CHILD") {
        // This process exits without running Rust destructors.  SQLite still
        // receives the OS close, leaving a genuine committed WAL and shared
        // memory file just as a process crash would.
        let path: std::path::PathBuf = raw_path.into();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0_i64)
            .unwrap();
        conn.execute("UPDATE schema_meta SET version = 1 WHERE id = 1", [])
            .unwrap();
        std::process::exit(86);
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stale-wal.db");

    // Establish a checkpointed main file on the current baseline first.  The
    // child process then commits a v1 marker into a genuine WAL and exits
    // without destructors, so the main file and logical database disagree as
    // they can after a crash.
    {
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            codehelion_store::schema::SCHEMA_VERSION
        );
    }
    let checkpoint = rusqlite::Connection::open(&path).unwrap();
    checkpoint
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(checkpoint);

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "feature_and_run_metadata::stale_wal_schema_rejection_preserves_the_real_database_and_sidecars",
            "--nocapture",
        ])
        .env("CODEHELION_STALE_WAL_CHILD", &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));

    let wal = sqlite_sidecar(&path, "-wal");
    let shm = sqlite_sidecar(&path, "-shm");
    let main_before = std::fs::read(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), main_before);
    assert!(
        wal.is_file(),
        "the schema downgrade must remain in a real WAL"
    );
    assert!(
        shm.is_file(),
        "the WAL writer must have a shared-memory file"
    );

    // The main file alone says the current baseline, whereas the same main file
    // with its real WAL says v1.  This is the boundary an immutable-main
    // preflight misses.
    let main_only_directory = tempfile::tempdir().unwrap();
    let main_only = main_only_directory.path().join("main-only.db");
    std::fs::copy(&path, &main_only).unwrap();
    let main_only_conn = rusqlite::Connection::open_with_flags(
        &main_only,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let main_only_version: i64 = main_only_conn
        .query_row("SELECT version FROM schema_meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(main_only_version, codehelion_store::schema::SCHEMA_VERSION);

    let private_directory = tempfile::tempdir().unwrap();
    let private = private_directory.path().join("with-wal.db");
    std::fs::copy(&path, &private).unwrap();
    std::fs::copy(&wal, sqlite_sidecar(&private, "-wal")).unwrap();
    let private_conn = rusqlite::Connection::open(&private).unwrap();
    let private_version: i64 = private_conn
        .query_row("SELECT version FROM schema_meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(private_version, 1);

    let before = [file_state(&path), file_state(&wal)];

    let error = Store::open(&path).unwrap_err();
    assert!(matches!(error, StoreError::UnsupportedSchema { found: 1 }));
    assert_eq!(
        [file_state(&path), file_state(&wal)],
        before,
        "rejection must not recover or delete the real WAL"
    );
    assert!(shm.is_file(), "the shared-memory index was removed");

    let error = Store::open_existing(&path).unwrap_err();
    assert!(matches!(error, StoreError::UnsupportedSchema { found: 1 }));
    assert_eq!(
        [file_state(&path), file_state(&wal)],
        before,
        "open_existing must validate the same way"
    );
    assert!(shm.is_file(), "the shared-memory index was removed");
}

#[test]
fn a_valid_wal_schema_is_opened_and_its_uncheckpointed_data_survives() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("valid-wal.db");
    {
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            codehelion_store::schema::SCHEMA_VERSION
        );
    }

    let writer = rusqlite::Connection::open(&path).unwrap();
    writer.pragma_update(None, "journal_mode", "WAL").unwrap();
    writer
        .pragma_update(None, "wal_autocheckpoint", 0_i64)
        .unwrap();
    writer
        .execute_batch(
            "CREATE TABLE wal_sentinel (value TEXT NOT NULL);
             INSERT INTO wal_sentinel (value) VALUES ('preserved');",
        )
        .unwrap();

    let store = Store::open(&path).unwrap();
    drop(store);
    let reader = rusqlite::Connection::open(&path).unwrap();
    let value: String = reader
        .query_row("SELECT value FROM wal_sentinel", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "preserved");
    drop(writer);
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
