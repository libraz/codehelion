use super::*;
use crate::artifact::ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION;
use crate::schema;

/// The build variant and completed scan run every artifact row references.
fn seed_source_run(store: &Store) {
    store
        .conn
        .execute(
            "INSERT INTO build_variant
                 (id, variant_fingerprint, canonical, analysis_mode, normalization_version)
             VALUES (1, 'aa', '{}', 'structural', 1)",
            [],
        )
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO scan_run
                 (id, build_variant_id, root_path, tool_version, config_hash, config_source,
                  analysis_mode, started_at, finished_at, status, min_clone_tokens)
             VALUES (1, 1, '/repo', 'test', 'hash', 'defaults', 'structural',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed', 20)",
            [],
        )
        .unwrap();
}

/// One saved artifact analysis with explicit recency timestamps.
fn insert_analysis(
    store: &Store,
    content: u8,
    build_variant: u8,
    started_at: &str,
    finished_at: &str,
) -> i64 {
    store
        .conn
        .execute(
            "INSERT INTO artifact_analysis
                 (schema_version, path, format, content_fingerprint, observed_bytes,
                  started_at, finished_at, status, ir_json, build_variant_fingerprint)
             VALUES ('artifact-ir-v1', 'fixture.wasm', 'wasm', ?1, 16, ?2, ?3, 'completed',
                     '{}', ?4)",
            params![
                [content; 16].as_slice(),
                started_at,
                finished_at,
                [build_variant; 16].as_slice(),
            ],
        )
        .unwrap();
    store.conn.last_insert_rowid()
}

/// One saved group estimate belonging to `analysis_id`.
fn insert_savings(store: &Store, analysis_id: i64, group: u8, build_variant: u8, estimated: i64) {
    store
        .conn
        .execute(
            "INSERT INTO artifact_analysis_clone_group_savings
                 (schema_version, artifact_analysis_id, source_scan_run_id,
                  clone_group_fingerprint, source_build_variant_fingerprint,
                  artifact_build_variant_fingerprint, duplicated_bytes,
                  estimated_refactor_savings_bytes, mapping_confidence, clone_confidence,
                  model_confidence, savings_confidence, model_schema_version, assumptions_json)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, 8, ?6, 'high', 1.0, 'low', 'low',
                     'refactor-savings-model-v1', '[]')",
            params![
                ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
                analysis_id,
                [group; 16].as_slice(),
                [9_u8; 16].as_slice(),
                [build_variant; 16].as_slice(),
                estimated,
            ],
        )
        .unwrap();
}

/// One controlled measurement of the estimate `analysis_id` holds.
fn calibration(analysis_id: i64, group: u8, verified: i64) -> ArtifactAnalysisSavingsCalibration {
    ArtifactAnalysisSavingsCalibration {
        schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
        artifact_analysis_id: analysis_id,
        source_scan_run_id: 1,
        clone_group_fingerprint: [group; 16],
        source_build_variant_fingerprint: [9; 16],
        before_artifact_build_variant_fingerprint: [5; 16],
        after_artifact_fingerprint: [13; 16],
        after_artifact_build_variant_fingerprint: [5; 16],
        estimated_refactor_savings_bytes: -2,
        verified_savings_bytes: verified,
        absolute_error_bytes: 5,
        relative_error: Some(1.5),
        recorded_at: "2026-07-30T00:01:00Z".to_owned(),
    }
}

fn hex(byte: u8) -> String {
    crate::fingerprint_hex([byte; 16])
}

#[test]
fn prune_retains_only_the_newest_artifacts_and_comparisons() {
    let mut store = Store::open_in_memory().unwrap();
    for ordinal in 1_u8..=3 {
        let timestamp = format!("2026-01-0{ordinal}T00:00:00Z");
        insert_analysis(&store, ordinal, 5, &timestamp, &timestamp);
        store
            .conn
            .execute(
                "INSERT INTO cross_variant_comparison
                     (comparison_id, policy_version, root_path, started_at, finished_at)
                 VALUES (?1, 'test', '/repo', ?2, ?2)",
                params![[ordinal; 16], timestamp],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO cross_language_comparison
                     (comparison_id, policy_version, root_path, started_at, finished_at)
                 VALUES (?1, 'test', '/repo', ?2, ?2)",
                params![[ordinal; 16], timestamp],
            )
            .unwrap();
    }

    let report = store.prune(1, 1).unwrap();

    assert_eq!(report.artifact_analyses, 2);
    assert_eq!(report.cross_variant_comparisons, 2);
    assert_eq!(report.cross_language_comparisons, 2);
    assert_eq!(store.table_count("artifact_analysis").unwrap(), 1);
    assert_eq!(store.table_count("cross_variant_comparison").unwrap(), 1);
    assert_eq!(store.table_count("cross_language_comparison").unwrap(), 1);
}

/// Pruning discards the partitions nobody finished and nothing else: a
/// completed scan is the history the tool exists to keep, so the retention
/// counts that bound the artifact and comparison tables do not reach it.
#[test]
fn prune_discards_incomplete_partitions_and_keeps_completed_scans() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .conn
        .execute(
            "INSERT INTO build_variant
                 (id, variant_fingerprint, canonical, analysis_mode, normalization_version)
             VALUES (1, 'aa', '{}', 'fast', 1)",
            [],
        )
        .unwrap();
    for (ordinal, status) in [(1_u8, "running"), (2, "completed"), (3, "completed")] {
        store
            .conn
            .execute(
                "INSERT INTO scan_run
                     (build_variant_id, root_path, tool_version, config_hash, config_source,
                      analysis_mode, started_at, finished_at, status, min_clone_tokens)
                 VALUES (1, '/repo', 'test', 'hash', 'defaults', 'fast', ?1, ?1, ?2, 20)",
                params![format!("2026-01-0{ordinal}T00:00:00Z"), status],
            )
            .unwrap();
    }

    let report = store.prune(1, 1).unwrap();

    assert_eq!(report.abandoned_runs, 1);
    // Both completed runs survive a prune asked to keep one of everything
    // it does bound, because no count or age rule applies to them.
    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    let statuses: Vec<String> = store
        .conn
        .prepare("SELECT status FROM scan_run ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(statuses, ["completed", "completed"]);
}

/// Retention and the default reference read one order. Two orders over two
/// timestamp columns agree only while the clock moves forward: after a step
/// backwards, an analysis started later can carry the older finish time, and
/// two orders would let a prune retire exactly the row a report resolves to.
#[test]
fn retention_and_the_default_reference_agree_on_the_newest_analysis() {
    let mut store = Store::open_in_memory().unwrap();
    let earlier_start =
        insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T09:00:00Z");
    let later_start = insert_analysis(
        &store,
        2,
        5,
        "2026-01-02T00:00:00Z",
        // The clock stepped back between the two analyses, so the newer one
        // finished at an earlier wall-clock time than the older one.
        "2026-01-01T01:00:00Z",
    );

    let latest = store.latest_artifact_analysis_id().unwrap();
    assert_eq!(latest, Some(later_start));

    let report = store.prune(1, 1).unwrap();

    assert_eq!(report.artifact_analyses, 1);
    assert_eq!(
        store.latest_artifact_analysis_id().unwrap(),
        Some(later_start)
    );
    let surviving: Vec<i64> = store
        .conn
        .prepare("SELECT id FROM artifact_analysis")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(surviving, vec![later_start]);
    assert!(!surviving.contains(&earlier_start));
}

/// A measurement recorded yesterday must not disappear because the analysis it
/// evaluates fell out of a recency window; the ledger is what makes an
/// estimate checkable at all.
#[test]
fn prune_keeps_the_analysis_a_recorded_measurement_evaluates() {
    let mut store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let measured = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    let middle = insert_analysis(&store, 2, 5, "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z");
    let newest = insert_analysis(&store, 3, 5, "2026-01-03T00:00:00Z", "2026-01-03T00:00:01Z");
    insert_savings(&store, measured, 12, 5, -2);
    store
        .record_artifact_savings_calibration(&calibration(measured, 12, 3))
        .unwrap();
    let samples_before = store
        .artifact_savings_calibrations_for_run(1)
        .unwrap()
        .len();

    let report = store.prune(1, 1).unwrap();

    // Only the analysis nothing measures is retired.
    assert_eq!(report.artifact_analyses, 1);
    assert_eq!(report.rows_removed_from("artifact_analysis"), 1);
    let surviving: Vec<i64> = store
        .conn
        .prepare("SELECT id FROM artifact_analysis ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(surviving, vec![measured, newest]);
    assert!(!surviving.contains(&middle));
    assert_eq!(
        store
            .artifact_savings_calibrations_for_run(1)
            .unwrap()
            .len(),
        samples_before,
        "a controlled measurement disappeared with a retention pass"
    );
}

/// Whatever a removed row does take with it through a foreign key is reported,
/// so nobody has to infer a deletion from a statistic that changed.
#[test]
fn prune_counts_every_row_a_removed_analysis_took_with_it() {
    let mut store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let retired = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    let kept = insert_analysis(&store, 2, 5, "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z");
    insert_savings(&store, retired, 12, 5, -2);
    insert_savings(&store, retired, 13, 5, -4);
    insert_savings(&store, kept, 12, 5, -2);

    let report = store.prune(1, 1).unwrap();

    assert_eq!(report.artifact_analyses, 1);
    assert_eq!(
        report.rows_removed_from("artifact_analysis_clone_group_savings"),
        2
    );
    assert!(
        report
            .cascaded
            .iter()
            .any(|entry| entry.table == "artifact_analysis_clone_group_savings" && entry.rows == 2),
        "the cascade was not reported: {:?}",
        report.cascaded
    );
    assert_eq!(report.total_rows_removed(), 3);
    assert_eq!(
        store
            .table_count("artifact_analysis_clone_group_savings")
            .unwrap(),
        1
    );
}

/// Taking a measurement again is the first thing anyone does when a number
/// looks wrong. Re-recording updates the row on file rather than failing the
/// command that carries it.
#[test]
fn re_recording_one_calibration_updates_the_row_it_already_has() {
    let mut store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let analysis = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    insert_savings(&store, analysis, 12, 5, -2);

    assert_eq!(
        store
            .record_artifact_savings_calibration(&calibration(analysis, 12, 3))
            .unwrap(),
        CalibrationRecord::Recorded
    );
    let mut second = calibration(analysis, 12, 7);
    second.recorded_at = "2026-07-31T00:00:00Z".to_owned();
    assert_eq!(
        store.record_artifact_savings_calibration(&second).unwrap(),
        CalibrationRecord::ReRecorded
    );

    assert_eq!(
        store
            .table_count("artifact_analysis_savings_calibration")
            .unwrap(),
        1
    );
    let stored = store.artifact_savings_calibrations(1, &hex(12)).unwrap();
    assert_eq!(stored, vec![second]);
}

/// A failure on this path names the measurement in this crate's own words. A
/// driver diagnostic would describe a constraint the caller never wrote.
#[test]
fn a_calibration_naming_an_absent_analysis_fails_in_the_stores_own_vocabulary() {
    let mut store = Store::open_in_memory().unwrap();
    seed_source_run(&store);

    let error = store
        .record_artifact_savings_calibration(&calibration(404, 12, 3))
        .unwrap_err();

    assert!(
        matches!(error, StoreError::MissingArtifactAnalysis { analysis_id } if analysis_id == 404),
        "not a typed store error: {error:?}"
    );
    assert!(!error.to_string().contains("constraint failed"));
}

/// Analysing one artifact twice describes one measurement twice. The store
/// takes the newest matching analysis and names it, instead of leaving the
/// calibration path unusable with no way to disambiguate it.
#[test]
fn two_analyses_of_one_artifact_resolve_to_the_newest_estimate() {
    let store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let first = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    let second = insert_analysis(&store, 1, 5, "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z");
    insert_savings(&store, first, 12, 5, -2);
    insert_savings(&store, second, 12, 5, -4);
    // A third analysis of a different artifact must not be considered.
    let other = insert_analysis(&store, 7, 5, "2026-01-03T00:00:00Z", "2026-01-03T00:00:01Z");
    insert_savings(&store, other, 12, 5, -9);

    let selected = store
        .select_clone_group_estimate(1, &hex(12), [1; 16], [5; 16])
        .unwrap()
        .expect("an estimate for this artifact and build variant");

    assert_eq!(selected.artifact_analysis_id, second);
    assert_eq!(selected.matching_analyses, 2);
    assert_eq!(selected.estimate.estimated_refactor_savings_bytes, -4);
    assert_eq!(selected.estimate.clone_group_fingerprint, [12; 16]);
}

/// A build variant the artifact was not built under is not this measurement,
/// however many estimates the run holds.
#[test]
fn estimate_selection_stays_inside_one_artifact_and_build_variant() {
    let store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let analysis = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    insert_savings(&store, analysis, 12, 5, -2);

    assert!(
        store
            .select_clone_group_estimate(1, &hex(12), [1; 16], [6; 16])
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .select_clone_group_estimate(1, &hex(12), [2; 16], [5; 16])
            .unwrap()
            .is_none()
    );
}

/// One group's estimates are read by the group's own scope. Reading the whole
/// analysis and narrowing afterwards made every report pay for every other
/// group it was going to render anyway.
#[test]
fn savings_for_one_group_read_only_that_groups_rows() {
    let store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let analysis = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    for group in 20_u8..60 {
        insert_savings(&store, analysis, group, 5, i64::from(group));
    }

    let scoped = store.clone_group_savings(1, &hex(30)).unwrap();

    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].0, analysis);
    assert_eq!(scoped[0].1.estimated_refactor_savings_bytes, 30);

    let plan: Vec<String> = store
        .conn
        .prepare(
            "EXPLAIN QUERY PLAN
                 SELECT artifact_analysis_id
                 FROM artifact_analysis_clone_group_savings
                 WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2",
        )
        .unwrap()
        .query_map(params![1_i64, [30_u8; 16].as_slice()], |row| row.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_artifact_analysis_savings_source_run")),
        "the group lookup does not use its index: {plan:?}"
    );
}

/// The whole-run read and the per-group read answer with the same values, so a
/// report that reads once renders exactly what reading per group rendered.
#[test]
fn reading_a_run_at_once_yields_what_reading_each_group_yielded() {
    let store = Store::open_in_memory().unwrap();
    seed_source_run(&store);
    let first = insert_analysis(&store, 1, 5, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z");
    let second = insert_analysis(&store, 2, 6, "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z");
    for group in 20_u8..30 {
        insert_savings(&store, first, group, 5, i64::from(group));
        insert_savings(&store, second, group, 6, -i64::from(group));
    }

    let whole_run = store.clone_group_savings_for_run(1).unwrap();

    assert_eq!(whole_run.len(), 10);
    for group in 20_u8..30 {
        assert_eq!(
            whole_run.get(&hex(group)),
            Some(&store.clone_group_savings(1, &hex(group)).unwrap()),
            "group {group} disagrees between the two reads"
        );
    }
}

/// One content identity nothing references, plus the unit that gives a run
/// something to lose.
fn seed_orphan_and_referenced_fingerprints(store: &Store, run_id: i64) {
    store
        .conn
        .execute_batch(&format!(
            "INSERT INTO fingerprint
                 (id, kind, hash_algo, hash, normalization_version, frontend_version,
                  analysis_mode, language, build_variant_id)
             VALUES (1, 'unit', 'blake3', randomblob(16), 1, 'f1', 'structural', 'rust', 1),
                    (2, 'unit', 'blake3', randomblob(16), 1, 'f1', 'structural', 'rust', 1);
             INSERT INTO source_unit
                 (scan_run_id, fingerprint_id, language, unit_kind, name, file_path,
                  start_line, end_line, token_count)
             VALUES ({run_id}, 1, 'rust', 'function', 'kept', 'src/lib.rs', 1, 4, 20);"
        ))
        .unwrap();
}

/// Only a delete can leave a content identity without a referent. A sweep on a
/// path that only inserts and updates reads every fingerprint in the database
/// to find nothing, and the writer is opened several times per scan.
#[test]
fn the_orphan_sweep_runs_only_after_a_delete_removed_rows() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .conn
        .execute(
            "INSERT INTO build_variant
                 (id, variant_fingerprint, canonical, analysis_mode, normalization_version)
             VALUES (1, 'aa', '{}', 'structural', 1)",
            [],
        )
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO scan_run
                 (id, build_variant_id, root_path, tool_version, config_hash, config_source,
                  analysis_mode, started_at, finished_at, status, min_clone_tokens)
             VALUES (1, 1, '/repo', 'test', 'hash', 'defaults', 'structural',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'running', 20)",
            [],
        )
        .unwrap();
    seed_orphan_and_referenced_fingerprints(&store, 1);

    // Replacing the active policy only inserts and updates suppression rows.
    store
        .activate_suppressions(&[crate::snapshot::SuppressionRuleRow {
            scope: "path_glob".to_owned(),
            pattern: "vendor/**".to_owned(),
            reason: None,
        }])
        .unwrap();

    assert_eq!(
        store.table_count("fingerprint").unwrap(),
        2,
        "an insert-only path swept identities it could not have orphaned"
    );

    // Discarding a partition does remove rows, so the sweep runs and both the
    // identity that lost its unit and the one that never had one are removed.
    store.discard_run(1).unwrap();

    assert_eq!(store.table_count("fingerprint").unwrap(), 0);
}

/// The gate is the delete's own row count, so a caller cannot sweep by
/// accident after removing nothing.
#[test]
fn a_sweep_asked_for_after_no_deletion_removes_nothing() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .conn
        .execute(
            "INSERT INTO build_variant
                 (id, variant_fingerprint, canonical, analysis_mode, normalization_version)
             VALUES (1, 'aa', '{}', 'structural', 1)",
            [],
        )
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO fingerprint
                 (kind, hash_algo, hash, normalization_version, frontend_version,
                  analysis_mode, language, build_variant_id)
             VALUES ('unit', 'blake3', randomblob(16), 1, 'f1', 'structural', 'rust', 1)",
            [],
        )
        .unwrap();

    let tx = store.conn.transaction().unwrap();
    assert_eq!(remove_orphaned_fingerprints(&tx, 0).unwrap(), 0);
    assert_eq!(remove_orphaned_fingerprints(&tx, 1).unwrap(), 1);
    tx.commit().unwrap();

    assert_eq!(store.table_count("fingerprint").unwrap(), 0);
}

/// The columns a `finding` row can hold are the columns its writer binds. A
/// database written before the unwritten byte columns were dropped keeps them
/// and still opens, because nothing binds or selects them.
#[test]
fn a_database_carrying_the_older_finding_columns_still_opens_and_reads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    {
        let store = Store::open(&path).unwrap();
        store
            .conn
            .execute_batch(
                "ALTER TABLE finding ADD COLUMN observed_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN duplicated_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN retained_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN shared_dependency_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN duplicated_data_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN upper_bound_savings_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN estimated_refactor_savings_bytes INTEGER;
                 ALTER TABLE finding ADD COLUMN verified_savings_bytes INTEGER;",
            )
            .unwrap();
    }

    let store = Store::open(&path).unwrap();

    assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION);
    assert_eq!(store.table_count("finding").unwrap(), 0);
}

/// The current baseline declares no `finding` column its writer cannot fill.
#[test]
fn the_finding_baseline_declares_only_columns_its_writer_binds() {
    let store = Store::open_in_memory().unwrap();
    let columns: BTreeSet<String> = store
        .conn
        .prepare("SELECT name FROM pragma_table_info('finding')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    assert_eq!(
        columns,
        BTreeSet::from([
            "id".to_owned(),
            "scan_run_id".to_owned(),
            "clone_group_id".to_owned(),
            "suppression_id".to_owned(),
            "clone_confidence".to_owned(),
            "semantic_confidence".to_owned(),
            "source_artifact_mapping_confidence".to_owned(),
            "savings_confidence".to_owned(),
            "maintenance_risk".to_owned(),
            "refactoring_difficulty".to_owned(),
            "final_priority".to_owned(),
        ])
    );
}
