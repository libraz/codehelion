//! Regression coverage for snapshot transaction boundaries.
//!
//! These cases deliberately use the public store API and a real `SQLite`
//! connection.  The database triggers stand in for failures at the exact
//! boundary where a normal run would otherwise be able to leave half of a
//! snapshot visible.

use super::*;

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_store::snapshot::{CrossVariantComparisonSnapshot, SnapshotComparisons};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

fn fast_variant() -> BuildVariant {
    BuildVariant::fast(LanguageSelection::default(), Language::Rust)
}

fn count(store: &Store, table: &str) -> i64 {
    store.table_count(table).expect("known store table")
}

fn rule(pattern: &str, reason: &str) -> SuppressionRuleRow {
    SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: pattern.to_string(),
        reason: Some(reason.to_string()),
    }
}

const fn empty_cross_variant() -> CrossVariantComparisonSnapshot<'static> {
    CrossVariantComparisonSnapshot {
        root_path: "/repo",
        comparison_id: CrossVariantComparisonId::from_bytes([0x71; 16]),
        policy_version: "test-cross-variant-v1",
        started_at: "2026-08-12T00:00:00Z",
        finished_at: "2026-08-12T00:00:01Z",
        origins: &[],
        groups: &[],
    }
}

fn suppression_state(path: &Path, pattern: &str) -> Option<(bool, Option<String>)> {
    let connection = Connection::open(path).expect("open SQLite database");
    connection
        .query_row(
            "SELECT active, reason FROM suppression WHERE pattern = ?1",
            params![pattern],
            |row| Ok((row.get::<_, bool>(0)?, row.get(1)?)),
        )
        .optional()
        .expect("query suppression state")
}

#[test]
fn predecessor_recheck_rolls_back_insert_and_preserves_the_prior_completed_run() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let mut store = Store::open(&database).expect("create database");
    let detectors = detector_versions();
    let predecessor = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .expect("record predecessor");

    // The trigger changes the predecessor after the candidate run INSERT but
    // before lineage is applied.  The second completed-state check must reject
    // the transaction and SQLite must roll both writes back.
    Connection::open(&database)
        .expect("open trigger connection")
        .execute_batch(
            "CREATE TRIGGER reopen_predecessor AFTER INSERT ON scan_run
             BEGIN UPDATE scan_run SET status = 'running' WHERE id = 1; END;",
        )
        .expect("install predecessor trigger");
    let error = store
        .record_snapshot_with_predecessor(&sample_snapshot(&variant, &detectors), Some(predecessor))
        .expect_err("reopened predecessor must fail atomic recording");
    assert!(matches!(error, StoreError::RunNotCompleted { run_id } if run_id == predecessor));
    assert_eq!(count(&store, "scan_run"), 1);
    assert_eq!(
        store
            .latest_completed_run("/repo")
            .expect("query completed predecessor")
            .expect("prior run remains completed")
            .id,
        predecessor
    );
    assert_eq!(count(&store, "clone_group"), 1);
}

#[test]
fn finalizer_rolls_back_comparison_and_all_partitions_when_completion_fails() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let prior = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .expect("record prior completed snapshot");
    let first = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage first partition");
    let mut second_snapshot = sample_snapshot(&variant, &detectors);
    second_snapshot.root_path = "/repo/second-partition";
    let second = store
        .record_snapshot_part_staged(&second_snapshot)
        .expect("stage second partition");
    Connection::open(&database)
        .expect("open trigger connection")
        .execute_batch(
            "CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON scan_run
             WHEN OLD.status = 'running' AND NEW.status = 'completed'
             BEGIN SELECT RAISE(ABORT, 'completion failure'); END;",
        )
        .expect("install completion trigger");
    let comparison = empty_cross_variant();
    let error = store
        .finalize_snapshot_parts(
            &[first, second],
            SnapshotComparisons {
                cross_variant: Some(&comparison),
                cross_language: None,
            },
        )
        .expect_err("completion trigger must abort finalization");
    assert!(matches!(error, StoreError::Sqlite { .. }));
    assert_eq!(count(&store, "scan_run"), 1);
    assert_eq!(
        store
            .latest_completed_run("/repo")
            .expect("query prior run")
            .expect("prior run remains")
            .id,
        prior
    );
    assert_eq!(count(&store, "cross_variant_comparison"), 0);
    assert_eq!(store.abandoned_runs().expect("query running runs").len(), 0);
}

#[test]
fn staged_lineage_failure_does_not_adopt_or_leave_a_completed_partition() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let prior = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .expect("record predecessor");
    let mut candidate = sample_snapshot(&variant, &detectors);
    let candidate_fingerprint = CloneGroupFingerprint::from_bytes([0x77; 16]);
    candidate.groups[0].fingerprint = candidate_fingerprint;
    candidate.groups[0].history = GroupOrigin::unconnected(&candidate_fingerprint);
    let staged = store
        .record_snapshot_part_staged(&candidate)
        .expect("stage candidate")
        .with_predecessor(Some(prior));
    Connection::open(&database)
        .expect("open trigger connection")
        .execute_batch(
            "CREATE TRIGGER reject_lineage BEFORE INSERT ON clone_group_lineage_parent
             BEGIN SELECT RAISE(ABORT, 'lineage failure'); END;",
        )
        .expect("install lineage trigger");
    let error = store
        .finalize_snapshot_parts(&[staged], SnapshotComparisons::default())
        .expect_err("lineage failure must abort finalization");
    assert!(matches!(error, StoreError::Sqlite { .. }));
    assert_eq!(count(&store, "scan_run"), 1);
    assert_eq!(count(&store, "clone_group_lineage_parent"), 0);
    assert_eq!(store.abandoned_runs().expect("query running runs").len(), 0);
}

#[test]
fn staged_suppression_set_is_exact_even_when_a_rule_hides_no_group() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![rule("src/matched-but-visible/**", "visible rule")];
    // No group points at suppression index 0: the configured rule matched the
    // source tree but did not hide the finding.  It still belongs to the
    // invocation's exact active suppression set.
    let staged = store
        .record_snapshot_part_staged(&snapshot)
        .expect("stage suppression policy");
    assert_eq!(
        suppression_state(&database, "src/matched-but-visible/**"),
        Some((false, Some("visible rule".to_string())))
    );
    store
        .finalize_snapshot_parts(&[staged], SnapshotComparisons::default())
        .expect("activate exact suppression set");
    assert_eq!(
        suppression_state(&database, "src/matched-but-visible/**"),
        Some((true, Some("visible rule".to_string())))
    );
}

#[test]
fn failed_staging_keeps_prior_rule_reason_and_removes_only_new_rows() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let mut prior_snapshot = sample_snapshot(&variant, &detectors);
    prior_snapshot.suppressions = vec![rule("src/**", "prior reason")];
    store
        .record_snapshot(&prior_snapshot)
        .expect("record prior policy");
    let mut staged_snapshot = sample_snapshot(&variant, &detectors);
    staged_snapshot.suppressions =
        vec![rule("src/**", "revised reason"), rule("new/**", "new rule")];
    let staged = store
        .record_snapshot_part_staged(&staged_snapshot)
        .expect("stage revised policy");
    assert_eq!(
        suppression_state(&database, "src/**"),
        Some((true, Some("prior reason".to_string())))
    );
    assert_eq!(
        suppression_state(&database, "new/**"),
        Some((false, Some("new rule".to_string())))
    );
    Connection::open(&database)
        .expect("open trigger connection")
        .execute_batch(
            "CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON scan_run
             WHEN OLD.status = 'running' AND NEW.status = 'completed'
             BEGIN SELECT RAISE(ABORT, 'suppression completion failure'); END;",
        )
        .expect("install completion trigger");
    assert!(
        store
            .finalize_snapshot_parts(&[staged], SnapshotComparisons::default())
            .is_err()
    );
    assert_eq!(
        suppression_state(&database, "src/**"),
        Some((true, Some("prior reason".to_string())))
    );
    assert_eq!(suppression_state(&database, "new/**"), None);
    assert_eq!(count(&store, "scan_run"), 1);
}

#[test]
fn successful_staging_revises_an_existing_rule_reason() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let mut prior = sample_snapshot(&variant, &detectors);
    prior.suppressions = vec![rule("src/**", "prior reason")];
    store.record_snapshot(&prior).expect("record prior policy");
    let mut revised = sample_snapshot(&variant, &detectors);
    revised.suppressions = vec![rule("src/**", "revised reason")];
    let staged = store
        .record_snapshot_part_staged(&revised)
        .expect("stage revised policy");
    store
        .finalize_snapshot_parts(&[staged], SnapshotComparisons::default())
        .expect("finalize revised policy");
    assert_eq!(
        suppression_state(&database, "src/**"),
        Some((true, Some("revised reason".to_string())))
    );
}

#[test]
fn finalizer_rejects_empty_duplicate_and_staged_predecessor_requests() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    assert!(matches!(
        store.finalize_snapshot_parts(&[], SnapshotComparisons::default()),
        Err(StoreError::InvalidSnapshotParts { .. })
    ));

    let first = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage first");
    let second = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage second");
    let error = store
        .finalize_snapshot_parts(
            &[
                first.clone(),
                first.clone(),
                second.with_predecessor(Some(first.run_id())),
            ],
            SnapshotComparisons::default(),
        )
        .expect_err("invalid handles must be rejected");
    assert!(matches!(error, StoreError::InvalidSnapshotParts { .. }));
    assert_eq!(count(&store, "scan_run"), 0);

    // A distinct request exercises the staged-as-predecessor guard without
    // being masked by the duplicate-run-id check above.
    let first = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage first predecessor candidate");
    let second = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage second predecessor candidate");
    let error = store
        .finalize_snapshot_parts(
            &[first.with_predecessor(Some(second.run_id())), second],
            SnapshotComparisons::default(),
        )
        .expect_err("a staged partition cannot be a predecessor");
    assert!(matches!(error, StoreError::InvalidSnapshotParts { .. }));
    assert_eq!(count(&store, "scan_run"), 0);

    let comparison = empty_cross_variant();
    let error = store
        .finalize_snapshot_parts(
            &[],
            SnapshotComparisons {
                cross_variant: Some(&comparison),
                cross_language: None,
            },
        )
        .expect_err("comparisons require staged partitions");
    assert!(matches!(error, StoreError::InvalidSnapshotParts { .. }));
    assert_eq!(count(&store, "cross_variant_comparison"), 0);
}

#[test]
fn abort_accepts_missing_and_running_handles_and_is_idempotent() {
    let dir = tempfile::tempdir().expect("temporary database directory");
    let database = dir.path().join("audit.db");
    let variant = fast_variant();
    let detectors = detector_versions();
    let mut store = Store::open(&database).expect("create database");
    let one = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage first");
    let two = store
        .record_snapshot_part_staged(&sample_snapshot(&variant, &detectors))
        .expect("stage second");
    store
        .abort_snapshot_parts(std::slice::from_ref(&one))
        .expect("abort first");
    store
        .abort_snapshot_parts(&[one.clone(), two.clone()])
        .expect("abort missing first and running second");
    store
        .abort_snapshot_parts(std::slice::from_ref(&two))
        .expect("abort already missing second");
    assert_eq!(count(&store, "scan_run"), 0);
}
