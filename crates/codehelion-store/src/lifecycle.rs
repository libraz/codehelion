//! Database lifecycle: one recency order, one retention contract, and the
//! recording paths that stay safe when the same measurement is taken twice.
//!
//! Which rows a maintenance operation keeps, which row a default reference
//! picks, and what re-recording an existing measurement does are one subject.
//! They live here together so no other layer repeats a column name or an
//! ordering: a caller asks this module for the newest analysis or for a
//! retention pass and never spells out how "newest" is decided.
//!
//! One private ordering constant in this module is that decision. It is what
//! [`Store::select_clone_group_estimate`] resolves several saved estimates of
//! one artifact with, so the estimate a measurement evaluates is always one
//! retention keeps.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::artifact::{
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisSavingsCalibration,
};
use crate::{Store, StoreError};

/// The one recency order for saved artifact analyses: the newest recorded
/// start first, with the row id as the only tiebreak.
///
/// Retention and the default report reference both read this, so the rows a
/// prune keeps as "the newest N" always contain the row a report calls "the
/// latest". Two orders over two timestamp columns agree only while the clock
/// moves forward, and a clock that steps backwards would otherwise let a prune
/// retire exactly the row the default reference resolves to.
pub(crate) const ARTIFACT_ANALYSIS_RECENCY: &str = "started_at DESC, id DESC";

/// Incomplete partitions younger than this may belong to a scan still
/// assembling comparisons, so only older ones are reaped on a writer open.
///
/// Age alone does not decide: a partition this process staged is owned by a
/// live invocation and is never reaped, however long the invocation runs.
const ABANDONED_RUN_GRACE_SECONDS: i64 = 24 * 60 * 60;

/// Tables whose rows an explicit retention pass removes directly.
///
/// Everything else that loses rows loses them to a foreign key, and is
/// reported as such.
const RETENTION_TABLES: [&str; 5] = [
    "scan_run",
    "artifact_analysis",
    "cross_variant_comparison",
    "cross_language_comparison",
    "fingerprint",
];

/// Identity of one open database, used to scope process-local state to the
/// database that state describes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DatabaseKey {
    /// A database file, by its resolved path.
    File(PathBuf),
    /// One private in-memory database, by the order this process opened it.
    Memory(u64),
}

impl DatabaseKey {
    /// Key one database file. The resolved path is preferred so two spellings
    /// of one file are one database; an unresolvable path keeps its spelling.
    pub(crate) fn for_path(path: &Path) -> Self {
        Self::File(std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
    }

    /// Key one private in-memory database. Two in-memory databases share no
    /// rows, so they must not share the state keyed by this value either.
    pub(crate) fn in_memory() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self::Memory(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Incomplete partitions this process staged, per database.
///
/// A multi-partition scan opens the writer once per step rather than once per
/// invocation, and each partition's finish time is the wall clock when that
/// partition ended. An invocation that runs longer than the grace period would
/// therefore meet its own first partition as an expired `running` row on a
/// later open. The rows a live invocation owns are recorded here for as long
/// as it owns them, and the reaper skips them regardless of elapsed time.
static LIVE_RUNS: LazyLock<Mutex<BTreeMap<DatabaseKey, BTreeSet<i64>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Take ownership of one staged partition on behalf of this invocation.
pub(crate) fn register_live_run(database: &DatabaseKey, run_id: i64) {
    let mut live = LIVE_RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    live.entry(database.clone()).or_default().insert(run_id);
}

/// Release partitions this invocation no longer owns, because they completed,
/// were aborted, or were discarded.
pub(crate) fn forget_live_runs(database: &DatabaseKey, run_ids: impl IntoIterator<Item = i64>) {
    let mut live = LIVE_RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(owned) = live.get_mut(database) {
        for run_id in run_ids {
            owned.remove(&run_id);
        }
        if owned.is_empty() {
            live.remove(database);
        }
    }
}

/// The partitions a live invocation currently owns in `database`.
fn live_runs(database: &DatabaseKey) -> BTreeSet<i64> {
    let live = LIVE_RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    live.get(database).cloned().unwrap_or_default()
}

/// Fingerprints are shared content identities rather than run-owned rows, so
/// their foreign keys cannot cascade. Retiring runs explicitly removes the
/// identities no remaining unit, fragment, or group references.
///
/// Only a delete can create an orphan. Callers pass the number of rows their
/// own delete removed, so an insert- or update-only path never pays for a scan
/// of every fingerprint in the database.
pub(crate) fn remove_orphaned_fingerprints(
    tx: &Transaction<'_>,
    removed_rows: usize,
) -> Result<usize, StoreError> {
    if removed_rows == 0 {
        return Ok(0);
    }
    Ok(tx.execute(
        "DELETE FROM fingerprint
         WHERE NOT EXISTS (SELECT 1 FROM source_unit u WHERE u.fingerprint_id = fingerprint.id)
           AND NOT EXISTS (SELECT 1 FROM fragment f WHERE f.fingerprint_id = fingerprint.id)
           AND NOT EXISTS (
               SELECT 1 FROM clone_group g WHERE g.group_fingerprint_id = fingerprint.id
           )",
        [],
    )?)
}

/// Refuse a run that is absent or has not completed its scan invocation.
///
/// One rule for every caller: reading a run's results and connecting a run to a
/// predecessor both require a finished invocation, and a partition still being
/// assembled is not one. A [`Transaction`] dereferences to its connection, so
/// the callers writing inside a transaction ask the same question of the rows
/// their own transaction can see.
pub(crate) fn ensure_completed_run(conn: &Connection, run_id: i64) -> Result<(), StoreError> {
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM scan_run WHERE id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .optional()?;
    match status.as_deref() {
        Some("completed") => Ok(()),
        Some(_) => Err(StoreError::RunNotCompleted { run_id }),
        None => Err(StoreError::RunNotFound { run_id }),
    }
}

/// Rows one table lost to the removal of a row it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadedRows {
    /// Table from the current schema.
    pub table: String,
    /// Rows removed from it.
    pub rows: usize,
}

/// Rows removed by one explicit cache-prune operation.
///
/// The named counts are the tables retention bounds directly. [`Self::cascaded`]
/// accounts for every other table that lost rows because a row it references
/// was removed, so the reported deletion is the whole deletion rather than the
/// part the policy asked for by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Incomplete scan partitions removed.
    pub abandoned_runs: usize,
    /// Standalone artifact analyses removed.
    pub artifact_analyses: usize,
    /// Cross-build-variant comparisons removed.
    pub cross_variant_comparisons: usize,
    /// Cross-language comparisons removed.
    pub cross_language_comparisons: usize,
    /// Content identities no remaining scan row references.
    pub orphaned_fingerprints: usize,
    /// Every other table that lost rows, in table-name order.
    pub cascaded: Vec<CascadedRows>,
}

impl PruneReport {
    /// Rows this operation removed from `table`, whether retention named the
    /// table or a referenced row took its rows away.
    #[must_use]
    pub fn rows_removed_from(&self, table: &str) -> usize {
        match table {
            "scan_run" => self.abandoned_runs,
            "artifact_analysis" => self.artifact_analyses,
            "cross_variant_comparison" => self.cross_variant_comparisons,
            "cross_language_comparison" => self.cross_language_comparisons,
            "fingerprint" => self.orphaned_fingerprints,
            other => self
                .cascaded
                .iter()
                .find(|entry| entry.table == other)
                .map_or(0, |entry| entry.rows),
        }
    }

    /// Every row this operation removed, from every table.
    #[must_use]
    pub fn total_rows_removed(&self) -> usize {
        RETENTION_TABLES
            .into_iter()
            .map(|table| self.rows_removed_from(table))
            .chain(self.cascaded.iter().map(|entry| entry.rows))
            .fold(0, usize::saturating_add)
    }
}

/// Outcome of recording one controlled before/after measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationRecord {
    /// The measurement was not on file and became a new row.
    Recorded,
    /// A measurement with this identity was already on file, and the stored
    /// row now carries this one.
    ReRecorded,
}

/// One saved group estimate, and the analysis the store took it from.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedCloneGroupEstimate {
    /// Analysis whose stored estimate was selected.
    pub artifact_analysis_id: i64,
    /// How many analyses held an estimate of the same identity.
    pub matching_analyses: usize,
    /// The selected estimate.
    pub estimate: ArtifactAnalysisCloneGroupSavings,
}

impl Store {
    /// The newest saved artifact analysis, if one exists.
    ///
    /// "Newest" is the order retention uses, so this row is always inside the
    /// set a prune keeps.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_artifact_analysis_id(&self) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                &format!(
                    "SELECT id FROM artifact_analysis ORDER BY {ARTIFACT_ANALYSIS_RECENCY} LIMIT 1"
                ),
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Record one controlled before/after measurement for a saved estimate.
    ///
    /// Recording is idempotent: a measurement is identified by the analysis,
    /// source group, and the two artifacts and build variants it compared, so
    /// re-measuring the same pair updates that row instead of failing. Taking
    /// the measurement again is the first thing anyone does when a number
    /// looks wrong, and it is what makes the number reproducible.
    ///
    /// # Errors
    ///
    /// Rejects an unknown schema, an invalid numeric measurement, or an
    /// analysis this database does not hold, in this crate's own vocabulary
    /// and without writing a partial calibration row.
    pub fn record_artifact_savings_calibration(
        &mut self,
        calibration: &ArtifactAnalysisSavingsCalibration,
    ) -> Result<CalibrationRecord, StoreError> {
        if calibration.schema_version != ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown artifact savings calibration schema".to_owned(),
            });
        }
        if calibration
            .relative_error
            .is_some_and(|value| !value.is_finite() || value.is_sign_negative())
        {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "calibration relative error must be finite and nonnegative".to_owned(),
            });
        }
        let tx = self.conn.transaction()?;
        let identity = params![
            calibration.artifact_analysis_id,
            calibration.source_scan_run_id,
            calibration.clone_group_fingerprint.as_slice(),
            calibration.source_build_variant_fingerprint,
            calibration.before_artifact_build_variant_fingerprint,
            calibration.after_artifact_fingerprint.as_slice(),
            calibration.after_artifact_build_variant_fingerprint,
        ];
        let analysis_exists: Option<i64> = tx
            .query_row(
                "SELECT id FROM artifact_analysis WHERE id = ?1",
                params![calibration.artifact_analysis_id],
                |row| row.get(0),
            )
            .optional()?;
        if analysis_exists.is_none() {
            return Err(StoreError::MissingArtifactAnalysis {
                analysis_id: calibration.artifact_analysis_id,
            });
        }
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM artifact_analysis_savings_calibration
                 WHERE artifact_analysis_id = ?1 AND source_scan_run_id = ?2
                   AND clone_group_fingerprint = ?3
                   AND source_build_variant_fingerprint = ?4
                   AND before_artifact_build_variant_fingerprint = ?5
                   AND after_artifact_fingerprint = ?6
                   AND after_artifact_build_variant_fingerprint = ?7",
                identity,
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "INSERT INTO artifact_analysis_savings_calibration
                 (schema_version, artifact_analysis_id, source_scan_run_id,
                  clone_group_fingerprint, source_build_variant_fingerprint,
                  before_artifact_build_variant_fingerprint, after_artifact_fingerprint,
                  after_artifact_build_variant_fingerprint, estimated_refactor_savings_bytes,
                  verified_savings_bytes, absolute_error_bytes, relative_error, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT (artifact_analysis_id, source_scan_run_id, clone_group_fingerprint,
                          source_build_variant_fingerprint,
                          before_artifact_build_variant_fingerprint, after_artifact_fingerprint,
                          after_artifact_build_variant_fingerprint)
             DO UPDATE SET
                 schema_version = excluded.schema_version,
                 estimated_refactor_savings_bytes = excluded.estimated_refactor_savings_bytes,
                 verified_savings_bytes = excluded.verified_savings_bytes,
                 absolute_error_bytes = excluded.absolute_error_bytes,
                 relative_error = excluded.relative_error,
                 recorded_at = excluded.recorded_at",
            params![
                calibration.schema_version,
                calibration.artifact_analysis_id,
                calibration.source_scan_run_id,
                calibration.clone_group_fingerprint.as_slice(),
                calibration.source_build_variant_fingerprint,
                calibration.before_artifact_build_variant_fingerprint,
                calibration.after_artifact_fingerprint.as_slice(),
                calibration.after_artifact_build_variant_fingerprint,
                calibration.estimated_refactor_savings_bytes,
                calibration.verified_savings_bytes,
                i64::try_from(calibration.absolute_error_bytes).unwrap_or(i64::MAX),
                calibration.relative_error,
                calibration.recorded_at,
            ],
        )?;
        tx.commit()?;
        Ok(if existing.is_some() {
            CalibrationRecord::ReRecorded
        } else {
            CalibrationRecord::Recorded
        })
    }

    /// Reap incomplete partitions whose last write is outside the grace period
    /// and that no live invocation owns. Called by the writing open path.
    pub(crate) fn discard_expired_abandoned_runs(&mut self) -> Result<(), StoreError> {
        let owned = live_runs(&self.database);
        let tx = self.conn.transaction()?;
        let mut sql = String::from(
            "DELETE FROM scan_run
             WHERE status = 'running'
               AND unixepoch(finished_at) IS NOT NULL
               AND unixepoch(finished_at) <= unixepoch('now') - ?1",
        );
        let mut bindings: Vec<i64> = vec![ABANDONED_RUN_GRACE_SECONDS];
        if !owned.is_empty() {
            sql.push_str(" AND id NOT IN (");
            for run_id in &owned {
                if bindings.len() > 1 {
                    sql.push(',');
                }
                bindings.push(*run_id);
                sql.push('?');
                sql.push_str(&bindings.len().to_string());
            }
            sql.push(')');
        }
        let discarded = tx.execute(&sql, rusqlite::params_from_iter(bindings))?;
        remove_orphaned_fingerprints(&tx, discarded)?;
        tx.commit()?;
        Ok(())
    }

    /// Apply explicit retention limits and compact the local database.
    ///
    /// The limits reach three tables: the newest artifact analyses and the
    /// newest of each comparison kind are retained under the one recency
    /// order, and everything older is removed. Incomplete scan partitions are
    /// removed outright, because a user pruning under the exclusive database
    /// lease is the one writer there could be, so any partition still marked
    /// running was abandoned.
    ///
    /// An analysis a controlled measurement evaluates is retained beyond the
    /// count: the calibration ledger is history, and losing a measurement
    /// taken yesterday because its analysis fell out of a recency window would
    /// silently change every later corpus statistic. Whatever a removed row
    /// does take with it through a foreign key is counted in the returned
    /// [`PruneReport`], table by table.
    ///
    /// Every other table is history and is kept indefinitely. Completed scan
    /// runs and the rows they own — scanned files, units, fragments, clone
    /// groups and their findings — are never pruned, by count or by age, so a
    /// tree scanned repeatedly accumulates one generation per scan. Nothing
    /// here bounds the database's size; `cache clear` is what discards
    /// recorded history. Fingerprints are the exception among the untouched
    /// tables: they are shared content identities rather than run-owned rows,
    /// so the ones no remaining row references are removed with the rows that
    /// referenced them.
    ///
    /// # Errors
    ///
    /// Returns an underlying database error. The row deletion is atomic;
    /// compaction runs only after it commits.
    pub fn prune(
        &mut self,
        keep_artifact_analyses: usize,
        keep_comparisons: usize,
    ) -> Result<PruneReport, StoreError> {
        let keep_artifacts = i64::try_from(keep_artifact_analyses).unwrap_or(i64::MAX);
        let keep_comparisons = i64::try_from(keep_comparisons).unwrap_or(i64::MAX);
        let tx = self.conn.transaction()?;
        let observed = tables_a_prune_can_reach(&tx, keep_artifacts, keep_comparisons)?;
        let before = row_counts(&tx, &observed)?;
        let abandoned_runs = tx.execute("DELETE FROM scan_run WHERE status = 'running'", [])?;
        let artifact_analyses = tx.execute(
            &format!(
                "DELETE FROM artifact_analysis
                 WHERE id NOT IN (
                     SELECT id FROM artifact_analysis
                     ORDER BY {ARTIFACT_ANALYSIS_RECENCY} LIMIT ?1
                 )
                   AND id NOT IN (
                     SELECT artifact_analysis_id FROM artifact_analysis_savings_calibration
                 )"
            ),
            [keep_artifacts],
        )?;
        let cross_variant_comparisons = tx.execute(
            "DELETE FROM cross_variant_comparison
             WHERE id NOT IN (
                 SELECT id FROM cross_variant_comparison
                 ORDER BY started_at DESC, id DESC LIMIT ?1
             )",
            [keep_comparisons],
        )?;
        let cross_language_comparisons = tx.execute(
            "DELETE FROM cross_language_comparison
             WHERE id NOT IN (
                 SELECT id FROM cross_language_comparison
                 ORDER BY started_at DESC, id DESC LIMIT ?1
             )",
            [keep_comparisons],
        )?;
        let removed = abandoned_runs
            .saturating_add(artifact_analyses)
            .saturating_add(cross_variant_comparisons)
            .saturating_add(cross_language_comparisons);
        remove_orphaned_fingerprints(&tx, removed)?;
        let after = row_counts(&tx, &observed)?;
        tx.commit()?;
        self.conn
            .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
        let mut report = PruneReport {
            abandoned_runs,
            artifact_analyses,
            cross_variant_comparisons,
            cross_language_comparisons,
            ..PruneReport::default()
        };
        for (table, count) in before {
            let removed = usize::try_from(count.saturating_sub(*after.get(&table).unwrap_or(&0)))
                .unwrap_or(usize::MAX);
            if removed == 0 {
                continue;
            }
            if table == "fingerprint" {
                report.orphaned_fingerprints = removed;
            } else if !RETENTION_TABLES.contains(&table.as_str()) {
                report.cascaded.push(CascadedRows {
                    table,
                    rows: removed,
                });
            }
        }
        Ok(report)
    }
}

/// Every table one retention pass can remove rows from: the tables it deletes
/// from directly, plus everything a foreign key can take with a removed row.
///
/// The graph is read from the database rather than listed here, so a schema
/// that grows a table cannot grow an unaccounted deletion with it. Tables
/// whose parent has nothing to remove are left out, so the common no-op prune
/// does not count the whole scan history.
fn tables_a_prune_can_reach(
    tx: &Transaction<'_>,
    keep_artifacts: i64,
    keep_comparisons: i64,
) -> Result<BTreeSet<String>, StoreError> {
    let mut reached = BTreeSet::from(["fingerprint".to_owned()]);
    let has_running: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM scan_run WHERE status = 'running')",
        [],
        |row| row.get(0),
    )?;
    if has_running {
        reached.insert("scan_run".to_owned());
    }
    for (table, keep) in [
        ("artifact_analysis", keep_artifacts),
        ("cross_variant_comparison", keep_comparisons),
        ("cross_language_comparison", keep_comparisons),
    ] {
        let count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?;
        if count > keep {
            reached.insert(table.to_owned());
        }
    }
    let mut references: Vec<(String, BTreeSet<String>)> = Vec::new();
    let tables: Vec<String> = tx
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name ASC",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for table in tables {
        let parents: BTreeSet<String> = tx
            .prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")?
            .query_map(params![table], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        if !parents.is_empty() {
            references.push((table, parents));
        }
    }
    let mut grew = true;
    while grew {
        grew = false;
        for (table, parents) in &references {
            if !reached.contains(table) && parents.iter().any(|parent| reached.contains(parent)) {
                reached.insert(table.clone());
                grew = true;
            }
        }
    }
    Ok(reached)
}

/// Current row count of each named table.
fn row_counts(
    tx: &Transaction<'_>,
    tables: &BTreeSet<String>,
) -> Result<BTreeMap<String, i64>, StoreError> {
    let mut counts = BTreeMap::new();
    for table in tables {
        let count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?;
        counts.insert(table.clone(), count);
    }
    Ok(counts)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
