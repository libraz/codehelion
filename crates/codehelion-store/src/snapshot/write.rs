use super::groups::{write_group, write_near_misses, write_sibling_groups};
use super::variant::{upsert_fingerprint, upsert_variant};
use super::{
    AbandonedRun, BTreeMap, BTreeSet, FileRow, OptionalExtension, Snapshot, Store, StoreError,
    SummaryRow, SuppressionRuleRow, Transaction, params,
};

/// Incomplete partitions younger than this may belong to a scan still
/// assembling comparisons. Older ones are safe to reap on the next writer
/// open, while the command-level database lease prevents concurrent writers.
const ABANDONED_RUN_GRACE_SECONDS: i64 = 24 * 60 * 60;

impl Store {
    /// List incomplete multi-partition snapshots in oldest-first order.
    ///
    /// # Errors
    ///
    /// Returns an underlying database error.
    pub fn abandoned_runs(&self) -> Result<Vec<AbandonedRun>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, root_path, started_at, finished_at
             FROM scan_run WHERE status = 'running'
             ORDER BY finished_at ASC, id ASC",
        )?;
        let runs = statement
            .query_map([], |row| {
                Ok(AbandonedRun {
                    id: row.get(0)?,
                    root_path: row.get(1)?,
                    started_at: row.get(2)?,
                    finished_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(runs)
    }

    /// Delete one incomplete partition and its run-owned rows.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RunNotFound`] when the row is absent,
    /// [`StoreError::RunNotRunning`] when it completed, or an underlying
    /// database error. Completed history is never discarded by this method.
    pub fn discard_run(&mut self, run_id: i64) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        let status = tx
            .query_row(
                "SELECT status FROM scan_run WHERE id = ?1",
                params![run_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match status.as_deref() {
            Some("running") => {}
            Some(_) => return Err(StoreError::RunNotRunning { run_id }),
            None => return Err(StoreError::RunNotFound { run_id }),
        }
        tx.execute("DELETE FROM scan_run WHERE id = ?1", params![run_id])?;
        crate::remove_orphaned_fingerprints(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Reap incomplete partitions whose last write is outside the grace
    /// period. Called only by the creating/writing open path.
    pub(crate) fn discard_expired_abandoned_runs(&mut self) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM scan_run
             WHERE status = 'running'
               AND unixepoch(finished_at) IS NOT NULL
               AND unixepoch(finished_at) <= unixepoch('now') - ?1",
            params![ABANDONED_RUN_GRACE_SECONDS],
        )?;
        crate::remove_orphaned_fingerprints(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Record one completed single-partition snapshot and return its row id.
    ///
    /// # Errors
    ///
    /// Any failure — malformed input (such as a member referencing a
    /// non-existent unit) or an underlying database error — rolls the whole
    /// replacement back; the prior completed snapshot remains intact. Older
    /// unreferenced snapshots are removed only after this one is complete.
    pub fn record_snapshot(&mut self, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
        validate_group_fingerprints(snapshot)?;
        let tx = self.conn.transaction()?;
        let run_id = write_snapshot(&tx, snapshot, SnapshotStatus::Completed)?;
        remove_superseded_snapshots(&tx, &[run_id])?;
        tx.commit()?;
        Ok(run_id)
    }

    /// Record one still-running partition of a multi-partition scan.
    ///
    /// Completed snapshots remain readable while the invocation is running.
    /// [`Self::complete_snapshot_parts`] must be called with every returned
    /// row id only after all partitions and requested comparisons succeeded.
    ///
    /// # Errors
    ///
    /// Returns any validation or database error while preserving transaction
    /// atomicity for the partition being written.
    pub fn record_snapshot_part(&mut self, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
        validate_group_fingerprints(snapshot)?;
        let tx = self.conn.transaction()?;
        let run_id = write_snapshot(&tx, snapshot, SnapshotStatus::Running)?;
        tx.commit()?;
        Ok(run_id)
    }

    /// Complete every partition of one successful multi-partition scan.
    ///
    /// State transition and retirement of superseded snapshots happen in one
    /// transaction, so a failure leaves every new row non-readable and every
    /// prior completed snapshot intact.
    ///
    /// # Errors
    ///
    /// Returns an error if any supplied row is no longer a running partition
    /// or if `SQLite` cannot perform the atomic transition.
    pub fn complete_snapshot_parts(&mut self, run_ids: &[i64]) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for run_id in run_ids {
            if tx.execute(
                "UPDATE scan_run SET status = 'completed' WHERE id = ?1 AND status = 'running'",
                params![run_id],
            )? != 1
            {
                return Err(StoreError::RunNotRunning { run_id: *run_id });
            }
        }
        remove_superseded_snapshots(&tx, run_ids)?;
        tx.commit()?;
        Ok(())
    }
}

/// Reject a silent stable-ID collision before a snapshot starts writing.
fn validate_group_fingerprints(snapshot: &Snapshot<'_>) -> Result<(), StoreError> {
    let mut emitted = BTreeSet::new();
    let mut findings = BTreeSet::new();
    for group in &snapshot.groups {
        let fingerprint = *group.fingerprint.as_bytes();
        if !emitted.insert(fingerprint) {
            return Err(StoreError::DuplicateGroupFingerprint {
                fingerprint: group.fingerprint.to_hex(),
            });
        }
        for member in &group.members {
            if !findings.insert(*member.finding.as_bytes()) {
                return Err(StoreError::DuplicateFindingId {
                    finding: member.finding.to_hex(),
                });
            }
        }
    }
    for siblings in &snapshot.sibling_groups {
        for sibling in &siblings.siblings {
            if !findings.insert(*sibling.finding.as_bytes()) {
                return Err(StoreError::DuplicateFindingId {
                    finding: sibling.finding.to_hex(),
                });
            }
        }
    }
    Ok(())
}

/// Retain completed snapshots needed as lineage predecessors.
///
/// A later scan can only explain a changed clone-group fingerprint by reading
/// the prior group's members and lineage. Completed snapshots are therefore
/// history, not replaceable cache entries. The cache maintenance surface owns
/// any explicit retention policy; recording a scan never discards evidence.
fn remove_superseded_snapshots(
    tx: &Transaction<'_>,
    _current_run_ids: &[i64],
) -> Result<(), StoreError> {
    crate::remove_orphaned_fingerprints(tx)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SnapshotStatus {
    Running,
    Completed,
}

impl SnapshotStatus {
    const fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
        }
    }
}

fn write_snapshot(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    status: SnapshotStatus,
) -> Result<i64, StoreError> {
    let variant_id = upsert_variant(tx, snapshot.variant)?;

    tx.execute(
        "INSERT INTO scan_run
             (build_variant_id, root_path, tool_version, config_hash, config_source, config_path,
              analysis_mode, started_at, finished_at, min_clone_tokens, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            variant_id,
            snapshot.root_path,
            snapshot.tool_version,
            snapshot.config_hash,
            snapshot.config_source,
            snapshot.config_path,
            snapshot.variant.mode.name(),
            snapshot.started_at,
            snapshot.finished_at,
            i64::from(snapshot.min_clone_tokens),
            status.name(),
        ],
    )?;
    let run_id = tx.last_insert_rowid();

    for (component, version) in snapshot.detector_versions {
        record_detector_version(tx, run_id, component, version)?;
    }

    let suppression_row_ids = write_suppressions(tx, &snapshot.suppressions)?;
    // Units first: members and features reference them by index.
    let unit_row_ids = write_units(tx, snapshot, run_id, variant_id)?;
    let mut group_row_ids = BTreeMap::new();
    for group in &snapshot.groups {
        let group_row_id = write_group(
            tx,
            snapshot,
            run_id,
            variant_id,
            group,
            &unit_row_ids,
            &suppression_row_ids,
        )?;
        group_row_ids.insert(*group.fingerprint.as_bytes(), group_row_id);
    }
    write_sibling_groups(
        tx,
        &snapshot.sibling_groups,
        &unit_row_ids,
        &group_row_ids,
        &suppression_row_ids,
    )?;
    write_near_misses(
        tx,
        run_id,
        &snapshot.near_misses,
        &unit_row_ids,
        &suppression_row_ids,
    )?;
    write_files(tx, &snapshot.files, run_id)?;
    // The compiler IR names its own schema, and every distinct one a run holds
    // becomes a declared detector version of that run: the per-unit column
    // says what each answer was written against, and nothing at run level
    // would otherwise say that this run holds compiler IR at all.
    for schema in crate::compiler::write(tx, snapshot, run_id, variant_id)? {
        record_detector_version(tx, run_id, crate::compiler::IR_SCHEMA_COMPONENT, &schema)?;
    }
    write_summary(tx, &snapshot.summary, run_id)?;
    Ok(run_id)
}

/// Declare `component` at `version` for `run_id`, reusing the existing row
/// when the pair has been recorded before.
fn record_detector_version(
    tx: &Transaction<'_>,
    run_id: i64,
    component: &str,
    version: &str,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT OR IGNORE INTO detector_version (component, version) VALUES (?1, ?2)",
        params![component, version],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO scan_run_detector_version (scan_run_id, detector_version_id)
         SELECT ?1, id FROM detector_version WHERE component = ?2 AND version = ?3",
        params![run_id, component, version],
    )?;
    Ok(())
}

/// Record what the run reported about itself: the source it read, the funnel
/// it narrowed through, and the rules that hid nothing.
#[allow(
    clippy::too_many_lines,
    reason = "the summary write keeps every persisted field and its SQL binding adjacent"
)]
fn write_summary(
    tx: &Transaction<'_>,
    summary: &SummaryRow,
    run_id: i64,
) -> Result<(), StoreError> {
    let count = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO run_summary
             (scan_run_id, analyzed_total, analyzed_rust, analyzed_c, analyzed_cpp,
              lines, tokens, lexer_diagnostics, unparsed_files, unparsed_tokens,
              excluded_generated, excluded_by_glob, excluded_too_large,
              excluded_binary, excluded_unreadable, excluded_symlinks,
              excluded_walk_errors,
              excluded_timed_out, excluded_skipped, guardrail_profile,
              guardrail_max_file_bytes, guardrail_parse_timeout_ms,
              guardrail_helper_timeout_ms, guardrail_posting_cap,
              guardrail_pair_budget, guardrail_sibling_candidate_budget,
              guardrail_sibling_per_group_cap, guardrail_sibling_total_cap,
              guardrail_max_component, folded_runs,
              subsumed_runs, split_components, pair_budget_exhausted, baseline_digest,
              excluded_language, excluded_symlink_files, excluded_symlink_directories,
              guardrail_near_miss_delta, guardrail_near_miss_cap,
              guardrail_verification_budget, guardrail_max_alignment_cells)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                 ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
                 ?39, ?40, ?41)",
        params![
            run_id,
            count(summary.analyzed_files.total),
            count(summary.analyzed_files.rust),
            count(summary.analyzed_files.c),
            count(summary.analyzed_files.cpp),
            count(summary.lines),
            count(summary.tokens),
            count(summary.lexer_diagnostics),
            summary.unparsed.map(|row| count(row.files)),
            summary.unparsed.map(|row| count(row.tokens)),
            count(summary.excluded_generated),
            count(summary.excluded_by_glob),
            count(summary.excluded_too_large),
            count(summary.excluded_binary),
            count(summary.excluded_unreadable),
            count(summary.excluded_symlinks),
            count(summary.excluded_walk_errors),
            count(summary.excluded_timed_out),
            count(summary.excluded_skipped),
            summary.guardrails.as_ref().map(|row| &row.profile),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.max_file_bytes)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.parse_timeout_ms)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.helper_timeout_ms)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.posting_cap)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.pair_budget)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.sibling_candidate_budget)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.sibling_per_group_cap)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.sibling_total_cap)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.max_component)),
            count(summary.folded_runs),
            count(summary.subsumed_runs),
            count(summary.split_components),
            summary.pair_budget_exhausted,
            summary.baseline_digest,
            count(summary.excluded_language),
            count(summary.excluded_symlink_files),
            count(summary.excluded_symlink_directories),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.near_miss_delta_bits)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.near_miss_cap)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.verification_budget)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.max_alignment_cells)),
        ],
    )?;
    let mut insert_stage = tx.prepare_cached(
        "INSERT INTO run_funnel_stage (scan_run_id, position, name, passed)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut insert_drop = tx.prepare_cached(
        "INSERT INTO run_funnel_drop
             (scan_run_id, position, ordinal, cause, dropped)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (position, stage) in summary.funnel.iter().enumerate() {
        let position = i64::try_from(position).unwrap_or(i64::MAX);
        insert_stage.execute(params![run_id, position, stage.name, count(stage.passed)])?;
        for (ordinal, drop) in stage.dropped.iter().enumerate() {
            insert_drop.execute(params![
                run_id,
                position,
                i64::try_from(ordinal).unwrap_or(i64::MAX),
                drop.cause,
                count(drop.count),
            ])?;
        }
    }
    drop(insert_drop);
    drop(insert_stage);
    let mut insert_unused_suppression = tx.prepare_cached(
        "INSERT INTO run_unused_suppression (scan_run_id, ordinal, scope, pattern)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, rule) in summary.unused_suppressions.iter().enumerate() {
        insert_unused_suppression.execute(params![
            run_id,
            i64::try_from(ordinal).unwrap_or(i64::MAX),
            rule.scope,
            rule.pattern,
        ])?;
    }
    Ok(())
}

/// Record the tree the run read, one row per file.
fn write_files(tx: &Transaction<'_>, files: &[FileRow], run_id: i64) -> Result<(), StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO scanned_file
             (scan_run_id, relative_path, content_hash, language, byte_len)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for file in files {
        insert.execute(params![
            run_id,
            file.relative_path,
            file.content_hash,
            file.language.name(),
            i64::try_from(file.byte_len).unwrap_or(i64::MAX),
        ])?;
    }
    Ok(())
}

/// Record the active suppression rules, reusing existing `(scope, pattern)`
/// rows so rules stay content-addressed across runs.
fn write_suppressions(
    tx: &Transaction<'_>,
    rules: &[SuppressionRuleRow],
) -> Result<Vec<i64>, StoreError> {
    // A rule is active only while the current invocation supplied it. Keep
    // historic finding references intact, but make a removed rule visibly
    // inactive instead of leaving its first-seen state frozen forever.
    tx.execute("UPDATE suppression SET active = 0 WHERE active = 1", [])?;
    let mut row_ids = Vec::with_capacity(rules.len());
    for rule in rules {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM suppression
                 WHERE scope = ?1 AND pattern = ?2",
                params![rule.scope, rule.pattern],
                |row| row.get(0),
            )
            .optional()?;
        let id = if let Some(id) = existing {
            tx.execute(
                "UPDATE suppression SET reason = ?2, active = 1 WHERE id = ?1",
                params![id, rule.reason],
            )?;
            id
        } else {
            tx.execute(
                "INSERT INTO suppression (scope, pattern, reason, active)
                 VALUES (?1, ?2, ?3, 1)",
                params![rule.scope, rule.pattern, rule.reason],
            )?;
            tx.last_insert_rowid()
        };
        row_ids.push(id);
    }
    Ok(row_ids)
}

fn write_units(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
) -> Result<Vec<i64>, StoreError> {
    let mut unit_row_ids = Vec::with_capacity(snapshot.units.len());
    let mut insert = tx.prepare_cached(
        "INSERT INTO source_unit
             (scan_run_id, fingerprint_id, language, unit_kind, name,
              file_path, start_line, end_line, token_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    for unit in &snapshot.units {
        let fp_id = upsert_fingerprint(
            tx,
            "unit",
            unit.fingerprint.as_bytes(),
            snapshot,
            variant_id,
            unit.language,
        )?;
        insert.execute(params![
            run_id,
            fp_id,
            unit.language.name(),
            unit.kind.name(),
            unit.name,
            unit.file_path,
            unit.start_line,
            unit.end_line,
            i64::try_from(unit.token_count).unwrap_or(i64::MAX),
        ])?;
        unit_row_ids.push(tx.last_insert_rowid());
    }
    Ok(unit_row_ids)
}
