use super::groups::{
    apply_lineage_adoptions_tx, plan_matching_lineages_tx, write_group, write_near_misses,
    write_sibling_groups,
};
use super::variant::{upsert_fingerprint, upsert_variant};
use super::{
    AbandonedRun, BTreeMap, BTreeSet, FileRow, OptionalExtension, Snapshot, SnapshotComparisons,
    StagedSnapshotPart, StagedSuppression, Store, StoreError, SummaryRow, SuppressionRuleRow,
    Transaction, params,
};

// Completed snapshots are retained rather than superseded. A later scan can
// only explain a changed clone-group fingerprint by reading the prior group's
// members and lineage, so a completed snapshot is history, not a replaceable
// cache entry. The cache maintenance surface owns any explicit retention
// policy; recording a scan never discards evidence, and therefore never
// creates an orphaned content identity either.

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
        let discarded = tx.execute("DELETE FROM scan_run WHERE id = ?1", params![run_id])?;
        crate::lifecycle::remove_orphaned_fingerprints(&tx, discarded)?;
        tx.commit()?;
        crate::lifecycle::forget_live_runs(&self.database, [run_id]);
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
        self.record_snapshot_with_predecessor(snapshot, None)
    }

    /// Atomically replace the globally active suppression policy without
    /// creating a scan run.
    ///
    /// Reused scans still need to make their current invocation policy visible
    /// when another scan changed the active rows since the reused run was
    /// recorded. The policy is therefore written in one transaction, with
    /// newly-created rows and every active-state change rolled back together
    /// if any database operation fails.
    ///
    /// # Errors
    ///
    /// Returns an underlying database error or suppression validation error.
    pub fn activate_suppressions(
        &mut self,
        rules: &[SuppressionRuleRow],
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        // Writing the policy only inserts and updates suppression rows, so no
        // content identity can be left without a referent here.
        write_suppressions(&tx, rules, true)?;
        tx.commit()?;
        Ok(())
    }

    /// Record one completed snapshot and atomically connect it to a selected
    /// completed predecessor, when one exists.
    ///
    /// The snapshot write, lineage planning/application, and fingerprint
    /// cleanup share one transaction. A failure in any of those operations
    /// therefore cannot leave a completed run whose lineage was only partly
    /// adopted.
    ///
    /// # Errors
    ///
    /// Returns any snapshot validation, lineage, cleanup, or database error.
    pub fn record_snapshot_with_predecessor(
        &mut self,
        snapshot: &Snapshot<'_>,
        predecessor_run: Option<i64>,
    ) -> Result<i64, StoreError> {
        validate_group_fingerprints(snapshot)?;
        let tx = self.conn.transaction()?;
        if let Some(predecessor_run) = predecessor_run {
            ensure_completed_run_tx(&tx, predecessor_run)?;
        }
        let (run_id, _) = write_snapshot(&tx, snapshot, SnapshotStatus::Completed, true)?;
        if let Some(predecessor_run) = predecessor_run {
            // Re-check after the INSERT. A database trigger or concurrent
            // writer must not be able to turn the selected predecessor into a
            // running row between the initial validation and lineage apply.
            ensure_completed_run_tx(&tx, predecessor_run)?;
            let adoptions = plan_matching_lineages_tx(&tx, run_id, predecessor_run)?;
            apply_lineage_adoptions_tx(&tx, run_id, predecessor_run, &adoptions)?;
        }
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
        let (run_id, _) = write_snapshot(&tx, snapshot, SnapshotStatus::Running, true)?;
        tx.commit()?;
        crate::lifecycle::register_live_run(&self.database, run_id);
        Ok(run_id)
    }

    /// Record one still-running partition and return the opaque staging token
    /// required to finalize or abort the invocation.
    ///
    /// # Errors
    ///
    /// Returns any snapshot validation or database error. Staging leaves
    /// suppression activation unchanged until finalization.
    pub fn record_snapshot_part_staged(
        &mut self,
        snapshot: &Snapshot<'_>,
    ) -> Result<StagedSnapshotPart, StoreError> {
        validate_group_fingerprints(snapshot)?;
        let tx = self.conn.transaction()?;
        let (run_id, suppressions) = write_snapshot(&tx, snapshot, SnapshotStatus::Running, false)?;
        tx.commit()?;
        crate::lifecycle::register_live_run(&self.database, run_id);
        Ok(StagedSnapshotPart {
            run_id,
            suppressions,
            predecessor_run: None,
        })
    }

    /// Atomically finalize every staged partition and any requested
    /// comparison rows.
    ///
    /// All running partitions are validated first. Comparison rows, lineage
    /// edges, suppression activation, completion state, and orphan cleanup
    /// are then written in one transaction. A savepoint lets a failed final
    /// operation remove the supplied staged runs before the transaction is
    /// committed, preserving the pre-invocation database state.
    ///
    /// # Errors
    ///
    /// Returns a validation, comparison, lineage, completion, cleanup, or
    /// database error. A failed finalization removes the supplied running
    /// partitions when `SQLite` permits the cleanup transaction to commit.
    pub fn finalize_snapshot_parts(
        &mut self,
        parts: &[StagedSnapshotPart],
        comparisons: SnapshotComparisons<'_>,
    ) -> Result<(), StoreError> {
        self.finalize_snapshot_parts_with_retired(parts, &[], comparisons)
    }

    /// Atomically finalize live staged partitions while also applying the
    /// suppression policy carried by partitions that were reused and already
    /// discarded from `scan_run`.
    ///
    /// `parts` are the live rows whose comparisons, lineage, and completion
    /// state are finalized. `retired_parts` are token-only policy inputs: they
    /// must not be running rows anymore, but their suppression rules still
    /// belong to this invocation's exact active set.
    ///
    /// # Errors
    ///
    /// Returns a validation, comparison, lineage, completion, cleanup, or
    /// database error. A failed finalization removes supplied live rows and
    /// any newly-created suppression rows named by either token collection.
    pub fn finalize_snapshot_parts_with_retired(
        &mut self,
        parts: &[StagedSnapshotPart],
        retired_parts: &[StagedSnapshotPart],
        comparisons: SnapshotComparisons<'_>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute_batch("SAVEPOINT codehelion_finalize")?;
        let result = (|| {
            if parts.is_empty()
                && (comparisons.cross_variant.is_some() || comparisons.cross_language.is_some())
            {
                return Err(StoreError::InvalidSnapshotParts {
                    reason: "comparisons require at least one staged partition".to_string(),
                });
            }
            if parts.is_empty() && retired_parts.is_empty() {
                return Err(StoreError::InvalidSnapshotParts {
                    reason: "at least one staged partition is required".to_string(),
                });
            }
            validate_snapshot_parts(&tx, parts, retired_parts)?;
            let suppression_union = validate_suppression_union(&tx, parts, retired_parts)?;
            if let Some(comparison) = comparisons.cross_variant {
                Self::write_cross_variant_comparison_tx(&tx, comparison)?;
            }
            if let Some(comparison) = comparisons.cross_language {
                Self::write_cross_language_comparison_tx(&tx, comparison)?;
            }
            for part in parts {
                if let Some(predecessor_run) = part.predecessor_run {
                    ensure_completed_run_tx(&tx, predecessor_run)?;
                    let adoptions = plan_matching_lineages_tx(&tx, part.run_id, predecessor_run)?;
                    apply_lineage_adoptions_tx(&tx, part.run_id, predecessor_run, &adoptions)?;
                }
            }
            activate_staged_suppressions(&tx, &suppression_union)?;
            for part in parts {
                if tx.execute(
                    "UPDATE scan_run SET status = 'completed' WHERE id = ?1 AND status = 'running'",
                    params![part.run_id],
                )? != 1
                {
                    return Err(StoreError::RunNotRunning {
                        run_id: part.run_id,
                    });
                }
            }
            tx.execute_batch("RELEASE codehelion_finalize")?;
            Ok(())
        })();
        // Whatever the outcome, this invocation no longer owns these
        // partitions: they either completed or were removed.
        let owned = parts
            .iter()
            .chain(retired_parts)
            .map(|part| part.run_id)
            .collect::<Vec<_>>();
        crate::lifecycle::forget_live_runs(&self.database, owned);
        match result {
            Ok(()) => match tx.commit() {
                Ok(()) => Ok(()),
                Err(primary) => {
                    let cleanup = (|| {
                        let cleanup_tx = self.conn.transaction()?;
                        cleanup_snapshot_parts_tx(&cleanup_tx, parts, retired_parts)?;
                        cleanup_tx.commit()?;
                        Ok::<(), StoreError>(())
                    })();
                    match cleanup {
                        Ok(()) => Err(StoreError::from(primary)),
                        Err(cleanup) => Err(StoreError::AtomicFinalization {
                            primary: primary.to_string(),
                            cleanup: cleanup.to_string(),
                        }),
                    }
                }
            },
            Err(error) => {
                let rollback_error = tx
                    .execute_batch("ROLLBACK TO codehelion_finalize; RELEASE codehelion_finalize")
                    .err()
                    .map(|error| error.to_string());
                let cleanup_error = cleanup_snapshot_parts_tx(&tx, parts, retired_parts)
                    .err()
                    .map(|error| error.to_string());
                let commit_error = if rollback_error.is_none() && cleanup_error.is_none() {
                    tx.commit().err().map(|error| error.to_string())
                } else {
                    None
                };
                if let Some(cleanup_error) = rollback_error.or(cleanup_error).or(commit_error) {
                    return Err(StoreError::AtomicFinalization {
                        primary: error.to_string(),
                        cleanup: cleanup_error,
                    });
                }
                Err(error)
            }
        }
    }

    /// Abort staged partitions and remove their run-owned rows.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied token refers to a completed run or
    /// when `SQLite` cannot remove the staged rows. Missing runs are accepted so
    /// callers can safely retry cleanup after a partially committed failure.
    pub fn abort_snapshot_parts(&mut self, parts: &[StagedSnapshotPart]) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for part in parts {
            let status = tx
                .query_row(
                    "SELECT status FROM scan_run WHERE id = ?1",
                    params![part.run_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match status.as_deref() {
                Some("running") | None => {}
                Some(_) => {
                    return Err(StoreError::RunNotRunning {
                        run_id: part.run_id,
                    });
                }
            }
        }
        let mut discarded = 0_usize;
        for part in parts {
            discarded = discarded.saturating_add(
                tx.execute("DELETE FROM scan_run WHERE id = ?1", params![part.run_id])?,
            );
        }
        cleanup_staged_suppressions(&tx, parts, &[])?;
        crate::lifecycle::remove_orphaned_fingerprints(&tx, discarded)?;
        tx.commit()?;
        crate::lifecycle::forget_live_runs(&self.database, parts.iter().map(|part| part.run_id));
        Ok(())
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
        tx.commit()?;
        crate::lifecycle::forget_live_runs(&self.database, run_ids.iter().copied());
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

fn ensure_completed_run_tx(tx: &Transaction<'_>, run_id: i64) -> Result<(), StoreError> {
    let status: Option<String> = tx
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

fn validate_snapshot_parts(
    tx: &Transaction<'_>,
    parts: &[StagedSnapshotPart],
    retired_parts: &[StagedSnapshotPart],
) -> Result<(), StoreError> {
    let mut run_ids: BTreeSet<i64> = BTreeSet::new();
    for part in parts.iter().chain(retired_parts) {
        if !run_ids.insert(part.run_id) {
            return Err(StoreError::InvalidSnapshotParts {
                reason: "a staged partition run id appears more than once".to_string(),
            });
        }
    }
    for part in retired_parts {
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM scan_run WHERE id = ?1",
                params![part.run_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.is_some() {
            return Err(StoreError::InvalidSnapshotParts {
                reason: format!("retired partition {} still has a scan_run row", part.run_id),
            });
        }
    }
    for part in parts {
        if part.predecessor_run == Some(part.run_id) {
            return Err(StoreError::InvalidSnapshotParts {
                reason: format!("partition {} names itself as predecessor", part.run_id),
            });
        }
        if part
            .predecessor_run
            .is_some_and(|predecessor| run_ids.contains(&predecessor))
        {
            return Err(StoreError::InvalidSnapshotParts {
                reason: format!(
                    "partition {} names a staged partition as predecessor",
                    part.run_id
                ),
            });
        }
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM scan_run WHERE id = ?1",
                params![part.run_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some("running") {
            return match status {
                Some(_) => Err(StoreError::RunNotRunning {
                    run_id: part.run_id,
                }),
                None => Err(StoreError::RunNotFound {
                    run_id: part.run_id,
                }),
            };
        }
        if let Some(predecessor_run) = part.predecessor_run {
            ensure_completed_run_tx(tx, predecessor_run)?;
        }
    }
    Ok(())
}

/// Validate and combine the opaque suppression policy from every partition
/// participating in one invocation. Different partitions may contribute
/// different rules; a repeated rule is valid only when its reason agrees.
fn validate_suppression_union(
    tx: &Transaction<'_>,
    parts: &[StagedSnapshotPart],
    retired_parts: &[StagedSnapshotPart],
) -> Result<BTreeMap<i64, Option<String>>, StoreError> {
    let mut suppression_union = BTreeMap::new();
    for part in parts.iter().chain(retired_parts) {
        let mut suppression_ids = BTreeSet::new();
        for suppression in &part.suppressions {
            if !suppression_ids.insert(suppression.id) {
                return Err(StoreError::InvalidSuppression {
                    reason: format!(
                        "staged partition {} names suppression {} more than once",
                        part.run_id, suppression.id
                    ),
                });
            }
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT id FROM suppression WHERE id = ?1",
                    params![suppression.id],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(StoreError::InvalidSuppression {
                    reason: format!(
                        "staged partition {} names missing suppression {}",
                        part.run_id, suppression.id
                    ),
                });
            }
            if let Some(existing) = suppression_union.get(&suppression.id)
                && existing != &suppression.reason
            {
                return Err(StoreError::InvalidSuppression {
                    reason: format!(
                        "staged partitions supplied different reasons for suppression {}",
                        suppression.id
                    ),
                });
            }
            suppression_union
                .entry(suppression.id)
                .or_insert_with(|| suppression.reason.clone());
        }
    }
    Ok(suppression_union)
}

fn cleanup_snapshot_parts_tx(
    tx: &Transaction<'_>,
    parts: &[StagedSnapshotPart],
    retired_parts: &[StagedSnapshotPart],
) -> Result<(), StoreError> {
    let mut discarded = 0_usize;
    for part in parts {
        discarded = discarded.saturating_add(tx.execute(
            "DELETE FROM scan_run WHERE id = ?1 AND status = 'running'",
            params![part.run_id],
        )?);
    }
    cleanup_staged_suppressions(tx, parts, retired_parts)?;
    crate::lifecycle::remove_orphaned_fingerprints(tx, discarded)?;
    Ok(())
}

/// Activate exactly the rules supplied by the staged invocation. Staging
/// leaves both existing and newly inserted rows untouched, so an interrupted
/// multi-partition invocation cannot alter the active policy seen by prior
/// completed runs.
fn activate_staged_suppressions(
    tx: &Transaction<'_>,
    suppression_union: &BTreeMap<i64, Option<String>>,
) -> Result<(), StoreError> {
    tx.execute("UPDATE suppression SET active = 0 WHERE active = 1", [])?;
    for (id, reason) in suppression_union {
        if tx.execute(
            "UPDATE suppression SET reason = ?2, active = 1 WHERE id = ?1",
            params![id, reason],
        )? != 1
        {
            return Err(StoreError::InvalidSuppression {
                reason: format!("staged suppression {id} is missing"),
            });
        }
    }
    Ok(())
}

fn cleanup_staged_suppressions(
    tx: &Transaction<'_>,
    parts: &[StagedSnapshotPart],
    retired_parts: &[StagedSnapshotPart],
) -> Result<(), StoreError> {
    let created_ids: BTreeSet<i64> = parts
        .iter()
        .chain(retired_parts)
        .flat_map(|part| &part.suppressions)
        .filter(|suppression| suppression.created)
        .map(|suppression| suppression.id)
        .collect();
    for id in created_ids {
        tx.execute(
            "DELETE FROM suppression
             WHERE id = ?1
               AND active = 0
               AND NOT EXISTS (SELECT 1 FROM finding WHERE suppression_id = suppression.id)
               AND NOT EXISTS (
                   SELECT 1 FROM clone_group_sibling WHERE suppression_id = suppression.id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM near_match_near_miss WHERE suppression_id = suppression.id
               )",
            params![id],
        )?;
    }
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
    activate_suppressions: bool,
) -> Result<(i64, Vec<StagedSuppression>), StoreError> {
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

    let (suppression_row_ids, suppressions) =
        write_suppressions(tx, &snapshot.suppressions, activate_suppressions)?;
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
    Ok((run_id, suppressions))
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
              guardrail_signature_sibling_candidate_budget,
              guardrail_signature_sibling_per_group_cap,
              guardrail_signature_sibling_total_cap, guardrail_max_component, folded_runs,
              subsumed_runs, split_components, pair_budget_exhausted, baseline_digest,
              excluded_language, excluded_symlink_files, excluded_symlink_directories,
              guardrail_near_miss_delta, guardrail_near_miss_cap,
              guardrail_verification_budget, guardrail_max_alignment_cells,
              guardrail_signature_sibling_max_units_per_signature,
              common_signatures_skipped, largest_skipped_signature_units,
              excluded_oversized_metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                 ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
                 ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48)",
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
                .and_then(|row| row.sibling_candidate_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.sibling_per_group_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.sibling_total_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_candidate_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_per_group_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_total_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.max_component.map(count)),
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
                .and_then(|row| row.near_miss_delta_bits.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.near_miss_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.verification_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.max_alignment_cells.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_max_units_per_signature.map(count)),
            count(summary.common_signatures_skipped),
            count(summary.largest_skipped_signature_units),
            count(summary.excluded_oversized_metadata),
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
    activate: bool,
) -> Result<(Vec<i64>, Vec<StagedSuppression>), StoreError> {
    // A rule is active only while the current invocation supplied it. Keep
    // historic finding references intact, but make a removed rule visibly
    // inactive instead of leaving its first-seen state frozen forever.
    if activate {
        tx.execute("UPDATE suppression SET active = 0 WHERE active = 1", [])?;
    }
    let mut row_ids = Vec::with_capacity(rules.len());
    let mut staged = Vec::with_capacity(rules.len());
    for rule in rules {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM suppression
                 WHERE scope = ?1 AND pattern = ?2",
                params![rule.scope, rule.pattern],
                |row| row.get(0),
            )
            .optional()?;
        let (id, created) = if let Some(id) = existing {
            if activate {
                tx.execute(
                    "UPDATE suppression SET reason = ?2, active = 1 WHERE id = ?1",
                    params![id, rule.reason],
                )?;
            }
            (id, false)
        } else {
            tx.execute(
                "INSERT INTO suppression (scope, pattern, reason, active)
                 VALUES (?1, ?2, ?3, ?4)",
                params![rule.scope, rule.pattern, rule.reason, activate],
            )?;
            (tx.last_insert_rowid(), true)
        };
        row_ids.push(id);
        staged.push(StagedSuppression {
            id,
            reason: rule.reason.clone(),
            created,
        });
    }
    Ok((row_ids, staged))
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::snapshot::{
        CrossVariantComparisonSnapshot, GroupOrigin, GroupRow, MemberRow, PriorityRow,
        SuppressionRuleRow,
    };
    use codehelion_core::clone_class::{CloneClass, CloneScope};
    use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
    use codehelion_core::stable_id::{
        CloneGroupFingerprint, CrossVariantComparisonId, FindingId, FragmentFingerprint,
    };

    const fn group_fingerprint(seed: u8) -> CloneGroupFingerprint {
        CloneGroupFingerprint::from_bytes([seed; 16])
    }

    const fn content_fingerprint() -> FragmentFingerprint {
        FragmentFingerprint::from_bytes([1; 16])
    }

    const fn finding(seed: u8) -> FindingId {
        FindingId::from_bytes([seed; 16])
    }

    fn snapshot(
        variant: &BuildVariant,
        group: Option<u8>,
        suppressions: Vec<SuppressionRuleRow>,
    ) -> Snapshot<'_> {
        let groups = group.map_or_else(Vec::new, |seed| {
            let fingerprint = group_fingerprint(seed);
            vec![GroupRow {
                fingerprint,
                history: GroupOrigin::unconnected(&fingerprint),
                clone_type: CloneClass::Type1,
                member_scope: CloneScope::Unit,
                test_code: false,
                test_code_evidence: None,
                split_pair: false,
                score: 1.0,
                entropy_bits: 1.0,
                suppress_reason: None,
                boilerplate: None,
                identifier_jaccard: None,
                has_loop: None,
                has_dynamic_allocation: None,
                call_count: None,
                width_family: false,
                ranked_down: false,
                statements: None,
                suppressed_by: None,
                priority: PriorityRow {
                    clone_confidence: 0.9,
                    maintenance_risk: 0.5,
                    refactoring_difficulty: 0.4,
                    final_priority: 0.7,
                    semantic_confidence: None,
                    source_artifact_confidence: None,
                    savings_confidence: None,
                },
                similarity: None,
                semantic: None,
                members: vec![MemberRow {
                    content: content_fingerprint(),
                    finding: finding(seed),
                    language: Language::Rust,
                    host_unit: None,
                    boilerplate: None,
                    file_path: "src/lib.rs".to_string(),
                    start_line: 1,
                    end_line: 2,
                    token_count: 2,
                }],
            }]
        });
        Snapshot {
            root_path: "/repo",
            tool_version: "0.1.0",
            config_hash: "test-config",
            config_source: "defaults",
            config_path: None,
            started_at: "2026-08-12T00:00:00Z",
            finished_at: "2026-08-12T00:00:01Z",
            variant,
            min_clone_tokens: 1,
            detector_versions: &[],
            suppressions,
            units: Vec::new(),
            groups,
            sibling_groups: Vec::new(),
            near_misses: Vec::new(),
            files: Vec::new(),
            compiler_helpers: Vec::new(),
            compiler_units: Vec::new(),
            summary: SummaryRow::default(),
        }
    }

    fn variant() -> BuildVariant {
        BuildVariant::fast(LanguageSelection::default(), Language::Rust)
    }

    fn count(store: &Store, table: &str) -> i64 {
        store
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn suppression_state(store: &Store, pattern: &str) -> Option<(bool, Option<String>)> {
        store
            .conn
            .query_row(
                "SELECT active, reason FROM suppression WHERE pattern = ?1",
                params![pattern],
                |row| Ok((row.get::<_, bool>(0)?, row.get(1)?)),
            )
            .optional()
            .unwrap()
    }

    fn rule(pattern: &str, reason: &str) -> SuppressionRuleRow {
        SuppressionRuleRow {
            scope: "path_glob".to_string(),
            pattern: pattern.to_string(),
            reason: Some(reason.to_string()),
        }
    }

    #[test]
    fn single_predecessor_recheck_rolls_back_when_insert_trigger_reopens_it() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let predecessor = store
            .record_snapshot(&snapshot(&variant, Some(9), Vec::new()))
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reopen_predecessor AFTER INSERT ON scan_run
                 BEGIN UPDATE scan_run SET status = 'running' WHERE id = 1; END;",
            )
            .unwrap();

        let error = store
            .record_snapshot_with_predecessor(
                &snapshot(&variant, Some(77), Vec::new()),
                Some(predecessor),
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::RunNotCompleted { run_id } if run_id == predecessor));
        assert_eq!(count(&store, "scan_run"), 1);
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT status FROM scan_run WHERE id = ?1",
                    params![predecessor],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "completed"
        );
        assert_eq!(count(&store, "clone_group"), 1);
    }

    #[test]
    fn single_lineage_failure_rolls_back_the_new_snapshot_and_history() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let predecessor = store
            .record_snapshot(&snapshot(&variant, Some(9), Vec::new()))
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_lineage BEFORE INSERT ON clone_group_lineage_parent
                 BEGIN SELECT RAISE(ABORT, 'lineage failure'); END;",
            )
            .unwrap();

        let error = store
            .record_snapshot_with_predecessor(
                &snapshot(&variant, Some(77), Vec::new()),
                Some(predecessor),
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::Sqlite { .. }));
        assert_eq!(count(&store, "scan_run"), 1);
        assert_eq!(count(&store, "clone_group_lineage_parent"), 0);
        assert_eq!(
            store
                .run_group_snapshots(predecessor)
                .unwrap()
                .first()
                .unwrap()
                .lineage,
            Some(codehelion_core::stable_id::group_lineage_id(
                &group_fingerprint(9)
            ))
        );
    }

    #[test]
    fn activation_refreshes_policy_without_creating_a_run() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_snapshot(&snapshot(
                &variant,
                None,
                vec![rule("old-policy/**", "old")],
            ))
            .unwrap();
        let runs_before = count(&store, "scan_run");

        store
            .activate_suppressions(&[rule("current-policy/**", "current")])
            .unwrap();

        assert_eq!(count(&store, "scan_run"), runs_before);
        assert_eq!(
            suppression_state(&store, "old-policy/**"),
            Some((false, Some("old".to_string())))
        );
        assert_eq!(
            suppression_state(&store, "current-policy/**"),
            Some((true, Some("current".to_string())))
        );
    }

    #[test]
    fn activation_failure_preserves_the_prior_policy() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_snapshot(&snapshot(
                &variant,
                None,
                vec![rule("prior-policy/**", "prior")],
            ))
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_policy_activation
                 BEFORE UPDATE OF active ON suppression
                 BEGIN SELECT RAISE(ABORT, 'policy activation failure'); END;",
            )
            .unwrap();

        let error = store
            .activate_suppressions(&[rule("new-policy/**", "new")])
            .unwrap_err();
        assert!(matches!(error, StoreError::Sqlite { .. }));
        assert_eq!(
            suppression_state(&store, "prior-policy/**"),
            Some((true, Some("prior".to_string())))
        );
        assert_eq!(suppression_state(&store, "new-policy/**"), None);
        assert_eq!(count(&store, "scan_run"), 1);
    }

    #[test]
    fn finalizer_removes_comparison_and_staged_run_when_completion_fails() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let token = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("src/failing/**", "staged")],
            ))
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON scan_run
                 WHEN OLD.status = 'running' AND NEW.status = 'completed'
                 BEGIN SELECT RAISE(ABORT, 'completion failure'); END;",
            )
            .unwrap();
        let origins = Vec::new();
        let groups = Vec::new();
        let comparison = CrossVariantComparisonSnapshot {
            root_path: "/repo",
            comparison_id: CrossVariantComparisonId::from_bytes([42; 16]),
            policy_version: "test",
            started_at: "2026-08-12T00:00:00Z",
            finished_at: "2026-08-12T00:00:01Z",
            origins: &origins,
            groups: &groups,
        };
        let error = store
            .finalize_snapshot_parts(
                std::slice::from_ref(&token),
                SnapshotComparisons {
                    cross_variant: Some(&comparison),
                    cross_language: None,
                },
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::Sqlite { .. }));
        assert_eq!(count(&store, "scan_run"), 0);
        assert_eq!(count(&store, "cross_variant_comparison"), 0);
        assert_eq!(suppression_state(&store, "src/failing/**"), None);
    }

    #[test]
    fn finalizer_lineage_failure_leaves_predecessor_and_no_staged_rows() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let predecessor = store
            .record_snapshot(&snapshot(&variant, Some(9), Vec::new()))
            .unwrap();
        let token = store
            .record_snapshot_part_staged(&snapshot(&variant, Some(77), Vec::new()))
            .unwrap()
            .with_predecessor(Some(predecessor));
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_staged_lineage BEFORE INSERT ON clone_group_lineage_parent
                 BEGIN SELECT RAISE(ABORT, 'staged lineage failure'); END;",
            )
            .unwrap();

        let error = store
            .finalize_snapshot_parts(&[token], SnapshotComparisons::default())
            .unwrap_err();
        assert!(matches!(error, StoreError::Sqlite { .. }));
        assert_eq!(count(&store, "scan_run"), 1);
        assert_eq!(count(&store, "clone_group_lineage_parent"), 0);
        assert_eq!(store.abandoned_runs().unwrap().len(), 0);
    }

    #[test]
    fn staged_suppression_activation_is_exact_and_abort_preserves_prior_state() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_snapshot(&snapshot(
                &variant,
                None,
                vec![rule("src/**", "old reason")],
            ))
            .unwrap();
        assert_eq!(
            suppression_state(&store, "src/**"),
            Some((true, Some("old reason".to_string())))
        );

        let revised = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("src/**", "new reason")],
            ))
            .unwrap();
        assert_eq!(
            suppression_state(&store, "src/**"),
            Some((true, Some("old reason".to_string())))
        );
        store
            .finalize_snapshot_parts(&[revised], SnapshotComparisons::default())
            .unwrap();
        assert_eq!(
            suppression_state(&store, "src/**"),
            Some((true, Some("new reason".to_string())))
        );

        let failed = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("src/**", "failed reason")],
            ))
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_suppression_completion BEFORE UPDATE OF status ON scan_run
                 WHEN OLD.status = 'running' AND NEW.status = 'completed'
                 BEGIN SELECT RAISE(ABORT, 'suppression completion failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .finalize_snapshot_parts(&[failed], SnapshotComparisons::default())
                .is_err()
        );
        assert_eq!(
            suppression_state(&store, "src/**"),
            Some((true, Some("new reason".to_string())))
        );
    }

    #[test]
    fn new_staged_suppression_becomes_active_only_on_success_and_is_removed_on_abort() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let token = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("generated/**", "generated")],
            ))
            .unwrap();
        assert_eq!(
            suppression_state(&store, "generated/**"),
            Some((false, Some("generated".to_string())))
        );
        store
            .abort_snapshot_parts(std::slice::from_ref(&token))
            .unwrap();
        assert_eq!(suppression_state(&store, "generated/**"), None);

        let token = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("generated/**", "generated")],
            ))
            .unwrap();
        store
            .finalize_snapshot_parts(&[token], SnapshotComparisons::default())
            .unwrap();
        assert_eq!(
            suppression_state(&store, "generated/**"),
            Some((true, Some("generated".to_string())))
        );
    }

    #[test]
    fn finalizer_activates_the_union_of_disjoint_suppression_sets() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("inline/**", "inline")],
            ))
            .unwrap();
        let second = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("boilerplate/**", "boilerplate")],
            ))
            .unwrap();

        store
            .finalize_snapshot_parts(&[first, second], SnapshotComparisons::default())
            .unwrap();

        assert_eq!(
            suppression_state(&store, "inline/**"),
            Some((true, Some("inline".to_string())))
        );
        assert_eq!(
            suppression_state(&store, "boilerplate/**"),
            Some((true, Some("boilerplate".to_string())))
        );
    }

    #[test]
    fn finalizer_accepts_duplicate_suppression_with_the_same_reason() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("width/**", "same reason")],
            ))
            .unwrap();
        let second = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("width/**", "same reason")],
            ))
            .unwrap();

        store
            .finalize_snapshot_parts(&[first, second], SnapshotComparisons::default())
            .unwrap();

        assert_eq!(count(&store, "suppression"), 1);
        assert_eq!(
            suppression_state(&store, "width/**"),
            Some((true, Some("same reason".to_string())))
        );
    }

    #[test]
    fn conflicting_suppression_reasons_abort_every_part_and_preserve_prior_policy() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_snapshot(&snapshot(
                &variant,
                None,
                vec![rule("test/**", "prior reason")],
            ))
            .unwrap();
        let first = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("test/**", "first reason"), rule("new/**", "new rule")],
            ))
            .unwrap();
        let second = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("test/**", "second reason")],
            ))
            .unwrap();

        let error = store
            .finalize_snapshot_parts(&[first, second], SnapshotComparisons::default())
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidSuppression { .. }));
        assert_eq!(count(&store, "scan_run"), 1);
        assert_eq!(
            suppression_state(&store, "test/**"),
            Some((true, Some("prior reason".to_string())))
        );
        assert_eq!(suppression_state(&store, "new/**"), None);
    }

    #[test]
    fn retired_token_contributes_suppression_policy_after_its_run_is_discarded() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let retired = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("reused/**", "reused")],
            ))
            .unwrap();
        store.discard_run(retired.run_id()).unwrap();
        let live = store
            .record_snapshot_part_staged(&snapshot(&variant, None, vec![rule("live/**", "live")]))
            .unwrap();

        store
            .finalize_snapshot_parts_with_retired(
                std::slice::from_ref(&live),
                std::slice::from_ref(&retired),
                SnapshotComparisons::default(),
            )
            .unwrap();
        store
            .abort_snapshot_parts(std::slice::from_ref(&retired))
            .unwrap();

        assert_eq!(
            suppression_state(&store, "reused/**"),
            Some((true, Some("reused".to_string())))
        );
        assert_eq!(
            suppression_state(&store, "live/**"),
            Some((true, Some("live".to_string())))
        );
    }

    #[test]
    fn policy_only_finalization_restores_reused_rules_when_every_partition_is_reused() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_snapshot(&snapshot(&variant, None, vec![rule("prior/**", "prior")]))
            .unwrap();
        let retired = store
            .record_snapshot_part_staged(&snapshot(
                &variant,
                None,
                vec![rule("reused-only/**", "reused")],
            ))
            .unwrap();
        store
            .record_snapshot(&snapshot(&variant, None, vec![rule("other/**", "other")]))
            .unwrap();
        store.discard_run(retired.run_id()).unwrap();

        store
            .finalize_snapshot_parts_with_retired(
                &[],
                std::slice::from_ref(&retired),
                SnapshotComparisons::default(),
            )
            .unwrap();

        assert_eq!(
            suppression_state(&store, "reused-only/**"),
            Some((true, Some("reused".to_string())))
        );
        assert_eq!(
            suppression_state(&store, "other/**"),
            Some((false, Some("other".to_string())))
        );
        assert_eq!(store.abandoned_runs().unwrap().len(), 0);
    }

    #[test]
    fn finalizer_rejects_duplicate_or_staged_predecessors_and_abort_is_idempotent() {
        let variant = variant();
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .record_snapshot_part_staged(&snapshot(&variant, None, Vec::new()))
            .unwrap();
        let second = store
            .record_snapshot_part_staged(&snapshot(&variant, None, Vec::new()))
            .unwrap();
        let invalid_parts = [first.with_predecessor(Some(second.run_id())), second];
        let error = store
            .finalize_snapshot_parts(&invalid_parts, SnapshotComparisons::default())
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidSnapshotParts { .. }));
        assert_eq!(count(&store, "scan_run"), 0);

        let one = store
            .record_snapshot_part_staged(&snapshot(&variant, None, Vec::new()))
            .unwrap();
        let two = store
            .record_snapshot_part_staged(&snapshot(&variant, None, Vec::new()))
            .unwrap();
        store
            .abort_snapshot_parts(std::slice::from_ref(&one))
            .unwrap();
        store.abort_snapshot_parts(&[one, two.clone()]).unwrap();
        store.abort_snapshot_parts(&[two]).unwrap();
        assert_eq!(count(&store, "scan_run"), 0);
    }
}
