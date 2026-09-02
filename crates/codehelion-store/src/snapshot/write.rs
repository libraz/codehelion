use super::groups::{
    apply_lineage_adoptions_tx, plan_matching_lineages_tx, write_group, write_near_misses,
    write_sibling_groups,
};
use super::variant::upsert_variant;
use super::{
    AbandonedRun, BTreeMap, OptionalExtension, Snapshot, SnapshotComparisons, StagedSnapshotPart,
    StagedSuppression, Store, StoreError, SuppressionRuleRow, Transaction, params,
};
use crate::lifecycle::ensure_completed_run;

mod rows;
mod suppression;
mod validate;

use rows::{record_detector_version, write_files, write_summary, write_suppressions, write_units};
use suppression::{
    SnapshotStatus, activate_staged_suppressions, cleanup_snapshot_parts_tx,
    cleanup_staged_suppressions,
};
use validate::{validate_group_fingerprints, validate_snapshot_parts, validate_suppression_union};

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
            ensure_completed_run(&tx, predecessor_run)?;
        }
        let (run_id, _) = write_snapshot(&tx, snapshot, SnapshotStatus::Completed, true)?;
        if let Some(predecessor_run) = predecessor_run {
            // Re-check after the INSERT. A database trigger or concurrent
            // writer must not be able to turn the selected predecessor into a
            // running row between the initial validation and lineage apply.
            ensure_completed_run(&tx, predecessor_run)?;
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
                    ensure_completed_run(&tx, predecessor_run)?;
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::snapshot::{
        CrossVariantComparisonSnapshot, GroupOrigin, GroupRow, MemberRow, PriorityRow, SummaryRow,
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
