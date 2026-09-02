//! Staged suppression policy and the cleanup a failed invocation owes.
//!
//! Staging leaves the active policy untouched until finalization, so an
//! interrupted multi-partition invocation cannot change what prior completed
//! runs are read against.

use crate::snapshot::{BTreeMap, BTreeSet, StagedSnapshotPart, StoreError, Transaction, params};

#[derive(Debug, Clone, Copy)]
pub(super) enum SnapshotStatus {
    Running,
    Completed,
}

impl SnapshotStatus {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
        }
    }
}

pub(super) fn cleanup_snapshot_parts_tx(
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
pub(super) fn activate_staged_suppressions(
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

pub(super) fn cleanup_staged_suppressions(
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
