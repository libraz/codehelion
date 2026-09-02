//! Pre-write checks that reject a snapshot before any row becomes durable.

use crate::lifecycle::ensure_completed_run;
use crate::snapshot::{
    BTreeMap, BTreeSet, OptionalExtension, Snapshot, StagedSnapshotPart, StoreError, Transaction,
    params,
};

/// Reject a silent stable-ID collision before a snapshot starts writing.
pub(super) fn validate_group_fingerprints(snapshot: &Snapshot<'_>) -> Result<(), StoreError> {
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

pub(super) fn validate_snapshot_parts(
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
            ensure_completed_run(tx, predecessor_run)?;
        }
    }
    Ok(())
}

/// Validate and combine the opaque suppression policy from every partition
/// participating in one invocation. Different partitions may contribute
/// different rules; a repeated rule is valid only when its reason agrees.
pub(super) fn validate_suppression_union(
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
