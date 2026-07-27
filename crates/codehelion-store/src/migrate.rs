//! Carrying recorded history across a change in how identifiers are made.
//!
//! A stable id is a hash of the rules as much as of the code, so improving a
//! rule moves every id computed under it. The audit database then holds two
//! runs of one tree that share not one identifier, and the comparison between
//! them reports every group as gone and every group as new — a year of
//! recorded history ending in a release note.
//!
//! The way across is not content, because content ids moved too. It is place:
//! the same tree read twice puts the same duplication in the same files and
//! units, whatever it is called afterwards. The caller works out which group
//! of the new run stands where a group of the old one stood; this module
//! writes that conclusion down, so the run after the migration compares
//! against a history that reaches back past it.
//!
//! # What is not rewritten
//!
//! A group of the newer run that already descends from something is left
//! exactly as it is, and reported rather than overwritten. Having a parent
//! means the ordinary comparison matched it on content, which means the rule
//! change did not touch it — its history is already right, and a migration
//! that replaced it would be substituting a guess from placement for an answer
//! the evidence supported.

use rusqlite::{OptionalExtension, Transaction, params};

use crate::query::parse_hex_id;
use crate::{Store, StoreError};

/// One group of a run taking over the history a group of an earlier run
/// belonged to.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageAdoption {
    /// Hex group fingerprint of the group in the run being rewritten.
    pub group: String,
    /// Hex group fingerprint of the group whose history it takes over.
    pub previous_group: String,
    /// Hex id of that history.
    pub lineage: String,
    /// Occurrences the two groups hold in the same place.
    pub shared: usize,
    /// Shared places as a fraction of the smaller group.
    pub overlap: f64,
}

/// What a rewrite did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Adopted {
    /// Groups whose history now reaches back past the rule change.
    pub taken: Vec<String>,
    /// Groups left alone because the ordinary comparison had already
    /// connected them, and an answer from evidence outranks one from
    /// placement.
    pub already_connected: Vec<String>,
    /// Groups neither run holds, named so a caller pointed at the wrong run
    /// finds out rather than reading a silent zero.
    pub unknown: Vec<String>,
}

impl Store {
    /// Record that each group of `run_id` continues the history its
    /// counterpart in `previous_run_id` belonged to.
    ///
    /// Applied as one transaction: a partly rewritten history is worse than
    /// one that was never rewritten, because it cannot be told apart from a
    /// tree where half the duplication genuinely moved.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when an identifier is not 32 hex digits;
    /// otherwise any underlying database error.
    pub fn adopt_lineage(
        &mut self,
        run_id: i64,
        previous_run_id: i64,
        adoptions: &[LineageAdoption],
    ) -> Result<Adopted, StoreError> {
        let tx = self.conn.transaction()?;
        let mut result = Adopted::default();
        for adoption in adoptions {
            let Some(child) = fingerprint_row(&tx, run_id, &adoption.group)? else {
                result.unknown.push(adoption.group.clone());
                continue;
            };
            if has_parent(&tx, run_id, child)? {
                result.already_connected.push(adoption.group.clone());
                continue;
            }
            let Some(parent) = fingerprint_row(&tx, previous_run_id, &adoption.previous_group)?
            else {
                result.unknown.push(adoption.previous_group.clone());
                continue;
            };
            adopt(&tx, run_id, child, parent, adoption)?;
            result.taken.push(adoption.group.clone());
        }
        tx.commit()?;
        Ok(result)
    }
}

/// Point one group at a history and record the connection it came through.
fn adopt(
    tx: &Transaction<'_>,
    run_id: i64,
    child: i64,
    parent: i64,
    adoption: &LineageAdoption,
) -> Result<(), StoreError> {
    let lineage = parse_hex_id(&adoption.lineage)?;
    tx.execute(
        "UPDATE group_lineage SET lineage_id = ?1
         WHERE scan_run_id = ?2 AND group_fingerprint_id = ?3",
        params![lineage.as_slice(), run_id, child],
    )?;
    tx.execute(
        "INSERT INTO group_lineage_edge
             (scan_run_id, child_group_fingerprint_id, parent_group_fingerprint_id,
              parent_lineage_id, is_primary, shared_content, overlap)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
         ON CONFLICT (scan_run_id, child_group_fingerprint_id,
                      parent_group_fingerprint_id) DO NOTHING",
        params![
            run_id,
            child,
            parent,
            lineage.as_slice(),
            i64::try_from(adoption.shared).unwrap_or(i64::MAX),
            adoption.overlap,
        ],
    )?;
    Ok(())
}

/// The fingerprint row a group of `run_id` is keyed by, or `None` when the run
/// holds no such group.
///
/// Scoped to the run rather than looked up by hash alone: one hash can have a
/// fingerprint row per build variant and rule set, and an edge has to name the
/// row the run in question wrote.
fn fingerprint_row(
    tx: &Transaction<'_>,
    run_id: i64,
    group_hex: &str,
) -> Result<Option<i64>, StoreError> {
    let bytes = parse_hex_id(group_hex)?;
    Ok(tx
        .query_row(
            "SELECT g.group_fingerprint_id
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             WHERE g.scan_run_id = ?1 AND f.hash = ?2",
            params![run_id, bytes.as_slice()],
            |row| row.get(0),
        )
        .optional()?)
}

/// Whether the ordinary comparison already found this group a past.
fn has_parent(tx: &Transaction<'_>, run_id: i64, child: i64) -> Result<bool, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM group_lineage_edge
         WHERE scan_run_id = ?1 AND child_group_fingerprint_id = ?2",
        params![run_id, child],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}
