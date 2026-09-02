//! Evidence-backed lineage between a new group and a predecessor group.
//!
//! Nothing recomputes lineage after the fact, so an edge is only recorded when
//! both runs asked the same question and the shared member content justifies
//! the continuation.

use rusqlite::OptionalExtension;

use crate::fingerprint::parse_hex_id;
use crate::snapshot::{
    AuditState, BTreeMap, BTreeSet, GroupRow, LineageAdoption, LineageAdoptionResult, StoreError,
    Transaction, params,
};

/// Validate and apply already-parsed lineage edges inside a caller-owned
/// transaction.
pub(in crate::snapshot) fn apply_lineage_adoptions_tx(
    tx: &Transaction<'_>,
    newer_run: i64,
    predecessor_run: i64,
    adoptions: &[ParsedAdoption],
) -> Result<LineageAdoptionResult, StoreError> {
    ensure_comparable_runs_tx(tx, newer_run, predecessor_run)?;
    let mut result = LineageAdoptionResult::default();
    for adoption in adoptions {
        let newer = tx
            .query_row(
                "SELECT g.id, g.lineage_state FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 WHERE g.scan_run_id = ?1 AND f.kind = 'clone_group' AND f.hash = ?2",
                params![newer_run, adoption.group.as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let predecessor = tx
            .query_row(
                "SELECT g.lineage FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 WHERE g.scan_run_id = ?1 AND f.kind = 'clone_group' AND f.hash = ?2",
                params![predecessor_run, adoption.previous_group.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let (Some((newer_group_id, state)), Some(previous_lineage)) = (newer, predecessor) else {
            result.unknown.push(adoption.group_hex.clone());
            continue;
        };
        if state != "new" {
            result.already_connected.push(adoption.group_hex.clone());
            continue;
        }
        if previous_lineage.as_slice() != adoption.lineage.as_slice() {
            return Err(StoreError::InvalidLineageEvidence {
                reason: format!(
                    "predecessor {} does not belong to requested lineage {}",
                    adoption.previous_group_hex, adoption.lineage_hex
                ),
            });
        }
        tx.execute(
            "UPDATE clone_group SET lineage = ?2, lineage_state = 'expanded' WHERE id = ?1",
            params![newer_group_id, adoption.lineage.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO clone_group_lineage_parent
                 (clone_group_id, ordinal, parent_fingerprint, parent_lineage, is_primary,
                  shared_content, compared_content, overlap)
             VALUES (?1, 0, ?2, ?3, 1, ?4, ?5, ?6)",
            params![
                newer_group_id,
                adoption.previous_group.as_slice(),
                adoption.lineage.as_slice(),
                adoption.shared,
                adoption.compared,
                adoption.overlap,
            ],
        )?;
        result.taken.push(adoption.group_hex.clone());
    }
    Ok(result)
}

/// Plan matching lineage edges using rows visible in the caller's transaction.
pub(in crate::snapshot) fn plan_matching_lineages_tx(
    tx: &Transaction<'_>,
    newer_run: i64,
    predecessor_run: i64,
) -> Result<Vec<ParsedAdoption>, StoreError> {
    let newer = lineage_candidates(tx, newer_run)?;
    let predecessors = lineage_candidates(tx, predecessor_run)?;
    matching_adoptions(&newer, &predecessors)
}

pub(super) fn matching_adoptions(
    newer: &BTreeMap<String, LineageCandidate>,
    predecessors: &BTreeMap<String, LineageCandidate>,
) -> Result<Vec<ParsedAdoption>, StoreError> {
    let mut adoptions = Vec::new();
    for (group, candidate) in newer {
        if candidate.state != "new" || candidate.contents.is_empty() {
            continue;
        }
        // A group the predecessor run already held under this fingerprint did
        // not change, so it has nothing to adopt: its history is its own. Its
        // member content can still overlap another predecessor group — split
        // pairs share content by construction — and without this the strongest
        // such overlap would take the unchanged group's identity away and
        // report it as newly connected.
        if predecessors.contains_key(group) {
            continue;
        }
        let Some((previous_group, previous, _)) = predecessors
            .iter()
            .filter_map(|(fingerprint, prior)| {
                let shared = candidate.contents.intersection(&prior.contents).count();
                (fingerprint != group && shared > 0).then_some((fingerprint, prior, shared))
            })
            .filter(|(_, _, shared)| shared.saturating_mul(2) >= candidate.contents.len())
            .max_by(|(left_id, _, left_shared), (right_id, _, right_shared)| {
                left_shared
                    .cmp(right_shared)
                    .then_with(|| right_id.cmp(left_id))
            })
        else {
            continue;
        };
        let shared = candidate.contents.intersection(&previous.contents).count();
        adoptions.push(ParsedAdoption {
            group_hex: group.clone(),
            group: parse_hex_id(group)?,
            previous_group_hex: previous_group.clone(),
            previous_group: parse_hex_id(previous_group)?,
            lineage_hex: previous.lineage.clone(),
            lineage: parse_hex_id(&previous.lineage)?,
            shared: i64::try_from(shared).unwrap_or(i64::MAX),
            // The rule weighed the shared contents against all of the new
            // group's contents, so that is the population the recorded
            // evidence is a share of.
            compared: Some(i64::try_from(candidate.contents.len()).unwrap_or(i64::MAX)),
            overlap: overlap_fraction(shared, candidate.contents.len()),
        });
    }
    Ok(adoptions)
}

/// Reject a lineage edge between two runs that were not asking the same
/// question.
///
/// Root, build variant and analysis mode all have to agree before one run's
/// findings continue another's. A lineage identifier shared across build
/// variants would report a finding compiled under one macro set as the
/// continuation of a finding from another, and nothing recomputes lineage
/// later, so the mistake would stay in the database.
fn ensure_comparable_runs_tx(
    tx: &Transaction<'_>,
    newer_run: i64,
    predecessor_run: i64,
) -> Result<(), StoreError> {
    let newer = run_identity_tx(tx, newer_run)?;
    let predecessor = run_identity_tx(tx, predecessor_run)?;
    if newer == predecessor {
        return Ok(());
    }
    Err(StoreError::InvalidLineageEvidence {
        reason: format!(
            "run {newer_run} and run {predecessor_run} differ in root, \
             build variant or analysis mode"
        ),
    })
}

/// What decides whether two runs are about the same question.
fn run_identity_tx(tx: &Transaction<'_>, run_id: i64) -> Result<(String, i64, String), StoreError> {
    tx.query_row(
        "SELECT root_path, build_variant_id, analysis_mode FROM scan_run WHERE id = ?1",
        params![run_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()?
    .ok_or(StoreError::RunNotFound { run_id })
}

#[allow(
    clippy::cast_precision_loss,
    reason = "the ratio is report evidence; set cardinalities are bounded by one scan"
)]
fn overlap_fraction(shared: usize, total: usize) -> f64 {
    shared as f64 / total as f64
}

pub(super) struct LineageCandidate {
    state: String,
    lineage: String,
    contents: BTreeSet<String>,
}

pub(super) fn lineage_candidates(
    conn: &rusqlite::Connection,
    run_id: i64,
) -> Result<BTreeMap<String, LineageCandidate>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT lower(hex(group_fingerprint.hash)), g.lineage_state, lower(hex(g.lineage)),
                lower(hex(content_fingerprint.hash))
         FROM clone_group g
         JOIN fingerprint group_fingerprint ON group_fingerprint.id = g.group_fingerprint_id
         JOIN clone_group_member member ON member.clone_group_id = g.id
         JOIN fragment fragment ON fragment.id = member.fragment_id
         JOIN fingerprint content_fingerprint ON content_fingerprint.id = fragment.fingerprint_id
         WHERE g.scan_run_id = ?1
         ORDER BY group_fingerprint.hash ASC, content_fingerprint.hash ASC",
    )?;
    let mut candidates = BTreeMap::new();
    for row in statement.query_map(params![run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (group, state, lineage, content) = row?;
        let candidate = candidates.entry(group).or_insert_with(|| LineageCandidate {
            state,
            lineage,
            contents: BTreeSet::new(),
        });
        candidate.contents.insert(content);
    }
    Ok(candidates)
}

pub(in crate::snapshot) struct ParsedAdoption {
    group_hex: String,
    group: [u8; 16],
    previous_group_hex: String,
    previous_group: [u8; 16],
    lineage_hex: String,
    lineage: [u8; 16],
    shared: i64,
    compared: Option<i64>,
    overlap: f64,
}

impl ParsedAdoption {
    pub(super) fn parse(adoption: &LineageAdoption) -> Result<Self, StoreError> {
        if !adoption.overlap.is_finite() || !(0.0..=1.0).contains(&adoption.overlap) {
            return Err(StoreError::InvalidLineageEvidence {
                reason: format!("overlap for group {} is outside 0..=1", adoption.group),
            });
        }
        if adoption
            .compared
            .is_some_and(|total| total < adoption.shared)
        {
            return Err(StoreError::InvalidLineageEvidence {
                reason: format!(
                    "group {} shares more content than it was compared on",
                    adoption.group
                ),
            });
        }
        Ok(Self {
            group_hex: adoption.group.clone(),
            group: parse_hex_id(&adoption.group)?,
            previous_group_hex: adoption.previous_group.clone(),
            previous_group: parse_hex_id(&adoption.previous_group)?,
            lineage_hex: adoption.lineage.clone(),
            lineage: parse_hex_id(&adoption.lineage)?,
            shared: i64::try_from(adoption.shared).unwrap_or(i64::MAX),
            compared: adoption
                .compared
                .map(|total| i64::try_from(total).unwrap_or(i64::MAX)),
            overlap: adoption.overlap,
        })
    }
}

pub(super) const fn lineage_state_name(state: AuditState) -> &'static str {
    match state {
        AuditState::New => "new",
        AuditState::Expanded => "expanded",
    }
}

pub(super) fn write_lineage_parents(
    tx: &Transaction<'_>,
    group_row_id: i64,
    group: &GroupRow,
) -> Result<(), StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO clone_group_lineage_parent
             (clone_group_id, ordinal, parent_fingerprint, parent_lineage, is_primary,
              shared_content, compared_content, overlap)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for (ordinal, parent) in group.history.parents.iter().enumerate() {
        insert.execute(params![
            group_row_id,
            i64::try_from(ordinal).unwrap_or(i64::MAX),
            parent.fingerprint.as_bytes().as_slice(),
            parent.lineage.as_bytes().as_slice(),
            parent.primary,
            i64::try_from(parent.shared_content).unwrap_or(i64::MAX),
            parent
                .compared_content
                .map(|total| i64::try_from(total).unwrap_or(i64::MAX)),
            parent.overlap,
        ])?;
    }
    Ok(())
}
