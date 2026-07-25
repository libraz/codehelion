//! The read path: every SQL query the CLI needs, as functions.
//!
//! SQL strings live here and nowhere else, so the CLI layer talks in domain
//! types. Result ordering is deterministic everywhere: groups order by their
//! fingerprint bytes (priority ordering joins in with the priority stage),
//! members by their anchor then row id — the same database always yields the
//! same output.

use codehelion_core::features::FeatureKind;
use rusqlite::{OptionalExtension, params};

use crate::{Store, StoreError};

/// Summary of one recorded scan run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// Row id of the run.
    pub id: i64,
    /// Scanned root path.
    pub root_path: String,
    /// Tool version that wrote the run.
    pub tool_version: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// RFC 3339 start time.
    pub started_at: String,
    /// RFC 3339 finish time, if the run completed.
    pub finished_at: Option<String>,
    /// Number of clone groups recorded for the run.
    pub group_count: i64,
}

/// One stored occurrence of a group's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// Hex form of the occurrence's stable finding id.
    pub finding_hex: String,
    /// Anchor: file path relative to the scan root.
    pub file_path: String,
    /// Anchor: 1-based first line.
    pub start_line: Option<i64>,
    /// Anchor: 1-based last line.
    pub end_line: Option<i64>,
    /// Size in tokens.
    pub token_count: i64,
    /// Name of the enclosing unit, when anchored to one.
    pub unit_name: Option<String>,
    /// Whether this is the group's canonical instance.
    pub is_canonical: bool,
}

/// One stored clone group with its members.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredGroup {
    /// Hex form of the group fingerprint.
    pub fingerprint_hex: String,
    /// Clone classification name (`type-1`, `type-2`, ...).
    pub clone_type: String,
    /// Minimum pairwise raw similarity.
    pub score: f64,
    /// Content entropy in bits.
    pub entropy_bits: f64,
    /// Noise marker name, if one fired.
    pub suppress_reason: Option<String>,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// The similarity breakdown, when the mode measured one (Structural).
    pub similarity: Option<StoredSimilarity>,
    /// The group's occurrences.
    pub members: Vec<StoredMember>,
}

/// A stored group's similarity breakdown, one measured dimension per field.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSimilarity {
    /// The composite-weight recipe version.
    pub weight_version: String,
    /// Verbatim leading-token agreement.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement.
    pub control_flow: f64,
    /// Type agreement, or `None` when types were unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit called
    /// anything.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group.
    pub min_pairwise: f64,
    /// The band the verdict was assigned, or `None` for a row written before
    /// the band was recorded. A band is a judgement, so an absent one is
    /// reported as absent rather than derived from the numbers after the fact.
    pub confidence_band: Option<String>,
}

/// One stored finding: the audited row of a group in a run.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFinding {
    /// Hex form of the group fingerprint the finding audits.
    pub group_fingerprint_hex: String,
    /// Audit state (`new`, `unchanged`, `resolved`, ...).
    pub audit_state: String,
    /// Clone confidence.
    pub clone_confidence: f64,
    /// Final priority; the derivation inputs stay on the group and its
    /// members rather than being collapsed into this one number.
    pub final_priority: f64,
    /// Scope of the suppression rule that suppressed the finding, if any
    /// (for example `path_glob` or `inline_comment`).
    pub suppression_scope: Option<String>,
}

/// Detail of one occurrence, looked up by its finding id (for `explain`).
///
/// The lookup carries the owning group's evidence, not just its identity: an
/// occurrence is only interesting together with what made it a finding.
#[derive(Debug, Clone, PartialEq)]
pub struct OccurrenceDetail {
    /// The occurrence itself.
    pub member: StoredMember,
    /// Hex form of the owning group's fingerprint.
    pub group_fingerprint_hex: String,
    /// The owning group's clone type name.
    pub clone_type: String,
    /// The owning group's score.
    pub score: f64,
    /// Number of occurrences in the owning group, this one included.
    pub member_count: i64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// The owning group's similarity breakdown, when the mode measured one.
    pub similarity: Option<StoredSimilarity>,
    /// The rule that suppressed the finding in this run, if one matched.
    pub suppression: Option<StoredSuppressionRef>,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run_id: i64,
}

/// The suppression rule a finding references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuppressionRef {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`, ...).
    pub scope: String,
    /// The rule's pattern.
    pub pattern: String,
}

/// One posting-list entry: an occurrence of a feature hash at a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureOccurrence {
    /// Run the occurrence was recorded in.
    pub scan_run_id: i64,
    /// Enclosing unit row, when anchored to one.
    pub source_unit_id: Option<i64>,
    /// Anchor: first byte covered.
    pub start_byte: i64,
    /// Anchor: one past the last byte covered.
    pub end_byte: i64,
    /// Kind-specific size (window length, subtree node count, ...).
    pub extent: i64,
}

impl Store {
    /// The posting list of one feature hash: every occurrence of `kind`/`hash`,
    /// deterministically ordered by run, unit and anchor. This is the read the
    /// candidate index builds on.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn feature_posting_list(
        &self,
        kind: FeatureKind,
        hash: &[u8; 16],
    ) -> Result<Vec<FeatureOccurrence>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT o.scan_run_id, o.source_unit_id, o.start_byte, o.end_byte, o.extent
             FROM feature_occurrence o
             JOIN feature_fingerprint f ON f.id = o.feature_fingerprint_id
             WHERE f.kind = ?1 AND f.hash = ?2
             ORDER BY o.scan_run_id ASC, o.source_unit_id ASC, o.start_byte ASC, o.id ASC",
        )?;
        let rows = stmt
            .query_map(params![kind.name(), hash.as_slice()], |row| {
                Ok(FeatureOccurrence {
                    scan_run_id: row.get(0)?,
                    source_unit_id: row.get(1)?,
                    start_byte: row.get(2)?,
                    end_byte: row.get(3)?,
                    extent: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// The most recently started scan run, if any.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_run(&self) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                [],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Every clone group of `run_id`, deterministically ordered by
    /// fingerprint bytes, each with its members.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_groups(&self, run_id: i64) -> Result<Vec<StoredGroup>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT g.id, lower(hex(f.hash)), g.clone_type, g.score, g.entropy_bits,
                    g.suppress_reason, g.boilerplate
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        )?;
        let rows: Vec<(i64, StoredGroup)> = stmt
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    StoredGroup {
                        fingerprint_hex: row.get(1)?,
                        clone_type: row.get(2)?,
                        score: row.get(3)?,
                        entropy_bits: row.get(4)?,
                        suppress_reason: row.get(5)?,
                        boilerplate: row.get(6)?,
                        similarity: None,
                        members: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut groups = Vec::with_capacity(rows.len());
        for (group_row_id, mut group) in rows {
            group.similarity = self.group_similarity(group_row_id)?;
            group.members = self.group_members(group_row_id)?;
            groups.push(group);
        }
        Ok(groups)
    }

    /// The similarity breakdown of one group row, or `None` when the mode
    /// measured none (Fast).
    fn group_similarity(&self, group_row_id: i64) -> Result<Option<StoredSimilarity>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT weight_version, lexical, structural, control_flow,
                        type_similarity, api, composite, min_pairwise,
                        confidence_band
                 FROM clone_group_similarity
                 WHERE clone_group_id = ?1",
                params![group_row_id],
                |row| {
                    Ok(StoredSimilarity {
                        weight_version: row.get(0)?,
                        lexical: row.get(1)?,
                        structural: row.get(2)?,
                        control_flow: row.get(3)?,
                        type_similarity: row.get(4)?,
                        api: row.get(5)?,
                        composite: row.get(6)?,
                        min_pairwise: row.get(7)?,
                        confidence_band: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// The members of one group row, ordered by anchor then row id.
    fn group_members(&self, group_row_id: i64) -> Result<Vec<StoredMember>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                    fr.token_count, u.name, m.is_canonical
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             LEFT JOIN source_unit u ON u.id = fr.source_unit_id
             WHERE m.clone_group_id = ?1
             ORDER BY fr.file_path ASC, fr.start_line ASC, fr.id ASC",
        )?;
        let members = stmt
            .query_map(params![group_row_id], map_member)?
            .collect::<Result<_, _>>()?;
        Ok(members)
    }

    /// Every finding of `run_id`, ordered by group fingerprint bytes.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_findings(&self, run_id: i64) -> Result<Vec<StoredFinding>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(gf.hash)), fi.audit_state, fi.clone_confidence, fi.final_priority,
                    s.scope
             FROM finding fi
             JOIN clone_group g ON g.id = fi.clone_group_id
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             WHERE fi.scan_run_id = ?1
             ORDER BY gf.hash ASC",
        )?;
        let findings = stmt
            .query_map(params![run_id], |row| {
                Ok(StoredFinding {
                    group_fingerprint_hex: row.get(0)?,
                    audit_state: row.get(1)?,
                    clone_confidence: row.get(2)?,
                    final_priority: row.get(3)?,
                    suppression_scope: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(findings)
    }

    /// Number of rows in `table` — a diagnostic for `doctor`/`cache status`
    /// and tests. The name is validated against the schema first, so this
    /// never interpolates arbitrary input into SQL.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownTable`] when `table` is not a known table;
    /// otherwise any underlying database error.
    pub fn table_count(&self, table: &str) -> Result<i64, StoreError> {
        let known: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )?;
        if known != 1 {
            return Err(StoreError::UnknownTable {
                table: table.to_string(),
            });
        }
        Ok(self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?)
    }

    /// Look up one occurrence by the hex form of its finding id.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `finding_hex` is not 32 hex digits;
    /// otherwise any underlying database error.
    pub fn occurrence(&self, finding_hex: &str) -> Result<Option<OccurrenceDetail>, StoreError> {
        let bytes = parse_hex_id(finding_hex)?;
        let found = self
            .conn
            .query_row(
                "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                        fr.token_count, u.name, m.is_canonical,
                        lower(hex(gf.hash)), g.clone_type, g.score, g.scan_run_id,
                        g.member_count, g.boilerplate, s.scope, s.pattern, g.id
                 FROM clone_group_member m
                 JOIN fragment fr ON fr.id = m.fragment_id
                 LEFT JOIN source_unit u ON u.id = fr.source_unit_id
                 JOIN clone_group g ON g.id = m.clone_group_id
                 JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
                 LEFT JOIN finding fi ON fi.clone_group_id = g.id
                                     AND fi.scan_run_id = g.scan_run_id
                 LEFT JOIN suppression s ON s.id = fi.suppression_id
                 WHERE m.finding_id = ?1
                 ORDER BY g.scan_run_id DESC
                 LIMIT 1",
                params![bytes.as_slice()],
                |row| {
                    let suppression = row
                        .get::<_, Option<String>>(13)?
                        .map(|scope| -> Result<_, rusqlite::Error> {
                            Ok(StoredSuppressionRef {
                                scope,
                                pattern: row.get(14)?,
                            })
                        })
                        .transpose()?;
                    Ok((
                        OccurrenceDetail {
                            member: map_member(row)?,
                            group_fingerprint_hex: row.get(7)?,
                            clone_type: row.get(8)?,
                            score: row.get(9)?,
                            scan_run_id: row.get(10)?,
                            member_count: row.get(11)?,
                            boilerplate: row.get(12)?,
                            similarity: None,
                            suppression,
                        },
                        row.get::<_, i64>(15)?,
                    ))
                },
            )
            .optional()?;
        let Some((mut detail, group_row_id)) = found else {
            return Ok(None);
        };
        detail.similarity = self.group_similarity(group_row_id)?;
        Ok(Some(detail))
    }
}

fn map_member(row: &rusqlite::Row<'_>) -> Result<StoredMember, rusqlite::Error> {
    Ok(StoredMember {
        finding_hex: row.get(0)?,
        file_path: row.get(1)?,
        start_line: row.get(2)?,
        end_line: row.get(3)?,
        token_count: row.get(4)?,
        unit_name: row.get(5)?,
        is_canonical: row.get::<_, i64>(6)? != 0,
    })
}

/// Parse a 32-digit hex identifier into its 16 bytes.
fn parse_hex_id(hex: &str) -> Result<[u8; 16], StoreError> {
    let malformed = || StoreError::MalformedId {
        id: hex.to_string(),
    };
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = core::str::from_utf8(chunk).map_err(|_| malformed())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_parse_and_reject_malformed_input() {
        let parsed = parse_hex_id("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(parsed[0], 0);
        assert_eq!(parsed[15], 0x0f);
        assert!(parse_hex_id("").is_err());
        assert!(parse_hex_id("zz0102030405060708090a0b0c0d0e0f").is_err());
        assert!(parse_hex_id("00010203").is_err());
    }
}
