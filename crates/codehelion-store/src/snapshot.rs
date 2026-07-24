//! The snapshot write path.
//!
//! A scan's results are committed as one atomic snapshot: every row of a
//! [`Snapshot`] lands inside a single transaction, so an interrupted write
//! leaves no partial scan in the database — the run either exists completely
//! or not at all.
//!
//! Fingerprint rows are content-addressed: identical identifiers produced
//! under the identical analysis context share one row across scans, which is
//! what lets a later scan correlate its groups with an earlier one by
//! fingerprint identity. Everything positional (paths, line ranges) is
//! written as anchor columns on the per-scan rows and participates in no
//! identity.

use codehelion_core::discovery::{BuildVariant, Language};
use codehelion_core::engine::CloneType;
use codehelion_core::frontend::UnitKind;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, HASH_ALGORITHM, UnitFingerprint,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{Store, StoreError};

/// One source unit observed by the scan.
#[derive(Debug, Clone)]
pub struct UnitRow {
    /// The unit's raw content fingerprint.
    pub fingerprint: UnitFingerprint,
    /// Language of the file the unit lives in.
    pub language: Language,
    /// The unit's kind.
    pub kind: UnitKind,
    /// Best-effort human label; never an identity.
    pub name: Option<String>,
    /// Anchor: path of the file, relative to the scan root.
    pub file_path: String,
    /// Anchor: 1-based first line.
    pub start_line: u32,
    /// Anchor: 1-based last line.
    pub end_line: u32,
    /// Size in tokens.
    pub token_count: usize,
}

/// One occurrence of a clone group's content.
#[derive(Debug, Clone)]
pub struct MemberRow {
    /// Content fingerprint of the matched slice.
    pub content: FragmentFingerprint,
    /// Stable identifier of this occurrence.
    pub finding: FindingId,
    /// Language of the file the occurrence lives in.
    pub language: Language,
    /// Index into [`Snapshot::units`] of the enclosing unit, if any.
    pub host_unit: Option<usize>,
    /// Anchor: path of the file, relative to the scan root.
    pub file_path: String,
    /// Anchor: 1-based first line.
    pub start_line: u32,
    /// Anchor: 1-based last line.
    pub end_line: u32,
    /// Size in tokens.
    pub token_count: usize,
}

/// One clone group with its members.
#[derive(Debug, Clone)]
pub struct GroupRow {
    /// The group's stable fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Clone classification.
    pub clone_type: CloneType,
    /// Minimum pairwise raw similarity across the group.
    pub score: f64,
    /// Shannon entropy of the shared content.
    pub entropy_bits: f64,
    /// Noise marker name (`low-entropy` / `high-frequency`), if one fired.
    pub suppress_reason: Option<String>,
    /// Index into [`Snapshot::suppressions`] of the rule that suppressed this
    /// group's finding, if one matched.
    pub suppressed_by: Option<usize>,
    /// Priority of this group's finding; the inputs it was derived from stay
    /// available on the group and member rows.
    pub final_priority: f64,
    /// The occurrences, in deterministic order; the first is canonical.
    pub members: Vec<MemberRow>,
}

/// One suppression rule active for the scan.
///
/// Rules are content-addressed by `(scope, pattern)`: recording the same rule
/// again reuses the existing row, so findings from different runs suppressed
/// by the same rule reference one row.
#[derive(Debug, Clone)]
pub struct SuppressionRuleRow {
    /// Rule scope; must be one of the schema's suppression scopes (for
    /// example `path_glob` or `inline_comment`).
    pub scope: String,
    /// The rule's pattern (a glob, a marker text, ...).
    pub pattern: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

/// Everything one scan run persists.
#[derive(Debug, Clone)]
pub struct Snapshot<'a> {
    /// Scanned root, as given by the user.
    pub root_path: &'a str,
    /// The tool version that produced the results.
    pub tool_version: &'a str,
    /// Hash of the effective configuration.
    pub config_hash: &'a str,
    /// RFC 3339 start time, supplied by the caller.
    pub started_at: &'a str,
    /// RFC 3339 finish time, supplied by the caller.
    pub finished_at: &'a str,
    /// The build variant the scan ran under.
    pub variant: &'a BuildVariant,
    /// Active `(component, version)` pairs, e.g. `("frontend.rust",
    /// "rust-lexer-v0")`.
    pub detector_versions: &'a [(String, String)],
    /// Suppression rules active for this scan, referenced by
    /// [`GroupRow::suppressed_by`].
    pub suppressions: Vec<SuppressionRuleRow>,
    /// Units observed in the scanned sources.
    pub units: Vec<UnitRow>,
    /// Detected clone groups.
    pub groups: Vec<GroupRow>,
}

impl Store {
    /// Persist `snapshot` as one atomic transaction and return the new scan
    /// run's row id.
    ///
    /// # Errors
    ///
    /// Any failure — malformed input (such as a member referencing a
    /// non-existent unit) or an underlying database error — rolls the whole
    /// snapshot back; no partial scan run is ever left behind.
    pub fn record_snapshot(&mut self, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        let run_id = write_snapshot(&tx, snapshot)?;
        tx.commit()?;
        Ok(run_id)
    }
}

fn write_snapshot(tx: &Transaction<'_>, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
    let variant_id = upsert_variant(tx, snapshot.variant)?;

    tx.execute(
        "INSERT INTO scan_run
             (build_variant_id, root_path, tool_version, config_hash,
              analysis_mode, started_at, finished_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'completed')",
        params![
            variant_id,
            snapshot.root_path,
            snapshot.tool_version,
            snapshot.config_hash,
            snapshot.variant.mode.name(),
            snapshot.started_at,
            snapshot.finished_at,
        ],
    )?;
    let run_id = tx.last_insert_rowid();

    for (component, version) in snapshot.detector_versions {
        tx.execute(
            "INSERT OR IGNORE INTO detector_version (component, version) VALUES (?1, ?2)",
            params![component, version],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO scan_run_detector_version (scan_run_id, detector_version_id)
             SELECT ?1, id FROM detector_version WHERE component = ?2 AND version = ?3",
            params![run_id, component, version],
        )?;
    }

    let suppression_row_ids = write_suppressions(tx, &snapshot.suppressions)?;
    // Units first: members reference them by index.
    let unit_row_ids = write_units(tx, snapshot, run_id, variant_id)?;
    for group in &snapshot.groups {
        write_group(
            tx,
            snapshot,
            run_id,
            variant_id,
            group,
            &unit_row_ids,
            &suppression_row_ids,
        )?;
    }
    Ok(run_id)
}

/// Record the active suppression rules, reusing existing `(scope, pattern)`
/// rows so rules stay content-addressed across runs.
fn write_suppressions(
    tx: &Transaction<'_>,
    rules: &[SuppressionRuleRow],
) -> Result<Vec<i64>, StoreError> {
    let mut row_ids = Vec::with_capacity(rules.len());
    for rule in rules {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM suppression
                 WHERE scope = ?1 AND pattern = ?2 AND active = 1",
                params![rule.scope, rule.pattern],
                |row| row.get(0),
            )
            .optional()?;
        let id = if let Some(id) = existing {
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
    for unit in &snapshot.units {
        let fp_id = upsert_fingerprint(
            tx,
            "unit",
            unit.fingerprint.as_bytes(),
            snapshot,
            variant_id,
            unit.language,
        )?;
        tx.execute(
            "INSERT INTO source_unit
                 (scan_run_id, fingerprint_id, language, unit_kind, name,
                  file_path, start_line, end_line, token_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                run_id,
                fp_id,
                unit.language.name(),
                unit.kind.name(),
                unit.name,
                unit.file_path,
                unit.start_line,
                unit.end_line,
                i64::try_from(unit.token_count).unwrap_or(i64::MAX),
            ],
        )?;
        unit_row_ids.push(tx.last_insert_rowid());
    }
    Ok(unit_row_ids)
}

#[allow(clippy::too_many_arguments)] // transaction hand-off, one call site
fn write_group(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
    group: &GroupRow,
    unit_row_ids: &[i64],
    suppression_row_ids: &[i64],
) -> Result<(), StoreError> {
    let group_fp_id =
        upsert_group_fingerprint(tx, group.fingerprint.as_bytes(), snapshot, variant_id)?;
    tx.execute(
        "INSERT INTO clone_group
             (scan_run_id, group_fingerprint_id, clone_type, member_count,
              score, entropy_bits, suppress_reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            run_id,
            group_fp_id,
            group.clone_type.name(),
            i64::try_from(group.members.len()).unwrap_or(i64::MAX),
            group.score,
            group.entropy_bits,
            group.suppress_reason,
        ],
    )?;
    let group_row_id = tx.last_insert_rowid();

    // The audited row for this group in this run. Differencing against
    // earlier runs is a later stage; every finding starts as `new`.
    let suppression_row_id = match group.suppressed_by {
        Some(index) => Some(*suppression_row_ids.get(index).ok_or(
            StoreError::UnknownSuppressionIndex {
                index,
                rules: suppression_row_ids.len(),
            },
        )?),
        None => None,
    };
    tx.execute(
        "INSERT INTO finding
             (scan_run_id, clone_group_id, audit_state, suppression_id,
              clone_confidence, final_priority)
         VALUES (?1, ?2, 'new', ?3, ?4, ?5)",
        params![
            run_id,
            group_row_id,
            suppression_row_id,
            group.score,
            group.final_priority,
        ],
    )?;

    for (index, member) in group.members.iter().enumerate() {
        let host_row_id = match member.host_unit {
            Some(unit_index) => Some(*unit_row_ids.get(unit_index).ok_or(
                StoreError::UnknownUnitIndex {
                    index: unit_index,
                    units: unit_row_ids.len(),
                },
            )?),
            None => None,
        };
        let fragment_fp_id = upsert_fingerprint(
            tx,
            "fragment",
            member.content.as_bytes(),
            snapshot,
            variant_id,
            member.language,
        )?;
        tx.execute(
            "INSERT INTO fragment
                 (scan_run_id, source_unit_id, fingerprint_id, fragment_kind,
                  file_path, start_line, end_line, token_count)
             VALUES (?1, ?2, ?3, 'matched_run', ?4, ?5, ?6, ?7)",
            params![
                run_id,
                host_row_id,
                fragment_fp_id,
                member.file_path,
                member.start_line,
                member.end_line,
                i64::try_from(member.token_count).unwrap_or(i64::MAX),
            ],
        )?;
        let fragment_row_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO clone_group_member
                 (clone_group_id, fragment_id, finding_id, is_canonical)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group_row_id,
                fragment_row_id,
                member.finding.as_bytes().as_slice(),
                i64::from(index == 0),
            ],
        )?;
    }
    Ok(())
}

fn upsert_variant(tx: &Transaction<'_>, variant: &BuildVariant) -> Result<i64, StoreError> {
    tx.execute(
        "INSERT OR IGNORE INTO build_variant
             (variant_fingerprint, canonical, analysis_mode, normalization_version)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            variant.fingerprint(),
            variant.canonical(),
            variant.mode.name(),
            variant.normalization_version,
        ],
    )?;
    Ok(tx.query_row(
        "SELECT id FROM build_variant WHERE variant_fingerprint = ?1",
        params![variant.fingerprint()],
        |row| row.get(0),
    )?)
}

fn upsert_fingerprint(
    tx: &Transaction<'_>,
    kind: &str,
    hash: &[u8; 16],
    snapshot: &Snapshot<'_>,
    variant_id: i64,
    language: Language,
) -> Result<i64, StoreError> {
    let frontend_version = frontend_version_for(snapshot, language);
    insert_fingerprint_row(
        tx,
        kind,
        hash,
        snapshot.variant.normalization_version,
        frontend_version,
        snapshot.variant.mode.name(),
        language.name(),
        variant_id,
    )
}

fn upsert_group_fingerprint(
    tx: &Transaction<'_>,
    hash: &[u8; 16],
    snapshot: &Snapshot<'_>,
    variant_id: i64,
) -> Result<i64, StoreError> {
    // Group fingerprints span languages and frontends; both columns hold the
    // empty string so the UNIQUE constraint still deduplicates them.
    insert_fingerprint_row(
        tx,
        "clone_group",
        hash,
        snapshot.variant.normalization_version,
        "",
        snapshot.variant.mode.name(),
        "",
        variant_id,
    )
}

#[allow(clippy::too_many_arguments)] // one row, one call site per column set
fn insert_fingerprint_row(
    tx: &Transaction<'_>,
    kind: &str,
    hash: &[u8; 16],
    normalization_version: u32,
    frontend_version: &str,
    mode: &str,
    language: &str,
    variant_id: i64,
) -> Result<i64, StoreError> {
    tx.execute(
        "INSERT OR IGNORE INTO fingerprint
             (kind, hash_algo, hash, normalization_version, frontend_version,
              analysis_mode, language, build_variant_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            kind,
            HASH_ALGORITHM,
            hash.as_slice(),
            normalization_version,
            frontend_version,
            mode,
            language,
            variant_id,
        ],
    )?;
    Ok(tx.query_row(
        "SELECT id FROM fingerprint
         WHERE kind = ?1 AND hash_algo = ?2 AND hash = ?3
           AND normalization_version = ?4 AND frontend_version = ?5
           AND analysis_mode = ?6 AND language = ?7 AND build_variant_id = ?8",
        params![
            kind,
            HASH_ALGORITHM,
            hash.as_slice(),
            normalization_version,
            frontend_version,
            mode,
            language,
            variant_id,
        ],
        |row| row.get(0),
    )?)
}

/// The frontend version active for `language` in this snapshot, from the
/// declared detector versions (`frontend.<language>` component).
fn frontend_version_for<'a>(snapshot: &'a Snapshot<'_>, language: Language) -> &'a str {
    let component = match language {
        Language::Rust => "frontend.rust",
        Language::C => "frontend.c",
        Language::Cpp => "frontend.cpp",
    };
    snapshot
        .detector_versions
        .iter()
        .find(|(c, _)| c == component)
        .map_or("unknown", |(_, v)| v.as_str())
}
