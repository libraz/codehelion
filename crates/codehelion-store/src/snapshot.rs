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
use codehelion_core::features::{
    FEATURE_SCHEMA_VERSION, FeatureKind, SHAPE_TAG_SLOTS, UnitFeatures,
};
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

/// A clone group's similarity breakdown, one measured dimension per field.
///
/// Persisted as one `clone_group_similarity` row. Every dimension stays
/// visible; there is no single collapsed score. `type_similarity` is `None`
/// when types are unavailable (Structural mode).
#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityBreakdownRow {
    /// The composite-weight recipe version this was scored under.
    pub weight_version: String,
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement (a syntactic approximation).
    pub control_flow: f64,
    /// Type agreement, or `None` when types are unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement.
    pub api: f64,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
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
    /// The similarity breakdown, when the mode measured one (Structural). Fast
    /// groups leave this `None`.
    pub similarity: Option<SimilarityBreakdownRow>,
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

/// The candidate-extraction features of one unit, ready to persist.
///
/// A row pairs a unit (by its index into [`Snapshot::units`]) with the
/// hash-valued feature occurrences it produced and its scalar features
/// (characteristic vector and control-flow profile). Feature hashes are
/// candidate-index keys, not stable identifiers; they are stored apart from
/// the stable [`fingerprint`](crate::schema) rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureRow {
    /// Index into [`Snapshot::units`] of the unit these features describe.
    pub host_unit: usize,
    /// The feature recipe version (`FEATURE_SCHEMA_VERSION`) these were
    /// derived under.
    pub feature_schema_version: &'static str,
    /// Characteristic-vector shape-tag counts.
    pub vector_counts: [u32; SHAPE_TAG_SLOTS],
    /// Deepest root-to-leaf path in the unit subtree.
    pub max_depth: u32,
    /// Total nodes in the unit subtree.
    pub node_count: u32,
    /// Control ops emitted for the unit.
    pub cfg_op_count: u32,
    /// Deepest loop nesting in the unit subtree.
    pub cfg_max_loop_depth: u32,
    /// Two-way conditionals in the unit subtree.
    pub cfg_branch_count: u32,
    /// The unit's hash-valued feature occurrences (windows, subtrees, cfg,
    /// api), each a posting-list entry.
    pub occurrences: Vec<FeatureOccurrenceRow>,
}

/// One occurrence of a feature hash at a source location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureOccurrenceRow {
    /// Which feature family produced the hash.
    pub kind: FeatureKind,
    /// The 16-byte feature hash.
    pub hash: [u8; 16],
    /// Anchor: first byte the occurrence covers.
    pub start_byte: usize,
    /// Anchor: one past the last byte the occurrence covers.
    pub end_byte: usize,
    /// Kind-specific size: window length, subtree node count, cfg op count or
    /// api-call count.
    pub extent: u32,
}

impl FeatureRow {
    /// Build a persistable row from a unit's extracted features, tagging it
    /// with its index into [`Snapshot::units`].
    #[must_use]
    pub fn from_unit(host_unit: usize, unit: &UnitFeatures) -> Self {
        let mut occurrences = Vec::new();
        for window in &unit.windows {
            occurrences.push(FeatureOccurrenceRow {
                kind: FeatureKind::StatementWindow,
                hash: *window.hash.as_bytes(),
                start_byte: window.range.start,
                end_byte: window.range.end,
                extent: clamp_u32(window.length),
            });
        }
        for subtree in &unit.subtrees {
            occurrences.push(FeatureOccurrenceRow {
                kind: FeatureKind::Subtree,
                hash: *subtree.hash.as_bytes(),
                start_byte: subtree.range.start,
                end_byte: subtree.range.end,
                extent: clamp_u32(subtree.node_count),
            });
        }
        occurrences.push(FeatureOccurrenceRow {
            kind: FeatureKind::Cfg,
            hash: *unit.cfg.hash.as_bytes(),
            start_byte: unit.range.start,
            end_byte: unit.range.end,
            extent: unit.cfg.op_count,
        });
        let api_extent = clamp_u32(unit.api.names.len());
        for (kind, hash) in [
            (FeatureKind::ApiCallSequence, unit.api.sequence_hash),
            (FeatureKind::ApiCallMultiset, unit.api.multiset_hash),
        ] {
            occurrences.push(FeatureOccurrenceRow {
                kind,
                hash: *hash.as_bytes(),
                start_byte: unit.range.start,
                end_byte: unit.range.end,
                extent: api_extent,
            });
        }
        Self {
            host_unit,
            feature_schema_version: FEATURE_SCHEMA_VERSION,
            vector_counts: unit.vector.counts,
            max_depth: unit.vector.max_depth,
            node_count: unit.vector.node_count,
            cfg_op_count: unit.cfg.op_count,
            cfg_max_loop_depth: unit.cfg.max_loop_depth,
            cfg_branch_count: unit.cfg.branch_count,
            occurrences,
        }
    }
}

fn clamp_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
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
    /// Per-unit candidate-extraction features, referencing [`Self::units`] by
    /// index. Empty in Fast mode, which derives no structural features.
    pub features: Vec<FeatureRow>,
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
    // Units first: members and features reference them by index.
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
    write_features(tx, snapshot, run_id, variant_id, &unit_row_ids)?;
    Ok(run_id)
}

/// Persist per-unit candidate-extraction features: the scalar `unit_feature`
/// row and every hash occurrence, deduplicating feature fingerprints by their
/// full analysis context.
fn write_features(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
    unit_row_ids: &[i64],
) -> Result<(), StoreError> {
    for feature in &snapshot.features {
        let unit_row_id =
            *unit_row_ids
                .get(feature.host_unit)
                .ok_or(StoreError::UnknownUnitIndex {
                    index: feature.host_unit,
                    units: unit_row_ids.len(),
                })?;
        let language = snapshot.units[feature.host_unit].language;
        let frontend_version = frontend_version_for(snapshot, language);
        tx.execute(
            "INSERT INTO unit_feature
                 (source_unit_id, feature_schema_version, vector_counts,
                  max_depth, node_count, cfg_op_count, cfg_max_loop_depth,
                  cfg_branch_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                unit_row_id,
                feature.feature_schema_version,
                encode_counts(&feature.vector_counts),
                feature.max_depth,
                feature.node_count,
                feature.cfg_op_count,
                feature.cfg_max_loop_depth,
                feature.cfg_branch_count,
            ],
        )?;
        for occ in &feature.occurrences {
            let fp_id = upsert_feature_fingerprint(
                tx,
                occ.kind,
                &occ.hash,
                feature.feature_schema_version,
                frontend_version,
                snapshot.variant.mode.name(),
                language.name(),
                variant_id,
            )?;
            tx.execute(
                "INSERT INTO feature_occurrence
                     (scan_run_id, feature_fingerprint_id, source_unit_id,
                      start_byte, end_byte, extent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run_id,
                    fp_id,
                    unit_row_id,
                    i64::try_from(occ.start_byte).unwrap_or(i64::MAX),
                    i64::try_from(occ.end_byte).unwrap_or(i64::MAX),
                    occ.extent,
                ],
            )?;
        }
    }
    Ok(())
}

/// Little-endian encoding of the characteristic-vector counts, one `u32` per
/// shape-tag slot.
fn encode_counts(counts: &[u32; SHAPE_TAG_SLOTS]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SHAPE_TAG_SLOTS * 4);
    for &count in counts {
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    bytes
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

    write_group_similarity(tx, group_row_id, group.similarity.as_ref())?;

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

/// Persist a group's similarity breakdown, when the mode measured one.
fn write_group_similarity(
    tx: &Transaction<'_>,
    group_row_id: i64,
    similarity: Option<&SimilarityBreakdownRow>,
) -> Result<(), StoreError> {
    let Some(similarity) = similarity else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO clone_group_similarity
             (clone_group_id, weight_version, lexical, structural,
              control_flow, type_similarity, api, composite, min_pairwise)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            group_row_id,
            similarity.weight_version,
            similarity.lexical,
            similarity.structural,
            similarity.control_flow,
            similarity.type_similarity,
            similarity.api,
            similarity.composite,
            similarity.min_pairwise,
        ],
    )?;
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

/// Insert (or reuse) a feature-fingerprint row and return its id. Feature
/// fingerprints deduplicate on their full context, `feature_schema_version`
/// included, so identical hashes from incompatible recipes stay distinct.
#[allow(clippy::too_many_arguments)] // one row, one call site per column set
fn upsert_feature_fingerprint(
    tx: &Transaction<'_>,
    kind: FeatureKind,
    hash: &[u8; 16],
    feature_schema_version: &str,
    frontend_version: &str,
    mode: &str,
    language: &str,
    variant_id: i64,
) -> Result<i64, StoreError> {
    tx.execute(
        "INSERT OR IGNORE INTO feature_fingerprint
             (kind, hash_algo, hash, feature_schema_version, frontend_version,
              analysis_mode, language, build_variant_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            kind.name(),
            HASH_ALGORITHM,
            hash.as_slice(),
            feature_schema_version,
            frontend_version,
            mode,
            language,
            variant_id,
        ],
    )?;
    Ok(tx.query_row(
        "SELECT id FROM feature_fingerprint
         WHERE kind = ?1 AND hash_algo = ?2 AND hash = ?3
           AND feature_schema_version = ?4 AND frontend_version = ?5
           AND analysis_mode = ?6 AND language = ?7 AND build_variant_id = ?8",
        params![
            kind.name(),
            HASH_ALGORITHM,
            hash.as_slice(),
            feature_schema_version,
            frontend_version,
            mode,
            language,
            variant_id,
        ],
        |row| row.get(0),
    )?)
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
