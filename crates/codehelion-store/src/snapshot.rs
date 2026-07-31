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

use std::collections::BTreeSet;

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{BuildConfiguration, BuildVariant, Language};
use codehelion_core::features::{
    FEATURE_SCHEMA_VERSION, FeatureKind, SHAPE_TAG_SLOTS, UnitFeatures,
};
use codehelion_core::frontend::UnitKind;
use codehelion_core::semantic::{SOG_SCHEMA_VERSION, SemanticOperationGraph};
use codehelion_core::stable_id::{
    CloneGroupFingerprint, CrossLanguageComparisonId, CrossLanguageGroupId,
    CrossVariantComparisonId, CrossVariantGroupId, FindingId, FragmentFingerprint, HASH_ALGORITHM,
    UnitFingerprint,
};
use codehelion_core::verify::Confidence;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::compiler::{CompilerHelperRow, CompilerUnitRow};
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

/// Where a group's finding was ranked, as separated measures.
///
/// Persisted onto the `finding` row, one column per measure. The composed
/// value is stored beside the measures rather than in place of them, so a
/// stored run can be asked why a finding was ranked where it was and not only
/// where that was.
///
/// The three reserved measures have no analysis behind them yet and are stored
/// as null. Null rather than zero: a measure nobody took and a measure that
/// came out at nothing are different facts about a run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PriorityRow {
    /// How sure the finding is duplication worth reporting.
    pub clone_confidence: f64,
    /// What keeping the copies in step costs.
    pub maintenance_risk: f64,
    /// What removing the duplication would cost.
    pub refactoring_difficulty: f64,
    /// The composed ranking value.
    pub final_priority: f64,
    /// How sure the finding is semantically equivalent. Reserved.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact. Reserved.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are. Reserved.
    pub savings_confidence: Option<f64>,
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
    /// Call-name multiset agreement, or `None` when neither unit calls
    /// anything and there was nothing to compare.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
    /// The band the verdict was assigned, which the numbers alone do not
    /// determine: it is the weakest band across the group's internal edges,
    /// lowered when no type evidence was available.
    pub confidence_band: Confidence,
}

/// One clone group with its members.
#[derive(Debug, Clone)]
pub struct GroupRow {
    /// The group's stable fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Clone classification.
    pub clone_type: CloneClass,
    /// What the members are: whole units, or runs of statements inside them.
    pub member_scope: CloneScope,
    /// Whether every member is test code. A recorded fact about the code, as
    /// `boilerplate` is: what a report does with it is a separate decision.
    pub test_code: bool,
    /// Whether this group is a verified pair that no larger group could hold,
    /// and so the one kind of group whose members appear in another too.
    pub split_pair: bool,
    /// Minimum pairwise raw similarity across the group.
    pub score: f64,
    /// Shannon entropy of the shared content.
    pub entropy_bits: f64,
    /// Noise marker name (`low-entropy` / `high-frequency`), if one fired.
    pub suppress_reason: Option<String>,
    /// The boilerplate shape every member matches, when they all match one.
    /// A recorded fact about the code, independent of what policy does with
    /// it.
    pub boilerplate: Option<Boilerplate>,
    /// Whether the members differ from each other by one integer width and
    /// nothing else. Recorded on the same footing as `boilerplate`, and kept
    /// apart from it because it describes how the members differ rather than
    /// what any one of them does.
    pub width_family: bool,
    /// Statements each member covers, for a group whose members are runs
    /// inside units; `None` for a whole-unit group, whose extent is the unit.
    pub statements: Option<u32>,
    /// Index into [`Snapshot::suppressions`] of the rule that suppressed this
    /// group's finding, if one matched.
    pub suppressed_by: Option<usize>,
    /// Where the group's finding was ranked, and on what grounds. The facts it
    /// was derived from stay available on the group and member rows.
    pub priority: PriorityRow,
    /// The similarity breakdown, when the mode measured one (Structural). Fast
    /// groups leave this `None`.
    pub similarity: Option<SimilarityBreakdownRow>,
    /// Registered SOG evidence for a restricted semantic finding. `None` for
    /// textual and structural clone classes.
    pub semantic: Option<SemanticEvidenceRow>,
    /// The occurrences, in deterministic order; the first is canonical.
    pub members: Vec<MemberRow>,
}

/// Persisted registered-rule evidence for one restricted semantic group.
#[derive(Debug, Clone)]
pub struct SemanticEvidenceRow {
    /// SOG schema version interpreted by the registered rule.
    pub schema_version: String,
    /// Stable registered-rule identifier.
    pub rule_id: String,
    /// Rule semantics revision.
    pub rule_version: u32,
    /// Conservative rule confidence before auxiliary features are applied.
    pub rule_confidence: f64,
    /// One serialized normalized graph for every group member, in member order.
    pub graphs: Vec<SemanticOperationGraphRow>,
    /// Explainable graph-local node correspondences.
    pub node_mappings: Vec<SemanticNodeMappingRow>,
}

/// One serialized normalized operation graph attached to a group member.
#[derive(Debug, Clone)]
pub struct SemanticOperationGraphRow {
    /// Schema version stored inside the graph itself.
    pub schema_version: String,
    /// Canonical JSON serialization of the graph.
    pub graph_json: String,
}

/// One graph-local node mapping recorded for semantic explain output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticNodeMappingRow {
    /// Zero-based position of the corresponding member graph. The canonical
    /// graph is at position zero, so this is always at least one.
    pub corresponding_member: u32,
    /// Node index in the canonical graph.
    pub canonical: u32,
    /// Node index in the corresponding graph.
    pub corresponding: u32,
}

/// One suppression rule active for the scan.
///
/// Rules are content-addressed by `(scope, pattern)`: identical rules share
/// one vocabulary row within the local database.
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
    /// The shortest clone the run would report, in tokens.
    ///
    /// Recorded because it decides what became a finding at all, and because
    /// the ranking reads every group's size against it: the same group is
    /// weaker evidence under a high floor than under a low one, and a stored
    /// ranking cannot be re-derived without knowing which was in force.
    pub min_clone_tokens: u32,
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
    /// Every source file the scan read, whether or not anything was found in
    /// it. A later scan of the same tree compares against this.
    pub files: Vec<FileRow>,
    /// The compiler helpers that took part, referenced by
    /// [`CompilerUnitRow::helper`]. Empty in the modes that ask no compiler
    /// anything.
    pub compiler_helpers: Vec<CompilerHelperRow>,
    /// Every unit a compiler was asked about, answered or not.
    ///
    /// Part of the snapshot rather than a later write, so that a run and what
    /// a compiler said about it arrive together: a run recorded without its
    /// compiler rows would read as one that never asked.
    pub compiler_units: Vec<CompilerUnitRow>,
    /// What the run reported about itself beyond the groups it found.
    pub summary: SummaryRow,
}

/// A separately persisted opt-in comparison across normal build variants.
///
/// It is intentionally not a [`Snapshot`]: no normal-snapshot or baseline
/// relation may be inferred from it.
#[derive(Debug, Clone)]
pub struct CrossVariantComparisonSnapshot<'a> {
    /// Scan root shared by the partition scans.
    pub root_path: &'a str,
    /// Comparison-domain identity.
    pub comparison_id: CrossVariantComparisonId,
    /// Version of the comparison policy.
    pub policy_version: &'a str,
    /// Clock values for this explicit comparison invocation.
    pub started_at: &'a str,
    /// Clock values for this explicit comparison invocation.
    pub finished_at: &'a str,
    /// Sorted origin build-variant fingerprints.
    pub origins: &'a [String],
    /// Exact groups found directly across the origins.
    pub groups: &'a [CrossVariantGroupRow],
}

/// One cross-build-variant exact clone group.
#[derive(Debug, Clone)]
pub struct CrossVariantGroupRow {
    /// Comparison-domain group identity.
    pub group_id: CrossVariantGroupId,
    /// Exact Type-1 clones only under the current policy.
    pub clone_type: CloneClass,
    /// Members retaining their own origin variant.
    pub members: Vec<CrossVariantMemberRow>,
}

/// An origin-aware cross-build-variant member.
#[derive(Debug, Clone)]
pub struct CrossVariantMemberRow {
    /// Fingerprint of the normal partition that produced this member.
    pub origin_variant: String,
    /// Source language.
    pub language: Language,
    /// Anchor relative to the comparison root.
    pub file_path: String,
    /// Anchor, 1-based.
    pub start_line: u32,
    /// Anchor, 1-based.
    pub end_line: u32,
    /// Best-effort unit name.
    pub unit_name: Option<String>,
    /// Token count of the exact unit.
    pub token_count: usize,
}

/// A separately persisted opt-in Rust-to-C++ semantic comparison.
///
/// Like [`CrossVariantComparisonSnapshot`], this cannot affect normal scan
/// snapshots or baselines.
#[derive(Debug, Clone)]
pub struct CrossLanguageComparisonSnapshot<'a> {
    /// Scan root shared by the partition scans.
    pub root_path: &'a str,
    /// Comparison-domain identity.
    pub comparison_id: CrossLanguageComparisonId,
    /// Version of the comparison policy.
    pub policy_version: &'a str,
    /// Clock value for this explicit comparison invocation.
    pub started_at: &'a str,
    /// Clock value for this explicit comparison invocation.
    pub finished_at: &'a str,
    /// Sorted origin build-variant fingerprints.
    pub origins: &'a [String],
    /// Verified semantic groups found directly across the origins.
    pub groups: &'a [CrossLanguageSemanticGroupRow],
}

/// One verified Rust-to-C++ restricted-semantic group.
#[derive(Debug, Clone)]
pub struct CrossLanguageSemanticGroupRow {
    /// Comparison-domain group identity.
    pub group_id: CrossLanguageGroupId,
    /// Registered correspondence rule identifier.
    pub rule_id: String,
    /// Registered correspondence rule revision.
    pub rule_version: u32,
    /// Conservative confidence after normalization coverage.
    pub semantic_confidence: f64,
    /// Applied closed API-correspondence identifiers in SOG order.
    pub correspondence_ids: Vec<String>,
    /// Members retaining their own origin variant and normalized graph.
    pub members: Vec<CrossLanguageSemanticMemberRow>,
}

/// One origin-aware member of a cross-language semantic group.
#[derive(Debug, Clone)]
pub struct CrossLanguageSemanticMemberRow {
    /// Fingerprint of the normal partition that produced this graph.
    pub origin_variant: String,
    /// Source language (Rust or C++ only).
    pub language: Language,
    /// Anchor relative to the comparison root.
    pub file_path: String,
    /// Anchor, 1-based.
    pub start_line: u32,
    /// Anchor, 1-based.
    pub end_line: u32,
    /// Best-effort unit name.
    pub unit_name: Option<String>,
    /// Schema version retained inside the graph itself.
    pub graph_schema_version: String,
    /// Canonical JSON serialization of the normalized graph.
    pub graph_json: String,
}

/// What a run's report says that its findings do not.
///
/// Everything here is a measurement of the run rather than of a group: how
/// much source went in, what each stage of the pipeline passed on, what was
/// dropped and why. A stage that discarded every candidate leaves no row
/// anywhere else, so without these a stored run can be listed again but not
/// described again.
///
/// Counts that *are* derivable from the stored groups — how many are Type-1,
/// how many are suppressed, how many live in tests — are deliberately absent:
/// a copy of a derivable value is a second answer waiting to disagree with
/// the first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SummaryRow {
    /// Source lines across the analysed files.
    pub lines: u64,
    /// Tokens across the analysed files.
    pub tokens: u64,
    /// Lexer diagnostics emitted while reading the sources.
    pub lexer_diagnostics: u64,
    /// Files holding tokens the parser could not attach to any structure, and
    /// how many such tokens there are. `None` in a mode that does not parse,
    /// which has nothing to report rather than nothing to report *yet*.
    pub unparsed: Option<UnparsedRow>,
    /// Files dropped for carrying a generated-code marker.
    pub excluded_generated: u64,
    /// Files dropped by the configured include/exclude globs.
    pub excluded_by_glob: u64,
    /// Files dropped for any other cause (size, binary content, read errors).
    pub excluded_skipped: u64,
    /// Duplicated runs left out because a reported whole-unit group already
    /// covers them.
    pub folded_runs: u64,
    /// Duplicated runs left out because a longer run covers every one of their
    /// occurrences.
    pub subsumed_runs: u64,
    /// Groups of related units cut because they were too large to refine as
    /// one piece.
    pub split_components: u64,
    /// Whether a candidate stage ran out of budget, making the result
    /// potentially incomplete.
    pub pair_budget_exhausted: bool,
    /// Digest of the frozen finding set the run was reported against, when it
    /// was given a baseline.
    pub baseline_digest: Option<String>,
    /// What each stage of the candidate pipeline passed on, in run order.
    pub funnel: Vec<FunnelStageRow>,
    /// Configured suppression rules that hid nothing in the run.
    pub unused_suppressions: Vec<UnusedRuleRow>,
}

/// How much of the source the parser could not follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnparsedRow {
    /// Files holding at least one unattached token.
    pub files: u64,
    /// How many such tokens there are.
    pub tokens: u64,
}

/// One stage of the candidate pipeline, with what it dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunnelStageRow {
    /// The stage's name, as the report prints it.
    pub name: String,
    /// How many items the stage passed on.
    pub passed: u64,
    /// What the stage dropped, by cause. Empty when it dropped nothing.
    pub dropped: Vec<FunnelDropRow>,
}

/// Items one stage dropped for one reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunnelDropRow {
    /// Why they were dropped, as a `snake_case` cause.
    pub cause: String,
    /// How many.
    pub count: u64,
}

/// One configured suppression rule that matched nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedRuleRow {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`).
    pub scope: String,
    /// The pattern as configured.
    pub pattern: String,
}

/// One source file a scan read.
///
/// Recorded for every discovered file, including the ones that contributed no
/// unit: what a run looked at is not derivable from what it found, and the
/// difference is exactly what a later run has to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// Path relative to the scan root.
    pub relative_path: String,
    /// Hash of the bytes that were read, as lowercase hex.
    pub content_hash: String,
    /// The language the file was analysed as, which for a header is the one
    /// the tree settled on rather than one the extension implies.
    pub language: Language,
    /// Size in bytes.
    pub byte_len: u64,
}

impl Store {
    /// Replace the stored snapshot atomically and return its row id.
    ///
    /// # Errors
    ///
    /// Any failure — malformed input (such as a member referencing a
    /// non-existent unit) or an underlying database error — rolls the whole
    /// replacement back; the prior completed snapshot remains intact.
    pub fn record_snapshot(&mut self, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
        self.record_snapshot_part(snapshot, true)
    }

    /// Record one partition of the current scan.
    ///
    /// The first partition replaces the prior scan; later partitions belong to
    /// that same invocation and are appended before its report is emitted.
    /// Callers must never use `false` to retain a completed earlier scan.
    ///
    /// # Errors
    ///
    /// Returns any validation or database error while preserving transaction
    /// atomicity for the partition being written.
    pub fn record_snapshot_part(
        &mut self,
        snapshot: &Snapshot<'_>,
        replace_existing: bool,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        if replace_existing {
            clear_previous_snapshot(&tx)?;
        }
        let run_id = write_snapshot(&tx, snapshot)?;
        tx.commit()?;
        Ok(run_id)
    }

    /// Persist one opt-in cross-build-variant comparison.
    ///
    /// Every invocation gets a row even when its comparison identity repeats,
    /// so an explicit comparison always describes the inputs it received.
    ///
    /// # Errors
    ///
    /// Returns an error when the comparison cannot be written atomically.
    pub fn record_cross_variant_comparison(
        &mut self,
        comparison: &CrossVariantComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO cross_variant_comparison
                 (comparison_id, policy_version, root_path, started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                comparison.comparison_id.as_bytes().as_slice(),
                comparison.policy_version,
                comparison.root_path,
                comparison.started_at,
                comparison.finished_at,
            ],
        )?;
        let comparison_row = tx.last_insert_rowid();
        for origin in comparison.origins {
            tx.execute(
                "INSERT INTO cross_variant_comparison_origin
                     (comparison_id, build_variant_fingerprint) VALUES (?1, ?2)",
                params![comparison_row, origin],
            )?;
        }
        for group in comparison.groups {
            tx.execute(
                "INSERT INTO cross_variant_clone_group
                     (comparison_id, group_id, clone_type, member_count)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    comparison_row,
                    group.group_id.as_bytes().as_slice(),
                    group.clone_type.name(),
                    i64::try_from(group.members.len()).unwrap_or(i64::MAX),
                ],
            )?;
            let group_row = tx.last_insert_rowid();
            for member in &group.members {
                tx.execute(
                    "INSERT INTO cross_variant_clone_member
                         (group_id, origin_variant_fingerprint, language, file_path,
                          start_line, end_line, unit_name, token_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        group_row,
                        member.origin_variant,
                        member.language.name(),
                        member.file_path,
                        i64::from(member.start_line),
                        i64::from(member.end_line),
                        member.unit_name,
                        i64::try_from(member.token_count).unwrap_or(i64::MAX),
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(comparison_row)
    }

    /// Persist one opt-in Rust-to-C++ semantic comparison.
    ///
    /// This uses tables distinct from both normal snapshots and exact
    /// cross-build comparisons, so the result domains stay separate.
    ///
    /// # Errors
    ///
    /// Returns an error when a group lacks its closed evidence or when the
    /// comparison cannot be written atomically.
    pub fn record_cross_language_comparison(
        &mut self,
        comparison: &CrossLanguageComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO cross_language_comparison
                 (comparison_id, policy_version, root_path, started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                comparison.comparison_id.as_bytes().as_slice(),
                comparison.policy_version,
                comparison.root_path,
                comparison.started_at,
                comparison.finished_at,
            ],
        )?;
        let comparison_row = tx.last_insert_rowid();
        for origin in comparison.origins {
            tx.execute(
                "INSERT INTO cross_language_comparison_origin
                     (comparison_id, build_variant_fingerprint) VALUES (?1, ?2)",
                params![comparison_row, origin],
            )?;
        }
        for group in comparison.groups {
            validate_cross_language_group(group)?;
            let correspondence_ids =
                serde_json::to_string(&group.correspondence_ids).map_err(|error| {
                    StoreError::InvalidSemanticEvidence {
                        reason: format!(
                            "serializing cross-language API correspondence IDs: {error}"
                        ),
                    }
                })?;
            tx.execute(
                "INSERT INTO cross_language_semantic_group
                     (comparison_id, group_id, rule_id, rule_version, semantic_confidence,
                      correspondence_ids_json, member_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    comparison_row,
                    group.group_id.as_bytes().as_slice(),
                    group.rule_id,
                    i64::from(group.rule_version),
                    group.semantic_confidence,
                    correspondence_ids,
                    i64::try_from(group.members.len()).unwrap_or(i64::MAX),
                ],
            )?;
            let group_row = tx.last_insert_rowid();
            for member in &group.members {
                tx.execute(
                    "INSERT INTO cross_language_semantic_member
                         (group_id, origin_variant_fingerprint, language, file_path,
                          start_line, end_line, unit_name, graph_schema_version, graph_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        group_row,
                        member.origin_variant,
                        member.language.name(),
                        member.file_path,
                        i64::from(member.start_line),
                        i64::from(member.end_line),
                        member.unit_name,
                        member.graph_schema_version,
                        member.graph_json,
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(comparison_row)
    }
}

/// Drop the earlier scan before writing its replacement.
///
/// A local database is the current scan's canonical storage, not a ledger.
fn clear_previous_snapshot(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute("DELETE FROM scan_run", [])?;
    Ok(())
}

fn validate_cross_language_group(group: &CrossLanguageSemanticGroupRow) -> Result<(), StoreError> {
    if !group.semantic_confidence.is_finite()
        || !(0.0..=1.0).contains(&group.semantic_confidence)
        || group.rule_id.is_empty()
        || group.correspondence_ids.is_empty()
        || group.members.len() != 2
    {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: "cross-language group lacks bounded rule evidence".to_string(),
        });
    }
    let mut has_rust = false;
    let mut has_cpp = false;
    let mut origins = BTreeSet::new();
    for member in &group.members {
        if !matches!(member.language, Language::Rust | Language::Cpp)
            || member.graph_schema_version != SOG_SCHEMA_VERSION
        {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member has an unsupported language or graph schema"
                    .to_string(),
            });
        }
        let graph: SemanticOperationGraph =
            serde_json::from_str(&member.graph_json).map_err(|error| {
                StoreError::InvalidSemanticEvidence {
                    reason: format!("decoding cross-language member graph: {error}"),
                }
            })?;
        if graph.schema_version != member.graph_schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member graph schema disagrees with its stored metadata"
                    .to_string(),
            });
        }
        if graph.language != member.language {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member graph language disagrees with its stored metadata"
                    .to_string(),
            });
        }
        has_rust |= member.language == Language::Rust;
        has_cpp |= member.language == Language::Cpp;
        origins.insert(member.origin_variant.as_str());
    }
    if !has_rust || !has_cpp || origins.len() != 2 {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: "cross-language group must contain one Rust and one C++ origin".to_string(),
        });
    }
    Ok(())
}

fn write_snapshot(tx: &Transaction<'_>, snapshot: &Snapshot<'_>) -> Result<i64, StoreError> {
    let variant_id = upsert_variant(tx, snapshot.variant)?;

    tx.execute(
        "INSERT INTO scan_run
             (build_variant_id, root_path, tool_version, config_hash,
              analysis_mode, started_at, finished_at, min_clone_tokens, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'completed')",
        params![
            variant_id,
            snapshot.root_path,
            snapshot.tool_version,
            snapshot.config_hash,
            snapshot.variant.mode.name(),
            snapshot.started_at,
            snapshot.finished_at,
            i64::from(snapshot.min_clone_tokens),
        ],
    )?;
    let run_id = tx.last_insert_rowid();

    for (component, version) in snapshot.detector_versions {
        record_detector_version(tx, run_id, component, version)?;
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
fn write_summary(
    tx: &Transaction<'_>,
    summary: &SummaryRow,
    run_id: i64,
) -> Result<(), StoreError> {
    let count = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO run_summary
             (scan_run_id, lines, tokens, lexer_diagnostics, unparsed_files,
              unparsed_tokens, excluded_generated, excluded_by_glob,
              excluded_skipped, folded_runs, subsumed_runs, split_components,
              pair_budget_exhausted, baseline_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            run_id,
            count(summary.lines),
            count(summary.tokens),
            count(summary.lexer_diagnostics),
            summary.unparsed.map(|row| count(row.files)),
            summary.unparsed.map(|row| count(row.tokens)),
            count(summary.excluded_generated),
            count(summary.excluded_by_glob),
            count(summary.excluded_skipped),
            count(summary.folded_runs),
            count(summary.subsumed_runs),
            count(summary.split_components),
            summary.pair_budget_exhausted,
            summary.baseline_digest,
        ],
    )?;
    for (position, stage) in summary.funnel.iter().enumerate() {
        let position = i64::try_from(position).unwrap_or(i64::MAX);
        tx.execute(
            "INSERT INTO run_funnel_stage (scan_run_id, position, name, passed)
             VALUES (?1, ?2, ?3, ?4)",
            params![run_id, position, stage.name, count(stage.passed)],
        )?;
        for (ordinal, drop) in stage.dropped.iter().enumerate() {
            tx.execute(
                "INSERT INTO run_funnel_drop
                     (scan_run_id, position, ordinal, cause, dropped)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    run_id,
                    position,
                    i64::try_from(ordinal).unwrap_or(i64::MAX),
                    drop.cause,
                    count(drop.count),
                ],
            )?;
        }
    }
    for (ordinal, rule) in summary.unused_suppressions.iter().enumerate() {
        tx.execute(
            "INSERT INTO run_unused_suppression (scan_run_id, ordinal, scope, pattern)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                run_id,
                i64::try_from(ordinal).unwrap_or(i64::MAX),
                rule.scope,
                rule.pattern,
            ],
        )?;
    }
    Ok(())
}

/// Record the tree the run read, one row per file.
fn write_files(tx: &Transaction<'_>, files: &[FileRow], run_id: i64) -> Result<(), StoreError> {
    for file in files {
        tx.execute(
            "INSERT INTO scanned_file
                 (scan_run_id, relative_path, content_hash, language, byte_len)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                run_id,
                file.relative_path,
                file.content_hash,
                file.language.name(),
                i64::try_from(file.byte_len).unwrap_or(i64::MAX),
            ],
        )?;
    }
    Ok(())
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
/// The persisted ranking for one group in one scan.
fn write_finding(
    tx: &Transaction<'_>,
    run_id: i64,
    group_row_id: i64,
    group: &GroupRow,
    suppression_row_ids: &[i64],
) -> Result<(), StoreError> {
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
             (scan_run_id, clone_group_id, suppression_id,
              clone_confidence, maintenance_risk, refactoring_difficulty,
              final_priority, semantic_confidence,
              source_artifact_mapping_confidence, savings_confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            group_row_id,
            suppression_row_id,
            group.priority.clone_confidence,
            group.priority.maintenance_risk,
            group.priority.refactoring_difficulty,
            group.priority.final_priority,
            group.priority.semantic_confidence,
            group.priority.source_artifact_confidence,
            group.priority.savings_confidence,
        ],
    )?;
    Ok(())
}

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
             (scan_run_id, group_fingerprint_id, clone_type, member_scope,
              member_count, score, entropy_bits, suppress_reason, boilerplate,
              test_code, split_pair, width_family, statements)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            run_id,
            group_fp_id,
            group.clone_type.name(),
            group.member_scope.name(),
            i64::try_from(group.members.len()).unwrap_or(i64::MAX),
            group.score,
            group.entropy_bits,
            group.suppress_reason,
            group.boilerplate.map(Boilerplate::name),
            group.test_code,
            group.split_pair,
            group.width_family,
            group.statements,
        ],
    )?;
    let group_row_id = tx.last_insert_rowid();

    write_finding(tx, run_id, group_row_id, group, suppression_row_ids)?;
    write_group_similarity(tx, group_row_id, group.similarity.as_ref())?;

    let mut fragment_row_ids = Vec::with_capacity(group.members.len());
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
        fragment_row_ids.push(fragment_row_id);
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
    if let Some(evidence) = &group.semantic {
        write_semantic_evidence(tx, group_row_id, &fragment_row_ids, evidence)?;
    }
    Ok(())
}

/// Persist the graph and rule evidence that makes a restricted semantic group
/// explainable. Member graph order is the group's canonical member order.
fn write_semantic_evidence(
    tx: &Transaction<'_>,
    group_row_id: i64,
    fragment_row_ids: &[i64],
    evidence: &SemanticEvidenceRow,
) -> Result<(), StoreError> {
    if evidence.schema_version != SOG_SCHEMA_VERSION {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: format!(
                "group evidence schema {} is not supported ({SOG_SCHEMA_VERSION})",
                evidence.schema_version
            ),
        });
    }
    if evidence.graphs.len() != fragment_row_ids.len() {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: format!(
                "{} graphs for {} group members",
                evidence.graphs.len(),
                fragment_row_ids.len()
            ),
        });
    }
    tx.execute(
        "INSERT INTO semantic_group_evidence
             (clone_group_id, schema_version, rule_id, rule_version, rule_confidence)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            group_row_id,
            evidence.schema_version,
            evidence.rule_id,
            evidence.rule_version,
            evidence.rule_confidence,
        ],
    )?;
    for (fragment_row_id, graph) in fragment_row_ids.iter().zip(&evidence.graphs) {
        if graph.schema_version != evidence.schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "member graph schema does not match group evidence".to_string(),
            });
        }
        let parsed: SemanticOperationGraph =
            serde_json::from_str(&graph.graph_json).map_err(|error| {
                StoreError::InvalidSemanticEvidence {
                    reason: format!("decoding member graph JSON: {error}"),
                }
            })?;
        if parsed.schema_version != graph.schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "member graph JSON schema does not match its row".to_string(),
            });
        }
        SemanticOperationGraph::new(
            parsed.language,
            parsed.build_variant_fingerprint,
            parsed.nodes,
            parsed.edges,
        )
        .map_err(|error| StoreError::InvalidSemanticEvidence {
            reason: format!("member graph violates the SOG contract: {error}"),
        })?;
        tx.execute(
            "INSERT INTO semantic_operation_graph (fragment_id, schema_version, graph_json)
             VALUES (?1, ?2, ?3)",
            params![fragment_row_id, graph.schema_version, graph.graph_json],
        )?;
    }
    for mapping in &evidence.node_mappings {
        tx.execute(
            "INSERT INTO semantic_node_mapping
                 (clone_group_id, corresponding_member, canonical_node, corresponding_node)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group_row_id,
                mapping.corresponding_member,
                mapping.canonical,
                mapping.corresponding
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
              control_flow, type_similarity, api, composite, min_pairwise,
              confidence_band)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            similarity.confidence_band.name(),
        ],
    )?;
    Ok(())
}

fn upsert_variant(tx: &Transaction<'_>, variant: &BuildVariant) -> Result<i64, StoreError> {
    let languages = variant
        .languages
        .enabled()
        .into_iter()
        .map(Language::name)
        .collect::<Vec<_>>()
        .join(",");
    let headers = variant.headers.map_or("", Language::name);
    // The languages whose builds were resolved, as a set: which of them a run
    // reached first is not a fact about the tree, and the identity beside this
    // column already carries what each was told.
    let build_language = variant
        .builds
        .iter()
        .map(BuildConfiguration::language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    // `ON CONFLICT DO NOTHING` rather than `INSERT OR IGNORE`: the variant is
    // expected to be there already, but only the fingerprint clash is
    // expected. `OR IGNORE` would swallow a `CHECK` violation too and leave the
    // row absent, which surfaces later as a variant that cannot be found rather
    // than as the value that was wrong.
    tx.execute(
        "INSERT INTO build_variant
             (variant_fingerprint, canonical, analysis_mode, normalization_version,
              languages, header_language, build_language)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (variant_fingerprint) DO NOTHING",
        params![
            variant.fingerprint(),
            variant.canonical(),
            variant.mode.name(),
            variant.normalization_version,
            languages,
            headers,
            build_language,
        ],
    )?;
    let id: i64 = tx.query_row(
        "SELECT id FROM build_variant WHERE variant_fingerprint = ?1",
        params![variant.fingerprint()],
        |row| row.get(0),
    )?;
    // Describe the row even when it was already there. Equal fingerprints are
    // equal variants, so this writes back what is already written — except on a
    // row recorded before variants were described, which is the row that has
    // nothing to say and is worth filling in.
    tx.execute(
        "UPDATE build_variant
            SET languages = ?2, header_language = ?3, build_language = ?4
          WHERE id = ?1",
        params![id, languages, headers, build_language],
    )?;
    write_variant_settings(tx, id, variant)?;
    Ok(id)
}

/// Record what the compiler was told, replacing whatever the row held.
///
/// The settings are derived from the same enumeration the variant's identity
/// is, so rewriting them for an existing row restores the same values; a row
/// from before they were recorded gains them.
fn write_variant_settings(
    tx: &Transaction<'_>,
    variant_id: i64,
    variant: &BuildVariant,
) -> Result<(), StoreError> {
    tx.execute(
        "DELETE FROM build_variant_setting WHERE build_variant_id = ?1",
        params![variant_id],
    )?;
    // Written under the language whose build it came from. The two languages
    // name some of the same settings — both have a `compiler_version` — and a
    // record keyed by the name alone would have one compiler's answer standing
    // for the other's.
    for build in &variant.builds {
        for setting in build.settings() {
            for (position, value) in setting.shape.values().into_iter().enumerate() {
                tx.execute(
                    "INSERT INTO build_variant_setting
                         (build_variant_id, language, name, position, value)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        variant_id,
                        build.language(),
                        setting.name,
                        i64::try_from(position).unwrap_or(i64::MAX),
                        value
                    ],
                )?;
            }
        }
    }
    Ok(())
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
