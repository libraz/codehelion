//! The snapshot write path.
//!
//! A single-partition scan's results are committed as one atomic snapshot:
//! every row of a [`Snapshot`] lands inside one transaction. A multi-partition
//! scan records each partition as non-readable `running` data, then atomically
//! promotes every partition only after the whole invocation succeeds. Thus an
//! interrupted semantic invocation leaves its prior completed snapshot intact.
//!
//! Fingerprint rows are content-addressed: identical identifiers produced
//! under the identical analysis context share one row across scans, which is
//! what lets a later scan correlate its groups with an earlier one by
//! fingerprint identity. Everything positional (paths, line ranges) is
//! written as anchor columns on the per-scan rows and participates in no
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{BuildConfiguration, BuildVariant, Language};
use codehelion_core::frontend::UnitKind;
use codehelion_core::semantic::{SOG_SCHEMA_VERSION, SemanticOperationGraph};
use codehelion_core::stable_id::{
    CloneGroupFingerprint, CrossLanguageComparisonId, CrossLanguageGroupId, CrossLanguageMemberId,
    CrossVariantComparisonId, CrossVariantGroupId, CrossVariantMemberId, FindingId,
    FragmentFingerprint, GroupLineageId, HASH_ALGORITHM, UnitFingerprint, group_lineage_id,
};
use codehelion_core::structural::SiblingBasis;
use codehelion_core::test_code::TestCodeEvidence;
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
    /// Boilerplate shape of the enclosing whole unit, when Structural mode
    /// classified it. A matched fragment has no standalone body to classify.
    pub boilerplate: Option<Boilerplate>,
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
    pub control_flow: Option<f64>,
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "persisted independent finding facts map directly to checked SQLite columns"
)]
pub struct GroupRow {
    /// The group's stable fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Durable history identifier for this group, independent of the current
    /// fingerprint. New groups begin from their fingerprint and later scans
    /// may adopt a predecessor's lineage with explicit overlap evidence.
    pub history: GroupOrigin,
    /// Clone classification.
    pub clone_type: CloneClass,
    /// What the members are: whole units, or runs of statements inside them.
    pub member_scope: CloneScope,
    /// Whether every member is test code. A recorded fact about the code, as
    /// `boilerplate` is: what a report does with it is a separate decision.
    pub test_code: bool,
    /// Why the group is test code, when every member is test code.
    pub test_code_evidence: Option<TestCodeEvidence>,
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
    /// Smallest raw-identifier Jaccard agreement to the canonical unit.
    /// Absent outside Structural whole-unit groups.
    pub identifier_jaccard: Option<f64>,
    /// Whether every member contains a loop, when Structural mode measured it.
    pub has_loop: Option<bool>,
    /// Whether every member calls a recognised allocation API.
    pub has_dynamic_allocation: Option<bool>,
    /// Fewest recovered call sites in any member.
    pub call_count: Option<u64>,
    /// Whether the members differ from each other by one integer width and
    /// nothing else. Recorded on the same footing as `boilerplate`, and kept
    /// apart from it because it describes how the members differ rather than
    /// what any one of them does.
    pub width_family: bool,
    /// Whether the effective presentation policy placed this finding after
    /// ordinary findings, independently of its numeric priority.
    pub ranked_down: bool,
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

/// Recorded continuity state for one group.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupOrigin {
    /// How this scan established continuity with prior findings.
    pub state: AuditState,
    /// The current lineage identifier.
    pub lineage: GroupLineageId,
    /// Evidence-backed predecessors retained for explainability.
    pub parents: Vec<LineageParent>,
}

impl GroupOrigin {
    /// Start a history at a newly observed group.
    #[must_use]
    pub fn unconnected(group: &CloneGroupFingerprint) -> Self {
        Self {
            state: AuditState::New,
            lineage: group_lineage_id(group),
            parents: Vec::new(),
        }
    }
}

/// How a recorded group entered its current lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// No predecessor was established for this group in this scan.
    New,
    /// Explicit overlap evidence connected this group to an earlier lineage.
    Expanded,
}

/// One predecessor selected when a group adopts prior lineage.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageParent {
    /// The predecessor's group fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// The predecessor's durable history identifier.
    pub lineage: GroupLineageId,
    /// Whether this predecessor is the canonical continuity edge.
    pub primary: bool,
    /// Number of shared content identities.
    pub shared_content: u64,
    /// How many distinct content identities the newer group had, which is the
    /// population [`Self::shared_content`] is a count out of.
    ///
    /// `None` for an edge whose writer did not measure one; a reader with no
    /// denominator reports the count alone rather than pairing it with a
    /// number from somewhere else.
    pub compared_content: Option<u64>,
    /// Fraction of the new group represented by the predecessor.
    pub overlap: f64,
}

/// A continuity edge selected by a scan comparison before it is committed.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageAdoption {
    /// Fingerprint of the newer group whose history should be extended.
    pub group: String,
    /// Fingerprint of the predecessor group that established the connection.
    pub previous_group: String,
    /// Existing lineage that the newer group must adopt.
    pub lineage: String,
    /// Number of shared content identities supporting this edge.
    pub shared: u64,
    /// How many distinct content identities the newer group was compared on.
    ///
    /// `None` when the caller cannot say, which records the count without a
    /// denominator rather than inviting one to be taken from elsewhere. When
    /// present it must be at least [`Self::shared`].
    pub compared: Option<u64>,
    /// Fraction of the new group represented by the predecessor.
    pub overlap: f64,
}

/// Outcome of committing a comparison's continuity edges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineageAdoptionResult {
    /// Newer groups whose lineage was extended.
    pub taken: Vec<String>,
    /// Newer groups that already had explicit continuity evidence.
    pub already_connected: Vec<String>,
    /// Requested newer groups or predecessors absent from the named runs.
    pub unknown: Vec<String>,
}

/// Siblings attached to one cohesive primary clone group.
///
/// They are intentionally outside [`GroupRow::members`]: a sibling is a
/// bounded, relaxed-threshold local mirror and must never reconstruct as a
/// primary group member.
#[derive(Debug, Clone)]
pub struct SiblingGroupRow {
    /// Stable fingerprint of the owning primary clone group.
    pub group: CloneGroupFingerprint,
    /// Incomplete local mirrors in deterministic order.
    pub siblings: Vec<SiblingRow>,
}

/// One persisted incomplete local mirror.
#[derive(Debug, Clone)]
pub struct SiblingRow {
    /// Index into [`Snapshot::units`] of the ungrouped sibling unit.
    pub unit: usize,
    /// The sibling unit's whole-unit content identity.
    pub content: FragmentFingerprint,
    /// Stable occurrence identity in the owning group domain.
    pub finding: FindingId,
    /// Independent candidate channel that supplied this sibling.
    pub basis: SiblingBasis,
    /// Exact normalized signature when the sibling came from the signature
    /// channel. Similarity siblings intentionally carry no signature.
    pub signature: Option<String>,
    /// How many units in the scanned tree share that normalized signature.
    /// A signature is only evidence while it stays rare, so the count travels
    /// with the sibling. Similarity siblings intentionally carry no count.
    pub signature_units: Option<usize>,
    /// The verifier classification.
    pub clone_type: CloneClass,
    /// The verifier confidence band.
    pub confidence: Confidence,
    /// Canonical-to-sibling per-dimension comparison evidence.
    pub similarity: SimilarityBreakdownRow,
    /// Body classification carried by the sibling's host unit, when any.
    pub boilerplate: Option<Boilerplate>,
    /// Index into [`Snapshot::suppressions`] of the rule hiding this sibling.
    pub suppressed_by: Option<usize>,
}

/// One bounded, run-scoped LSH diagnostic that fell just below the primary
/// near-match estimate gate.
///
/// Unlike a [`SiblingRow`], this has no owning group and no finding identity:
/// it was never verified or promoted into a primary clone relation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NearMissRow {
    /// Index into [`Snapshot::units`] of the lower proposed unit.
    pub left: usize,
    /// Index into [`Snapshot::units`] of the higher proposed unit.
    pub right: usize,
    /// MinHash-estimated Jaccard similarity that fell below the primary gate.
    pub estimated_jaccard: f64,
    /// Index into [`Snapshot::suppressions`] of the rule hiding this diagnostic.
    pub suppressed_by: Option<usize>,
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

/// Everything one scan run persists.
#[derive(Debug, Clone)]
pub struct Snapshot<'a> {
    /// Scanned root, as [`path_key`](crate::path_key()) spells the canonical
    /// path of the tree that was read.
    ///
    /// Every lookup that asks about a root — run reuse, baselines, lineage —
    /// compares this column against a key produced by that same function, so a
    /// snapshot recorded under any other spelling of the path is one no later
    /// question reaches, and each scan of the tree silently looks like its
    /// first. Rendering it for a reader is [`display_path`](crate::display_path).
    pub root_path: &'a str,
    /// The tool version that produced the results.
    pub tool_version: &'a str,
    /// Hash of the effective configuration.
    pub config_hash: &'a str,
    /// How the effective configuration was selected.
    pub config_source: &'a str,
    /// Configuration file path when one supplied the effective settings.
    pub config_path: Option<&'a str>,
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
    /// "rust-lexer-v1")`.
    pub detector_versions: &'a [(String, String)],
    /// Suppression rules active for this scan, referenced by
    /// [`GroupRow::suppressed_by`].
    pub suppressions: Vec<SuppressionRuleRow>,
    /// Units observed in the scanned sources.
    pub units: Vec<UnitRow>,
    /// Detected clone groups.
    pub groups: Vec<GroupRow>,
    /// Incomplete local mirrors keyed by their owning primary group.
    pub sibling_groups: Vec<SiblingGroupRow>,
    /// Bounded LSH diagnostics that are not primary findings or group members.
    pub near_misses: Vec<NearMissRow>,
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
    /// Scan root shared by the partition scans, spelled by
    /// [`path_key`](crate::path_key()) like every other recorded root.
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
    /// Stable occurrence identity; source anchors are reporting only.
    pub member_id: CrossVariantMemberId,
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
    /// Scan root shared by the partition scans, spelled by
    /// [`path_key`](crate::path_key()) like every other recorded root.
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
    /// Stable occurrence identity; source anchors are reporting only.
    pub member_id: CrossLanguageMemberId,
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
    /// Files that successfully reached analysis, split by language.
    pub analyzed_files: FileCountsRow,
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
    /// Files dropped because they exceeded the configured size ceiling.
    pub excluded_too_large: u64,
    /// Files dropped because their head identified them as binary.
    pub excluded_binary: u64,
    /// Files the walker or selected frontend could not read.
    pub excluded_unreadable: u64,
    /// Symbolic links deliberately left unresolved by the source walker.
    pub excluded_symlinks: u64,
    /// Directory entries the source walker could not read.
    pub excluded_walk_errors: u64,
    /// Files dropped after exceeding the configured parse-time allowance.
    pub excluded_timed_out: u64,
    /// Files excluded because their language was disabled for this scan.
    pub excluded_language: u64,
    /// Symbolic-link files deliberately left unresolved by the source walker.
    pub excluded_symlink_files: u64,
    /// Symbolic-link directories deliberately left unresolved by the source walker.
    pub excluded_symlink_directories: u64,
    /// The concrete resource profile applied to this run, when one was.
    pub guardrails: Option<GuardrailsRow>,
    /// Files dropped for causes other than generated markers or globs.
    ///
    /// This is retained as the sum of the reason-specific fields for the
    /// summary's original public aggregate. Consumers needing an explanation
    /// use the individual fields above.
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
    /// Signature keys left out of the sibling candidate index because more
    /// units shared them than the rarity limit admits.
    pub common_signatures_skipped: u64,
    /// Units sharing the most widely shared excluded signature key.
    pub largest_skipped_signature_units: u64,
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

/// Analysed-file counts recorded with a summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileCountsRow {
    /// All files that reached analysis.
    pub total: u64,
    /// Analysed Rust files.
    pub rust: u64,
    /// Analysed C files.
    pub c: u64,
    /// Analysed C++ files.
    pub cpp: u64,
}

/// Concrete resource ceilings a scan applied for one profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailsRow {
    /// Name of the applied profile.
    pub profile: String,
    /// Largest file read, in bytes.
    pub max_file_bytes: u64,
    /// Per-file parse allowance, in milliseconds.
    pub parse_timeout_ms: u64,
    /// Compiler-helper request allowance, in milliseconds.
    pub helper_timeout_ms: u64,
    /// Largest posting list admitted to pairing.
    pub posting_cap: u64,
    /// Largest candidate-pair budget per pass.
    pub pair_budget: u64,
    /// IEEE-754 bits of the Structural near-miss diagnostic band.
    pub near_miss_delta_bits: u64,
    /// Maximum Structural near-miss diagnostics retained.
    pub near_miss_cap: u64,
    /// Largest Structural pairs passed to precise verification.
    pub verification_budget: u64,
    /// Largest dynamic-programming cell count for one Structural alignment.
    pub max_alignment_cells: u64,
    /// Largest number of post-grouping sibling candidates compared in one run.
    pub sibling_candidate_budget: u64,
    /// Largest number of sibling findings retained for one clone group.
    pub sibling_per_group_cap: u64,
    /// Largest number of sibling findings retained across one run.
    pub sibling_total_cap: u64,
    /// Largest number of signature-sibling candidates compared in one run.
    pub signature_sibling_candidate_budget: u64,
    /// Largest number of signature siblings retained for one clone group.
    pub signature_sibling_per_group_cap: u64,
    /// Largest number of signature siblings retained across one run.
    pub signature_sibling_total_cap: u64,
    /// Largest number of units that may share a signature before that
    /// signature stops being sibling evidence.
    pub signature_sibling_max_units_per_signature: u64,
    /// Largest related component refined together.
    pub max_component: u64,
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

/// One incomplete multi-partition scan left behind by an interrupted command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonedRun {
    /// Database row id of the incomplete partition.
    pub id: i64,
    /// Source root the partition was scanning.
    pub root_path: String,
    /// Invocation start time shared by its sibling partitions.
    pub started_at: String,
    /// Time this partition finished writing its incomplete snapshot.
    pub finished_at: String,
}

/// One suppression row held by a staged partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSuppression {
    /// The content-addressed suppression row.
    id: i64,
    /// The reason supplied by this invocation, to apply only on commit.
    reason: Option<String>,
    /// Whether staging created this row and abort may therefore remove it.
    created: bool,
}

/// Opaque handle returned for a staged snapshot partition.
///
/// The suppression identifiers are deliberately carried by the handle rather
/// than reconstructed from finding rows: a configured rule may match source
/// code without hiding a persisted finding, and must still become active only
/// when the whole invocation commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSnapshotPart {
    /// The running snapshot row to promote or abort.
    run_id: i64,
    /// Every suppression row supplied by this partition, in input order.
    suppressions: Vec<StagedSuppression>,
    /// The completed predecessor selected before this invocation started.
    predecessor_run: Option<i64>,
}

impl StagedSnapshotPart {
    /// Return the database row id carried by this store-issued handle.
    #[must_use]
    pub const fn run_id(&self) -> i64 {
        self.run_id
    }

    /// Attach the predecessor selected by the CLI before finalization.
    #[must_use]
    pub const fn with_predecessor(mut self, predecessor_run: Option<i64>) -> Self {
        self.predecessor_run = predecessor_run;
        self
    }
}

/// An owned collection of optional comparison writes supplied to the atomic
/// multi-partition finalizer.
///
/// The concrete comparison snapshots are borrowed by the finalizer. CLI code
/// keeps their owned preparation objects alive until this call returns.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnapshotComparisons<'a> {
    /// Optional exact cross-build-variant comparison.
    pub cross_variant: Option<&'a CrossVariantComparisonSnapshot<'a>>,
    /// Optional restricted cross-language semantic comparison.
    pub cross_language: Option<&'a CrossLanguageComparisonSnapshot<'a>>,
}

mod groups;
mod variant;
mod write;
