//! Report records for comparisons kept outside the primary findings:
//! diagnostic near matches, sibling mirrors, and the explicitly requested
//! cross-variant and cross-language domains.

use crate::report::{FunnelStage, Member, Suppression};
use codehelion_core::semantic::SemanticOperationGraph;
use serde::Serialize;

/// One bounded LSH proposal that passed the size gate but fell just below the
/// primary estimated-Jaccard threshold.
#[derive(Debug, Serialize)]
pub struct NearMiss {
    /// MinHash-estimated Jaccard similarity below the primary gate.
    pub estimated_jaccard: f64,
    /// Lower side of the canonical proposal pair.
    pub left: NearMissUnit,
    /// Higher side of the canonical proposal pair.
    pub right: NearMissUnit,
    /// Why this diagnostic is hidden from default reports; `None` when visible.
    pub suppressed: Option<Suppression>,
}

/// A source-unit anchor for a diagnostic near-match proposal.
#[derive(Debug, Serialize)]
pub struct NearMissUnit {
    /// Stable whole-unit fingerprint, encoded as lowercase hexadecimal.
    pub unit_fingerprint: String,
    /// Source language.
    pub language: String,
    /// Source path relative to the scan root.
    pub file: String,
    /// 1-based source anchor.
    pub start_line: u32,
    /// 1-based source anchor.
    pub end_line: u32,
    /// Best-effort unit name, when parsing recovered one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Token count of the whole unit.
    pub tokens: u64,
}

/// Sibling findings owned by one primary clone group.
#[derive(Debug, Serialize)]
pub struct GroupSiblings {
    /// Fingerprint of the primary group that owns these local mirrors.
    pub group_fingerprint: String,
    /// Incomplete copies, in deterministic source-content order.
    pub siblings: Vec<Sibling>,
}

/// One incomplete local mirror of a primary group's canonical member.
#[derive(Debug, Serialize)]
pub struct Sibling {
    /// Clone class measured by the verifier. A relaxed-only hit is Type-3.
    pub clone_type: String,
    /// The verifier confidence band; relaxed-only hits are low confidence.
    pub confidence_band: String,
    /// Independent candidate channel that supplied this sibling.
    pub basis: String,
    /// Exact normalized signature for signature-channel siblings. Similarity
    /// siblings carry no signature because their evidence is score-based.
    pub signature: Option<String>,
    /// How many units in the tree share that signature. A signature is
    /// evidence only while it is rare, so the count travels with the finding
    /// and the reader weighs it; it never moves `confidence_band`.
    pub signature_units: Option<u64>,
    /// Canonical-to-sibling verifier evidence.
    pub similarity: SiblingSimilarity,
    /// The ungrouped unit. It is intentionally not repeated in the owning
    /// group's `members` collection.
    pub member: Member,
    /// Why this supplemental finding is hidden from default reports.
    pub suppressed: Option<Suppression>,
}

/// Per-dimension evidence for one sibling comparison.
#[derive(Debug, Clone, Serialize)]
pub struct SiblingSimilarity {
    /// Composite-weight recipe used for the comparison.
    pub weight_version: String,
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement, when both sides had such evidence.
    pub control_flow: Option<f64>,
    /// Type agreement, when compiler evidence was available.
    pub type_similarity: Option<f64>,
    /// Call-surface agreement, when either side called an API.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
}

/// An explicitly requested comparison across independent build variants.
///
/// This is intentionally outside [`Report`](crate::report::Report): it does not aggregate ordinary
/// findings, coverage, savings, or baselines.
#[derive(Debug, Serialize)]
pub struct CrossVariantComparison {
    /// Comparison-domain schema and policy version.
    pub policy_version: String,
    /// Stable comparison-domain identity.
    pub comparison_id: String,
    /// What was actually compared, never a claim about all structural output.
    pub comparison_kind: String,
    /// Sorted fingerprints of every origin partition in scope.
    pub origin_variants: Vec<String>,
    /// Exact groups found directly across the origin variants.
    pub groups: Vec<CrossVariantGroup>,
}

/// An explicitly requested build-variant comparison that could not run.
///
/// This is deliberately distinct from an empty completed comparison: an
/// empty `groups` list means the requested domain was searched and contained
/// no exact clones, while this record says the comparison had fewer than two
/// independent partitions to search.
#[derive(Debug, Serialize)]
pub struct CrossVariantComparisonNotRun {
    /// Stable spelling for consumers that distinguish this from a completed
    /// comparison.
    pub status: String,
    /// The comparison operation that was requested.
    pub comparison_kind: String,
    /// Why the requested operation was not run.
    pub reason: String,
    /// Distinct normal scan partitions that were available to compare.
    pub origin_variants: Vec<String>,
}

/// One cross-build-variant group in an exported comparison.
#[derive(Debug, Serialize)]
pub struct CrossVariantGroup {
    /// Stable comparison-domain group id.
    pub id: String,
    /// Clone classification under the comparison policy.
    pub clone_type: String,
    /// Origin-aware members.
    pub members: Vec<CrossVariantMember>,
}

/// One origin-aware comparison member.
#[derive(Debug, Serialize)]
pub struct CrossVariantMember {
    /// Normal partition that produced this member.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// Source anchor relative to the scan root.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Best-effort unit name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Matched token count.
    pub token_count: usize,
}

/// An explicitly requested Rust-to-C++ semantic comparison.
///
/// It is deliberately outside [`Report`](crate::report::Report): normal snapshots, savings,
/// baselines stay partition-local.
#[derive(Debug, Serialize)]
pub struct CrossLanguageComparison {
    /// Comparison-domain policy version.
    pub policy_version: String,
    /// Stable comparison-domain identity.
    pub comparison_id: String,
    /// What the comparison actually verified.
    pub comparison_kind: String,
    /// Sorted fingerprints of every origin partition in scope.
    pub origin_variants: Vec<String>,
    /// Candidate-selection accounting for this independent comparison.
    pub funnel: Vec<FunnelStage>,
    /// Whether a resource ceiling truncated this comparison's candidate
    /// search, so verified groups may be incomplete.
    pub search_truncated: bool,
    /// Verified Rust-to-C++ groups.
    pub groups: Vec<CrossLanguageGroup>,
}

/// An explicitly requested Rust-to-C++ comparison that could not run.
///
/// This is distinct from an empty completed comparison: the latter searched
/// both languages and found no registered correspondence, while this record
/// names the missing input required to start the comparison.
#[derive(Debug, Serialize)]
pub struct CrossLanguageComparisonNotRun {
    /// Stable spelling for consumers that distinguish this from a completed
    /// comparison.
    pub status: String,
    /// The comparison operation that was requested.
    pub comparison_kind: String,
    /// Why the requested operation was not run.
    pub reason: String,
    /// Distinct normal scan partitions that were available to compare.
    pub origin_variants: Vec<String>,
}

/// One verified cross-language restricted-semantic group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroup {
    /// Stable comparison-domain group identifier.
    pub id: String,
    /// Applied registered rule identifier.
    pub rule_id: String,
    /// Applied registered rule revision.
    pub rule_version: u32,
    /// Confidence, kept separate from ordinary clone confidence.
    pub semantic_confidence: f64,
    /// Closed API or compiler-construct correspondence identifiers used by the rule.
    pub correspondence_ids: Vec<String>,
    /// Origin-aware members and their normalised graphs.
    pub members: Vec<CrossLanguageMember>,
}

/// One member of a cross-language semantic group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageMember {
    /// Fingerprint of the partition that produced this graph.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// File relative to the comparison root.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Best-effort unit name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Normalized graph that justified this member.
    pub graph: SemanticOperationGraph,
}
