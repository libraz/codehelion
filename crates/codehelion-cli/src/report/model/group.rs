//! Clone-group report records: the group itself, its members' evidence, and
//! the counts taken over them.

use crate::report::{GroupBaseline, Member, Suppression};
use codehelion_core::semantic::SemanticOperationGraph;
use codehelion_core::test_code::TestCodeEvidence;
use serde::Serialize;

/// Clone-group counts by type.
#[derive(Debug, Serialize)]
pub struct GroupCounts {
    /// All groups.
    pub total: u64,
    /// Verbatim (Type-1) groups.
    pub type_1: u64,
    /// Renamed (Type-2) groups.
    pub type_2: u64,
    /// Gapped (Type-3) groups. Always zero in modes that report no gapped
    /// clones.
    pub type_3: u64,
    /// Findings justified by registered semantic rules only. Always zero in
    /// modes that do not ask compiler helpers.
    pub restricted_semantic: u64,
    /// How many of the total describe a duplicated run inside units that are
    /// not clones of each other, rather than whole duplicated units. Always
    /// zero in modes that only compare whole units.
    pub fragment_scope: u64,
    /// Duplicated runs left out of the listing because a reported whole-unit
    /// group already covers them — the same duplication described twice.
    /// Reported so the fold is visible rather than silent.
    pub folded_runs: u64,
    /// Duplicated runs left out because a longer run covers every one of
    /// their occurrences and claims at least as much about them.
    pub subsumed_runs: u64,
    /// How many of the total live wholly in a test suite. Always zero in modes
    /// that cannot read the marker.
    pub test_code: u64,
}

/// Suppressed-group counts by mechanism.
#[derive(Debug, Serialize)]
pub struct SuppressedCounts {
    /// Groups the engine marked as noise.
    pub noise: u64,
    /// Groups hidden by a configured or inline suppression rule.
    pub by_rule: u64,
    /// Groups hidden because every occurrence sits in a vendored tree.
    ///
    /// Counted separately, and included in
    /// [`by_rule`](Self::by_rule), because this is the one rule that fires
    /// without anybody configuring it. A default nobody can see is a default
    /// nobody can disagree with.
    pub vendored: u64,
}

/// How a group relates to the same tree's preceding run.
///
/// Removing part of a group's duplication has two possible outcomes that look
/// nothing alike in a report: the group keeps its fingerprint and shrinks, or
/// it retires and a successor takes over its history under a new fingerprint.
/// Without this, one edit reads as unfinished work and the other as a fix
/// plus a fresh finding.
#[derive(Debug, Clone, Serialize)]
pub struct GroupIdentity {
    /// `retained` when the preceding run knew this same fingerprint,
    /// `adopted` when a new fingerprint took over an earlier group's history.
    pub origin: String,
    /// The run this was decided against.
    pub compared_with_run: i64,
    /// The predecessor whose history an `adopted` group took over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adopted_from: Option<String>,
    /// Distinct member contents this group shares with that predecessor. The
    /// connection was decided on this quantity, so it is the evidence for it.
    ///
    /// Contents rather than members: several members of one group can carry
    /// the same content, and the rule that adopted the history counted
    /// contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_members: Option<u64>,
    /// Distinct member contents this group was compared on: the population
    /// [`Self::shared_members`] was counted out of.
    ///
    /// A count is only evidence beside what it is a count out of, and both
    /// numbers have to come from one population. `None` when the recorded
    /// connection carries no measured population, in which case a reader
    /// states the shared count alone rather than pairing it with a number that
    /// counts something else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compared_members: Option<u64>,
}

/// The origin value of a group the preceding run already knew by fingerprint.
pub const IDENTITY_RETAINED: &str = "retained";

/// The origin value of a group that took over an earlier group's history.
pub const IDENTITY_ADOPTED: &str = "adopted";

/// One clone group.
#[derive(Debug, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independently established finding classification"
)]
pub struct Group {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`, or
    /// `restricted-semantic`).
    pub clone_type: String,
    /// What each member is: `unit` for a whole duplicated unit, `fragment`
    /// for a run of statements duplicated inside units that need not be
    /// clones of each other.
    ///
    /// The two answer different questions about the same code, so a reader
    /// has to be able to tell them apart. They share one ranking because they
    /// compete for the same attention.
    pub scope: String,
    /// Statements each member covers, for fragment-scope groups; `None` for
    /// unit-scope groups, whose extent is the unit itself.
    pub statements: Option<u64>,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Shannon entropy, in bits, of the canonical occurrence's normalized
    /// token distribution. This remains evidence even when the normalized
    /// ratio marks the group as degenerate repetition.
    pub entropy_bits: f64,
    /// Ranking value with the inputs it was computed from.
    pub priority: Priority,
    /// How this group came by the history it carries, when there was an
    /// earlier run to come by one from. `None` when nothing connects it to a
    /// predecessor, which is every group of a first scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<GroupIdentity>,
    /// Per-dimension similarity evidence, when the mode measured it; `None`
    /// in modes that match content exactly and score no dimensions.
    pub similarity: Option<Similarity>,
    /// Minimum raw-identifier Jaccard agreement against the canonical
    /// occurrence.
    ///
    /// For fragment-scope groups and split pairs, this is triage proxy evidence
    /// for whether a shared refactoring target may exist, not a similarity
    /// measure. It never affects clone detection, classification, or grouping;
    /// ranking may use it only as weak refactoring-difficulty evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_jaccard: Option<f64>,
    /// Material work shared by every member, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_materiality: Option<BodyMateriality>,
    /// The boilerplate shape shared by at least four fifths of members
    /// (`trivial-body`, `forwarding`, `macro-repetition`). Member-level
    /// classifications keep any exceptions visible; the configured category
    /// policy is stated either way.
    pub boilerplate: Option<String>,
    /// Whether every member is test code. A group spanning a suite and the
    /// code it exercises is not test code: that duplication crosses the
    /// boundary, which is the case worth reading.
    pub test_code: bool,
    /// Why every member is test code, when [`Self::test_code`] is true.
    ///
    /// `marker` wins when the group contains both marker- and path-derived
    /// members; `path` means every member was recognised from a configured
    /// test path. `null` means the group is not wholly test code.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the members differ from each other by one integer width and
    /// nothing else: one routine the type system made the author write once
    /// per width. Stated separately from `boilerplate` because it is a
    /// statement about how the members differ rather than about what any one
    /// of them does.
    pub width_family: bool,
    /// Whether this is a pair reported on its own because no group could hold
    /// both its members.
    ///
    /// A group asserts that every member is a copy of every other; being a
    /// copy is not transitive, so a unit can be a copy of two units that are
    /// not copies of each other, and only one of those relations fits in a
    /// group. Such a pair is reported as its own two-member finding, which
    /// means its members also appear elsewhere: these are the only findings
    /// that overlap.
    pub split_pair: bool,
    /// The finding that already reports the stretch this one is a narrower
    /// cut of, hex-encoded; `None` when no other finding in the run covers
    /// every one of its occurrences.
    ///
    /// The engine folds the cuts that state the same thing. What it keeps
    /// apart is the cuts that state different things about one place: four
    /// statements matching verbatim inside eight that match up to renaming is
    /// two facts, and dropping either would report less than was measured.
    /// Both are worth keeping and neither is worth reading twice, so a finding
    /// that sits inside another names the one reporting the wider stretch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrower_cut_of: Option<String>,
    /// Whether the effective suppression policy places this group after
    /// ordinary findings. Persisted in the report so consumers need not
    /// reconstruct policy from classifications.
    pub ranked_down: bool,
    /// Why the group is hidden from default reports; `None` when visible.
    pub suppressed: Option<Suppression>,
    /// What the baseline the run was given says about this group; `None` when
    /// the run was given none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<GroupBaseline>,
    /// Registered-rule evidence for a restricted semantic finding. Absent for
    /// textual and structural clone classes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticEvidence>,
    /// Artifact-correlated refactoring estimates for this exact clone group.
    ///
    /// These are estimates, never a guarantee of a reduction. The list is
    /// empty until an artifact analysis has established a correlation for this
    /// recorded scan run.
    pub artifact_savings: Vec<ArtifactSavings>,
    /// Every occurrence, the canonical instance first.
    pub members: Vec<Member>,
}

/// One artifact-derived estimate attached to a clone group.
///
/// The source and artifact build variants remain explicit because matching
/// source text to a binary built under another configuration is evidence, not
/// identity. The amount is a model output and stays distinct from observed or
/// verified bytes.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactSavings {
    /// Stored artifact-analysis identifier that produced this estimate.
    pub artifact_analysis_id: i64,
    /// Fingerprint of the source build variant that named the clone group.
    pub source_build_variant_fingerprint: String,
    /// Fingerprint of the artifact build variant that supplied byte evidence.
    pub artifact_build_variant_fingerprint: String,
    /// Attributed duplicate bytes observed in the correlated artifact.
    pub duplicated_bytes: u64,
    /// Modelled refactoring savings in bytes; may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Confidence that source and artifact identities were mapped correctly.
    pub mapping_confidence: String,
    /// Confidence that this source group is a clone.
    pub clone_confidence: f64,
    /// Confidence in the refactoring model itself.
    pub model_confidence: String,
    /// Combined confidence in the stated estimate.
    pub savings_confidence: String,
    /// Version of the model that produced the estimate.
    pub model_schema_version: String,
    /// Structured, model-specific assumptions retained with the estimate.
    pub assumptions: serde_json::Value,
}

/// Explainable evidence attached to a restricted semantic finding.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticEvidence {
    /// Version of the normalized operation-graph schema the rules read.
    pub schema_version: String,
    /// Every registered rule applied to establish this correspondence.
    pub rules: Vec<SemanticRuleEvidence>,
    /// The normalized operation graphs for the canonical and corresponding
    /// members, in that order.
    pub graphs: Vec<SemanticOperationGraph>,
    /// Graph-local node correspondences, in canonical source order.
    pub node_mappings: Vec<SemanticNodeMapping>,
}

/// One registered rule contributing to a semantic finding.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticRuleEvidence {
    /// Stable registry identifier.
    pub id: String,
    /// Rule semantics revision.
    pub version: u32,
    /// Semantic confidence after this rule's base confidence and available
    /// normalization coverage are combined.
    pub confidence: f64,
}

/// One explainable correspondence between graph-local operation positions.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SemanticNodeMapping {
    /// Zero-based position of the corresponding member in the semantic
    /// evidence's graph list. Zero is the canonical graph and is not a valid
    /// corresponding position.
    pub corresponding_member: u32,
    /// Node position in the canonical member graph.
    pub canonical: u32,
    /// Node position in the corresponding member graph.
    pub corresponding: u32,
}

/// A group's similarity evidence, one measured dimension per field.
///
/// Every dimension stays visible: the composite never replaces the
/// breakdown. An unavailable dimension is `None` — reported as absent, not
/// as a guessed number.
#[derive(Debug, Serialize)]
pub struct Similarity {
    /// The composite-weight recipe version the group was scored under.
    pub weight_version: String,
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement, or `None` when neither member has
    /// control-flow operations to compare.
    pub control_flow: Option<f64>,
    /// Type agreement, or `None` when types are unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit calls
    /// anything and there is nothing to compare.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
    /// Confidence band of the classification (`high`, `medium`, `low`).
    ///
    /// A scan always reports one. It is `None` only when the evidence comes
    /// from a stored run recorded before the band was persisted: a band is a
    /// judgement, so an unrecorded one is reported as absent rather than
    /// re-derived from the numbers.
    pub confidence_band: Option<String>,
}

/// Conservative material-body evidence shared by every group member.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BodyMateriality {
    /// Whether every member contains at least one loop.
    pub has_loop: bool,
    /// Whether every member calls a recognised allocation API.
    pub has_dynamic_allocation: bool,
    /// Fewest recovered call sites in any member.
    pub call_count: u64,
}

/// Where a group belongs in the report, as separated measures.
///
/// [`value`](Self::value) is what the report is ordered by, and it never
/// appears without the three measures it composes or the facts they were read
/// from. Everything here is on `0..1` and computed from the group alone, so
/// the same group ranks the same in every run it appears in.
#[derive(Debug, Clone, Serialize)]
pub struct Priority {
    /// The composed ranking value.
    pub value: f64,
    /// How sure the finding is duplication worth reporting.
    pub clone_confidence: f64,
    /// What keeping the copies in step costs.
    pub maintenance_risk: f64,
    /// What removing the duplication would cost.
    pub refactoring_difficulty: f64,
    /// How sure the finding is semantically equivalent. Absent until a
    /// compiler backend measures it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact. Absent until an
    /// artifact backend measures it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are. Absent: nothing measures savings
    /// yet, and a number here would read as a guarantee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub savings_confidence: Option<f64>,
    /// The facts the measures were read from.
    pub inputs: PriorityInputs,
}

/// What the ranking read about a group.
///
/// Reported in full so that a reader who disagrees with where a finding landed
/// can see which input put it there, and so that the ranking can be reproduced
/// from the published report rather than taken on trust.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityInputs {
    /// Token count of the smallest occurrence, which is what decides how
    /// easily the group could have matched by coincidence.
    pub smallest_member_tokens: u64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: u64,
    /// Occurrences in the group.
    pub instances: u64,
    /// Minimum pairwise similarity across the group.
    pub similarity: f64,
    /// Distinct files the occurrences sit in.
    pub files: u64,
    /// Distinct directories the occurrences sit in.
    pub directories: u64,
    /// Distinct languages the occurrences are written in.
    pub languages: u64,
    /// The run's minimum clone length, which the sizes are read against.
    pub min_clone_tokens: u64,
    /// Minimum raw identifier-set Jaccard agreement against the canonical
    /// member, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_jaccard: Option<f64>,
    /// Weakest call-surface agreement, when Structural mode measured one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_similarity: Option<f64>,
    /// Whether every member contains a loop, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_loop: Option<bool>,
    /// Whether every member calls a recognised allocation API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_dynamic_allocation: Option<bool>,
    /// Fewest call sites in any member, when Structural mode measured them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_count: Option<u64>,
    /// How often the duplicated code changed. Absent: no mode reads repository
    /// history yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub churn: Option<f64>,
    /// How many people own the copies. Absent, on the same footing as
    /// [`churn`](Self::churn).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership_spread: Option<f64>,
}
