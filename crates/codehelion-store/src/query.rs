//! The read path: every SQL query the CLI needs, as functions.
//!
//! SQL strings live here and nowhere else, so the CLI layer talks in domain
//! types. Result ordering is deterministic everywhere: groups order by their
//! fingerprint bytes (priority ordering joins in with the priority stage),
//! members in the order the run recorded them — the same database always
//! yields the same output.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_core::semantic::{SOG_SCHEMA_VERSION, SemanticOperationGraph};
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, GroupLineageId, UnitFingerprint,
};
use codehelion_core::test_code::TestCodeEvidence;
use rusqlite::{OptionalExtension, Row, params};

use crate::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisMappingConfidence, ArtifactAnalysisSavingsCalibration,
    ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSourceReason, MappingEvidence, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
};
use crate::fingerprint::BuildVariantFingerprint;
use crate::snapshot::{
    FileCountsRow, FunnelDropRow, FunnelStageRow, GuardrailsRow, SummaryRow, UnparsedRow,
    UnusedRuleRow,
};
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

/// Durable identity recorded for one group in a completed scan run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredGroupSnapshot {
    /// The group's current fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// The lineage the group belongs to.
    pub lineage: Option<GroupLineageId>,
}

/// Content and `BuildVariant` identities of one standalone artifact analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactAnalysisIdentity {
    /// Standalone analysis row id.
    pub analysis_id: i64,
    /// Format label recorded by the artifact backend.
    pub format: String,
    /// Content-derived artifact identity.
    pub content_fingerprint: [u8; 16],
    /// Build-configuration identity, when one was supplied at analysis time.
    pub build_variant_fingerprint: Option<BuildVariantFingerprint>,
}

/// Complete persisted input needed to re-render one standalone artifact analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactAnalysis {
    /// Standalone analysis row id.
    pub analysis_id: i64,
    /// Schema version declared by the persisted artifact IR row.
    pub schema_version: String,
    /// User-provided artifact path retained when the analysis was recorded.
    pub path: String,
    /// Canonical versioned artifact IR retained by the analysis.
    pub ir_json: String,
    /// Manifest path for the recorded build variant, when supplied.
    pub build_variant_manifest_path: Option<String>,
    /// Content-derived build-variant identity, when supplied.
    pub build_variant_fingerprint: Option<BuildVariantFingerprint>,
}

/// Where a recorded run came from: enough of its identity to say whether a
/// judgement made about its results still describes a later run.
///
/// A stable id is only meaningful under the conditions it was computed in, so
/// an artefact derived from a run (a baseline, an exported diff) has to carry
/// them. The build variant is the decisive one — it folds mode, languages and
/// normalization version into one fingerprint — but the detector versions are
/// recorded beside it, because a fingerprint schema change moves every id
/// without the variant noticing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOrigin {
    /// Row id of the run.
    pub id: i64,
    /// Scanned root path.
    pub root_path: String,
    /// Tool version that wrote the run.
    pub tool_version: String,
    /// How the effective configuration was selected.
    pub config_source: String,
    /// Configuration file path when one supplied the effective settings.
    pub config_path: Option<String>,
    /// Smallest clone the run could report, in tokens.
    pub min_clone_tokens: i64,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// RFC 3339 start time shared by every partition of one scan invocation.
    pub started_at: String,
    /// RFC 3339 finish time.
    pub finished_at: String,
    /// The build variant's fingerprint.
    pub variant_fingerprint: String,
    /// Normalization version the variant was built under.
    pub normalization_version: i64,
    /// Every recorded `(component, version)` pair, ordered by component.
    pub detector_versions: Vec<(String, String)>,
}

/// A stored build variant, as what it was rather than as the hash it is
/// known by.
///
/// The description is optional throughout: a variant recorded before a run
/// wrote down what it was analysed under says nothing here, which is not the
/// same claim as a build that was resolved and had nothing to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVariant {
    /// Row id of the variant.
    pub id: i64,
    /// Its fingerprint, which is what results are attributed to.
    pub fingerprint: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// The languages the run enumerated, comma-separated in a fixed order.
    pub languages: Option<String>,
    /// The grammar bare `.h` headers were read with; empty when the run
    /// enumerated neither C nor C++.
    pub header_language: Option<String>,
    /// Which languages' builds were resolved, comma-separated in a fixed
    /// order; empty when none was.
    pub build_language: Option<String>,
    /// What each compiler was told, in the order it was told, grouped by
    /// language and then by setting name.
    pub settings: Vec<StoredSetting>,
}

/// One recorded value of one build setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSetting {
    /// Which language's build it belongs to. Empty on a row recorded before a
    /// run could resolve more than one, and so before the question arose.
    pub language: String,
    /// The setting's stable name.
    pub name: String,
    /// Its position within that setting, for the ones that are sequences.
    pub position: i64,
    /// The value as it was given.
    pub value: String,
}

/// One stored occurrence of a group's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// Hex form of the occurrence's stable finding id.
    pub finding_hex: String,
    /// Hex form of the content fingerprint of the matched slice.
    ///
    /// Two occurrences of the same content share it, which is what makes a
    /// result exported from one machine comparable with a run on another: the
    /// finding id is derived from the group fingerprint and moves with it,
    /// while this does not.
    pub content_hex: String,
    /// Language the occurrence was read as (`rust`, `c`, `cpp`).
    pub language: String,
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
    /// Boilerplate shape of the enclosing whole unit, when Structural mode
    /// classified it. `None` also covers fragments, which have no whole body.
    pub boilerplate: Option<String>,
    /// Whether this is the group's canonical instance.
    pub is_canonical: bool,
}

/// One clone group looked up on its own, with the run that recorded it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredGroupDetail {
    /// Run the group was read from.
    pub run_id: i64,
    /// The group itself.
    pub group: StoredGroup,
}

/// A kind of recorded identifier a lookup can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// One occurrence of a clone group.
    Occurrence,
    /// A clone group, as its report heading names it.
    CloneGroup,
    /// A supplemental sibling finding attached to a primary clone group.
    Sibling,
    /// A group from an explicit cross-language comparison.
    CrossLanguageGroup,
    /// A group from an explicit cross-build-variant comparison.
    CrossVariantGroup,
}

impl IdKind {
    /// What this kind is called when a message has to name it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Occurrence => "finding",
            Self::CloneGroup => "clone group",
            Self::Sibling => "sibling finding",
            Self::CrossLanguageGroup => "cross-language comparison group",
            Self::CrossVariantGroup => "cross-build-variant comparison group",
        }
    }
}

/// One sibling finding looked up by the ID exported in a report.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSiblingDetail {
    /// Run that recorded the sibling.
    pub run_id: i64,
    /// Primary group that owns the supplemental finding.
    pub group_fingerprint_hex: String,
    /// The sibling and its verifier evidence.
    pub sibling: StoredSibling,
}

/// One persisted cross-build-variant group, read for its standalone explain
/// view rather than treated as an ordinary scan finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVariantGroupDetail {
    /// Stable identity of the explicit comparison that recorded this group.
    pub comparison_id_hex: String,
    /// Version of the comparison policy.
    pub policy_version: String,
    /// Scan root shared by the compared partitions.
    pub root_path: String,
    /// Origin `BuildVariant` fingerprints retained by the comparison.
    pub origin_variants: Vec<String>,
    /// Stable comparison-domain group identity.
    pub group_id_hex: String,
    /// Clone classification under the comparison policy.
    pub clone_type: String,
    /// Origin-aware exact-clone members.
    pub members: Vec<CrossVariantGroupMember>,
}

/// One member of a persisted cross-build-variant clone group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVariantGroupMember {
    /// `BuildVariant` fingerprint of the normal partition that produced it.
    pub origin_variant: String,
    /// Source language (`c` or `cpp`).
    pub language: String,
    /// Source path relative to the comparison root.
    pub file_path: String,
    /// One-based source range start.
    pub start_line: u32,
    /// One-based source range end.
    pub end_line: u32,
    /// Best-effort enclosing unit name.
    pub unit_name: Option<String>,
    /// Matched token count.
    pub token_count: usize,
}

/// One recorded identifier matching a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMatch {
    /// What the id identifies.
    pub kind: IdKind,
    /// The full hex id.
    pub id: String,
}

/// One stored clone group with its members.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredGroup {
    /// Hex form of the group fingerprint.
    pub fingerprint_hex: String,
    /// Clone classification name (`type-1`, `type-2`, ...).
    pub clone_type: String,
    /// What the members are: `unit` for whole duplicated units, `fragment`
    /// for a run of statements duplicated inside them.
    pub member_scope: String,
    /// Minimum pairwise raw similarity.
    pub score: f64,
    /// Content entropy in bits.
    pub entropy_bits: f64,
    /// Noise marker name, if one fired.
    pub suppress_reason: Option<String>,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether the group is a verified pair no larger group could hold, and
    /// so the one kind whose members appear in another group too.
    pub split_pair: bool,
    /// Whether every member is test code.
    pub test_code: bool,
    /// Why every member is test code, when [`Self::test_code`] is true.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the members differ from each other by one integer width and
    /// nothing else.
    pub width_family: bool,
    /// Statements each member covers, for a fragment-scope group; `None` for a
    /// whole-unit group, and for a row written before runs recorded it.
    pub statements: Option<i64>,
    /// Smallest raw-identifier Jaccard agreement to the canonical unit.
    pub identifier_jaccard: Option<f64>,
    /// Whether every member contains a loop, when Structural mode measured it.
    pub has_loop: Option<bool>,
    /// Whether every member calls a recognised allocation API.
    pub has_dynamic_allocation: Option<bool>,
    /// Fewest recovered call sites in any member.
    pub call_count: Option<i64>,
    /// The similarity breakdown, when the mode measured one (Structural).
    pub similarity: Option<StoredSimilarity>,
    /// The rule that hid the group in its run, when one matched. Absent for a
    /// group the run reported.
    pub suppressed_by: Option<StoredSuppressionRef>,
    /// Registered SOG evidence for a restricted semantic group.
    pub semantic: Option<StoredSemanticEvidence>,
    /// The group's occurrences.
    pub members: Vec<StoredMember>,
    /// Supplemental incomplete local mirrors, never primary members.
    pub siblings: Vec<StoredSibling>,
}

/// One sibling reconstructed from the dedicated group-sibling table.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSibling {
    /// The verifier classification.
    pub clone_type: String,
    /// The verifier confidence band.
    pub confidence_band: String,
    /// Composite-weight recipe used by the comparison.
    pub weight_version: String,
    /// Per-dimension verifier evidence.
    pub lexical: f64,
    /// Per-dimension verifier evidence.
    pub structural: f64,
    /// Per-dimension verifier evidence.
    pub control_flow: Option<f64>,
    /// Per-dimension verifier evidence.
    pub type_similarity: Option<f64>,
    /// Per-dimension verifier evidence.
    pub api: Option<f64>,
    /// Composite verifier similarity.
    pub composite: f64,
    /// Independent candidate channel that supplied this sibling.
    pub basis: String,
    /// Exact normalized signature for signature-channel siblings.
    pub signature: Option<String>,
    /// How many units in the scanned tree share that normalized signature,
    /// for signature-channel siblings.
    pub signature_units: Option<i64>,
    /// The ungrouped sibling occurrence.
    pub member: StoredMember,
    /// The rule that hid this supplemental finding in its run.
    pub suppressed_by: Option<StoredSuppressionRef>,
}

/// One source-unit anchor retained for a run-scoped near-match diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNearMissUnit {
    /// Whole-unit fingerprint in canonical hexadecimal form.
    pub fingerprint_hex: String,
    /// Source language.
    pub language: String,
    /// Source path relative to the scan root.
    pub file_path: String,
    /// 1-based source anchor.
    pub start_line: Option<i64>,
    /// 1-based source anchor.
    pub end_line: Option<i64>,
    /// Token count of the unit.
    pub token_count: i64,
    /// Best-effort unit name.
    pub unit_name: Option<String>,
}

/// One bounded LSH proposal that missed the primary estimate threshold.
///
/// It deliberately carries no group or finding identity: it was not verified
/// and therefore is not a primary clone finding.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredNearMiss {
    /// MinHash-estimated Jaccard similarity below the primary gate.
    pub estimated_jaccard: f64,
    /// Lower side of the canonical proposal pair.
    pub left: StoredNearMissUnit,
    /// Higher side of the canonical proposal pair.
    pub right: StoredNearMissUnit,
    /// The rule that hid this diagnostic in its run.
    pub suppressed_by: Option<StoredSuppressionRef>,
}

/// Decode the constrained evidence label stored with a clone group.
fn stored_test_code_evidence(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<TestCodeEvidence>> {
    let value: Option<String> = row.get(column)?;
    value
        .map(|value| {
            TestCodeEvidence::from_name(&value).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown test-code evidence {value:?}"),
                    )),
                )
            })
        })
        .transpose()
}

/// Registered-rule evidence read back for a restricted semantic group.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSemanticEvidence {
    /// SOG schema version interpreted by the rule.
    pub schema_version: String,
    /// Stable registered-rule identifier.
    pub rule_id: String,
    /// Rule semantics revision.
    pub rule_version: u32,
    /// Conservative rule confidence before auxiliary evidence.
    pub rule_confidence: f64,
    /// The normalized graphs in canonical-member order, decoded from the
    /// versioned JSON stored with each member fragment.
    pub graphs: Vec<SemanticOperationGraph>,
    /// Explainable graph-local node correspondences in canonical order.
    pub node_mappings: Vec<StoredSemanticNodeMapping>,
}

/// One graph-local correspondence read from semantic evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSemanticNodeMapping {
    /// Zero-based position of the graph containing the corresponding node.
    pub corresponding_member: u32,
    /// Node index in the canonical graph.
    pub canonical: u32,
    /// Node index in the corresponding graph.
    pub corresponding: u32,
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
    pub control_flow: Option<f64>,
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

/// One stored finding: the ranked row of a group in a scan.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFinding {
    /// Hex form of the group fingerprint the finding belongs to.
    pub group_fingerprint_hex: String,
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
    /// What the owning group's members are (`unit` or `fragment`).
    pub member_scope: String,
    /// The owning group's score.
    pub score: f64,
    /// The owning group's normalized-token entropy, in bits.
    pub entropy_bits: f64,
    /// Number of occurrences in the owning group, this one included.
    pub member_count: i64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the owning group is test code.
    pub test_code: bool,
    /// Why every member of the owning group is test code, when it is test
    /// code.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the owning group is a verified pair no larger group could hold.
    pub split_pair: bool,
    /// The owning group's similarity breakdown, when the mode measured one.
    pub similarity: Option<StoredSimilarity>,
    /// Registered SOG evidence, when the owning group is restricted semantic.
    pub semantic: Option<StoredSemanticEvidence>,
    /// Where the run ranked the finding, and the facts it ranked on. Absent
    /// for a group with no audited finding row.
    pub priority: Option<StoredPriority>,
    /// Engine-derived noise reason, when one marked the owning group.
    pub suppress_reason: Option<String>,
    /// The rule that suppressed the finding in this run, if one matched.
    pub suppression: Option<StoredSuppressionRef>,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run_id: i64,
}

/// One persisted Rust-to-C++ semantic group, read for its standalone explain
/// view rather than treated as an ordinary scan finding.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossLanguageGroupDetail {
    /// Stable identity of the explicit comparison that recorded this group.
    pub comparison_id_hex: String,
    /// Version of the comparison policy.
    pub policy_version: String,
    /// Scan root shared by the compared partitions.
    pub root_path: String,
    /// Origin `BuildVariant` fingerprints retained by the comparison.
    pub origin_variants: Vec<String>,
    /// Stable comparison-domain semantic-group identity.
    pub group_id_hex: String,
    /// Registered semantic correspondence rule.
    pub rule_id: String,
    /// Registered rule revision.
    pub rule_version: u32,
    /// Confidence after the available evidence was combined.
    pub semantic_confidence: f64,
    /// Closed API correspondences that established the group.
    pub correspondence_ids: Vec<String>,
    /// Origin-aware members and their stored normalized operation graphs.
    pub members: Vec<CrossLanguageGroupMember>,
}

/// One member of a persisted cross-language semantic group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossLanguageGroupMember {
    /// `BuildVariant` fingerprint of the normal partition that produced it.
    pub origin_variant: String,
    /// Source language (`rust` or `cpp`).
    pub language: String,
    /// Source path relative to the comparison root.
    pub file_path: String,
    /// One-based source range start.
    pub start_line: u32,
    /// One-based source range end.
    pub end_line: u32,
    /// Best-effort enclosing unit name.
    pub unit_name: Option<String>,
    /// Revalidated normalized operation graph.
    pub graph: SemanticOperationGraph,
}

/// How a recorded group came by the history it carries.
///
/// A group either kept the fingerprint an earlier run knew it by, or took
/// over an earlier group's history under a different fingerprint. Told apart,
/// the two read as one piece of work; conflated, the same edit looks like a
/// fix in one place and an unfixed finding in another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGroupOrigin {
    /// The group this describes.
    pub group_fingerprint_hex: String,
    /// The predecessor whose history this group took over, absent when the
    /// group started a history of its own.
    pub adopted_from: Option<StoredLineageParent>,
}

/// The predecessor a group took its history from, and the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLineageParent {
    /// Fingerprint the predecessor group was known by.
    pub fingerprint_hex: String,
    /// Member contents the two groups have in common. This is the quantity
    /// the connection was decided on, so it is what explains the decision.
    pub shared_content: i64,
    /// The newer group's distinct member contents: the population
    /// [`Self::shared_content`] was counted out of.
    ///
    /// A share is only evidence beside what it is a share of, and the two
    /// numbers have to come from the same population — the newer group's
    /// contents, not its members, of which several can carry one content.
    /// `None` for an edge recorded without a measured population; a reader
    /// then reports the count on its own rather than dividing it by a number
    /// that counts something else.
    pub compared_content: Option<i64>,
}

/// Where a stored run ranked a finding, and what it read to get there.
///
/// Read back rather than recomputed. The rules a run ranked under are the
/// rules that release carried, and re-deriving the number under today's would
/// answer a question nobody asked — the recorded value is what the run acted
/// on. Every measure a run did not take is `None`, including the ones a newer
/// release computes and an older one did not.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPriority {
    /// How sure the finding was duplication worth reporting.
    pub clone_confidence: f64,
    /// What keeping the copies in step was judged to cost.
    pub maintenance_risk: Option<f64>,
    /// What removing the duplication was judged to cost.
    pub refactoring_difficulty: Option<f64>,
    /// The composed ranking value.
    pub final_priority: f64,
    /// How sure the finding is semantically equivalent.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are.
    pub savings_confidence: Option<f64>,
    /// The group facts the measures were read from.
    pub facts: StoredRankingFacts,
}

/// What a stored group looks like to the ranking.
///
/// Derived from the group's own rows rather than stored a second time: a copy
/// of a derivable value is a second answer waiting to disagree with the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRankingFacts {
    /// Token count of the smallest occurrence.
    pub smallest_member_tokens: i64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: i64,
    /// Occurrences in the group.
    pub instances: i64,
    /// Distinct files the occurrences sit in.
    pub files: i64,
    /// Distinct directories the occurrences sit in.
    pub directories: i64,
    /// Distinct languages the occurrences are written in.
    pub languages: i64,
    /// The run's minimum clone length. `None` for a run recorded before runs
    /// stored the floor they reported under.
    pub min_clone_tokens: Option<i64>,
}

/// The suppression rule a finding references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuppressionRef {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`, ...).
    pub scope: String,
    /// The rule's pattern.
    pub pattern: String,
    /// Rule judgement recorded with the suppression, when one was supplied.
    pub reason: Option<String>,
    /// Whether the referenced rule was active in the database row.
    pub active: Option<bool>,
}

/// One source-to-artifact correspondence read from a standalone artifact analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactMapping {
    /// Row id of the artifact analysis which supplied the mapping.
    pub analysis_id: i64,
    /// Version of this mapping record's evidence vocabulary.
    pub schema_version: String,
    /// Content-derived artifact symbol identity.
    pub artifact_symbol_fingerprint: [u8; 16],
    /// Whether the source reference identifies a unit or fragment.
    pub source_kind: ArtifactAnalysisSourceKind,
    /// Content-derived source unit or fragment identity.
    pub source_fingerprint: [u8; 16],
    /// Stable discriminator of this source occurrence (`FindingId` for fragments).
    pub source_instance_fingerprint: [u8; 16],
    /// Build variant that minted the source identity.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Versioned independent facts that justify the correspondence.
    pub evidence: MappingEvidence,
    /// Confidence that the stored evidence supports the correspondence.
    pub confidence: ArtifactAnalysisMappingConfidence,
    /// Bytes attributed to this source, when the evidence supports a split.
    pub attributed_bytes: Option<u64>,
    /// Build variant under which the correspondence was established.
    pub build_variant_fingerprint: BuildVariantFingerprint,
}

/// Raw mapping columns read before their versioned fields are validated.
struct ArtifactMappingSqlRow {
    analysis_id: i64,
    schema_version: String,
    artifact_symbol_fingerprint: Vec<u8>,
    source_kind: String,
    source_fingerprint: Vec<u8>,
    source_instance_fingerprint: Vec<u8>,
    evidence_json: String,
    confidence: String,
    attributed_bytes: Option<i64>,
    build_variant_fingerprint: Vec<u8>,
    source_build_variant_fingerprint: Option<Vec<u8>>,
}

/// A symbol deliberately left without a source correspondence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactUnmappedSymbol {
    /// Content-derived artifact symbol identity.
    pub artifact_symbol_fingerprint: [u8; 16],
    /// Parser-established reason that a correspondence was not recorded.
    pub reason: ArtifactAnalysisUnmappedReason,
}

/// A source identity explicitly absent from one artifact analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactUnmappedSource {
    /// Whether the source reference identifies a unit or fragment.
    pub source_kind: ArtifactAnalysisSourceKind,
    /// Content-derived source unit or fragment identity.
    pub source_fingerprint: [u8; 16],
    /// Stable discriminator of this unmatched source occurrence.
    pub source_instance_fingerprint: [u8; 16],
    /// Build variant that minted the source identity.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Parser- or correlation-established reason for the absence.
    pub reason: ArtifactAnalysisUnmappedSourceReason,
}

/// Persisted coverage figures for one explicit source-run correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactAnalysisCorrelation {
    /// Version of the stored summary shape.
    pub schema_version: String,
    /// Source scan whose stable identities were considered.
    pub source_scan_run_id: i64,
    /// Number of retained correspondence rows.
    pub mapping_count: u64,
    /// Number of symbols observed in the artifact analysis.
    pub artifact_symbol_count: u64,
    /// Number of observed symbols with at least one retained mapping.
    pub mapped_symbol_count: u64,
    /// Sum of observed symbol sizes.
    pub artifact_symbol_bytes: u64,
    /// Sum of observed mapped symbol sizes.
    pub mapped_symbol_bytes: u64,
}

/// One source unit available as a candidate for artifact correlation.
///
/// The identity keeps the kind it was minted as: a fragment fingerprint or a
/// finding id cannot be written into [`Self::fingerprint`], because a caller
/// that correlates the wrong kind of identity produces an attribution nothing
/// downstream can tell apart from a correct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceUnitIdentity {
    /// Content-derived stable unit identity.
    pub fingerprint: UnitFingerprint,
    /// Build variant that minted this unit identity.
    pub build_variant_fingerprint: BuildVariantFingerprint,
    /// Path relative to the scan root.
    pub file_path: String,
    /// Best-effort declared unit name, when the frontend established one.
    ///
    /// This is display evidence rather than an identity. A caller using it
    /// for source/artifact correlation must retain all equal-name candidates.
    pub name: Option<String>,
    /// Frontend-recovered declaration kind, such as `function` or `method`.
    /// It distinguishes same-named declarations that share a source file.
    pub unit_kind: String,
    /// One-based ordinal among otherwise identical declarations in the same
    /// file. It distinguishes duplicate occurrences without hashing source
    /// positions.
    pub occurrence_ordinal: u32,
    /// First source line covered by the unit, when available.
    pub start_line: Option<u32>,
    /// Last source line covered by the unit, when available.
    pub end_line: Option<u32>,
}

/// A clone finding fragment available for source/artifact correlation.
///
/// Only fragments that belong to a persisted clone group are returned. Parser
/// implementation fragments that never became findings do not need a durable
/// artifact-absence record.
///
/// The three identities it carries are three different kinds of thing — the
/// content of the slice, this occurrence of it, and the group that holds every
/// occurrence — so each keeps the newtype it was minted as. They are all
/// 128-bit digests, so nothing but the type tells them apart, and a swap would
/// attribute artifact bytes to a source identity that never named them:
///
/// ```
/// use codehelion_core::stable_id::{CloneGroupFingerprint, FindingId, FragmentFingerprint};
/// use codehelion_store::query::SourceFragmentIdentity;
///
/// let fragment = SourceFragmentIdentity {
///     fingerprint: FragmentFingerprint::from_bytes([1; 16]),
///     finding_id: FindingId::from_bytes([2; 16]),
///     clone_group_fingerprint: CloneGroupFingerprint::from_bytes([3; 16]),
///     is_canonical: true,
///     clone_confidence: 1.0,
///     build_variant_fingerprint: [4; 16],
///     file_path: "src/lib.rs".to_owned(),
///     start_line: Some(10),
///     end_line: Some(20),
/// };
/// assert_eq!(fragment.finding_id.as_bytes(), &[2; 16]);
/// ```
///
/// Exchanging two of them is a compile error rather than a silent mismatch:
///
/// ```compile_fail,E0308
/// use codehelion_core::stable_id::{CloneGroupFingerprint, FindingId, FragmentFingerprint};
/// use codehelion_store::query::SourceFragmentIdentity;
///
/// let fragment = SourceFragmentIdentity {
///     // The content identity and the occurrence identity are swapped.
///     fingerprint: FindingId::from_bytes([2; 16]),
///     finding_id: FragmentFingerprint::from_bytes([1; 16]),
///     clone_group_fingerprint: CloneGroupFingerprint::from_bytes([3; 16]),
///     is_canonical: true,
///     clone_confidence: 1.0,
///     build_variant_fingerprint: [4; 16],
///     file_path: "src/lib.rs".to_owned(),
///     start_line: Some(10),
///     end_line: Some(20),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SourceFragmentIdentity {
    /// Content-derived stable fragment identity.
    pub fingerprint: FragmentFingerprint,
    /// Stable identifier of this clone-member occurrence.
    pub finding_id: FindingId,
    /// Content-derived group identity owning this occurrence.
    pub clone_group_fingerprint: CloneGroupFingerprint,
    /// Whether this occurrence is the group's retained canonical member.
    pub is_canonical: bool,
    /// Clone similarity score recorded for the owning group.
    pub clone_confidence: f64,
    /// Build variant that minted this fragment identity.
    pub build_variant_fingerprint: BuildVariantFingerprint,
    /// Path containing this finding occurrence.
    pub file_path: String,
    /// First source line covered by the occurrence, when available.
    pub start_line: Option<u32>,
    /// Last source line covered by the occurrence, when available.
    pub end_line: Option<u32>,
}

/// A compiler-resolved callable anchor available to source/artifact correlation.
///
/// It is intentionally not linked to a source unit in storage. The caller
/// performs the containment check against the scan's unit anchors, preserving
/// the distinction between compiler fact and correlation inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResolvedSymbol {
    /// Resolved compiler spelling for a callable defined in the scan tree.
    pub name: String,
    /// Definition anchor when present, otherwise the expansion anchor.
    pub file_path: String,
    /// One-based line in [`Self::file_path`].
    pub line: u32,
    /// Macro definition anchor when this symbol was expanded elsewhere.
    ///
    /// The ordinary source mapping uses [`Self::file_path`] and [`Self::line`]
    /// (the definition side when available). This extra fact preserves that
    /// the correspondence originated in a declarative macro rather than an
    /// independently written function.
    pub macro_definition: Option<SourceMacroDefinition>,
}

/// Definition location that distinguishes generated macro code from source
/// written at the expansion site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMacroDefinition {
    /// Path the macro body was written in.
    pub file_path: String,
    /// One-based line in [`Self::file_path`].
    pub line: u32,
}

/// A statically resolved source call available to artifact-call correlation.
///
/// The source unit containing the call remains a caller-side containment
/// check, and dynamic or unresolved dispatch is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResolvedCall {
    /// Compiler-resolved target spelling.
    pub target_name: String,
    /// Definition anchor when present, otherwise the expansion anchor.
    pub file_path: String,
    /// One-based line in [`Self::file_path`].
    pub line: u32,
}

/// A compiler-reported generic or template specialization anchor.
///
/// The key is only evidence when an artifact's demangled full name can be
/// normalized to the same specialization spelling. It is not an identity for
/// a source unit or an artifact symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInstantiation {
    /// Definition spelling supplied by the compiler helper.
    pub definition: String,
    /// Optional compiler-produced spelling for artifact correlation.
    pub artifact_match_key: Option<String>,
    /// Versioned compiler-specific specialization key.
    pub instantiation_key: String,
    /// Definition anchor when present, otherwise the expansion anchor.
    pub file_path: String,
    /// One-based line in [`Self::file_path`].
    pub line: u32,
    /// One-based final line of the source definition, when reported by the
    /// compiler.
    pub definition_end_line: Option<u32>,
    /// Translation unit or crate that reported this specialization.
    ///
    /// This is compiler evidence, not a source identity. The same header
    /// definition can legitimately appear under many translation units.
    pub translation_unit: String,
}

mod artifact;
mod common;
mod groups;
mod run;
mod source;
