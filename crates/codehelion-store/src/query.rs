//! The read path: every SQL query the CLI needs, as functions.
//!
//! SQL strings live here and nowhere else, so the CLI layer talks in domain
//! types. Result ordering is deterministic everywhere: groups order by their
//! fingerprint bytes (priority ordering joins in with the priority stage),
//! members in the order the run recorded them — the same database always
//! yields the same output.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_core::features::FeatureKind;
use codehelion_core::semantic::{SOG_SCHEMA_VERSION, SemanticOperationGraph};
use rusqlite::{OptionalExtension, params};

use crate::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisMappingConfidence, ArtifactAnalysisSavingsCalibration,
    ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSourceReason, MappingEvidence, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
};
use crate::snapshot::{FunnelDropRow, FunnelStageRow, SummaryRow, UnparsedRow, UnusedRuleRow};
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
    pub build_variant_fingerprint: Option<[u8; 16]>,
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
    /// Analysis mode name.
    pub analysis_mode: String,
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
    /// Number of occurrences in the owning group, this one included.
    pub member_count: i64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the owning group is test code.
    pub test_code: bool,
    /// Whether the owning group is a verified pair no larger group could hold.
    pub split_pair: bool,
    /// The owning group's similarity breakdown, when the mode measured one.
    pub similarity: Option<StoredSimilarity>,
    /// Registered SOG evidence, when the owning group is restricted semantic.
    pub semantic: Option<StoredSemanticEvidence>,
    /// Where the run ranked the finding, and the facts it ranked on. Absent
    /// for a group with no audited finding row.
    pub priority: Option<StoredPriority>,
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
    pub source_build_variant_fingerprint: [u8; 16],
    /// Versioned independent facts that justify the correspondence.
    pub evidence: MappingEvidence,
    /// Confidence that the stored evidence supports the correspondence.
    pub confidence: ArtifactAnalysisMappingConfidence,
    /// Bytes attributed to this source, when the evidence supports a split.
    pub attributed_bytes: Option<u64>,
    /// Build variant under which the correspondence was established.
    pub build_variant_fingerprint: [u8; 16],
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
    pub source_build_variant_fingerprint: [u8; 16],
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceUnitIdentity {
    /// Content-derived stable unit identity.
    pub fingerprint: [u8; 16],
    /// Build variant that minted this unit identity.
    pub build_variant_fingerprint: [u8; 16],
    /// Path relative to the scan root.
    pub file_path: String,
    /// Best-effort declared unit name, when the frontend established one.
    ///
    /// This is display evidence rather than an identity. A caller using it
    /// for source/artifact correlation must retain all equal-name candidates.
    pub name: Option<String>,
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
#[derive(Debug, Clone, PartialEq)]
pub struct SourceFragmentIdentity {
    /// Content-derived stable fragment identity.
    pub fingerprint: [u8; 16],
    /// Stable identifier of this clone-member occurrence.
    pub finding_id: [u8; 16],
    /// Content-derived group identity owning this occurrence.
    pub clone_group_fingerprint: [u8; 16],
    /// Whether this occurrence is the group's retained canonical member.
    pub is_canonical: bool,
    /// Clone similarity score recorded for the owning group.
    pub clone_confidence: f64,
    /// Build variant that minted this fragment identity.
    pub build_variant_fingerprint: [u8; 16],
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

impl Store {
    /// Source units recorded by one scan, in deterministic path and anchor order.
    ///
    /// The returned identities carry their own build variants. A caller must
    /// retain that value when it turns a path match into a correspondence.
    ///
    /// # Errors
    ///
    /// Returns an error when stored fingerprints cannot be represented by
    /// this build's stable fingerprint schema.
    pub fn source_units(&self, scan_run_id: i64) -> Result<Vec<SourceUnitIdentity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT f.hash, bv.variant_fingerprint, u.file_path, u.name, u.start_line, u.end_line
             FROM source_unit u
             JOIN fingerprint f ON f.id = u.fingerprint_id
             JOIN build_variant bv ON bv.id = f.build_variant_id
             WHERE u.scan_run_id = ?1
             ORDER BY u.file_path ASC, u.start_line ASC, u.end_line ASC, f.hash ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(fingerprint, build_variant, file_path, name, start_line, end_line)| {
                    Ok(SourceUnitIdentity {
                        fingerprint: fingerprint_from_blob("fingerprint.hash", fingerprint)?,
                        build_variant_fingerprint: parse_build_variant_reference(&build_variant)?,
                        file_path,
                        name,
                        start_line: positive_line("source_unit.start_line", start_line)?,
                        end_line: positive_line("source_unit.end_line", end_line)?,
                    })
                },
            )
            .collect()
    }

    /// Clone finding fragments recorded by one scan, in stable identity order.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored fingerprint cannot be represented by
    /// this build's stable fingerprint schema.
    pub fn source_clone_fragments(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceFragmentIdentity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT f.hash, m.finding_id, gf.hash, m.is_canonical, g.score,
                    bv.variant_fingerprint, r.file_path,
                    r.start_line, r.end_line
             FROM fragment r
             JOIN clone_group_member m ON m.fragment_id = r.id
             JOIN clone_group g ON g.id = m.clone_group_id
             JOIN fingerprint f ON f.id = r.fingerprint_id
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             JOIN build_variant bv ON bv.id = f.build_variant_id
             WHERE r.scan_run_id = ?1 AND g.scan_run_id = ?1
             ORDER BY gf.hash ASC, m.is_canonical DESC, m.finding_id ASC,
                      f.hash ASC, bv.variant_fingerprint ASC, r.file_path ASC,
                      r.start_line ASC, r.end_line ASC, r.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    fingerprint,
                    finding_id,
                    clone_group_fingerprint,
                    is_canonical,
                    clone_confidence,
                    build_variant,
                    file_path,
                    start_line,
                    end_line,
                )| {
                    Ok(SourceFragmentIdentity {
                        fingerprint: fingerprint_from_blob("fingerprint.hash", fingerprint)?,
                        finding_id: fingerprint_from_blob(
                            "clone_group_member.finding_id",
                            finding_id,
                        )?,
                        clone_group_fingerprint: fingerprint_from_blob(
                            "clone_group.group_fingerprint",
                            clone_group_fingerprint,
                        )?,
                        is_canonical: is_canonical != 0,
                        clone_confidence,
                        build_variant_fingerprint: parse_build_variant_reference(&build_variant)?,
                        file_path,
                        start_line: positive_line("fragment.start_line", start_line)?,
                        end_line: positive_line("fragment.end_line", end_line)?,
                    })
                },
            )
            .collect()
    }

    /// Local compiler-resolved function anchors from one source scan.
    ///
    /// Only symbols the compiler marked as belonging to the scanned tree are
    /// returned. The source unit relationship remains a caller-side
    /// containment check rather than a persisted assertion.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded compiler anchor has an invalid line.
    pub fn source_resolved_symbols(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceResolvedSymbol>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.name, COALESCE(s.definition_file, s.expansion_file),
                    COALESCE(s.definition_start_line, s.expansion_start_line),
                    s.definition_file, s.definition_start_line,
                    s.expansion_file, s.expansion_start_line
             FROM compiler_symbol s
             JOIN compiler_unit u ON u.id = s.compiler_unit_id
             WHERE u.scan_run_id = ?1
               AND s.symbol_kind = 'function'
               AND s.external = 0
             ORDER BY s.name ASC, COALESCE(s.definition_file, s.expansion_file) ASC,
                      COALESCE(s.definition_start_line, s.expansion_start_line) ASC, s.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    name,
                    file_path,
                    line,
                    definition_file,
                    definition_line,
                    expansion_file,
                    expansion_line,
                )| {
                    let line = positive_line("compiler_symbol.definition_start_line", Some(line))?
                        .ok_or_else(|| StoreError::UnknownVocabulary {
                            field: "compiler_symbol.definition_start_line",
                            value: "NULL".to_owned(),
                        })?;
                    let macro_definition = match (
                        definition_file,
                        definition_line,
                        expansion_file,
                        expansion_line,
                    ) {
                        (
                            Some(definition_file),
                            Some(definition_line),
                            Some(expansion_file),
                            Some(expansion_line),
                        ) if definition_file != expansion_file
                            || definition_line != expansion_line =>
                        {
                            Some(SourceMacroDefinition {
                                line: positive_line(
                                    "compiler_symbol.definition_start_line",
                                    Some(definition_line),
                                )?
                                .ok_or_else(|| {
                                    StoreError::UnknownVocabulary {
                                        field: "compiler_symbol.definition_start_line",
                                        value: "NULL".to_owned(),
                                    }
                                })?,
                                file_path: definition_file,
                            })
                        }
                        _ => None,
                    };
                    Ok(SourceResolvedSymbol {
                        name,
                        file_path,
                        line,
                        macro_definition,
                    })
                },
            )
            .collect()
    }

    /// Statically resolved local call anchors from one source scan.
    ///
    /// Dynamic and unresolved dispatch cannot establish an independent
    /// call-graph correspondence, so they are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded compiler call anchor has an invalid line.
    pub fn source_resolved_calls(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceResolvedCall>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.target_symbol, COALESCE(c.definition_file, c.expansion_file),
                    COALESCE(c.definition_start_line, c.expansion_start_line)
             FROM compiler_call c
             JOIN compiler_unit u ON u.id = c.compiler_unit_id
             WHERE u.scan_run_id = ?1 AND c.resolution = 'static'
             ORDER BY c.target_symbol ASC,
                      COALESCE(c.definition_file, c.expansion_file) ASC,
                      COALESCE(c.definition_start_line, c.expansion_start_line) ASC, c.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(target_name, file_path, line)| {
                let line = positive_line("compiler_call.definition_start_line", Some(line))?
                    .ok_or_else(|| StoreError::UnknownVocabulary {
                        field: "compiler_call.definition_start_line",
                        value: "NULL".to_owned(),
                    })?;
                Ok(SourceResolvedCall {
                    target_name,
                    file_path,
                    line,
                })
            })
            .collect()
    }

    /// Local compiler-reported generic and template instantiation anchors.
    ///
    /// These rows remain separate from source units; correlation performs the
    /// containment check and only accepts a key that agrees with an artifact's
    /// demangled full name.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded instantiation anchor has an invalid line.
    pub fn source_instantiations(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceInstantiation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT i.definition, i.artifact_match_key, i.instantiation_key, u.file_path,
                    COALESCE(i.definition_file, i.expansion_file),
                    COALESCE(i.definition_start_line, i.expansion_start_line),
                    i.definition_end_line
             FROM compiler_instantiation i
             JOIN compiler_unit u ON u.id = i.compiler_unit_id
             WHERE u.scan_run_id = ?1
             ORDER BY i.instantiation_key ASC,
                      COALESCE(i.definition_file, i.expansion_file) ASC,
                      COALESCE(i.definition_start_line, i.expansion_start_line) ASC, i.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    definition,
                    artifact_match_key,
                    instantiation_key,
                    translation_unit,
                    file_path,
                    line,
                    definition_end_line,
                )| {
                    let line =
                        positive_line("compiler_instantiation.definition_start_line", Some(line))?
                            .ok_or_else(|| StoreError::UnknownVocabulary {
                                field: "compiler_instantiation.definition_start_line",
                                value: "NULL".to_owned(),
                            })?;
                    Ok(SourceInstantiation {
                        definition,
                        artifact_match_key,
                        instantiation_key,
                        file_path,
                        line,
                        definition_end_line: positive_line(
                            "compiler_instantiation.definition_end_line",
                            definition_end_line,
                        )?,
                        translation_unit,
                    })
                },
            )
            .collect()
    }

    /// Every mapping recorded for one artifact analysis, in stable evidence order.
    ///
    /// The result retains all ambiguous candidates. Callers must not collapse
    /// them to a single source merely because they share an artifact symbol.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer mapping vocabulary.
    pub fn artifact_mappings(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactMapping>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT schema_version, artifact_symbol_fingerprint, source_kind,
                    source_fingerprint, source_instance_fingerprint, evidence_json, mapping_confidence,
                    attributed_bytes, build_variant_fingerprint, source_build_variant_fingerprint
             FROM artifact_analysis_source_mapping
             WHERE artifact_analysis_id = ?1
             ORDER BY artifact_symbol_fingerprint ASC, source_kind ASC,
                      source_fingerprint ASC, source_instance_fingerprint ASC, evidence_json ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    schema_version,
                    artifact_symbol_fingerprint,
                    source_kind,
                    source_fingerprint,
                    source_instance_fingerprint,
                    evidence_json,
                    confidence,
                    attributed_bytes,
                    build_variant_fingerprint,
                    source_build_variant_fingerprint,
                )| {
                    if schema_version != SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION {
                        return Err(StoreError::InvalidMappingEvidence {
                            reason: "unknown source-artifact mapping schema".to_owned(),
                        });
                    }
                    Ok(StoredArtifactMapping {
                        analysis_id,
                        schema_version,
                        artifact_symbol_fingerprint: fingerprint_from_blob(
                            "artifact_analysis_source_mapping.artifact_symbol_fingerprint",
                            artifact_symbol_fingerprint,
                        )?,
                        source_kind: ArtifactAnalysisSourceKind::from_sql(&source_kind)?,
                        source_fingerprint: fingerprint_from_blob(
                            "artifact_analysis_source_mapping.source_fingerprint",
                            source_fingerprint,
                        )?,
                        source_instance_fingerprint: fingerprint_from_blob(
                            "artifact_analysis_source_mapping.source_instance_fingerprint",
                            source_instance_fingerprint,
                        )?,
                        source_build_variant_fingerprint: source_build_variant_fingerprint
                            .ok_or_else(|| StoreError::InvalidMappingEvidence {
                                reason: "source build variant is absent".to_owned(),
                            })
                            .and_then(|value| {
                                fingerprint_from_blob(
                                    "artifact_analysis_source_mapping.source_build_variant_fingerprint",
                                    value,
                                )
                            })?,
                        evidence: MappingEvidence::from_json(&evidence_json)?,
                        confidence: ArtifactAnalysisMappingConfidence::from_sql(&confidence)?,
                        attributed_bytes: attributed_bytes.map(u64::try_from).transpose().map_err(
                            |_| StoreError::UnknownVocabulary {
                                field: "artifact_analysis_source_mapping.attributed_bytes",
                                value: attributed_bytes.unwrap_or_default().to_string(),
                            },
                        )?,
                        build_variant_fingerprint: fingerprint_from_blob(
                            "artifact_analysis_source_mapping.build_variant_fingerprint",
                            build_variant_fingerprint,
                        )?,
                    })
                },
            )
            .collect()
    }

    /// Identity facts for one standalone artifact analysis.
    ///
    /// # Errors
    ///
    /// Returns malformed stored fingerprints rather than using an analysis
    /// whose content or `BuildVariant` cannot be established.
    pub fn artifact_analysis_identity(
        &self,
        analysis_id: i64,
    ) -> Result<Option<StoredArtifactAnalysisIdentity>, StoreError> {
        self.conn
            .query_row(
                "SELECT format, content_fingerprint, build_variant_fingerprint
                 FROM artifact_analysis WHERE id = ?1",
                [analysis_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(format, content_fingerprint, build_variant_fingerprint)| {
                Ok(StoredArtifactAnalysisIdentity {
                    analysis_id,
                    format,
                    content_fingerprint: fingerprint_from_blob(
                        "artifact_analysis.content_fingerprint",
                        content_fingerprint,
                    )?,
                    build_variant_fingerprint: build_variant_fingerprint
                        .map(|value| {
                            fingerprint_from_blob(
                                "artifact_analysis.build_variant_fingerprint",
                                value,
                            )
                        })
                        .transpose()?,
                })
            })
            .transpose()
    }

    /// Clone classification recorded for one source-run group.
    ///
    /// # Errors
    ///
    /// Returns malformed group identities rather than assigning a calibration
    /// measurement to a guessed stratum.
    pub fn clone_group_type(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Option<String>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        self.conn
            .query_row(
                "SELECT clone_group.clone_type
                 FROM clone_group
                 JOIN fingerprint ON fingerprint.id = clone_group.group_fingerprint_id
                 WHERE clone_group.scan_run_id = ?1 AND fingerprint.hash = ?2
                 ORDER BY clone_group.id ASC
                 LIMIT 1",
                params![source_scan_run_id, fingerprint.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Every fragment mapping whose stable occurrence discriminator is
    /// `finding_hex`, across every artifact analysis.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `finding_hex` is not a stable ID;
    /// otherwise the same errors as [`Self::artifact_mappings`].
    pub fn artifact_fragment_mappings(
        &self,
        finding_hex: &str,
    ) -> Result<Vec<StoredArtifactMapping>, StoreError> {
        let finding_id = parse_hex_id(finding_hex)?;
        let analysis_ids: Vec<i64> = self
            .conn
            .prepare(
                "SELECT DISTINCT artifact_analysis_id
                 FROM artifact_analysis_source_mapping
                 WHERE source_kind = 'fragment' AND source_instance_fingerprint = ?1
                 ORDER BY artifact_analysis_id ASC",
            )?
            .query_map([finding_id.as_slice()], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let mut mappings = Vec::new();
        for analysis_id in analysis_ids {
            mappings.extend(
                self.artifact_mappings(analysis_id)?
                    .into_iter()
                    .filter(|mapping| {
                        mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
                            && mapping.source_instance_fingerprint == finding_id
                    }),
            );
        }
        Ok(mappings)
    }

    /// Every persisted savings record for one source run and clone group.
    ///
    /// # Errors
    ///
    /// Returns an error when the group fingerprint is malformed or a stored
    /// savings row carries unknown vocabulary.
    pub fn clone_group_savings(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Vec<(i64, ArtifactAnalysisCloneGroupSavings)>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        let analysis_ids: Vec<i64> = self
            .conn
            .prepare(
                "SELECT DISTINCT artifact_analysis_id
                 FROM artifact_analysis_clone_group_savings
                 WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2
                 ORDER BY artifact_analysis_id ASC",
            )?
            .query_map(params![source_scan_run_id, fingerprint.as_slice()], |row| {
                row.get(0)
            })?
            .collect::<Result<_, _>>()?;
        let mut savings = Vec::new();
        for analysis_id in analysis_ids {
            savings.extend(
                self.artifact_clone_group_savings(analysis_id)?
                    .into_iter()
                    .filter(|estimate| {
                        estimate.source_scan_run_id == source_scan_run_id
                            && estimate.clone_group_fingerprint == fingerprint
                    })
                    .map(|estimate| (analysis_id, estimate)),
            );
        }
        Ok(savings)
    }

    /// Symbols that one artifact analysis explicitly left unmapped.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer unmapped-reason vocabulary.
    pub fn artifact_unmapped_symbols(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactUnmappedSymbol>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT artifact_symbol_fingerprint, reason
             FROM artifact_analysis_unmapped_symbol
             WHERE artifact_analysis_id = ?1
             ORDER BY artifact_symbol_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(fingerprint, reason)| {
                Ok(StoredArtifactUnmappedSymbol {
                    artifact_symbol_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_symbol.artifact_symbol_fingerprint",
                        fingerprint,
                    )?,
                    reason: ArtifactAnalysisUnmappedReason::from_sql(&reason)?,
                })
            })
            .collect()
    }

    /// Source identities that one artifact analysis explicitly left unmatched.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer unmapped-source vocabulary.
    pub fn artifact_unmapped_sources(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactUnmappedSource>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT source_kind, source_fingerprint, source_instance_fingerprint, reason,
                    source_build_variant_fingerprint
             FROM artifact_analysis_unmapped_source
             WHERE artifact_analysis_id = ?1
             ORDER BY source_kind ASC, source_fingerprint ASC, source_instance_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(source_kind, source_fingerprint, source_instance_fingerprint, reason, source_build_variant_fingerprint)| {
                Ok(StoredArtifactUnmappedSource {
                    source_kind: ArtifactAnalysisSourceKind::from_sql(&source_kind)?,
                    source_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_source.source_fingerprint",
                        source_fingerprint,
                    )?,
                    source_instance_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_source.source_instance_fingerprint",
                        source_instance_fingerprint,
                    )?,
                    source_build_variant_fingerprint: source_build_variant_fingerprint
                        .ok_or_else(|| StoreError::InvalidMappingEvidence {
                            reason: "source build variant is absent".to_owned(),
                        })
                        .and_then(|value| {
                            fingerprint_from_blob(
                                "artifact_analysis_unmapped_source.source_build_variant_fingerprint",
                                value,
                            )
                        })?,
                    reason: ArtifactAnalysisUnmappedSourceReason::from_sql(&reason)?,
                })
            })
            .collect()
    }

    /// Persisted clone-group refactoring estimates for one artifact analysis.
    ///
    /// # Errors
    ///
    /// Returns an error when a row carries an unknown schema or vocabulary.
    pub fn artifact_clone_group_savings(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<ArtifactAnalysisCloneGroupSavings>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT schema_version, source_scan_run_id, clone_group_fingerprint,
                    source_build_variant_fingerprint, artifact_build_variant_fingerprint,
                    duplicated_bytes, estimated_refactor_savings_bytes,
                    mapping_confidence, clone_confidence, model_confidence,
                    savings_confidence, model_schema_version, assumptions_json
             FROM artifact_analysis_clone_group_savings
             WHERE artifact_analysis_id = ?1
             ORDER BY clone_group_fingerprint ASC, source_build_variant_fingerprint ASC,
                      artifact_build_variant_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, f64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(
                schema_version,
                source_scan_run_id,
                clone_group_fingerprint,
                source_build_variant_fingerprint,
                artifact_build_variant_fingerprint,
                duplicated_bytes,
                estimated_refactor_savings_bytes,
                mapping_confidence,
                clone_confidence,
                model_confidence,
                savings_confidence,
                model_schema_version,
                assumptions_json,
            )| {
                if schema_version != ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "unknown artifact clone-group savings schema".to_owned(),
                    });
                }
                let assumptions: serde_json::Value = serde_json::from_str(&assumptions_json)
                    .map_err(|_| StoreError::InvalidMappingEvidence {
                        reason: "savings assumptions are not valid JSON".to_owned(),
                    })?;
                if !assumptions.is_array() {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "savings assumptions are not a JSON array".to_owned(),
                    });
                }
                Ok(ArtifactAnalysisCloneGroupSavings {
                    schema_version,
                    source_scan_run_id,
                    clone_group_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.clone_group_fingerprint",
                        clone_group_fingerprint,
                    )?,
                    source_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.source_build_variant_fingerprint",
                        source_build_variant_fingerprint,
                    )?,
                    artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.artifact_build_variant_fingerprint",
                        artifact_build_variant_fingerprint,
                    )?,
                    duplicated_bytes: nonnegative_u64(
                        "artifact_analysis_clone_group_savings.duplicated_bytes",
                        duplicated_bytes,
                    )?,
                    estimated_refactor_savings_bytes,
                    mapping_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &mapping_confidence,
                    )?,
                    clone_confidence,
                    model_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &model_confidence,
                    )?,
                    savings_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &savings_confidence,
                    )?,
                    model_schema_version,
                    assumptions_json,
                })
            })
            .collect()
    }

    /// Controlled before/after measurements recorded for one source group.
    ///
    /// # Errors
    ///
    /// Returns malformed IDs, unknown schema versions, and invalid numeric
    /// values instead of silently treating them as calibration data.
    pub fn artifact_savings_calibrations(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Vec<ArtifactAnalysisSavingsCalibration>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        let mut stmt = self.conn.prepare(
            "SELECT schema_version, artifact_analysis_id, source_build_variant_fingerprint,
                    before_artifact_build_variant_fingerprint, after_artifact_fingerprint,
                    after_artifact_build_variant_fingerprint, estimated_refactor_savings_bytes,
                    verified_savings_bytes, absolute_error_bytes, relative_error, recorded_at
             FROM artifact_analysis_savings_calibration
             WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2
             ORDER BY artifact_analysis_id ASC, after_artifact_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map(params![source_scan_run_id, fingerprint.as_slice()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<f64>>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(
                schema_version,
                artifact_analysis_id,
                source_build_variant_fingerprint,
                before_artifact_build_variant_fingerprint,
                after_artifact_fingerprint,
                after_artifact_build_variant_fingerprint,
                estimated_refactor_savings_bytes,
                verified_savings_bytes,
                absolute_error_bytes,
                relative_error,
                recorded_at,
            )| {
                if schema_version != ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "unknown artifact savings calibration schema".to_owned(),
                    });
                }
                if relative_error
                    .is_some_and(|value| !value.is_finite() || value.is_sign_negative())
                {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "calibration relative error must be finite and nonnegative"
                            .to_owned(),
                    });
                }
                Ok(ArtifactAnalysisSavingsCalibration {
                    schema_version,
                    artifact_analysis_id,
                    source_scan_run_id,
                    clone_group_fingerprint: fingerprint,
                    source_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.source_build_variant_fingerprint",
                        source_build_variant_fingerprint,
                    )?,
                    before_artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.before_artifact_build_variant_fingerprint",
                        before_artifact_build_variant_fingerprint,
                    )?,
                    after_artifact_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.after_artifact_fingerprint",
                        after_artifact_fingerprint,
                    )?,
                    after_artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.after_artifact_build_variant_fingerprint",
                        after_artifact_build_variant_fingerprint,
                    )?,
                    estimated_refactor_savings_bytes,
                    verified_savings_bytes,
                    absolute_error_bytes: nonnegative_u64(
                        "artifact_analysis_savings_calibration.absolute_error_bytes",
                        absolute_error_bytes,
                    )?,
                    relative_error,
                    recorded_at,
                })
            })
            .collect()
    }

    /// Every controlled calibration retained for one source run, ordered by
    /// stable clone-group fingerprint and then by artifact identity.
    ///
    /// # Errors
    ///
    /// Returns malformed stored group identities rather than omitting their
    /// measurements from a corpus-level statistic.
    pub fn artifact_savings_calibrations_for_run(
        &self,
        source_scan_run_id: i64,
    ) -> Result<Vec<ArtifactAnalysisSavingsCalibration>, StoreError> {
        let groups: Vec<Vec<u8>> = self
            .conn
            .prepare(
                "SELECT DISTINCT clone_group_fingerprint
                 FROM artifact_analysis_savings_calibration
                 WHERE source_scan_run_id = ?1
                 ORDER BY clone_group_fingerprint ASC",
            )?
            .query_map([source_scan_run_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let mut calibrations = Vec::new();
        for group in groups {
            let fingerprint = fingerprint_from_blob(
                "artifact_analysis_savings_calibration.clone_group_fingerprint",
                group,
            )?;
            let hex = hex_fingerprint(fingerprint);
            calibrations.extend(self.artifact_savings_calibrations(source_scan_run_id, &hex)?);
        }
        Ok(calibrations)
    }

    /// Coverage figures recorded with one explicit source-run correlation.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains an
    /// unknown correlation-summary schema.
    pub fn artifact_correlation(
        &self,
        analysis_id: i64,
    ) -> Result<Option<StoredArtifactAnalysisCorrelation>, StoreError> {
        self.conn
            .query_row(
                "SELECT schema_version, source_scan_run_id, mapping_count, artifact_symbol_count,
                        mapped_symbol_count, artifact_symbol_bytes, mapped_symbol_bytes
                 FROM artifact_analysis_correlation
                 WHERE artifact_analysis_id = ?1",
                [analysis_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    schema_version,
                    source_scan_run_id,
                    mapping_count,
                    artifact_symbol_count,
                    mapped_symbol_count,
                    artifact_symbol_bytes,
                    mapped_symbol_bytes,
                )| {
                    if schema_version != ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION {
                        return Err(StoreError::InvalidMappingEvidence {
                            reason: "unknown artifact correlation summary schema".to_owned(),
                        });
                    }
                    Ok(StoredArtifactAnalysisCorrelation {
                        schema_version,
                        source_scan_run_id,
                        mapping_count: nonnegative_u64(
                            "artifact_analysis_correlation.mapping_count",
                            mapping_count,
                        )?,
                        artifact_symbol_count: nonnegative_u64(
                            "artifact_analysis_correlation.artifact_symbol_count",
                            artifact_symbol_count,
                        )?,
                        mapped_symbol_count: nonnegative_u64(
                            "artifact_analysis_correlation.mapped_symbol_count",
                            mapped_symbol_count,
                        )?,
                        artifact_symbol_bytes: nonnegative_u64(
                            "artifact_analysis_correlation.artifact_symbol_bytes",
                            artifact_symbol_bytes,
                        )?,
                        mapped_symbol_bytes: nonnegative_u64(
                            "artifact_analysis_correlation.mapped_symbol_bytes",
                            mapped_symbol_bytes,
                        )?,
                    })
                },
            )
            .transpose()
    }

    /// Number of separately recorded cross-build-variant comparisons.
    ///
    /// This deliberately reads a table outside `scan_run`: normal scan
    /// history must not be interpreted as comparison history.
    ///
    /// # Errors
    ///
    /// Returns an error when the comparison table cannot be read.
    pub fn cross_variant_comparison_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM cross_variant_comparison", [], |row| {
                row.get(0)
            })?)
    }

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

    /// One scan run by row id, if the database holds it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_summary(&self, run_id: i64) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 WHERE r.id = ?1",
                params![run_id],
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

    /// The files one run read, by path relative to the scan root, each with
    /// the hash of what it held.
    ///
    /// Empty for a run that recorded no files, which is every run written
    /// before the tree was recorded at all. "Read nothing" and "did not say"
    /// are not distinguishable after the fact, so a caller that needs the
    /// difference has to decide what an empty answer means to it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_tree(&self, run_id: i64) -> Result<BTreeMap<String, String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT relative_path, content_hash FROM scanned_file
             WHERE scan_run_id = ?1
             ORDER BY relative_path",
        )?;
        let mut tree = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (path, hash) = row?;
            tree.insert(path, hash);
        }
        Ok(tree)
    }

    /// Row id of the newest completed run over `root_path`, optionally
    /// narrowed to one build variant.
    ///
    /// Narrowing is what makes two runs comparable file by file; leaving it
    /// open is for the callers that read a run in order to *record* which
    /// variant it used, and so cannot name it in advance.
    fn completed_run_id(
        &self,
        root_path: &str,
        variant_fingerprint: Option<&str>,
    ) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT r.id
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND (?2 IS NULL OR v.variant_fingerprint = ?2)
                   AND r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                params![root_path, variant_fingerprint],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// How many files of each language a run read, by language name.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_language_counts(&self, run_id: i64) -> Result<BTreeMap<String, u64>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT language, count(*) FROM scanned_file
             WHERE scan_run_id = ?1 GROUP BY language ORDER BY language",
        )?;
        let mut counts = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (language, count) = row?;
            counts.insert(language, u64::try_from(count).unwrap_or(0));
        }
        Ok(counts)
    }

    /// The newest completed run over `root_path`, with the identity a
    /// judgement about its results has to be qualified by.
    ///
    /// This does not narrow to a variant: the caller is reading the current
    /// snapshot in order to record what it was, so the variant is an answer
    /// rather than a question.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_completed_run(&self, root_path: &str) -> Result<Option<RunOrigin>, StoreError> {
        let Some(run_id) = self.completed_run_id(root_path, None)? else {
            return Ok(None);
        };
        self.run_origin(run_id).map(Some)
    }

    /// The identity of one run by row id: the conditions its stable ids were
    /// computed under, which every judgement about its results is qualified
    /// by.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error, including the case of a run id
    /// this database does not hold.
    pub fn run_origin(&self, run_id: i64) -> Result<RunOrigin, StoreError> {
        let mut origin = self.conn.query_row(
            "SELECT r.root_path, r.tool_version, r.analysis_mode, r.finished_at,
                    v.variant_fingerprint, v.normalization_version
             FROM scan_run r
             JOIN build_variant v ON v.id = r.build_variant_id
             WHERE r.id = ?1",
            params![run_id],
            |row| {
                Ok(RunOrigin {
                    id: run_id,
                    root_path: row.get(0)?,
                    tool_version: row.get(1)?,
                    analysis_mode: row.get(2)?,
                    finished_at: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    variant_fingerprint: row.get(4)?,
                    normalization_version: row.get(5)?,
                    detector_versions: Vec::new(),
                })
            },
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT d.component, d.version
             FROM scan_run_detector_version rd
             JOIN detector_version d ON d.id = rd.detector_version_id
             WHERE rd.scan_run_id = ?1
             ORDER BY d.component ASC, d.version ASC",
        )?;
        origin.detector_versions = stmt
            .query_map(params![run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(origin)
    }

    /// What the variant `fingerprint` names was analysed under, or `None` when
    /// this database holds no such variant.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn build_variant(&self, fingerprint: &str) -> Result<Option<StoredVariant>, StoreError> {
        let Some(mut variant) = self
            .conn
            .query_row(
                "SELECT id, variant_fingerprint, analysis_mode, languages,
                        header_language, build_language
                 FROM build_variant
                 WHERE variant_fingerprint = ?1",
                params![fingerprint],
                |row| {
                    Ok(StoredVariant {
                        id: row.get(0)?,
                        fingerprint: row.get(1)?,
                        analysis_mode: row.get(2)?,
                        languages: row.get(3)?,
                        header_language: row.get(4)?,
                        build_language: row.get(5)?,
                        settings: Vec::new(),
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT language, name, position, value
             FROM build_variant_setting
             WHERE build_variant_id = ?1
             ORDER BY language ASC, name ASC, position ASC",
        )?;
        variant.settings = stmt
            .query_map(params![variant.id], |row| {
                Ok(StoredSetting {
                    language: row.get(0)?,
                    name: row.get(1)?,
                    position: row.get(2)?,
                    value: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Some(variant))
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
                    g.suppress_reason, g.boilerplate, g.member_scope, g.test_code,
                    g.split_pair, s.scope, s.pattern, g.width_family, g.statements,
                    g.identifier_jaccard, g.has_loop, g.has_dynamic_allocation, g.call_count
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             LEFT JOIN finding fi ON fi.clone_group_id = g.id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        )?;
        let rows: Vec<(i64, StoredGroup)> = stmt
            .query_map(params![run_id], |row| {
                let scope: Option<String> = row.get(10)?;
                let pattern: Option<String> = row.get(11)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    StoredGroup {
                        fingerprint_hex: row.get(1)?,
                        clone_type: row.get(2)?,
                        member_scope: row.get(7)?,
                        score: row.get(3)?,
                        entropy_bits: row.get(4)?,
                        suppress_reason: row.get(5)?,
                        boilerplate: row.get(6)?,
                        test_code: row.get(8)?,
                        split_pair: row.get(9)?,
                        width_family: row.get(12)?,
                        statements: row.get(13)?,
                        identifier_jaccard: row.get(14)?,
                        has_loop: row.get(15)?,
                        has_dynamic_allocation: row.get(16)?,
                        call_count: row.get(17)?,
                        similarity: None,
                        semantic: None,
                        suppressed_by: scope
                            .zip(pattern)
                            .map(|(scope, pattern)| StoredSuppressionRef { scope, pattern }),
                        members: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut groups = Vec::with_capacity(rows.len());
        for (group_row_id, mut group) in rows {
            group.similarity = self.group_similarity(group_row_id)?;
            group.semantic = self.group_semantic_evidence(group_row_id)?;
            group.members = self.group_members(group_row_id)?;
            groups.push(group);
        }
        Ok(groups)
    }

    /// The priority a recorded run assigned one clone group.
    ///
    /// This intentionally reads the stored values instead of applying the
    /// current ranking configuration. Reformatting a run must describe the
    /// decision that run made.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_group_priority(
        &self,
        run_id: i64,
        group_fingerprint_hex: &str,
    ) -> Result<Option<StoredPriority>, StoreError> {
        let group_id = self
            .conn
            .query_row(
                "SELECT g.id
                 FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 WHERE g.scan_run_id = ?1 AND lower(hex(f.hash)) = ?2",
                params![run_id, group_fingerprint_hex],
                |row| row.get(0),
            )
            .optional()?;
        group_id.map_or_else(|| Ok(None), |id| self.group_priority(id, run_id))
    }

    /// Registered SOG evidence attached to one clone group, when the group
    /// was recorded by restricted semantic detection.
    fn group_semantic_evidence(
        &self,
        group_row_id: i64,
    ) -> Result<Option<StoredSemanticEvidence>, StoreError> {
        let evidence = self
            .conn
            .query_row(
                "SELECT schema_version, rule_id, rule_version, rule_confidence
                 FROM semantic_group_evidence
                 WHERE clone_group_id = ?1",
                params![group_row_id],
                |row| {
                    Ok(StoredSemanticEvidence {
                        schema_version: row.get(0)?,
                        rule_id: row.get(1)?,
                        rule_version: row.get(2)?,
                        rule_confidence: row.get(3)?,
                        graphs: Vec::new(),
                        node_mappings: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut evidence) = evidence else {
            return Ok(None);
        };
        evidence.node_mappings = self
            .conn
            .prepare(
                "SELECT corresponding_member, canonical_node, corresponding_node
                 FROM semantic_node_mapping
                 WHERE clone_group_id = ?1
                 ORDER BY corresponding_member ASC, canonical_node ASC, corresponding_node ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok(StoredSemanticNodeMapping {
                    corresponding_member: row.get(0)?,
                    canonical: row.get(1)?,
                    corresponding: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        let graph_json: Vec<String> = self
            .conn
            .prepare(
                "SELECT sog.graph_json
                 FROM semantic_operation_graph sog
                 JOIN clone_group_member member ON member.fragment_id = sog.fragment_id
                 JOIN fragment fragment ON fragment.id = sog.fragment_id
                 JOIN fingerprint fingerprint ON fingerprint.id = fragment.fingerprint_id
                 WHERE member.clone_group_id = ?1
                 ORDER BY member.is_canonical DESC, fingerprint.hash ASC",
            )?
            .query_map(params![group_row_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        evidence.graphs = graph_json
            .into_iter()
            .map(|graph| Self::decode_stored_sog(&evidence.schema_version, &graph))
            .collect::<Result<_, _>>()?;
        Ok(Some(evidence))
    }

    /// Decode and revalidate stored graph JSON before handing it to a report.
    fn decode_stored_sog(
        evidence_schema_version: &str,
        graph_json: &str,
    ) -> Result<SemanticOperationGraph, StoreError> {
        if evidence_schema_version != SOG_SCHEMA_VERSION {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: format!(
                    "stored group schema {evidence_schema_version} is not supported ({SOG_SCHEMA_VERSION})"
                ),
            });
        }
        let graph: SemanticOperationGraph = serde_json::from_str(graph_json).map_err(|error| {
            StoreError::InvalidSemanticEvidence {
                reason: format!("decoding stored SOG: {error}"),
            }
        })?;
        if graph.schema_version != evidence_schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "stored graph schema does not match group evidence".to_string(),
            });
        }
        SemanticOperationGraph::new(
            graph.language,
            graph.build_variant_fingerprint,
            graph.nodes,
            graph.edges,
        )
        .map_err(|error| StoreError::InvalidSemanticEvidence {
            reason: format!("stored graph violates the SOG contract: {error}"),
        })
    }

    /// What the run reported about itself beyond its findings, or `None` for a
    /// run recorded before runs stored it.
    ///
    /// Absent means the run cannot be described again, not that it measured
    /// nothing — a caller rebuilding a report from a stored run has to treat
    /// the two differently.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_summary_row(&self, run_id: i64) -> Result<Option<SummaryRow>, StoreError> {
        let summary = self
            .conn
            .query_row(
                "SELECT lines, tokens, lexer_diagnostics, unparsed_files,
                        unparsed_tokens, excluded_generated, excluded_by_glob,
                        excluded_skipped, folded_runs, subsumed_runs,
                        split_components, pair_budget_exhausted, baseline_digest
                 FROM run_summary WHERE scan_run_id = ?1",
                params![run_id],
                |row| {
                    let count = |value: i64| u64::try_from(value).unwrap_or(0);
                    let files: Option<i64> = row.get(3)?;
                    let tokens: Option<i64> = row.get(4)?;
                    Ok(SummaryRow {
                        lines: count(row.get(0)?),
                        tokens: count(row.get(1)?),
                        lexer_diagnostics: count(row.get(2)?),
                        unparsed: files.zip(tokens).map(|(files, tokens)| UnparsedRow {
                            files: count(files),
                            tokens: count(tokens),
                        }),
                        excluded_generated: count(row.get(5)?),
                        excluded_by_glob: count(row.get(6)?),
                        excluded_skipped: count(row.get(7)?),
                        folded_runs: count(row.get(8)?),
                        subsumed_runs: count(row.get(9)?),
                        split_components: count(row.get(10)?),
                        pair_budget_exhausted: row.get(11)?,
                        baseline_digest: row.get(12)?,
                        funnel: Vec::new(),
                        unused_suppressions: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut summary) = summary else {
            return Ok(None);
        };
        summary.funnel = self.run_funnel(run_id)?;
        summary.unused_suppressions = self.run_unused_suppressions(run_id)?;
        Ok(Some(summary))
    }

    /// The run's candidate pipeline, stage by stage in run order, each stage
    /// carrying what it dropped.
    fn run_funnel(&self, run_id: i64) -> Result<Vec<FunnelStageRow>, StoreError> {
        let mut stages = self
            .conn
            .prepare(
                "SELECT position, name, passed FROM run_funnel_stage
                 WHERE scan_run_id = ?1 ORDER BY position ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelStageRow {
                        name: row.get(1)?,
                        passed: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                        dropped: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let drops = self
            .conn
            .prepare(
                "SELECT position, cause, dropped FROM run_funnel_drop
                 WHERE scan_run_id = ?1 ORDER BY position ASC, ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelDropRow {
                        cause: row.get(1)?,
                        count: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (position, drop) in drops {
            if let Some((_, stage)) = stages.iter_mut().find(|(at, _)| *at == position) {
                stage.dropped.push(drop);
            }
        }
        Ok(stages.into_iter().map(|(_, stage)| stage).collect())
    }

    /// The configured rules the run found nothing for, in the order it named
    /// them.
    fn run_unused_suppressions(&self, run_id: i64) -> Result<Vec<UnusedRuleRow>, StoreError> {
        Ok(self
            .conn
            .prepare(
                "SELECT scope, pattern FROM run_unused_suppression
                 WHERE scan_run_id = ?1 ORDER BY ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok(UnusedRuleRow {
                    scope: row.get(0)?,
                    pattern: row.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()?)
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

    /// The members of one group row, in the order the run recorded them.
    ///
    /// Fragment rows are written as the run listed the occurrences, so their
    /// row ids carry that order and the canonical instance comes first. Any
    /// other ordering would be this layer's opinion rather than the run's, and
    /// a report rebuilt from these rows has to list what the run listed.
    fn group_members(&self, group_row_id: i64) -> Result<Vec<StoredMember>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                    fr.token_count, u.name, m.is_canonical, lower(hex(ff.hash)),
                    ff.language, m.boilerplate
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             LEFT JOIN source_unit u ON u.id = fr.source_unit_id
             WHERE m.clone_group_id = ?1
             ORDER BY fr.id ASC",
        )?;
        let members = stmt
            .query_map(params![group_row_id], |row| map_member(row, 7))?
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
            "SELECT lower(hex(gf.hash)), fi.clone_confidence, fi.final_priority,
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
                    clone_confidence: row.get(1)?,
                    final_priority: row.get(2)?,
                    suppression_scope: row.get(3)?,
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
                        g.member_count, g.boilerplate, s.scope, s.pattern, g.id,
                        g.member_scope, g.test_code, g.split_pair, lower(hex(ff.hash)),
                        ff.language, m.boilerplate
                 FROM clone_group_member m
                 JOIN fragment fr ON fr.id = m.fragment_id
                 JOIN fingerprint ff ON ff.id = fr.fingerprint_id
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
                            member: map_member(row, 19)?,
                            group_fingerprint_hex: row.get(7)?,
                            clone_type: row.get(8)?,
                            member_scope: row.get(16)?,
                            score: row.get(9)?,
                            scan_run_id: row.get(10)?,
                            member_count: row.get(11)?,
                            boilerplate: row.get(12)?,
                            test_code: row.get(17)?,
                            split_pair: row.get(18)?,
                            similarity: None,
                            semantic: None,
                            priority: None,
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
        detail.semantic = self.group_semantic_evidence(group_row_id)?;
        detail.priority = self.group_priority(group_row_id, detail.scan_run_id)?;
        Ok(Some(detail))
    }

    /// Look up one explicit Rust-to-C++ semantic comparison group by its
    /// stable comparison-domain id.
    ///
    /// The newest persisted comparison wins when the same deterministic group
    /// identity was recorded more than once. This does not merge comparisons:
    /// the returned origin variants remain those of that one invocation.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `group_hex` is not 32 hex digits;
    /// otherwise any underlying database or persisted-SOG validation error.
    pub fn cross_language_group(
        &self,
        group_hex: &str,
    ) -> Result<Option<CrossLanguageGroupDetail>, StoreError> {
        let group_id = parse_hex_id(group_hex)?;
        let Some((group_row_id, comparison_row_id, mut detail)) =
            self.cross_language_group_header(group_id)?
        else {
            return Ok(None);
        };
        detail.origin_variants = self.cross_language_origins(comparison_row_id)?;
        detail.members = self.cross_language_members(group_row_id)?;
        Ok(Some(detail))
    }

    fn cross_language_group_header(
        &self,
        group_id: [u8; 16],
    ) -> Result<Option<(i64, i64, CrossLanguageGroupDetail)>, StoreError> {
        self.conn
            .query_row(
                "SELECT g.id, c.id, lower(hex(c.comparison_id)), c.policy_version, c.root_path,
                        lower(hex(g.group_id)), g.rule_id, g.rule_version, g.semantic_confidence,
                        g.correspondence_ids_json
                 FROM cross_language_semantic_group g
                 JOIN cross_language_comparison c ON c.id = g.comparison_id
                 WHERE g.group_id = ?1
                 ORDER BY c.started_at DESC, c.id DESC
                 LIMIT 1",
                params![group_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        CrossLanguageGroupDetail {
                            comparison_id_hex: row.get(2)?,
                            policy_version: row.get(3)?,
                            root_path: row.get(4)?,
                            origin_variants: Vec::new(),
                            group_id_hex: row.get(5)?,
                            rule_id: row.get(6)?,
                            rule_version: row.get(7)?,
                            semantic_confidence: row.get(8)?,
                            correspondence_ids: serde_json::from_str::<Vec<String>>(
                                &row.get::<_, String>(9)?,
                            )
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    9,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                            members: Vec::new(),
                        },
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn cross_language_origins(&self, comparison_row_id: i64) -> Result<Vec<String>, StoreError> {
        self.conn
            .prepare(
                "SELECT build_variant_fingerprint
                 FROM cross_language_comparison_origin
                 WHERE comparison_id = ?1
                 ORDER BY build_variant_fingerprint ASC",
            )?
            .query_map(params![comparison_row_id], |row| row.get(0))?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    fn cross_language_members(
        &self,
        group_row_id: i64,
    ) -> Result<Vec<CrossLanguageGroupMember>, StoreError> {
        let members: Vec<StoredCrossLanguageMemberRow> = self
            .conn
            .prepare(
                "SELECT origin_variant_fingerprint, language, file_path, start_line, end_line,
                        unit_name, graph_schema_version, graph_json
                 FROM cross_language_semantic_member
                 WHERE group_id = ?1
                 ORDER BY origin_variant_fingerprint ASC, language ASC, file_path ASC,
                          start_line ASC, end_line ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        members
            .into_iter()
            .map(decode_cross_language_member)
            .collect()
    }

    /// Where a run ranked one group's finding, with the facts behind it.
    fn group_priority(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<Option<StoredPriority>, StoreError> {
        let facts = self.ranking_facts(group_row_id, run_id)?;
        Ok(self
            .conn
            .query_row(
                "SELECT clone_confidence, maintenance_risk, refactoring_difficulty,
                        final_priority, semantic_confidence,
                        source_artifact_mapping_confidence, savings_confidence
                 FROM finding
                 WHERE clone_group_id = ?1 AND scan_run_id = ?2",
                params![group_row_id, run_id],
                |row| {
                    Ok(StoredPriority {
                        clone_confidence: row.get(0)?,
                        maintenance_risk: row.get(1)?,
                        refactoring_difficulty: row.get(2)?,
                        final_priority: row.get(3)?,
                        semantic_confidence: row.get(4)?,
                        source_artifact_confidence: row.get(5)?,
                        savings_confidence: row.get(6)?,
                        facts,
                    })
                },
            )
            .optional()?)
    }

    /// One stored group as the ranking reads it.
    ///
    /// The directory count is taken in Rust rather than in SQL: splitting a
    /// path is not something an expression over `TEXT` does readably, and the
    /// member count of a group is small enough that reading the paths costs
    /// nothing.
    fn ranking_facts(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<StoredRankingFacts, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT fr.file_path, fr.token_count, ff.language
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             WHERE m.clone_group_id = ?1",
        )?;
        let rows = statement.query_map(params![group_row_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut tokens: Vec<i64> = Vec::new();
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut directories: BTreeSet<String> = BTreeSet::new();
        let mut languages: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let (path, token_count, language) = row?;
            tokens.push(token_count);
            directories.insert(
                path.rfind('/')
                    .map_or_else(String::new, |cut| path[..cut].to_string()),
            );
            files.insert(path);
            languages.insert(language);
        }
        let min_clone_tokens = self.conn.query_row(
            "SELECT min_clone_tokens FROM scan_run WHERE id = ?1",
            params![run_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(StoredRankingFacts {
            smallest_member_tokens: tokens.iter().copied().min().unwrap_or(0),
            largest_member_tokens: tokens.iter().copied().max().unwrap_or(0),
            instances: i64::try_from(tokens.len()).unwrap_or(i64::MAX),
            files: i64::try_from(files.len()).unwrap_or(i64::MAX),
            directories: i64::try_from(directories.len()).unwrap_or(i64::MAX),
            languages: i64::try_from(languages.len()).unwrap_or(i64::MAX),
            min_clone_tokens,
        })
    }
}

fn hex_fingerprint(fingerprint: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(fingerprint.len().saturating_mul(2));
    for byte in fingerprint {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

/// Read one member from a row whose first seven columns are the member's, and
/// whose content and language columns start at `content` — the two queries
/// that select members place the pair differently but always adjacently.
fn map_member(row: &rusqlite::Row<'_>, content: usize) -> Result<StoredMember, rusqlite::Error> {
    Ok(StoredMember {
        finding_hex: row.get(0)?,
        content_hex: row.get(content)?,
        language: row.get(content + 1)?,
        file_path: row.get(1)?,
        start_line: row.get(2)?,
        end_line: row.get(3)?,
        token_count: row.get(4)?,
        unit_name: row.get(5)?,
        boilerplate: row.get(content + 2)?,
        is_canonical: row.get::<_, i64>(6)? != 0,
    })
}

type StoredCrossLanguageMemberRow = (
    String,
    String,
    String,
    i64,
    i64,
    Option<String>,
    String,
    String,
);

fn decode_cross_language_member(
    (origin_variant, language, file_path, start_line, end_line, unit_name, schema, graph):
        StoredCrossLanguageMemberRow,
) -> Result<CrossLanguageGroupMember, StoreError> {
    Ok(CrossLanguageGroupMember {
        origin_variant,
        language,
        file_path,
        start_line: positive_cross_language_line("start_line", start_line)?,
        end_line: positive_cross_language_line("end_line", end_line)?,
        unit_name,
        graph: Store::decode_stored_sog(&schema, &graph)?,
    })
}

fn positive_cross_language_line(field: &'static str, value: i64) -> Result<u32, StoreError> {
    u32::try_from(value)
        .ok()
        .filter(|line| *line > 0)
        .ok_or_else(|| StoreError::UnknownVocabulary {
            field: match field {
                "start_line" => "cross_language_semantic_member.start_line",
                "end_line" => "cross_language_semantic_member.end_line",
                _ => "cross_language_semantic_member.line",
            },
            value: value.to_string(),
        })
}

fn fingerprint_from_blob(field: &'static str, value: Vec<u8>) -> Result<[u8; 16], StoreError> {
    let length = value.len();
    value
        .try_into()
        .map_err(|_| StoreError::MalformedFingerprint { field, length })
}

fn positive_line(field: &'static str, value: Option<i64>) -> Result<Option<u32>, StoreError> {
    value
        .map(|line| {
            u32::try_from(line)
                .ok()
                .filter(|line| *line > 0)
                .ok_or_else(|| StoreError::UnknownVocabulary {
                    field,
                    value: line.to_string(),
                })
        })
        .transpose()
}

/// Reduce the 32-byte build-variant digest stored by `build_variant` to the
/// 16-byte content-fingerprint reference used by source/artifact mappings.
///
/// The database records a full BLAKE3 digest for variant lookup, while mapping
/// rows use the project's standard 128-bit fingerprint width. Taking the
/// leading bytes preserves a deterministic reference without confusing this
/// representation with one of the stable IDs parsed by [`parse_hex_id`].
fn parse_build_variant_reference(hex: &str) -> Result<[u8; 16], StoreError> {
    let malformed = || StoreError::MalformedId { id: hex.to_owned() };
    if hex.len() != 64 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut out = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).take(out.len()).enumerate() {
        let pair = core::str::from_utf8(chunk).map_err(|_| malformed())?;
        out[index] = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

fn nonnegative_u64(field: &'static str, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::UnknownVocabulary {
        field,
        value: value.to_string(),
    })
}

/// Parse a 32-digit hex identifier into its 16 bytes.
pub(crate) fn parse_hex_id(hex: &str) -> Result<[u8; 16], StoreError> {
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

    #[test]
    fn build_variant_references_keep_the_first_128_bits_of_the_full_digest() {
        let parsed = parse_build_variant_reference(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        assert_eq!(
            parsed,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(parse_build_variant_reference("00010203").is_err());
    }
}
