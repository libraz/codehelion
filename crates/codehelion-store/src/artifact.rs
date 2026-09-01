//! Atomic persistence for standalone compiled-artifact analyses.
//!
//! These rows deliberately do not pretend to be source scans. The existing
//! source-linked artifact tables remain available for later source-artifact
//! mapping; this module records the parser evidence available now.

use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::fingerprint::BuildVariantFingerprint;
use crate::{Store, StoreError};

/// Largest versioned artifact IR document retained for one analysis.
///
/// The relational rows retain the queryable summary independently. This cap
/// prevents a single parser result from growing the local audit database
/// without bound while preserving enough IR for `artifact report` to
/// faithfully re-render ordinary analyses.
pub const MAX_ARTIFACT_IR_JSON_BYTES: usize = 64 * 1024 * 1024;

/// One standalone artifact-analysis write.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactAnalysisSnapshot<'a> {
    /// Version of the format-neutral IR that supplied the values.
    pub schema_version: &'a str,
    /// User-provided artifact path, retained as an anchor rather than identity.
    pub path: &'a str,
    /// Detected container format label.
    pub format: &'a str,
    /// Content-derived 16-byte artifact fingerprint.
    pub content_fingerprint: [u8; 16],
    /// Byte length directly observed from the input.
    pub observed_bytes: u64,
    /// Canonical versioned Artifact IR JSON, including format-specific facts.
    pub ir_json: &'a str,
    /// User-supplied build manifest path, when the artifact has such evidence.
    pub build_variant_manifest_path: Option<&'a str>,
    /// Content-derived identity of that build manifest.
    pub build_variant_fingerprint: Option<BuildVariantFingerprint>,
    /// RFC 3339 timestamp taken before parsing.
    pub started_at: &'a str,
    /// RFC 3339 timestamp taken after parsing.
    pub finished_at: &'a str,
    /// Symbols the backend established, in deterministic parser order.
    pub symbols: &'a [ArtifactAnalysisSymbol],
    /// Outcome of every source-map reference the artifact declared.
    pub source_maps: &'a [ArtifactAnalysisSourceMap],
    /// Limits installed for an artifact analysed under the untrusted preset.
    pub containment: Option<ArtifactAnalysisContainment>,
    /// Source/artifact correspondences established by independent evidence.
    pub mappings: &'a [ArtifactAnalysisMapping],
    /// Symbols deliberately left unmapped rather than guessed.
    pub unmapped_symbols: &'a [ArtifactAnalysisUnmappedSymbol],
    /// Source identities deliberately left unmatched rather than inferred.
    pub unmapped_sources: &'a [ArtifactAnalysisUnmappedSource],
    /// Coverage values for an explicitly requested source-run correlation.
    pub correlation: Option<ArtifactAnalysisCorrelation>,
    /// Group-level refactoring estimates derived from explicit fragment mappings.
    pub clone_group_savings: &'a [ArtifactAnalysisCloneGroupSavings],
}

/// Coverage summary for one explicit source-run correlation.
///
/// This is distinct from the mapping rows: it makes a point-in-time coverage
/// result queryable without reinterpreting a later source scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactAnalysisCorrelation {
    /// Version of this summary record's shape.
    pub schema_version: &'static str,
    /// The source scan whose stable identities were considered.
    pub source_scan_run_id: i64,
    /// Number of retained many-to-many correspondence rows.
    pub mapping_count: u64,
    /// Number of symbols observed in the artifact analysis.
    pub artifact_symbol_count: u64,
    /// Number of observed symbols with at least one retained mapping.
    pub mapped_symbol_count: u64,
    /// Sum of observed symbol sizes.
    pub artifact_symbol_bytes: u64,
    /// Sum of observed symbol sizes having at least one retained mapping.
    pub mapped_symbol_bytes: u64,
}

/// Current record shape for an artifact correlation coverage summary.
pub const ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION: &str = "artifact-correlation-summary-v1";

/// Limits installed for one artifact analysed under the untrusted preset.
///
/// An analysis that ran without the preset has no such record. The values are
/// the ones the run actually installed, so a later report states the same
/// containment the analysis stated rather than the defaults of the build
/// reading it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactAnalysisContainment {
    /// Input ceiling the analysis refused to read past.
    pub max_input_bytes: u64,
    /// Deadline the isolated worker ran under.
    pub worker_timeout_seconds: u64,
    /// Virtual-memory ceiling installed in that worker.
    pub worker_memory_limit_bytes: u64,
}

/// One source-map reference an artifact declared, with what resolving it
/// established.
///
/// Resolution reads a local file at most; nothing is fetched, and no source
/// text is retained. The token positions the analysis correlated with are
/// deliberately not stored: they are parser-local evidence, and the mapping
/// rows keep the stable identities that outlive them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnalysisSourceMap {
    /// The reference exactly as the artifact declared it.
    pub uri: String,
    /// What resolving that reference established.
    pub outcome: ArtifactAnalysisSourceMapOutcome,
}

/// The outcome of resolving one declared source-map reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactAnalysisSourceMapOutcome {
    /// A local map was read, and named these sources.
    Resolved {
        /// Local path the reference resolved to.
        local_path: String,
        /// Source names the map declares, in the order the analysis reported.
        sources: Vec<String>,
    },
    /// No local map was read, for one established reason.
    Unavailable {
        /// Why the reference did not resolve.
        reason: ArtifactAnalysisSourceMapReason,
    },
}

/// Reasons a declared source-map reference did not resolve to a local map.
///
/// The analysis produces these reasons and a report restates them, so both
/// directions of the vocabulary are public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisSourceMapReason {
    /// The reference names something other than a local relative path.
    NonLocalReference,
    /// The artifact's own directory could not be established.
    ArtifactParentUnavailable,
    /// Nothing exists at the resolved path.
    MapNotFound,
    /// The path resolves outside the artifact's directory.
    OutsideArtifactDirectory,
    /// The path is not a readable regular file.
    MapNotReadable,
    /// The map is larger than the configured input ceiling.
    MapExceedsSizeLimit,
    /// The file is a source map of a kind this build does not read.
    UnsupportedSourceMapKind,
    /// The file is not a decodable source map.
    InvalidSourceMap,
}

impl ArtifactAnalysisSourceMapReason {
    /// Every reason this build can record, in declaration order.
    ///
    /// The schema's vocabulary for the column is built from this list, so a
    /// reason the analysis can produce is a reason the column accepts.
    pub const ALL: [Self; 8] = [
        Self::NonLocalReference,
        Self::ArtifactParentUnavailable,
        Self::MapNotFound,
        Self::OutsideArtifactDirectory,
        Self::MapNotReadable,
        Self::MapExceedsSizeLimit,
        Self::UnsupportedSourceMapKind,
        Self::InvalidSourceMap,
    ];

    /// Where `self` sits in [`Self::ALL`]. Exhaustive, so a new reason cannot
    /// compile without a place in the list.
    const fn position(self) -> usize {
        match self {
            Self::NonLocalReference => 0,
            Self::ArtifactParentUnavailable => 1,
            Self::MapNotFound => 2,
            Self::OutsideArtifactDirectory => 3,
            Self::MapNotReadable => 4,
            Self::MapExceedsSizeLimit => 5,
            Self::UnsupportedSourceMapKind => 6,
            Self::InvalidSourceMap => 7,
        }
    }

    /// The stored spelling of this reason, which is also the spelling every
    /// rendering of a report prints.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::NonLocalReference => "non_local_reference",
            Self::ArtifactParentUnavailable => "artifact_parent_unavailable",
            Self::MapNotFound => "map_not_found",
            Self::OutsideArtifactDirectory => "outside_artifact_directory",
            Self::MapNotReadable => "map_not_readable",
            Self::MapExceedsSizeLimit => "map_exceeds_size_limit",
            Self::UnsupportedSourceMapKind => "unsupported_source_map_kind",
            Self::InvalidSourceMap => "invalid_source_map",
        }
    }

    /// The reason a stored or reported spelling names.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownVocabulary`] for a spelling no build in
    /// this vocabulary produces.
    pub fn from_sql(value: &str) -> Result<Self, StoreError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_sql() == value)
            .ok_or_else(|| StoreError::UnknownVocabulary {
                field: "artifact_analysis_source_map_resolution.reason",
                value: value.to_owned(),
            })
    }
}

/// The list holds each source-map reason once, at the place the exhaustive
/// match gives it.
const _: () = {
    let mut at = 0;
    while at < ArtifactAnalysisSourceMapReason::ALL.len() {
        assert!(ArtifactAnalysisSourceMapReason::ALL[at].position() == at);
        at += 1;
    }
};

/// One versioned source/artifact-correlated clone-group estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactAnalysisCloneGroupSavings {
    /// Version of this savings record and structured assumptions vocabulary.
    pub schema_version: String,
    /// Source scan whose group identity and members were considered.
    pub source_scan_run_id: i64,
    /// Stable clone-group fingerprint.
    pub clone_group_fingerprint: [u8; 16],
    /// Build variant that minted the source group.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Build variant of the artifact receiving the attribution.
    pub artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Fully attributed observed duplicate bytes for the group.
    pub duplicated_bytes: u64,
    /// Model-derived refactoring estimate; it may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Mapping-confidence category retained separately from the estimate.
    pub mapping_confidence: ArtifactAnalysisSavingsConfidence,
    /// Score emitted by the source clone engine.
    pub clone_confidence: f64,
    /// Confidence in the model assumptions.
    pub model_confidence: ArtifactAnalysisSavingsConfidence,
    /// Confidence in this estimate, without collapsing the components.
    pub savings_confidence: ArtifactAnalysisSavingsConfidence,
    /// Model vocabulary version.
    pub model_schema_version: String,
    /// Canonical JSON array of structured assumptions.
    pub assumptions_json: String,
}

/// Fixed confidence vocabulary for persisted savings components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisSavingsConfidence {
    /// Direct evidence establishes the component.
    High,
    /// Conservative inference supports the component.
    Medium,
    /// Significant model uncertainty remains.
    Low,
    /// Required evidence is absent.
    Unavailable,
}

impl ArtifactAnalysisSavingsConfidence {
    const fn as_sql(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unavailable => "unavailable",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        match value {
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_clone_group_savings.savings_confidence",
                value: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for ArtifactAnalysisSavingsConfidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_sql())
    }
}

/// Current savings-record schema.
pub const ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION: &str =
    "artifact-clone-group-savings-v1";

/// One measured before/after outcome evaluating a persisted group estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactAnalysisSavingsCalibration {
    /// Versioned calibration-record shape.
    pub schema_version: String,
    /// Analysis that produced the estimate being evaluated.
    pub artifact_analysis_id: i64,
    /// Source run and stable group identity of that estimate.
    pub source_scan_run_id: i64,
    /// Stable clone-group identity.
    pub clone_group_fingerprint: [u8; 16],
    /// Build variants remain separate rather than being inferred from paths.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Build variant of the analyzed before artifact.
    pub before_artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Content-derived identity of the measured after artifact.
    pub after_artifact_fingerprint: [u8; 16],
    /// Build variant of the measured after artifact.
    pub after_artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Estimate retained verbatim; it may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Observed before-minus-after size difference; it may be negative.
    pub verified_savings_bytes: i64,
    /// Absolute difference between estimate and observation.
    pub absolute_error_bytes: u64,
    /// Error relative to a nonzero observation, absent for zero baseline.
    pub relative_error: Option<f64>,
    /// RFC 3339 time the controlled comparison was recorded.
    pub recorded_at: String,
}

/// Current calibration-record schema.
pub const ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION: &str =
    "artifact-savings-calibration-v1";

/// Distribution summary for independently retained calibration errors.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ArtifactSavingsCalibrationStatistics {
    /// Number of controlled measurements, including zero-verified cases.
    pub samples: u64,
    /// Median absolute byte error, or absent when no measurement exists.
    pub median_absolute_error_bytes: Option<f64>,
    /// Nearest-rank 90th percentile absolute byte error.
    pub p90_absolute_error_bytes: Option<u64>,
    /// Number of measurements for which relative error is meaningful.
    pub relative_error_samples: u64,
    /// Median relative error, excluding zero-verified measurements.
    pub median_relative_error: Option<f64>,
    /// Nearest-rank 90th percentile relative error.
    pub p90_relative_error: Option<f64>,
}

/// Summarize controlled calibration errors without merging their source facts.
///
/// The median averages the two central values for an even population. The p90
/// uses the nearest-rank definition, so small corpora never invent an
/// interpolated measurement. Relative error is absent for a zero verified
/// value because no denominator was observed.
#[must_use]
pub fn artifact_savings_calibration_statistics(
    calibrations: &[ArtifactAnalysisSavingsCalibration],
) -> ArtifactSavingsCalibrationStatistics {
    let mut absolute: Vec<_> = calibrations
        .iter()
        .map(|value| value.absolute_error_bytes)
        .collect();
    absolute.sort_unstable();
    let mut relative: Vec<_> = calibrations
        .iter()
        .filter_map(|value| value.relative_error)
        .collect();
    relative.sort_by(f64::total_cmp);
    ArtifactSavingsCalibrationStatistics {
        samples: u64::try_from(absolute.len()).unwrap_or(u64::MAX),
        median_absolute_error_bytes: median_u64(&absolute),
        p90_absolute_error_bytes: percentile_u64(&absolute, 90),
        relative_error_samples: u64::try_from(relative.len()).unwrap_or(u64::MAX),
        median_relative_error: median_f64(&relative),
        p90_relative_error: percentile_f64(&relative, 90),
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "the report intentionally exposes byte-error medians as floating-point values"
)]
fn median_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let middle = values.len().checked_div(2)?;
    if values.len().is_multiple_of(2) {
        Some(f64::midpoint(
            values[middle - 1] as f64,
            values[middle] as f64,
        ))
    } else {
        Some(values[middle] as f64)
    }
}

fn median_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let middle = values.len().checked_div(2)?;
    if values.len().is_multiple_of(2) {
        Some(f64::midpoint(values[middle - 1], values[middle]))
    } else {
        Some(values[middle])
    }
}

fn percentile_u64(values: &[u64], percentile: usize) -> Option<u64> {
    nearest_rank(values.len(), percentile).map(|index| values[index])
}

fn percentile_f64(values: &[f64], percentile: usize) -> Option<f64> {
    nearest_rank(values.len(), percentile).map(|index| values[index])
}

fn nearest_rank(length: usize, percentile: usize) -> Option<usize> {
    let rank = length.checked_mul(percentile)?.saturating_add(99) / 100;
    rank.checked_sub(1)
}

/// One artifact symbol persisted without raw code bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnalysisSymbol {
    /// Content-derived stable symbol identity.
    pub fingerprint: [u8; 16],
    /// Parser-provided display name.
    pub name: Option<String>,
    /// Whether the parser established this symbol as exported.
    pub exported: bool,
    /// Format-local section index, stored only as an anchor.
    pub section_index: Option<u32>,
    /// Observed start offset.
    pub offset: u64,
    /// Observed or inferred size.
    pub size_bytes: u64,
    /// Whether the size was inferred.
    pub size_inferred: bool,
    /// Content fingerprint of exact code bytes.
    pub code_fingerprint: [u8; 16],
    /// Normalization recipe, if the backend decoded instructions.
    pub normalization_version: Option<String>,
    /// Content fingerprint of the normalized representation.
    pub normalization_fingerprint: Option<[u8; 16]>,
}

/// One many-to-many source-to-artifact correspondence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnalysisMapping {
    /// Version of this mapping record's shape and evidence vocabulary.
    pub schema_version: String,
    /// Content-derived artifact symbol identity within the analysis.
    pub artifact_symbol_fingerprint: [u8; 16],
    /// Whether the source reference identifies a unit or fragment.
    pub source_kind: ArtifactAnalysisSourceKind,
    /// Content-derived source unit or fragment identity.
    pub source_fingerprint: [u8; 16],
    /// Stable discriminator of the mapped source occurrence.
    ///
    /// Unit mappings repeat [`Self::source_fingerprint`]. Fragment mappings
    /// carry the member's `FindingId`, which distinguishes content-identical
    /// clone occurrences without relying on a source position or database row.
    pub source_instance_fingerprint: [u8; 16],
    /// Build variant that minted the source identity.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Versioned independent evidence facts for the correspondence.
    pub evidence: MappingEvidence,
    /// Bytes attributed to this source, or absent when the evidence has no split.
    pub attributed_bytes: Option<u64>,
    /// Build variant that made this correspondence meaningful.
    pub build_variant_fingerprint: BuildVariantFingerprint,
}

/// Current record shape for source-to-artifact correspondences.
pub const SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION: &str = "source-artifact-mapping-v1";

fn supported_mapping_schema(schema_version: &str) -> bool {
    schema_version == SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION
}

/// Current JSON shape for source-to-artifact correspondence evidence.
pub const MAPPING_EVIDENCE_SCHEMA_VERSION: &str = "source-artifact-evidence-v1";

/// Only operation recipe understood by the unreleased v1 evidence contract.
pub const FUNCTION_RECIPE_VERSION: &str = "source-artifact-operation-recipe-v1";

/// Versioned, local-only evidence used to justify one correspondence.
///
/// The source and artifact fingerprints live on [`ArtifactAnalysisMapping`].
/// This value records only why that pair was retained, so it can be exported
/// and later re-evaluated without using a file offset or symbol-table index as
/// an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingEvidence {
    /// Version of this JSON evidence shape.
    pub schema_version: String,
    /// Independently observed facts supporting the correspondence.
    pub facts: Vec<MappingEvidenceFact>,
    /// Number of source candidates that remain after applying the facts.
    pub candidate_count: u32,
    /// Whether the observed facts disagree with one another.
    pub has_conflict: bool,
}

impl MappingEvidence {
    /// Build evidence under the current versioned schema.
    #[must_use]
    pub fn new(facts: Vec<MappingEvidenceFact>, candidate_count: u32, has_conflict: bool) -> Self {
        Self {
            schema_version: MAPPING_EVIDENCE_SCHEMA_VERSION.to_owned(),
            facts,
            candidate_count,
            has_conflict,
        }
    }

    /// Derive the confidence without selecting an ambiguous candidate.
    ///
    /// A direct debug or source-map location is exact only for one
    /// non-conflicting candidate. Two different non-direct evidence families
    /// are strong. One family is weak. Conflicts or multiple candidates are
    /// always ambiguous, and empty evidence is not mappable.
    #[must_use]
    pub fn confidence(&self) -> Option<ArtifactAnalysisMappingConfidence> {
        if self.schema_version != MAPPING_EVIDENCE_SCHEMA_VERSION
            || self.facts.is_empty()
            || self.candidate_count == 0
            || self.facts.iter().any(|fact| {
                matches!(
                    fact,
                    MappingEvidenceFact::FunctionRecipe { recipe_version }
                        if recipe_version != FUNCTION_RECIPE_VERSION
                )
            })
        {
            return None;
        }
        if self.has_conflict || self.candidate_count > 1 {
            return Some(ArtifactAnalysisMappingConfidence::Ambiguous);
        }
        if self
            .facts
            .iter()
            .any(MappingEvidenceFact::is_direct_location)
            && self.attribution_is_whole_symbol().is_none_or(|whole| whole)
        {
            return Some(ArtifactAnalysisMappingConfidence::Exact);
        }
        let mut families = [false; 5];
        for fact in &self.facts {
            families[fact.family_index()] = true;
        }
        if families.into_iter().filter(|present| *present).count() >= 2 {
            Some(ArtifactAnalysisMappingConfidence::Strong)
        } else {
            Some(ArtifactAnalysisMappingConfidence::Weak)
        }
    }

    fn json(&self) -> Result<String, StoreError> {
        Ok(serde_json::to_string(self)?)
    }

    pub(crate) fn from_json(value: &str) -> Result<Self, StoreError> {
        let evidence: Self = serde_json::from_str(value)?;
        if evidence.confidence().is_none() {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown schema, no facts, or no remaining candidate".to_owned(),
            });
        }
        Ok(evidence)
    }

    /// Whether byte attribution covered the entire artifact symbol, when the
    /// correlation established an attribution split.
    #[must_use]
    pub fn attribution_is_whole_symbol(&self) -> Option<bool> {
        self.facts.iter().rev().find_map(|fact| match fact {
            MappingEvidenceFact::WholeSymbolAttribution => Some(true),
            MappingEvidenceFact::ProportionalSymbolAttribution { .. } => Some(false),
            _ => None,
        })
    }
}

/// One fact established without executing source code or an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MappingEvidenceFact {
    /// DWARF location or inline stack identified this source path.
    Dwarf {
        /// Local path from the debug location.
        source_path: String,
    },
    /// PDB location or inline stack identified this source path.
    Pdb {
        /// Local path from the PDB location.
        source_path: String,
    },
    /// A local source map identified this source URL.
    SourceMap {
        /// Local source URL named by the source map.
        source_url: String,
    },
    /// Demangled names agree, but names alone do not prove uniqueness.
    SymbolName {
        /// Source-side resolved symbol spelling.
        source_symbol: String,
        /// Artifact-side demangled symbol spelling.
        artifact_symbol: String,
    },
    /// A pre-existing linker map placed the symbol in this object file.
    LinkerMap {
        /// Object path recorded in the linker map.
        object_path: String,
    },
    /// A closed source/artifact operation recipe matched.
    ///
    /// This is deliberately not a source or instruction fingerprint. Both
    /// producers must have proved the complete shared recipe before this fact
    /// can be emitted.
    FunctionRecipe {
        /// Closed operation recipe used for the comparison.
        recipe_version: String,
    },
    /// Established caller/callee neighborhoods agree.
    CallGraphNeighborhood,
    /// A compiler-reported generic or template instantiation key agrees.
    GenericOrigin {
        /// Compiler-reported spelling of the generic definition that owns the
        /// specialization.
        ///
        /// This distinguishes separately declared templates with identical
        /// normalized source bodies. The surrounding source fingerprint still
        /// identifies the content; this compiler-confirmed spelling keeps the
        /// aggregation from merging their emitted bytes.
        definition: String,
        /// Compiler-reported specialization or instantiation key.
        instantiation_key: String,
        /// Translation units that independently reported this specialization.
        ///
        /// The entries are display evidence only; stable source identity stays
        /// on the surrounding mapping record.
        translation_units: Vec<String>,
    },
    /// A compiler anchor says generated code was written in this macro body.
    MacroOrigin {
        /// Path of the declarative macro definition.
        definition_path: String,
    },
    /// The source fragment covers every source line attributed to its symbol.
    WholeSymbolAttribution,
    /// The source fragment covers only a bounded share of the symbol's source
    /// lines, so observed bytes are attributed proportionally.
    ProportionalSymbolAttribution {
        /// Number of covered source lines.
        covered_lines: u32,
        /// Number of source lines observed for the artifact symbol.
        symbol_lines: u32,
    },
}

impl MappingEvidenceFact {
    const fn is_direct_location(&self) -> bool {
        matches!(
            self,
            Self::Dwarf { .. } | Self::Pdb { .. } | Self::SourceMap { .. }
        )
    }

    const fn family_index(&self) -> usize {
        match self {
            Self::Dwarf { .. } | Self::Pdb { .. } | Self::SourceMap { .. } => 0,
            Self::SymbolName { .. } => 1,
            Self::LinkerMap { .. } => 2,
            Self::FunctionRecipe { .. } => 3,
            Self::CallGraphNeighborhood
            | Self::GenericOrigin { .. }
            | Self::MacroOrigin { .. }
            | Self::WholeSymbolAttribution
            | Self::ProportionalSymbolAttribution { .. } => 4,
        }
    }
}

/// Stable source-reference kind for an artifact mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisSourceKind {
    /// A whole source unit.
    Unit,
    /// A source fragment within a unit.
    Fragment,
}

impl ArtifactAnalysisSourceKind {
    const fn as_sql(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Fragment => "fragment",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        match value {
            "unit" => Ok(Self::Unit),
            "fragment" => Ok(Self::Fragment),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_source_mapping.source_kind",
                value: value.to_owned(),
            }),
        }
    }
}

/// Confidence vocabulary for independently recorded mapping evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisMappingConfidence {
    /// Debug/source evidence establishes the mapping directly.
    Exact,
    /// Multiple independent sources agree.
    Strong,
    /// One non-conflicting but incomplete source supports it.
    Weak,
    /// Multiple plausible sources remain and all are retained.
    Ambiguous,
}

impl ArtifactAnalysisMappingConfidence {
    const fn as_sql(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Strong => "strong",
            Self::Weak => "weak",
            Self::Ambiguous => "ambiguous",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        match value {
            "exact" => Ok(Self::Exact),
            "strong" => Ok(Self::Strong),
            "weak" => Ok(Self::Weak),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_source_mapping.mapping_confidence",
                value: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for ArtifactAnalysisMappingConfidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_sql())
    }
}

/// A symbol explicitly left unmapped with a parser-established reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnalysisUnmappedSymbol {
    /// Content-derived artifact symbol identity within the analysis.
    pub artifact_symbol_fingerprint: [u8; 16],
    /// Controlled reason vocabulary; unknown evidence is not guessed.
    pub reason: ArtifactAnalysisUnmappedReason,
}

/// A source identity explicitly absent from an artifact analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnalysisUnmappedSource {
    /// Whether the source reference identifies a unit or fragment.
    pub source_kind: ArtifactAnalysisSourceKind,
    /// Content-derived source unit or fragment identity.
    pub source_fingerprint: [u8; 16],
    /// Stable discriminator of the unmatched source occurrence.
    ///
    /// Unit rows repeat [`Self::source_fingerprint`]; fragment rows carry
    /// the member's `FindingId`.
    pub source_instance_fingerprint: [u8; 16],
    /// Build variant that minted the source identity.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Parser- or correlation-established reason for the absence.
    pub reason: ArtifactAnalysisUnmappedSourceReason,
}

/// Reasons why a source identity did not become an artifact correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisUnmappedSourceReason {
    /// No available artifact evidence established a correspondence.
    NoArtifactEvidence,
    /// The source was not reachable in this artifact.
    DeadCode,
    /// Inlining removed a standalone symbol boundary.
    InlinedAway,
    /// Link-time optimization merged the source into another unit.
    LtoAbsorbed,
    /// This build variant did not compile the source.
    NotCompiledForVariant,
    /// Available evidence disagreed.
    EvidenceConflict,
}

impl ArtifactAnalysisUnmappedSourceReason {
    /// Every reason this build can record, in declaration order.
    ///
    /// The schema's vocabulary for the column is built from this list, so a
    /// reason the analysis can produce is a reason the column accepts.
    pub const ALL: [Self; 6] = [
        Self::NoArtifactEvidence,
        Self::DeadCode,
        Self::InlinedAway,
        Self::LtoAbsorbed,
        Self::NotCompiledForVariant,
        Self::EvidenceConflict,
    ];

    /// Where `self` sits in [`Self::ALL`]. Exhaustive, so a new reason cannot
    /// compile without a place in the list.
    const fn position(self) -> usize {
        match self {
            Self::NoArtifactEvidence => 0,
            Self::DeadCode => 1,
            Self::InlinedAway => 2,
            Self::LtoAbsorbed => 3,
            Self::NotCompiledForVariant => 4,
            Self::EvidenceConflict => 5,
        }
    }

    pub(crate) const fn as_sql(self) -> &'static str {
        match self {
            Self::NoArtifactEvidence => "no_artifact_evidence",
            Self::DeadCode => "dead_code",
            Self::InlinedAway => "inlined_away",
            Self::LtoAbsorbed => "lto_absorbed",
            Self::NotCompiledForVariant => "not_compiled_for_variant",
            Self::EvidenceConflict => "evidence_conflict",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_sql() == value)
            .ok_or_else(|| StoreError::UnknownVocabulary {
                field: "artifact_analysis_unmapped_source.reason",
                value: value.to_owned(),
            })
    }
}

/// The list holds each source reason once, at the place the exhaustive match
/// gives it.
const _: () = {
    let mut at = 0;
    while at < ArtifactAnalysisUnmappedSourceReason::ALL.len() {
        assert!(ArtifactAnalysisUnmappedSourceReason::ALL[at].position() == at);
        at += 1;
    }
};

/// Reasons why source correlation could not establish a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisUnmappedReason {
    /// The artifact has no usable debug information.
    DebugInfoMissing,
    /// Debug information was present but could not be decoded safely.
    DebugInfoUnreadable,
    /// Symbol boundaries were degraded by stripping.
    Stripped,
    /// No usable demangled name exists.
    DemangleFailed,
    /// The symbol belongs outside the selected source scope.
    OutsideSourceScope,
    /// Available evidence disagrees.
    EvidenceConflict,
}

impl ArtifactAnalysisUnmappedReason {
    /// Every reason this build can record, in declaration order.
    ///
    /// The schema's vocabulary for the column is built from this list. A
    /// binary whose debug information cannot be decoded is exactly the input
    /// the artifact reader exists to survive, so the reason for it has to be
    /// storable rather than fatal to the whole analysis.
    pub const ALL: [Self; 6] = [
        Self::DebugInfoMissing,
        Self::DebugInfoUnreadable,
        Self::Stripped,
        Self::DemangleFailed,
        Self::OutsideSourceScope,
        Self::EvidenceConflict,
    ];

    /// Where `self` sits in [`Self::ALL`]. Exhaustive, so a new reason cannot
    /// compile without a place in the list.
    const fn position(self) -> usize {
        match self {
            Self::DebugInfoMissing => 0,
            Self::DebugInfoUnreadable => 1,
            Self::Stripped => 2,
            Self::DemangleFailed => 3,
            Self::OutsideSourceScope => 4,
            Self::EvidenceConflict => 5,
        }
    }

    pub(crate) const fn as_sql(self) -> &'static str {
        match self {
            Self::DebugInfoMissing => "debug_info_missing",
            Self::DebugInfoUnreadable => "debug_info_unreadable",
            Self::Stripped => "stripped",
            Self::DemangleFailed => "demangle_failed",
            Self::OutsideSourceScope => "outside_source_scope",
            Self::EvidenceConflict => "evidence_conflict",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_sql() == value)
            .ok_or_else(|| StoreError::UnknownVocabulary {
                field: "artifact_analysis_unmapped_symbol.reason",
                value: value.to_owned(),
            })
    }
}

/// The list holds each symbol reason once, at the place the exhaustive match
/// gives it.
const _: () = {
    let mut at = 0;
    while at < ArtifactAnalysisUnmappedReason::ALL.len() {
        assert!(ArtifactAnalysisUnmappedReason::ALL[at].position() == at);
        at += 1;
    }
};

impl Store {
    /// Record one complete artifact analysis and return its row id.
    ///
    /// # Errors
    ///
    /// All rows are written in one transaction; a failed symbol write leaves
    /// no parent analysis behind.
    pub fn record_artifact_analysis(
        &mut self,
        snapshot: &ArtifactAnalysisSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        validate_artifact_ir_size(snapshot.ir_json.len())?;
        validate_artifact_ir_schema(snapshot)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO artifact_analysis
                 (schema_version, path, format, content_fingerprint, observed_bytes,
                  ir_json, build_variant_manifest_path, build_variant_fingerprint,
                  started_at, finished_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'completed')",
            params![
                snapshot.schema_version,
                snapshot.path,
                snapshot.format,
                snapshot.content_fingerprint.as_slice(),
                i64::try_from(snapshot.observed_bytes).unwrap_or(i64::MAX),
                snapshot.ir_json,
                snapshot.build_variant_manifest_path,
                snapshot.build_variant_fingerprint,
                snapshot.started_at,
                snapshot.finished_at,
            ],
        )?;
        let analysis_id = tx.last_insert_rowid();
        for (ordinal, symbol) in snapshot.symbols.iter().enumerate() {
            tx.execute(
                "INSERT INTO artifact_analysis_symbol
                     (analysis_id, ordinal, fingerprint, name, exported, section_index, offset, size_bytes,
                      size_inferred, code_fingerprint, normalization_version, normalization_fingerprint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    analysis_id,
                    i64::try_from(ordinal).unwrap_or(i64::MAX),
                    symbol.fingerprint.as_slice(),
                    symbol.name,
                    i64::from(symbol.exported),
                    symbol.section_index.map(i64::from),
                    i64::try_from(symbol.offset).unwrap_or(i64::MAX),
                    i64::try_from(symbol.size_bytes).unwrap_or(i64::MAX),
                    i64::from(symbol.size_inferred),
                    symbol.code_fingerprint.as_slice(),
                    symbol.normalization_version,
                    symbol.normalization_fingerprint.map(|value| value.to_vec()),
                ],
            )?;
        }
        record_source_maps(&tx, analysis_id, snapshot.source_maps)?;
        record_containment(&tx, analysis_id, snapshot.containment)?;
        record_mappings(&tx, analysis_id, snapshot.mappings)?;
        for unmapped in snapshot.unmapped_symbols {
            tx.execute(
                "INSERT INTO artifact_analysis_unmapped_symbol
                     (artifact_analysis_id, artifact_symbol_fingerprint, reason)
                 VALUES (?1, ?2, ?3)",
                params![
                    analysis_id,
                    unmapped.artifact_symbol_fingerprint.as_slice(),
                    unmapped.reason.as_sql(),
                ],
            )?;
        }
        for unmapped in snapshot.unmapped_sources {
            tx.execute(
                "INSERT INTO artifact_analysis_unmapped_source
                     (artifact_analysis_id, source_kind, source_fingerprint, reason,
                      source_build_variant_fingerprint, source_instance_fingerprint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    analysis_id,
                    unmapped.source_kind.as_sql(),
                    unmapped.source_fingerprint.as_slice(),
                    unmapped.reason.as_sql(),
                    unmapped.source_build_variant_fingerprint,
                    unmapped.source_instance_fingerprint.as_slice(),
                ],
            )?;
        }
        if let Some(correlation) = snapshot.correlation {
            tx.execute(
                "INSERT INTO artifact_analysis_correlation
                     (artifact_analysis_id, schema_version, source_scan_run_id, mapping_count,
                      artifact_symbol_count, mapped_symbol_count, artifact_symbol_bytes,
                      mapped_symbol_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    analysis_id,
                    correlation.schema_version,
                    correlation.source_scan_run_id,
                    i64::try_from(correlation.mapping_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.artifact_symbol_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.mapped_symbol_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.artifact_symbol_bytes).unwrap_or(i64::MAX),
                    i64::try_from(correlation.mapped_symbol_bytes).unwrap_or(i64::MAX),
                ],
            )?;
        }
        record_clone_group_savings(&tx, analysis_id, snapshot.clone_group_savings)?;
        tx.commit()?;
        Ok(analysis_id)
    }
}

/// Ensure the storage-column schema and the self-describing IR agree before
/// either can become durable state.
fn validate_artifact_ir_schema(snapshot: &ArtifactAnalysisSnapshot<'_>) -> Result<(), StoreError> {
    let value: serde_json::Value = serde_json::from_str(snapshot.ir_json).map_err(|error| {
        StoreError::InvalidArtifactIrSchema {
            reason: format!("IR JSON does not parse: {error}"),
        }
    })?;
    let Some(document_schema) = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(StoreError::InvalidArtifactIrSchema {
            reason: "IR JSON has no string schema_version".to_owned(),
        });
    };
    if document_schema != snapshot.schema_version {
        return Err(StoreError::InvalidArtifactIrSchema {
            reason: format!(
                "row declares {}, but IR JSON declares {document_schema}",
                snapshot.schema_version
            ),
        });
    }
    Ok(())
}

const fn validate_artifact_ir_size(size_bytes: usize) -> Result<(), StoreError> {
    if size_bytes > MAX_ARTIFACT_IR_JSON_BYTES {
        return Err(StoreError::ArtifactIrTooLarge {
            size_bytes,
            maximum_bytes: MAX_ARTIFACT_IR_JSON_BYTES,
        });
    }
    Ok(())
}

fn record_clone_group_savings(
    tx: &Transaction<'_>,
    analysis_id: i64,
    savings: &[ArtifactAnalysisCloneGroupSavings],
) -> Result<(), StoreError> {
    for estimate in savings {
        if estimate.schema_version != ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown artifact clone-group savings schema".to_owned(),
            });
        }
        let assumptions: serde_json::Value = serde_json::from_str(&estimate.assumptions_json)
            .map_err(|_| StoreError::InvalidMappingEvidence {
                reason: "savings assumptions are not valid JSON".to_owned(),
            })?;
        if !assumptions.is_array() {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "savings assumptions are not a JSON array".to_owned(),
            });
        }
        tx.execute(
            "INSERT INTO artifact_analysis_clone_group_savings
                 (schema_version, artifact_analysis_id, source_scan_run_id,
                  clone_group_fingerprint, source_build_variant_fingerprint,
                  artifact_build_variant_fingerprint, duplicated_bytes,
                  estimated_refactor_savings_bytes, mapping_confidence,
                  clone_confidence, model_confidence, savings_confidence,
                  model_schema_version, assumptions_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                estimate.schema_version,
                analysis_id,
                estimate.source_scan_run_id,
                estimate.clone_group_fingerprint.as_slice(),
                estimate.source_build_variant_fingerprint,
                estimate.artifact_build_variant_fingerprint,
                i64::try_from(estimate.duplicated_bytes).unwrap_or(i64::MAX),
                estimate.estimated_refactor_savings_bytes,
                estimate.mapping_confidence.as_sql(),
                estimate.clone_confidence,
                estimate.model_confidence.as_sql(),
                estimate.savings_confidence.as_sql(),
                estimate.model_schema_version,
                estimate.assumptions_json,
            ],
        )?;
    }
    Ok(())
}

/// Persist the ceilings an untrusted analysis installed.
///
/// An analysis that ran without the preset writes no row, which is what keeps
/// a later report from presenting the reading build's defaults as limits some
/// earlier run was held to.
fn record_containment(
    tx: &Transaction<'_>,
    analysis_id: i64,
    containment: Option<ArtifactAnalysisContainment>,
) -> Result<(), StoreError> {
    let Some(containment) = containment else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO artifact_analysis_containment
             (artifact_analysis_id, max_input_bytes, worker_timeout_seconds,
              worker_memory_limit_bytes)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            analysis_id,
            i64::try_from(containment.max_input_bytes).unwrap_or(i64::MAX),
            i64::try_from(containment.worker_timeout_seconds).unwrap_or(i64::MAX),
            i64::try_from(containment.worker_memory_limit_bytes).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

/// Persist the outcome of each declared source-map reference, in the order the
/// analysis reported them.
///
/// The ordinal is the reference's position in that report and nothing else: it
/// keeps the list in the order the artifact declared it, so a re-render prints
/// the same sequence.
fn record_source_maps(
    tx: &Transaction<'_>,
    analysis_id: i64,
    source_maps: &[ArtifactAnalysisSourceMap],
) -> Result<(), StoreError> {
    for (ordinal, source_map) in source_maps.iter().enumerate() {
        let ordinal = i64::try_from(ordinal).unwrap_or(i64::MAX);
        let (local_path, reason) = match &source_map.outcome {
            ArtifactAnalysisSourceMapOutcome::Resolved { local_path, .. } => {
                (Some(local_path.as_str()), None)
            }
            ArtifactAnalysisSourceMapOutcome::Unavailable { reason } => {
                (None, Some(reason.as_sql()))
            }
        };
        tx.execute(
            "INSERT INTO artifact_analysis_source_map_resolution
                 (artifact_analysis_id, ordinal, uri, local_path, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![analysis_id, ordinal, source_map.uri, local_path, reason],
        )?;
        let ArtifactAnalysisSourceMapOutcome::Resolved { sources, .. } = &source_map.outcome else {
            continue;
        };
        for (position, source) in sources.iter().enumerate() {
            tx.execute(
                "INSERT INTO artifact_analysis_source_map_resolution_source
                     (artifact_analysis_id, ordinal, position, source_name)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    analysis_id,
                    ordinal,
                    i64::try_from(position).unwrap_or(i64::MAX),
                    source,
                ],
            )?;
        }
    }
    Ok(())
}

fn record_mappings(
    tx: &Transaction<'_>,
    analysis_id: i64,
    mappings: &[ArtifactAnalysisMapping],
) -> Result<(), StoreError> {
    for mapping in mappings {
        if !supported_mapping_schema(&mapping.schema_version) {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown source-artifact mapping schema".to_owned(),
            });
        }
        let confidence =
            mapping
                .evidence
                .confidence()
                .ok_or_else(|| StoreError::InvalidMappingEvidence {
                    reason: "unknown schema, no facts, or no remaining candidate".to_owned(),
                })?;
        tx.execute(
            "INSERT INTO artifact_analysis_source_mapping
                 (schema_version, artifact_analysis_id, artifact_symbol_fingerprint,
                  source_kind, source_fingerprint, evidence_json, mapping_confidence,
                  attributed_bytes, build_variant_fingerprint, source_build_variant_fingerprint,
                  source_instance_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                mapping.schema_version,
                analysis_id,
                mapping.artifact_symbol_fingerprint.as_slice(),
                mapping.source_kind.as_sql(),
                mapping.source_fingerprint.as_slice(),
                mapping.evidence.json()?,
                confidence.as_sql(),
                mapping
                    .attributed_bytes
                    .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                mapping.build_variant_fingerprint,
                mapping.source_build_variant_fingerprint,
                mapping.source_instance_fingerprint.as_slice(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]
mod tests;
