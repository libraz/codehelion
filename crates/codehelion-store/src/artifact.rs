//! Atomic persistence for standalone compiled-artifact analyses.
//!
//! These rows deliberately do not pretend to be source scans. The existing
//! source-linked artifact tables remain available for later source-artifact
//! mapping; this module records the parser evidence available now.

use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

use crate::{Store, StoreError};

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
    pub build_variant_fingerprint: Option<[u8; 16]>,
    /// RFC 3339 timestamp taken before parsing.
    pub started_at: &'a str,
    /// RFC 3339 timestamp taken after parsing.
    pub finished_at: &'a str,
    /// Symbols the backend established, in deterministic parser order.
    pub symbols: &'a [ArtifactAnalysisSymbol],
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
    pub source_build_variant_fingerprint: [u8; 16],
    /// Build variant of the artifact receiving the attribution.
    pub artifact_build_variant_fingerprint: [u8; 16],
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
    pub source_build_variant_fingerprint: [u8; 16],
    /// Build variant of the analyzed before artifact.
    pub before_artifact_build_variant_fingerprint: [u8; 16],
    /// Content-derived identity of the measured after artifact.
    pub after_artifact_fingerprint: [u8; 16],
    /// Build variant of the measured after artifact.
    pub after_artifact_build_variant_fingerprint: [u8; 16],
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
    if values.len() % 2 == 0 {
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
    if values.len() % 2 == 0 {
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
    pub source_build_variant_fingerprint: [u8; 16],
    /// Versioned independent evidence facts for the correspondence.
    pub evidence: MappingEvidence,
    /// Bytes attributed to this source, or absent when the evidence has no split.
    pub attributed_bytes: Option<u64>,
    /// Build variant that made this correspondence meaningful.
    pub build_variant_fingerprint: [u8; 16],
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
            Self::CallGraphNeighborhood | Self::GenericOrigin { .. } | Self::MacroOrigin { .. } => {
                4
            }
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
    pub source_build_variant_fingerprint: [u8; 16],
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
    const fn as_sql(self) -> &'static str {
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
        match value {
            "no_artifact_evidence" => Ok(Self::NoArtifactEvidence),
            "dead_code" => Ok(Self::DeadCode),
            "inlined_away" => Ok(Self::InlinedAway),
            "lto_absorbed" => Ok(Self::LtoAbsorbed),
            "not_compiled_for_variant" => Ok(Self::NotCompiledForVariant),
            "evidence_conflict" => Ok(Self::EvidenceConflict),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_unmapped_source.reason",
                value: value.to_owned(),
            }),
        }
    }
}

/// Reasons why source correlation could not establish a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisUnmappedReason {
    /// The artifact has no usable debug information.
    DebugInfoMissing,
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
    const fn as_sql(self) -> &'static str {
        match self {
            Self::DebugInfoMissing => "debug_info_missing",
            Self::Stripped => "stripped",
            Self::DemangleFailed => "demangle_failed",
            Self::OutsideSourceScope => "outside_source_scope",
            Self::EvidenceConflict => "evidence_conflict",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        match value {
            "debug_info_missing" => Ok(Self::DebugInfoMissing),
            "stripped" => Ok(Self::Stripped),
            "demangle_failed" => Ok(Self::DemangleFailed),
            "outside_source_scope" => Ok(Self::OutsideSourceScope),
            "evidence_conflict" => Ok(Self::EvidenceConflict),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_unmapped_symbol.reason",
                value: value.to_owned(),
            }),
        }
    }
}

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
                snapshot
                    .build_variant_fingerprint
                    .map(|value| value.to_vec()),
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
                    unmapped.source_build_variant_fingerprint.as_slice(),
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

    /// Record one controlled before/after measurement for a saved estimate.
    ///
    /// # Errors
    ///
    /// Rejects an unknown schema or an invalid numeric measurement without
    /// writing a partial calibration row.
    pub fn record_artifact_savings_calibration(
        &mut self,
        calibration: &ArtifactAnalysisSavingsCalibration,
    ) -> Result<(), StoreError> {
        if calibration.schema_version != ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown artifact savings calibration schema".to_owned(),
            });
        }
        if calibration
            .relative_error
            .is_some_and(|value| !value.is_finite() || value.is_sign_negative())
        {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "calibration relative error must be finite and nonnegative".to_owned(),
            });
        }
        self.conn.execute(
            "INSERT INTO artifact_analysis_savings_calibration
                 (schema_version, artifact_analysis_id, source_scan_run_id,
                  clone_group_fingerprint, source_build_variant_fingerprint,
                  before_artifact_build_variant_fingerprint, after_artifact_fingerprint,
                  after_artifact_build_variant_fingerprint, estimated_refactor_savings_bytes,
                  verified_savings_bytes, absolute_error_bytes, relative_error, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                calibration.schema_version,
                calibration.artifact_analysis_id,
                calibration.source_scan_run_id,
                calibration.clone_group_fingerprint.as_slice(),
                calibration.source_build_variant_fingerprint.as_slice(),
                calibration
                    .before_artifact_build_variant_fingerprint
                    .as_slice(),
                calibration.after_artifact_fingerprint.as_slice(),
                calibration
                    .after_artifact_build_variant_fingerprint
                    .as_slice(),
                calibration.estimated_refactor_savings_bytes,
                calibration.verified_savings_bytes,
                i64::try_from(calibration.absolute_error_bytes).unwrap_or(i64::MAX),
                calibration.relative_error,
                calibration.recorded_at,
            ],
        )?;
        Ok(())
    }
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
                estimate.source_build_variant_fingerprint.as_slice(),
                estimate.artifact_build_variant_fingerprint.as_slice(),
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
                mapping.build_variant_fingerprint.as_slice(),
                mapping.source_build_variant_fingerprint.as_slice(),
                mapping.source_instance_fingerprint.as_slice(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn calibration_statistics_keep_relative_errors_separate_from_zero_measurements() {
        let calibration =
            |absolute_error_bytes, relative_error| ArtifactAnalysisSavingsCalibration {
                schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
                artifact_analysis_id: 1,
                source_scan_run_id: 2,
                clone_group_fingerprint: [3; 16],
                source_build_variant_fingerprint: [4; 16],
                before_artifact_build_variant_fingerprint: [5; 16],
                after_artifact_fingerprint: [6; 16],
                after_artifact_build_variant_fingerprint: [5; 16],
                estimated_refactor_savings_bytes: 0,
                verified_savings_bytes: 0,
                absolute_error_bytes,
                relative_error,
                recorded_at: "2026-07-30T00:00:00Z".to_owned(),
            };
        let statistics = artifact_savings_calibration_statistics(&[
            calibration(1, Some(0.1)),
            calibration(3, None),
            calibration(8, Some(0.8)),
            calibration(10, Some(1.0)),
        ]);
        assert_eq!(statistics.samples, 4);
        assert_eq!(statistics.median_absolute_error_bytes, Some(5.5));
        assert_eq!(statistics.p90_absolute_error_bytes, Some(10));
        assert_eq!(statistics.relative_error_samples, 3);
        assert_eq!(statistics.median_relative_error, Some(0.8));
        assert_eq!(statistics.p90_relative_error, Some(1.0));
        assert_eq!(
            artifact_savings_calibration_statistics(&[]),
            ArtifactSavingsCalibrationStatistics {
                samples: 0,
                median_absolute_error_bytes: None,
                p90_absolute_error_bytes: None,
                relative_error_samples: 0,
                median_relative_error: None,
                p90_relative_error: None,
            }
        );
    }

    #[test]
    fn mapping_evidence_derives_confidence_without_forcing_a_candidate() {
        let name = MappingEvidenceFact::SymbolName {
            source_symbol: "crate::entry".to_owned(),
            artifact_symbol: "crate::entry".to_owned(),
        };
        assert_eq!(
            MappingEvidence::new(vec![name.clone()], 1, false).confidence(),
            Some(ArtifactAnalysisMappingConfidence::Weak)
        );
        assert_eq!(
            MappingEvidence::new(
                vec![
                    name,
                    MappingEvidenceFact::FunctionRecipe {
                        recipe_version: FUNCTION_RECIPE_VERSION.to_owned(),
                    },
                ],
                1,
                false,
            )
            .confidence(),
            Some(ArtifactAnalysisMappingConfidence::Strong)
        );
        assert_eq!(
            MappingEvidence::new(
                vec![MappingEvidenceFact::Dwarf {
                    source_path: "src/lib.rs".to_owned(),
                }],
                1,
                false,
            )
            .confidence(),
            Some(ArtifactAnalysisMappingConfidence::Exact)
        );
        assert_eq!(
            MappingEvidence::new(
                vec![MappingEvidenceFact::Dwarf {
                    source_path: "src/lib.rs".to_owned(),
                }],
                2,
                false,
            )
            .confidence(),
            Some(ArtifactAnalysisMappingConfidence::Ambiguous)
        );
        assert_eq!(
            MappingEvidence::new(Vec::new(), 0, false).confidence(),
            None
        );
    }

    #[test]
    fn operation_recipe_evidence_accepts_only_its_current_v1_contract() {
        let evidence = MappingEvidence::new(
            vec![MappingEvidenceFact::FunctionRecipe {
                recipe_version: FUNCTION_RECIPE_VERSION.to_owned(),
            }],
            1,
            false,
        );
        let value = serde_json::to_value(&evidence).expect("evidence serializes");
        assert_eq!(value["facts"][0]["kind"], "function_recipe");
        assert_eq!(
            evidence.confidence(),
            Some(ArtifactAnalysisMappingConfidence::Weak)
        );

        let stale = MappingEvidence::new(
            vec![MappingEvidenceFact::FunctionRecipe {
                recipe_version: "source-artifact-operation-recipe-other".to_owned(),
            }],
            1,
            false,
        );
        assert_eq!(stale.confidence(), None);
        assert!(MappingEvidence::from_json(
            r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"function_fingerprint","recipe_version":"source-artifact-operation-recipe-v1"}],"candidate_count":1,"has_conflict":false}"#,
        )
        .is_err());
    }

    #[test]
    fn generic_origin_evidence_requires_every_v1_field() {
        let result = MappingEvidence::from_json(
            r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"generic_origin","instantiation_key":"crate::render<u8>"}],"candidate_count":1,"has_conflict":false}"#,
        );
        assert!(result.is_err());
        let result = MappingEvidence::from_json(
            r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"generic_origin","definition":"crate::render","instantiation_key":"crate::render<u8>"}],"candidate_count":1,"has_conflict":false}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_mapping_without_evidence_is_rejected_without_persisting_the_analysis() {
        let mut store = Store::open_in_memory().unwrap();
        let mappings = [ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: [2; 16],
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: [3; 16],
            source_instance_fingerprint: [3; 16],
            source_build_variant_fingerprint: [4; 16],
            evidence: MappingEvidence::new(Vec::new(), 0, false),
            attributed_bytes: None,
            build_variant_fingerprint: [5; 16],
        }];

        let error = store
            .record_artifact_analysis(&ArtifactAnalysisSnapshot {
                schema_version: "artifact-ir-v1",
                path: "fixture.so",
                format: "elf",
                content_fingerprint: [1; 16],
                observed_bytes: 0,
                ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
                build_variant_manifest_path: None,
                build_variant_fingerprint: None,
                started_at: "2026-07-30T00:00:00Z",
                finished_at: "2026-07-30T00:00:01Z",
                symbols: &[],
                mappings: &mappings,
                unmapped_symbols: &[],
                unmapped_sources: &[],
                correlation: None,
                clone_group_savings: &[],
            })
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidMappingEvidence { .. }));
        let analysis_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM artifact_analysis", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(analysis_count, 0);
    }

    #[test]
    fn artifact_analyses_with_distinct_build_variants_stay_distinct() {
        let mut store = Store::open_in_memory().unwrap();
        for (content_fingerprint, build_variant_fingerprint) in
            [([1; 16], [2; 16]), ([3; 16], [4; 16])]
        {
            store
                .record_artifact_analysis(&ArtifactAnalysisSnapshot {
                    schema_version: "artifact-ir-v1",
                    path: "fixture.wasm",
                    format: "wasm",
                    content_fingerprint,
                    observed_bytes: 8,
                    ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
                    build_variant_manifest_path: Some("build-variant.json"),
                    build_variant_fingerprint: Some(build_variant_fingerprint),
                    started_at: "2026-07-30T00:00:00Z",
                    finished_at: "2026-07-30T00:00:01Z",
                    symbols: &[],
                    mappings: &[],
                    unmapped_symbols: &[],
                    unmapped_sources: &[],
                    correlation: None,
                    clone_group_savings: &[],
                })
                .unwrap();
        }
        let variants: Vec<Vec<u8>> = store
            .conn
            .prepare(
                "SELECT build_variant_fingerprint
                 FROM artifact_analysis
                 ORDER BY build_variant_fingerprint ASC",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(variants, vec![vec![2; 16], vec![4; 16]]);
    }

    #[test]
    fn standalone_analysis_and_symbols_commit_together() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .conn
            .execute(
                "INSERT INTO build_variant
                     (variant_fingerprint, canonical, analysis_mode, normalization_version)
                 VALUES (?1, ?2, 'structural', 1)",
                ["0123456789abcdef0123456789abcdef", "fixture-variant"],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO scan_run
                     (build_variant_id, root_path, tool_version, config_hash, analysis_mode,
                      started_at, finished_at, status)
                 VALUES (1, 'fixture', 'test', 'config', 'structural',
                         '2026-07-30T00:00:00Z', '2026-07-30T00:00:01Z', 'completed')",
                [],
            )
            .unwrap();
        let symbols = [ArtifactAnalysisSymbol {
            fingerprint: [2; 16],
            name: Some("entry".to_owned()),
            exported: true,
            section_index: Some(1),
            offset: 4,
            size_bytes: 8,
            size_inferred: false,
            code_fingerprint: [3; 16],
            normalization_version: Some("wasm-opcode-v1".to_owned()),
            normalization_fingerprint: Some([4; 16]),
        }];
        let mappings = [ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: [2; 16],
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: [6; 16],
            source_instance_fingerprint: [11; 16],
            source_build_variant_fingerprint: [9; 16],
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::Dwarf {
                    source_path: "src/lib.rs".to_owned(),
                }],
                1,
                false,
            ),
            attributed_bytes: Some(8),
            build_variant_fingerprint: [5; 16],
        }];
        let unmapped_symbols = [ArtifactAnalysisUnmappedSymbol {
            artifact_symbol_fingerprint: [7; 16],
            reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
        }];
        let unmapped_sources = [
            ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Unit,
                source_fingerprint: [8; 16],
                source_instance_fingerprint: [8; 16],
                source_build_variant_fingerprint: [9; 16],
                reason: ArtifactAnalysisUnmappedSourceReason::InlinedAway,
            },
            ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Unit,
                source_fingerprint: [10; 16],
                source_instance_fingerprint: [10; 16],
                source_build_variant_fingerprint: [9; 16],
                reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
            },
        ];
        let savings = [ArtifactAnalysisCloneGroupSavings {
            schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_owned(),
            source_scan_run_id: 1,
            clone_group_fingerprint: [12; 16],
            source_build_variant_fingerprint: [9; 16],
            artifact_build_variant_fingerprint: [5; 16],
            duplicated_bytes: 8,
            estimated_refactor_savings_bytes: -2,
            mapping_confidence: ArtifactAnalysisSavingsConfidence::High,
            clone_confidence: 1.0,
            model_confidence: ArtifactAnalysisSavingsConfidence::Low,
            savings_confidence: ArtifactAnalysisSavingsConfidence::Low,
            model_schema_version: "refactor-savings-model-v1".to_owned(),
            assumptions_json: r#"[{"kind":"inlining_outcome_unknown"}]"#.to_owned(),
        }];
        let id = store
            .record_artifact_analysis(&ArtifactAnalysisSnapshot {
                schema_version: "artifact-ir-v1",
                path: "fixture.wasm",
                format: "wasm",
                content_fingerprint: [1; 16],
                observed_bytes: 12,
                ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
                build_variant_manifest_path: Some("build-variant.json"),
                build_variant_fingerprint: Some([5; 16]),
                started_at: "2026-07-30T00:00:00Z",
                finished_at: "2026-07-30T00:00:01Z",
                symbols: &symbols,
                mappings: &mappings,
                unmapped_symbols: &unmapped_symbols,
                unmapped_sources: &unmapped_sources,
                correlation: Some(ArtifactAnalysisCorrelation {
                    schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
                    source_scan_run_id: 1,
                    mapping_count: 1,
                    artifact_symbol_count: 1,
                    mapped_symbol_count: 1,
                    artifact_symbol_bytes: 8,
                    mapped_symbol_bytes: 8,
                }),
                clone_group_savings: &savings,
            })
            .unwrap();
        let count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM artifact_analysis_symbol WHERE analysis_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let ir_json: String = store
            .conn
            .query_row(
                "SELECT ir_json FROM artifact_analysis WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ir_json, r#"{"schema_version":"artifact-ir-v1"}"#);
        let variant: (Option<String>, Option<Vec<u8>>) = store
            .conn
            .query_row(
                "SELECT build_variant_manifest_path, build_variant_fingerprint
                 FROM artifact_analysis WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(variant.0.as_deref(), Some("build-variant.json"));
        assert_eq!(variant.1, Some(vec![5; 16]));
        assert_eq!(
            store.artifact_analysis_identity(id).unwrap(),
            Some(crate::query::StoredArtifactAnalysisIdentity {
                analysis_id: id,
                format: "wasm".to_owned(),
                content_fingerprint: [1; 16],
                build_variant_fingerprint: Some([5; 16]),
            })
        );
        let mapping: (String, String, i64) = store
            .conn
            .query_row(
                "SELECT source_kind, mapping_confidence, attributed_bytes
                 FROM artifact_analysis_source_mapping WHERE artifact_analysis_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(mapping, ("fragment".to_owned(), "exact".to_owned(), 8));
        let unmapped: String = store
            .conn
            .query_row(
                "SELECT reason FROM artifact_analysis_unmapped_symbol
                 WHERE artifact_analysis_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unmapped, "debug_info_missing");
        let stored_mappings = store.artifact_mappings(id).unwrap();
        assert_eq!(stored_mappings.len(), 1);
        assert_eq!(stored_mappings[0].artifact_symbol_fingerprint, [2; 16]);
        assert_eq!(
            stored_mappings[0].source_kind,
            ArtifactAnalysisSourceKind::Fragment
        );
        assert_eq!(stored_mappings[0].source_fingerprint, [6; 16]);
        assert_eq!(stored_mappings[0].source_instance_fingerprint, [11; 16]);
        assert_eq!(stored_mappings[0].source_build_variant_fingerprint, [9; 16]);
        assert_eq!(
            stored_mappings[0].confidence,
            ArtifactAnalysisMappingConfidence::Exact
        );
        assert_eq!(
            stored_mappings[0].evidence,
            MappingEvidence::new(
                vec![MappingEvidenceFact::Dwarf {
                    source_path: "src/lib.rs".to_owned(),
                }],
                1,
                false,
            )
        );
        assert_eq!(stored_mappings[0].attributed_bytes, Some(8));
        let stored_unmapped = store.artifact_unmapped_symbols(id).unwrap();
        assert_eq!(stored_unmapped.len(), 1);
        assert_eq!(stored_unmapped[0].artifact_symbol_fingerprint, [7; 16]);
        assert_eq!(
            stored_unmapped[0].reason,
            ArtifactAnalysisUnmappedReason::DebugInfoMissing
        );
        let stored_unmapped_sources = store.artifact_unmapped_sources(id).unwrap();
        assert_eq!(stored_unmapped_sources.len(), 2);
        assert_eq!(store.artifact_clone_group_savings(id).unwrap(), savings);
        assert_eq!(
            store
                .artifact_fragment_mappings("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                .unwrap(),
            stored_mappings
        );
        assert_eq!(
            store
                .clone_group_savings(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
                .unwrap(),
            vec![(id, savings[0].clone())]
        );
        assert_eq!(
            store
                .clone_group_type(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
                .unwrap(),
            None,
        );
        let calibration = ArtifactAnalysisSavingsCalibration {
            schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
            artifact_analysis_id: id,
            source_scan_run_id: 1,
            clone_group_fingerprint: [12; 16],
            source_build_variant_fingerprint: [9; 16],
            before_artifact_build_variant_fingerprint: [5; 16],
            after_artifact_fingerprint: [13; 16],
            after_artifact_build_variant_fingerprint: [5; 16],
            estimated_refactor_savings_bytes: -2,
            verified_savings_bytes: 3,
            absolute_error_bytes: 5,
            relative_error: Some(5.0 / 3.0),
            recorded_at: "2026-07-30T00:01:00Z".to_owned(),
        };
        store
            .record_artifact_savings_calibration(&calibration)
            .unwrap();
        let saved: (i64, i64, i64, f64) = store
            .conn
            .query_row(
                "SELECT estimated_refactor_savings_bytes, verified_savings_bytes,
                        absolute_error_bytes, relative_error
                 FROM artifact_analysis_savings_calibration
                 WHERE artifact_analysis_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(saved.0, -2);
        assert_eq!(saved.1, 3);
        assert_eq!(saved.2, 5);
        assert!((saved.3 - (5.0 / 3.0)).abs() < f64::EPSILON);
        assert_eq!(
            store
                .artifact_savings_calibrations(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
                .unwrap(),
            vec![calibration.clone()]
        );
        assert_eq!(
            store.artifact_savings_calibrations_for_run(1).unwrap(),
            vec![calibration]
        );
        assert_eq!(
            store.artifact_correlation(id).unwrap(),
            Some(crate::query::StoredArtifactAnalysisCorrelation {
                schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION.to_owned(),
                source_scan_run_id: 1,
                mapping_count: 1,
                artifact_symbol_count: 1,
                mapped_symbol_count: 1,
                artifact_symbol_bytes: 8,
                mapped_symbol_bytes: 8,
            })
        );
        assert_eq!(
            stored_unmapped_sources[0].source_kind,
            ArtifactAnalysisSourceKind::Unit
        );
        assert_eq!(
            stored_unmapped_sources[0].source_instance_fingerprint,
            [8; 16]
        );
        assert_eq!(stored_unmapped_sources[0].source_fingerprint, [8; 16]);
        assert_eq!(
            stored_unmapped_sources[0].source_build_variant_fingerprint,
            [9; 16]
        );
        assert_eq!(
            stored_unmapped_sources[0].reason,
            ArtifactAnalysisUnmappedSourceReason::InlinedAway
        );
        assert_eq!(stored_unmapped_sources[1].source_fingerprint, [10; 16]);
        assert_eq!(
            stored_unmapped_sources[1].reason,
            ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence
        );
    }
}
