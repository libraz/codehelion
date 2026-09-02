//! Source-to-artifact correspondence vocabulary and its evidence contract.
//!
//! A correspondence is retained only when locally observable facts justify it.
//! Nothing here selects between ambiguous candidates: the confidence category
//! records what the evidence supports and leaves every candidate stored.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::StoreError;
use crate::fingerprint::BuildVariantFingerprint;

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

pub(super) fn supported_mapping_schema(schema_version: &str) -> bool {
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

    pub(super) fn json(&self) -> Result<String, StoreError> {
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
    pub(super) const fn as_sql(self) -> &'static str {
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
    pub(super) const fn as_sql(self) -> &'static str {
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
