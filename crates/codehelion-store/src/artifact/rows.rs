//! Row vocabulary for one standalone artifact analysis.
//!
//! These types describe what a parser observed and what it deliberately left
//! unresolved. The correspondence vocabulary lives in [`super::mapping`] and
//! the savings vocabulary in [`super::calibration`].

use crate::StoreError;
use crate::fingerprint::BuildVariantFingerprint;

use super::calibration::ArtifactAnalysisCloneGroupSavings;
use super::mapping::{ArtifactAnalysisMapping, ArtifactAnalysisSourceKind};

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
