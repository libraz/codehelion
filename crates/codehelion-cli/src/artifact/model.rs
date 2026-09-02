//! Serializable artifact report models and comparison deltas.

use super::{
    ARTIFACT_REPORT_SCHEMA_VERSION, ArtifactCorrelationReport, ArtifactIr, BinaryFormat, Serialize,
    metrics,
};

mod assumption;
mod columns;
mod comparison;

pub(super) use assumption::{
    AssumptionScope, ReportAssumption, comparison_assumptions, dead_code_unavailability,
    qualify_sizes, report_assumptions, retained_size_unavailability,
};
pub(super) use columns::{ARTIFACT_CSV_HEADER, COMPARE_CSV_HEADER, column, compare_column};
#[cfg(test)]
pub(super) use columns::{EVERY_RECORD, RECORD_COLUMNS};
pub(super) use comparison::{
    ArtifactComparisonReport, BuildVariantEvidence, CalibrationReport, ComparisonArtifact,
    ComparisonBuildVariant, SymbolDelta, code_section_bytes, data_segment_bytes,
    pairs_both_artifacts,
};

/// Stable summary of one artifact report, excluding raw code and data bytes.
#[derive(Debug, Serialize)]
pub(super) struct ArtifactReport {
    pub(super) schema_version: &'static str,
    pub(super) path: String,
    pub(super) analysis_id: Option<i64>,
    pub(super) build_variant: Option<ComparisonBuildVariant>,
    pub(super) correlation: Option<ArtifactCorrelationReport>,
    pub(super) containment: Option<ArtifactContainment>,
    pub(super) format: BinaryFormat,
    pub(super) fingerprint: String,
    pub(super) observed_bytes: u64,
    pub(super) architecture: Option<String>,
    pub(super) skipped_architectures: Vec<String>,
    pub(super) code_section_bytes: u64,
    pub(super) data_segment_bytes: u64,
    pub(super) sections: usize,
    pub(super) section_details: Vec<SectionReport>,
    pub(super) imports: usize,
    pub(super) import_details: Vec<ImportReport>,
    pub(super) symbols: Vec<SymbolReport>,
    pub(super) entry_points: usize,
    pub(super) calls: usize,
    pub(super) relocations: usize,
    pub(super) relocation_details: Vec<RelocationReport>,
    pub(super) source_mappings: usize,
    pub(super) source_maps: Vec<SourceMapResolution>,
    pub(super) archive_members: Vec<ArchiveMemberReport>,
    pub(super) data_segments: usize,
    pub(super) data_segment_details: Vec<DataSegmentReport>,
    pub(super) capabilities: codehelion_artifact::ArtifactCapabilities,
    pub(super) sizes: metrics::SizeClassification,
    pub(super) dead_code: Option<metrics::DeadCodeReport>,
    pub(super) retained_sizes: Option<Vec<metrics::RetainedSize>>,
    pub(super) duplicates: DuplicateSummary,
    pub(super) duplicate_groups: DuplicateGroups,
}

/// Limits successfully installed for an untrusted artifact operation.
#[derive(Debug, Serialize)]
pub(super) struct ArtifactContainment {
    pub(super) max_input_bytes: u64,
    pub(super) worker_timeout_seconds: u64,
    pub(super) worker_memory_limit_bytes: u64,
    /// How many structures the parse would build out of debug information
    /// before it stopped and reported the debug information as not fully read.
    ///
    /// Stated because the input ceiling alone does not imply it: debug
    /// metadata describes address ranges and line rows far more compactly than
    /// the structures a reader builds from them, so a reader who knows only
    /// how many bytes were accepted cannot tell how far those bytes were
    /// allowed to expand.
    pub(super) max_debug_derived_items: u64,
}

/// Display-safe section facts, including the size breakdown omitted from the
/// original artifact report.
#[derive(Debug, Serialize)]
pub(super) struct SectionReport {
    pub(super) name: Option<String>,
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) executable: bool,
}

/// One declared dependency without loading or resolving it.
#[derive(Debug, Serialize)]
pub(super) struct ImportReport {
    pub(super) module: Option<String>,
    pub(super) name: Option<String>,
    pub(super) kind: codehelion_artifact::ArtifactImportKind,
}

/// One parser-established relocation anchor.
#[derive(Debug, Serialize)]
pub(super) struct RelocationReport {
    pub(super) section: Option<u32>,
    pub(super) offset: u64,
    pub(super) kind: String,
    pub(super) target: Option<String>,
}

/// One data region represented without exposing its raw bytes.
#[derive(Debug, Serialize)]
pub(super) struct DataSegmentReport {
    pub(super) fingerprint: String,
    pub(super) section: Option<u32>,
    pub(super) offset: u64,
    pub(super) size: u64,
}

/// Display-safe provenance for one archive member.
#[derive(Debug, Serialize)]
pub(super) struct ArchiveMemberReport {
    pub(super) name: String,
    pub(super) fingerprint: String,
    /// Where the member sits in the archive; absent for a thin member, which
    /// the archive names rather than carries.
    pub(super) offset: Option<u64>,
    /// The member's observed length; absent for the same reason. Not zero:
    /// no length is not a length of zero.
    pub(super) size: Option<u64>,
    pub(super) format: Option<BinaryFormat>,
    pub(super) thin: bool,
    pub(super) parse_error: Option<String>,
}

/// Result of one locally declared WASM source-map reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct SourceMapResolution {
    pub(super) uri: String,
    #[serde(flatten)]
    pub(super) status: SourceMapResolutionStatus,
}

/// A source-map outcome that does not require fetching or retaining source text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum SourceMapResolutionStatus {
    Resolved {
        local_path: String,
        sources: Vec<String>,
        #[serde(skip)]
        locations: Vec<SourceMapLocation>,
    },
    Unavailable {
        reason: &'static str,
    },
}

/// One source-map location used only while correlating the current analysis.
///
/// Generated offsets and source-map token positions are parser-local evidence;
/// persisted mappings retain the stable source and artifact identities instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SourceMapLocation {
    pub(super) generated_offset: u64,
    pub(super) source_url: String,
    pub(super) source_line: Option<u32>,
}

impl ArtifactReport {
    pub(super) fn from_ir(
        path: &std::path::Path,
        artifact: &ArtifactIr,
        analysis_id: Option<i64>,
        build_variant: Option<ComparisonBuildVariant>,
    ) -> Self {
        let duplicates = metrics::find_duplicates(artifact);
        let data =
            metrics::find_duplicate_data(artifact, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        // Size categories, the reachability verdict and retained sizes are
        // three questions about one call graph and one soundness verdict.
        // Walking the artifact once for all three is what keeps them from
        // answering the soundness question differently.
        let graph = metrics::CallGraph::from_ir(artifact);
        let mut sizes = graph.classify_sizes_from_duplicates(&duplicates, &data);
        qualify_sizes(&mut sizes, &artifact.skipped_architectures);
        Self {
            schema_version: ARTIFACT_REPORT_SCHEMA_VERSION,
            path: path.display().to_string(),
            analysis_id,
            build_variant,
            correlation: None,
            containment: None,
            format: artifact.format,
            fingerprint: artifact.fingerprint.to_hex(),
            observed_bytes: artifact.observed_bytes,
            architecture: artifact.architecture.clone(),
            skipped_architectures: artifact.skipped_architectures.clone(),
            code_section_bytes: code_section_bytes(artifact),
            data_segment_bytes: data_segment_bytes(artifact),
            sections: artifact.sections.len(),
            section_details: section_reports(artifact),
            imports: artifact.imports.len(),
            import_details: import_reports(artifact),
            symbols: artifact
                .symbols
                .iter()
                .map(|symbol| SymbolReport {
                    fingerprint: symbol.fingerprint.to_hex(),
                    name: symbol.name.clone(),
                    exported: symbol.exported,
                    offset: symbol.offset,
                    size: symbol.size,
                    size_inferred: symbol.size_inferred,
                })
                .collect(),
            entry_points: artifact.entry_points.len(),
            calls: artifact.calls.len(),
            relocations: artifact.relocations.len(),
            relocation_details: relocation_reports(artifact),
            source_mappings: artifact.source_mappings.len(),
            source_maps: Vec::new(),
            archive_members: artifact
                .archive_members
                .iter()
                .map(|member| ArchiveMemberReport {
                    name: member.name.clone(),
                    fingerprint: member.fingerprint.to_hex(),
                    offset: member.offset,
                    size: member.size,
                    format: member.format,
                    thin: member.thin,
                    parse_error: member.parse_error.clone(),
                })
                .collect(),
            data_segments: artifact.data_segments.len(),
            data_segment_details: data_segment_reports(artifact),
            capabilities: artifact.capabilities,
            sizes,
            dead_code: graph.dead_code_candidates(),
            retained_sizes: graph.retained_sizes(),
            duplicates: DuplicateSummary {
                exact_groups: duplicates.exact.len(),
                exact_duplicated_bytes: duplicates
                    .exact
                    .iter()
                    .map(|group| group.duplicated_bytes)
                    .sum(),
                normalized_groups: duplicates.normalized.len(),
                normalized_duplicated_bytes: duplicates
                    .normalized
                    .iter()
                    .map(|group| group.duplicated_bytes)
                    .sum(),
            },
            duplicate_groups: DuplicateGroups {
                exact: duplicates.exact,
                normalized: duplicates.normalized,
                data,
            },
        }
    }

    pub(super) fn with_correlation(
        mut self,
        correlation: Option<ArtifactCorrelationReport>,
    ) -> Self {
        self.correlation = correlation;
        self
    }

    pub(super) const fn with_containment(
        mut self,
        containment: Option<ArtifactContainment>,
    ) -> Self {
        self.containment = containment;
        self
    }

    pub(super) fn with_source_maps(mut self, source_maps: Vec<SourceMapResolution>) -> Self {
        self.source_maps = source_maps;
        self
    }
}

pub(super) fn section_reports(artifact: &ArtifactIr) -> Vec<SectionReport> {
    artifact
        .sections
        .iter()
        .map(|section| SectionReport {
            name: section.name.clone(),
            offset: section.offset,
            size: section.size,
            executable: section.executable,
        })
        .collect()
}

pub(super) fn import_reports(artifact: &ArtifactIr) -> Vec<ImportReport> {
    artifact
        .imports
        .iter()
        .map(|import| ImportReport {
            module: import.module.clone(),
            name: import.name.clone(),
            kind: import.kind,
        })
        .collect()
}

pub(super) fn relocation_reports(artifact: &ArtifactIr) -> Vec<RelocationReport> {
    artifact
        .relocations
        .iter()
        .map(|relocation| RelocationReport {
            section: relocation.section,
            offset: relocation.offset,
            kind: relocation.kind.clone(),
            target: relocation.target.clone(),
        })
        .collect()
}

pub(super) fn data_segment_reports(artifact: &ArtifactIr) -> Vec<DataSegmentReport> {
    artifact
        .data_segments
        .iter()
        .map(|segment| DataSegmentReport {
            fingerprint: segment.fingerprint.to_hex(),
            section: segment.section,
            offset: segment.offset,
            size: segment.bytes.len() as u64,
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub(super) struct SymbolReport {
    pub(super) fingerprint: String,
    pub(super) name: Option<String>,
    pub(super) exported: bool,
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) size_inferred: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct DuplicateSummary {
    pub(super) exact_groups: usize,
    pub(super) exact_duplicated_bytes: u64,
    pub(super) normalized_groups: usize,
    pub(super) normalized_duplicated_bytes: u64,
}

/// Full equality groups, separate from the summary so clients cannot mistake
/// normalized similarity for byte-for-byte equality.
#[derive(Debug, Serialize)]
pub(super) struct DuplicateGroups {
    pub(super) exact: Vec<metrics::DuplicateGroup>,
    pub(super) normalized: Vec<metrics::DuplicateGroup>,
    pub(super) data: Vec<metrics::DuplicateGroup>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use codehelion_artifact::{ArtifactCall, ArtifactFingerprint, ArtifactSymbol};

    fn symbol(fingerprint: ArtifactFingerprint, exported: bool, offset: u64) -> ArtifactSymbol {
        ArtifactSymbol {
            fingerprint,
            name: None,
            exported,
            section: None,
            offset,
            size: 2,
            size_inferred: false,
            code: vec![1, 2],
            normalized: None,
            body_fingerprint: None,
            inline_stack: Vec::new(),
        }
    }

    /// Reachability caveats are stated by the metric that computes them, so a
    /// report must pass them through rather than restate them: an artifact that
    /// is ambiguous twice over would otherwise print each caveat twice.
    #[test]
    fn a_reachability_caveat_is_stated_once_per_report() {
        let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"\0asm\x01\0\0\0");
        artifact.capabilities.call_graph = true;
        let shared = ArtifactFingerprint::from_content("symbol", b"same");
        artifact.symbols = vec![symbol(shared, true, 0), symbol(shared, false, 4)];
        artifact.calls.push(ArtifactCall {
            caller: shared,
            target: Some(ArtifactFingerprint::from_content("symbol", b"absent")),
            unresolved: None,
        });

        let report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);

        let dead_code = report.dead_code.as_ref().expect("an exported root exists");
        assert!(!dead_code.definitive);
        let mut stated = dead_code.assumptions.clone();
        stated.sort();
        let unique = stated.len();
        stated.dedup();
        assert_eq!(stated.len(), unique, "{:?}", dead_code.assumptions);
        assert!(
            stated
                .iter()
                .any(|assumption| assumption.contains("share one content fingerprint")),
            "{stated:?}"
        );
        assert!(
            stated
                .iter()
                .any(|assumption| assumption.contains("matches no symbol")),
            "{stated:?}"
        );
    }
}
