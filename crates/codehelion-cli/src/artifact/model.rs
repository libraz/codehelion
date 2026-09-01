//! Serializable artifact report models and comparison deltas.

use super::{
    ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION, ARTIFACT_REPORT_SCHEMA_VERSION,
    ArtifactCorrelationReport, ArtifactIr, BTreeMap, BTreeSet, BinaryFormat,
    EstimatedRefactorSavingsBytes, ObservedSizeReductionBytes, Serialize, VerifiedSavingsBytes,
    metrics,
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

/// Versioned before/after result based only on parser-observed facts.
#[derive(Debug, Serialize)]
pub(super) struct ArtifactComparisonReport {
    pub(super) schema_version: &'static str,
    pub(super) before: ComparisonArtifact,
    pub(super) after: ComparisonArtifact,
    pub(super) containment: Option<ArtifactContainment>,
    pub(super) observed_size_reduction_bytes: ObservedSizeReductionBytes,
    pub(super) duplicated_code_delta_bytes: i128,
    pub(super) duplicated_data_delta_bytes: Option<i128>,
    /// Signed change in executable section bytes, so an observed difference
    /// can be attributed to code rather than to embedded data.
    pub(super) code_section_delta_bytes: i128,
    /// Signed change in data segment bytes, the other half of that question.
    pub(super) data_segment_delta_bytes: i128,
    pub(super) calibration: Option<CalibrationReport>,
    pub(super) symbol_changes: SymbolChanges,
    pub(super) symbol_deltas: Vec<SymbolDelta>,
    pub(super) duplicate_group_deltas: Vec<DuplicateGroupDelta>,
    pub(super) build_variant_warning: Option<String>,
    pub(super) assumptions: Vec<String>,
}

/// One controlled group-level measurement persisted from this comparison.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationReport {
    pub(super) source_run: i64,
    pub(super) clone_group_fingerprint: String,
    /// Saved analysis whose stored estimate this measurement calibrated.
    ///
    /// Analysing one artifact twice leaves several analyses of one identity,
    /// so the report names the one the measurement was taken against instead
    /// of leaving the choice invisible.
    pub(super) artifact_analysis_id: i64,
    /// How many saved analyses held an estimate of that same identity.
    pub(super) matching_analyses: usize,
    /// Whether a measurement of this identity was already on file, in which
    /// case recording refreshed that row rather than failing the comparison.
    pub(super) already_recorded: bool,
    pub(super) estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes,
    pub(super) verified_savings_bytes: VerifiedSavingsBytes,
    pub(super) absolute_error_bytes: u64,
    pub(super) relative_error: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(super) struct ComparisonArtifact {
    pub(super) path: String,
    pub(super) format: BinaryFormat,
    pub(super) fingerprint: String,
    pub(super) architecture: Option<String>,
    pub(super) skipped_architectures: Vec<String>,
    pub(super) build_variant: Option<ComparisonBuildVariant>,
    /// Executable section bytes, derived exactly as the single-artifact report
    /// derives them, so both surfaces answer "code or data?" the same way.
    pub(super) code_section_bytes: u64,
    /// Data segment bytes, derived the same way for the same reason.
    pub(super) data_segment_bytes: u64,
    pub(super) sizes: metrics::SizeClassification,
}

/// User-provided build-configuration evidence associated with one artifact.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ComparisonBuildVariant {
    pub(super) manifest_path: String,
    pub(super) fingerprint: String,
}

/// Validated build-condition evidence that is safe to persist as a fingerprint.
#[derive(Debug, Clone)]
pub(super) struct BuildVariantEvidence {
    pub(super) manifest_path: String,
    pub(super) fingerprint: codehelion_artifact::ArtifactFingerprint,
}

impl BuildVariantEvidence {
    pub(super) fn for_report(&self) -> ComparisonBuildVariant {
        ComparisonBuildVariant {
            manifest_path: self.manifest_path.clone(),
            fingerprint: self.fingerprint.to_hex(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct SymbolChanges {
    pub(super) added: usize,
    pub(super) removed: usize,
    pub(super) modified_named_symbols: usize,
}

/// One changed parser-established symbol, ordered by absolute size delta.
#[derive(Debug, Serialize)]
pub(super) struct SymbolDelta {
    pub(super) kind: &'static str,
    pub(super) name: Option<String>,
    pub(super) fingerprint: String,
    pub(super) size_delta_bytes: i128,
}

/// What a comparison established about one symbol, as [`SymbolDelta::kind`]
/// spells it.
///
/// The first two name a symbol identity that occurs on one side only. The
/// other two name one symbol found on both sides whose bytes are not the same
/// bytes: identity is derived from the normalized instruction stream, which
/// drops immediates, so a build that only rewrote a constant or narrowed its
/// encoding arrives here rather than as an addition and a removal.
pub(super) mod symbol_change {
    /// A symbol identity present only in the later artifact.
    pub(in crate::artifact) const ADDED: &str = "added";
    /// A symbol identity present only in the earlier artifact.
    pub(in crate::artifact) const REMOVED: &str = "removed";
    /// One symbol found on both sides whose observed byte size changed.
    pub(in crate::artifact) const RESIZED: &str = "resized";
    /// One symbol found on both sides whose bytes changed while its observed
    /// size did not.
    pub(in crate::artifact) const MODIFIED: &str = "modified";
}

/// Whether this change names one symbol on both sides rather than one side.
///
/// A paired change is identified by the single fingerprint both sides share,
/// so it stays readable without a name; an unpaired one carries a different
/// fingerprint on each side and needs the name to be matched up by a reader.
pub(super) fn pairs_both_artifacts(kind: &str) -> bool {
    matches!(kind, symbol_change::RESIZED | symbol_change::MODIFIED)
}

/// The symbols one identity covers, as the earlier and the later artifact
/// carry them.
type SymbolsOfOneIdentity<'a> = (
    Vec<&'a codehelion_artifact::ArtifactSymbol>,
    Vec<&'a codehelion_artifact::ArtifactSymbol>,
);

/// Everything one comparison uses to tell two builds of one symbol apart.
///
/// [`ArtifactSymbol::fingerprint`] is the grouping key and stays so: it is the
/// identity the rest of the artifact pipeline routes calls, duplicates and
/// correlations through. It is derived from the normalized instruction stream,
/// which deliberately drops immediates, so it cannot answer whether the bytes
/// behind it moved. The body identity and the observed size answer that, and
/// they are held beside the key rather than folded into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolContent {
    /// Identity of the instruction bytes including their immediates, absent
    /// for a backend that does not decode operands.
    body: Option<codehelion_artifact::ArtifactFingerprint>,
    /// Observed byte size, which is evidence of a change on its own.
    size: u64,
}

impl SymbolContent {
    /// The content of one parser-established symbol.
    const fn of(symbol: &codehelion_artifact::ArtifactSymbol) -> Self {
        Self {
            body: symbol.body_fingerprint,
            size: symbol.size,
        }
    }
}

/// One equality-group change. `kind` identifies the independent equality
/// relation so a normalized match is never presented as an exact-byte match.
#[derive(Debug, Serialize)]
pub(super) struct DuplicateGroupDelta {
    pub(super) kind: &'static str,
    pub(super) fingerprint: String,
    pub(super) duplicated_bytes_delta: i128,
    pub(super) members_delta: i128,
}

impl ArtifactComparisonReport {
    pub(super) fn new(
        before_path: &std::path::Path,
        before: &ArtifactIr,
        before_variant: Option<ComparisonBuildVariant>,
        after_path: &std::path::Path,
        after: &ArtifactIr,
        after_variant: Option<ComparisonBuildVariant>,
    ) -> Self {
        let before_duplicates = metrics::find_duplicates(before);
        let before_data =
            metrics::find_duplicate_data(before, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let mut before_sizes = metrics::CallGraph::from_ir(before)
            .classify_sizes_from_duplicates(&before_duplicates, &before_data);
        qualify_sizes(&mut before_sizes, &before.skipped_architectures);
        let after_duplicates = metrics::find_duplicates(after);
        let after_data =
            metrics::find_duplicate_data(after, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let mut after_sizes = metrics::CallGraph::from_ir(after)
            .classify_sizes_from_duplicates(&after_duplicates, &after_data);
        qualify_sizes(&mut after_sizes, &after.skipped_architectures);
        let before_symbols = symbol_counts(before);
        let after_symbols = symbol_counts(after);
        let added = count_difference(&after_symbols, &before_symbols);
        let removed = count_difference(&before_symbols, &after_symbols);
        let modified_named_symbols = modified_named_symbols(before, after);
        let symbol_deltas = symbol_deltas(before, after);
        let duplicate_group_deltas = duplicate_group_deltas(
            &before_duplicates,
            &before_data,
            &after_duplicates,
            &after_data,
        );
        let mut assumptions = vec![
            "symbol identity is content-derived; an equal name with a changed fingerprint is reported as modified"
                .to_owned(),
            "symbol identity drops instruction immediates, so a symbol found on both sides whose bytes still differ is reported as resized or modified rather than as unchanged"
                .to_owned(),
            "observed_size_reduction_bytes is a measured artifact-byte difference, not a refactoring estimate"
                .to_owned(),
            VERIFIED_SAVINGS_NEEDS_CONTROL.to_owned(),
        ];
        if before.format != after.format {
            assumptions.push(
                "the artifact formats differ; size and symbol changes may reflect format changes"
                    .to_owned(),
            );
        }
        if !before.skipped_architectures.is_empty() || !after.skipped_architectures.is_empty() {
            assumptions.push(CONTAINER_WIDE_OBSERVED_BYTES.to_owned());
        }
        // The warning has a reported field of its own, and one condition
        // stated twice reads as two independent conditions.
        let build_variant_warning =
            build_variant_warning(before_variant.as_ref(), after_variant.as_ref());
        Self {
            schema_version: ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION,
            before: ComparisonArtifact {
                path: before_path.display().to_string(),
                format: before.format,
                fingerprint: before.fingerprint.to_hex(),
                architecture: before.architecture.clone(),
                skipped_architectures: before.skipped_architectures.clone(),
                build_variant: before_variant,
                code_section_bytes: code_section_bytes(before),
                data_segment_bytes: data_segment_bytes(before),
                sizes: before_sizes.clone(),
            },
            after: ComparisonArtifact {
                path: after_path.display().to_string(),
                format: after.format,
                fingerprint: after.fingerprint.to_hex(),
                architecture: after.architecture.clone(),
                skipped_architectures: after.skipped_architectures.clone(),
                build_variant: after_variant,
                code_section_bytes: code_section_bytes(after),
                data_segment_bytes: data_segment_bytes(after),
                sizes: after_sizes.clone(),
            },
            containment: None,
            observed_size_reduction_bytes: ObservedSizeReductionBytes(
                i128::from(before_sizes.observed_bytes) - i128::from(after_sizes.observed_bytes),
            ),
            duplicated_code_delta_bytes: difference(
                after_sizes.duplicated_bytes,
                before_sizes.duplicated_bytes,
            ),
            duplicated_data_delta_bytes: after_sizes
                .duplicated_data_bytes
                .zip(before_sizes.duplicated_data_bytes)
                .map(|(after, before)| difference(after, before)),
            code_section_delta_bytes: difference(
                code_section_bytes(after),
                code_section_bytes(before),
            ),
            data_segment_delta_bytes: difference(
                data_segment_bytes(after),
                data_segment_bytes(before),
            ),
            calibration: None,
            symbol_changes: SymbolChanges {
                added,
                removed,
                modified_named_symbols,
            },
            symbol_deltas,
            duplicate_group_deltas,
            build_variant_warning,
            assumptions,
        }
    }
}

pub(super) fn build_variant_warning(
    before: Option<&ComparisonBuildVariant>,
    after: Option<&ComparisonBuildVariant>,
) -> Option<String> {
    match (before, after) {
        (Some(before), Some(after)) if before.fingerprint != after.fingerprint => Some(
            "build variants differ; size and symbol changes may reflect build-condition changes"
                .to_owned(),
        ),
        (Some(_), None) | (None, Some(_)) => Some(
            "only one build variant was supplied; build-condition differences cannot be assessed"
                .to_owned(),
        ),
        (None, None) => Some(
            "no build variants were supplied; build-condition differences cannot be assessed"
                .to_owned(),
        ),
        (Some(_), Some(_)) => None,
    }
}

pub(super) fn duplicate_group_deltas(
    before_duplicates: &metrics::DuplicateReport,
    before_data: &[metrics::DuplicateGroup],
    after_duplicates: &metrics::DuplicateReport,
    after_data: &[metrics::DuplicateGroup],
) -> Vec<DuplicateGroupDelta> {
    let groups = |duplicates: &metrics::DuplicateReport, data: &[metrics::DuplicateGroup]| {
        [
            ("exact", duplicates.exact.as_slice()),
            ("normalized", duplicates.normalized.as_slice()),
            ("data", data),
        ]
        .into_iter()
        .flat_map(|(kind, groups)| {
            groups.iter().map(move |group| {
                (
                    (kind, group.fingerprint),
                    (group.duplicated_bytes, group.members.len()),
                )
            })
        })
        .collect::<BTreeMap<_, _>>()
    };
    let before_groups = groups(before_duplicates, before_data);
    let after_groups = groups(after_duplicates, after_data);
    let keys: BTreeSet<_> = before_groups
        .keys()
        .chain(after_groups.keys())
        .copied()
        .collect();
    keys.into_iter()
        .filter_map(|(kind, fingerprint)| {
            let (before_bytes, before_members) = before_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let (after_bytes, after_members) = after_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let duplicated_bytes_delta = difference(after_bytes, before_bytes);
            let members_delta =
                i128::try_from(after_members).ok()? - i128::try_from(before_members).ok()?;
            (duplicated_bytes_delta != 0 || members_delta != 0).then(|| DuplicateGroupDelta {
                kind,
                fingerprint: fingerprint.to_hex(),
                duplicated_bytes_delta,
                members_delta,
            })
        })
        .collect()
}

/// Every per-symbol difference between two artifacts, ordered by absolute size
/// delta.
///
/// Symbols are collected under the identity the rest of the pipeline uses, and
/// within one such group the members that carry the same bytes on both sides
/// are struck off against each other first. What is left is one symbol the two
/// builds disagree about: it is paired and reported as
/// [`symbol_change::RESIZED`] or [`symbol_change::MODIFIED`], rather than
/// silently cancelling because normalization erased what changed. Only members
/// with nothing to pair against remain an addition or a removal.
pub(super) fn symbol_deltas(before: &ArtifactIr, after: &ArtifactIr) -> Vec<SymbolDelta> {
    let mut groups: BTreeMap<codehelion_artifact::ArtifactFingerprint, SymbolsOfOneIdentity<'_>> =
        BTreeMap::new();
    for symbol in &before.symbols {
        groups.entry(symbol.fingerprint).or_default().0.push(symbol);
    }
    for symbol in &after.symbols {
        groups.entry(symbol.fingerprint).or_default().1.push(symbol);
    }
    let mut result = Vec::new();
    for (fingerprint, (before_members, after_members)) in groups {
        let fingerprint = fingerprint.to_hex();
        let (before_changed, after_changed) = unmatched_content(before_members, after_members);
        let mut before_changed = before_changed.into_iter();
        let mut after_changed = after_changed.into_iter();
        loop {
            match (before_changed.next(), after_changed.next()) {
                (Some(earlier), Some(later)) => result.push(SymbolDelta {
                    kind: if earlier.size == later.size {
                        symbol_change::MODIFIED
                    } else {
                        symbol_change::RESIZED
                    },
                    // Both sides share one identity, so either name is the
                    // symbol's; the later artifact is what the report is about.
                    name: later.name.clone().or_else(|| earlier.name.clone()),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: difference(later.size, earlier.size),
                }),
                (Some(earlier), None) => result.push(SymbolDelta {
                    kind: symbol_change::REMOVED,
                    name: earlier.name.clone(),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: -i128::from(earlier.size),
                }),
                (None, Some(later)) => result.push(SymbolDelta {
                    kind: symbol_change::ADDED,
                    name: later.name.clone(),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: i128::from(later.size),
                }),
                (None, None) => break,
            }
        }
    }
    result.sort_by(|left, right| {
        right
            .size_delta_bytes
            .unsigned_abs()
            .cmp(&left.size_delta_bytes.unsigned_abs())
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

/// Strike off the members of one identity group that carry the same bytes on
/// both sides, and return what each side has left.
///
/// Byte-equal members are the ones a comparison has nothing to say about, so
/// cancelling them first is what keeps a symbol that did change from being
/// paired against an unrelated twin. Both remainders come back in a
/// content-then-offset order, so the pairing that follows does not depend on
/// the order the symbols happened to be laid out in.
fn unmatched_content<'a>(
    before: Vec<&'a codehelion_artifact::ArtifactSymbol>,
    after: Vec<&'a codehelion_artifact::ArtifactSymbol>,
) -> SymbolsOfOneIdentity<'a> {
    let mut unmatched: BTreeMap<SymbolContent, usize> = BTreeMap::new();
    for symbol in &before {
        *unmatched.entry(SymbolContent::of(symbol)).or_default() += 1;
    }
    let mut remaining_after = Vec::new();
    for symbol in after {
        match unmatched.get_mut(&SymbolContent::of(symbol)) {
            Some(count) if *count > 0 => *count -= 1,
            _ => remaining_after.push(symbol),
        }
    }
    let mut remaining_before = Vec::new();
    for symbol in before {
        if let Some(count) = unmatched.get_mut(&SymbolContent::of(symbol))
            && *count > 0
        {
            *count -= 1;
            remaining_before.push(symbol);
        }
    }
    let order = |symbol: &&codehelion_artifact::ArtifactSymbol| (symbol.size, symbol.offset);
    remaining_before.sort_by_key(order);
    remaining_after.sort_by_key(order);
    (remaining_before, remaining_after)
}

pub(super) fn symbol_counts(
    artifact: &ArtifactIr,
) -> BTreeMap<codehelion_artifact::ArtifactFingerprint, usize> {
    let mut counts = BTreeMap::new();
    for symbol in &artifact.symbols {
        *counts.entry(symbol.fingerprint).or_default() += 1;
    }
    counts
}

pub(super) fn count_difference(
    left: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
    right: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
) -> usize {
    left.iter()
        .map(|(fingerprint, count)| count.saturating_sub(*right.get(fingerprint).unwrap_or(&0)))
        .sum()
}

/// How many named symbols one artifact carries differently from the other.
///
/// A name is counted when it belongs to exactly one symbol on each side and
/// those two symbols are not the same symbol. That is a question about the
/// grouping identity and about the bytes behind it: two builds of one function
/// whose opcode sequence did not move share the identity, so the body identity
/// and the observed size are what separate them, exactly as they do in
/// [`symbol_deltas`].
pub(super) fn modified_named_symbols(before: &ArtifactIr, after: &ArtifactIr) -> usize {
    let names = |artifact: &ArtifactIr| {
        let mut result: BTreeMap<
            String,
            BTreeSet<(codehelion_artifact::ArtifactFingerprint, SymbolContent)>,
        > = BTreeMap::new();
        for symbol in &artifact.symbols {
            if let Some(name) = symbol.name.as_deref() {
                result
                    .entry(name.to_owned())
                    .or_default()
                    .insert((symbol.fingerprint, SymbolContent::of(symbol)));
            }
        }
        result
    };
    let before_names = names(before);
    let after_names = names(after);
    before_names
        .iter()
        .filter(|(name, identities)| {
            identities.len() == 1
                && after_names.get(*name).is_some_and(|after_identities| {
                    after_identities.len() == 1 && after_identities != *identities
                })
        })
        .count()
}

pub(super) fn difference(after: u64, before: u64) -> i128 {
    i128::from(after) - i128::from(before)
}

/// Executable section bytes observed in one artifact.
pub(super) fn code_section_bytes(artifact: &ArtifactIr) -> u64 {
    artifact
        .sections
        .iter()
        .filter(|section| section.executable)
        .map(|section| section.size)
        .sum()
}

/// Data segment bytes observed in one artifact.
pub(super) fn data_segment_bytes(artifact: &ArtifactIr) -> u64 {
    artifact
        .data_segments
        .iter()
        .map(|segment| segment.bytes.len() as u64)
        .sum()
}

/// Where in a report one qualifying statement belongs.
///
/// Text prints a statement under the block whose numbers it qualifies, CSV
/// names that block in a column, and JSON carries it inside that block. The
/// scope is what lets three renderings place one statement without any of them
/// inventing a fourth statement, dropping one, or printing one twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AssumptionScope {
    /// Qualifies the size categories.
    Sizes,
    /// States why reachability-derived sizes are absent.
    RetainedSizes,
    /// Qualifies the reachability verdict.
    DeadCode,
    /// The build-condition warning, which the report also exposes as its own
    /// field and which therefore has exactly one place in each rendering.
    BuildVariant,
    /// Qualifies a before/after comparison as a whole.
    Comparison,
}

impl AssumptionScope {
    /// The CSV spelling of this scope.
    pub(super) const fn field(self) -> &'static str {
        match self {
            Self::Sizes => "sizes",
            Self::RetainedSizes => "retained_sizes",
            Self::DeadCode => "dead_code",
            Self::BuildVariant => "build_variant",
            Self::Comparison => "comparison",
        }
    }
}

/// One qualifying statement together with the block it qualifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReportAssumption<'a> {
    /// The reported block this statement qualifies.
    pub(super) scope: AssumptionScope,
    /// The statement itself, as the report carries it.
    pub(super) text: &'a str,
}

/// How the metrics crate opens each reason it withdraws a reachability size.
///
/// Those reasons name the condition that actually held for one artifact, so a
/// report states them instead of asserting a single canned cause.
const WITHDRAWN_SIZE_PREFIX: &str = "retained and shared dependency sizes need";

/// What the upper bound leaves out, said in the categories it actually leaves
/// out.
///
/// Derived from the list the bound is built from rather than written down
/// beside it: a duplicated category added later appears in this sentence
/// without anyone remembering to edit it, which is the failure the sentence
/// existed to describe in the first place.
fn upper_bound_omissions() -> String {
    use metrics::ReportedSize as _;

    let excluded: Vec<&str> = metrics::upper_bound_excludes()
        .into_iter()
        .map(metrics::ReportedSize::key)
        .collect();
    format!(
        "{} counts duplicate code only and excludes {}",
        metrics::SizeCategory::UpperBoundSavings.key(),
        excluded.join(" and ")
    )
}

/// Byte counts read from a container outlive the slice selected inside it.
const CONTAINER_WIDE_OBSERVED_BYTES: &str = "observed byte counts cover the whole container, including the skipped architecture slices; only section, symbol and duplicate counts are limited to the selected architecture";

/// A verified saving belongs to one refactoring only under a controlled pair.
const VERIFIED_SAVINGS_NEEDS_CONTROL: &str = "verified_savings_bytes attributes the whole observed artifact difference to the calibrated clone group, which holds only when the two artifacts differ in nothing else; this comparison establishes the artifact format and the build variant and nothing further";

/// State what the reported size fields leave out, beside what their derivation
/// already assumed.
///
/// These reach every rendering because they are added while the report is
/// built: JSON serializes them from the same vector text and CSV read.
pub(super) fn qualify_sizes(
    sizes: &mut metrics::SizeClassification,
    skipped_architectures: &[String],
) {
    if sizes.upper_bound_savings_bytes.is_some() {
        sizes.assumptions.push(upper_bound_omissions());
    }
    if !skipped_architectures.is_empty() {
        sizes
            .assumptions
            .push(CONTAINER_WIDE_OBSERVED_BYTES.to_owned());
    }
}

/// Every statement qualifying one artifact report, each stated once.
pub(super) fn report_assumptions(report: &ArtifactReport) -> Vec<ReportAssumption<'_>> {
    let withdrawn = report.retained_sizes.is_none();
    let mut assumptions: Vec<_> = report
        .sizes
        .assumptions
        .iter()
        .map(|text| ReportAssumption {
            scope: if withdrawn && text.starts_with(WITHDRAWN_SIZE_PREFIX) {
                AssumptionScope::RetainedSizes
            } else {
                AssumptionScope::Sizes
            },
            text: text.as_str(),
        })
        .collect();
    if let Some(dead_code) = &report.dead_code {
        assumptions.extend(dead_code.assumptions.iter().map(|text| ReportAssumption {
            scope: AssumptionScope::DeadCode,
            text: text.as_str(),
        }));
    }
    stated_once(assumptions)
}

/// Every statement qualifying one comparison, each stated once.
pub(super) fn comparison_assumptions(
    report: &ArtifactComparisonReport,
) -> Vec<ReportAssumption<'_>> {
    let mut assumptions: Vec<_> = report
        .build_variant_warning
        .iter()
        .map(|text| ReportAssumption {
            scope: AssumptionScope::BuildVariant,
            text: text.as_str(),
        })
        .collect();
    assumptions.extend(report.assumptions.iter().map(|text| ReportAssumption {
        scope: AssumptionScope::Comparison,
        text: text.as_str(),
    }));
    stated_once(assumptions)
}

/// Drop a statement that repeats one already collected.
fn stated_once(assumptions: Vec<ReportAssumption<'_>>) -> Vec<ReportAssumption<'_>> {
    let mut stated = BTreeSet::new();
    assumptions
        .into_iter()
        .filter(|assumption| stated.insert(assumption.text))
        .collect()
}

/// Why a report carries no reachability verdict, naming the condition that
/// actually held rather than one of the two that could have.
pub(super) const fn dead_code_unavailability(report: &ArtifactReport) -> &'static str {
    if report.capabilities.call_graph {
        "no parser-established root: this artifact declares no export, entry point, or recorded function reference"
    } else {
        "this format backend establishes no call edges"
    }
}

/// Why a report carries no retained sizes, naming each condition that held.
///
/// The reasons come from the walk that withdrew the values, so a report never
/// explains an absent number with a condition that did not fire.
pub(super) fn retained_size_unavailability(report: &ArtifactReport) -> Vec<&str> {
    report
        .sizes
        .assumptions
        .iter()
        .filter(|text| text.starts_with(WITHDRAWN_SIZE_PREFIX))
        .map(String::as_str)
        .collect()
}

/// Every artifact CSV column, in the order they are written.
///
/// The CSV is one union table discriminated by `record_type`. A column is
/// named for exactly one quantity: a record that has no such quantity leaves
/// it empty rather than borrowing a neighbouring column, and a quantity the
/// text or JSON rendering states has a column of its own. Columns are only
/// ever appended, so a consumer reading by position keeps reading the same
/// value after a release adds one.
pub(super) const ARTIFACT_CSV_HEADER: &[&str] = &[
    "record_type",
    "path",
    "format",
    "kind",
    "fingerprint",
    "name",
    "offset",
    "size",
    "duplicated_bytes",
    "retained_bytes",
    "dead_code_status",
    "observed_bytes",
    "source_run",
    "mappings",
    "mapped_symbols",
    "unmapped_symbols",
    "upper_bound_savings_bytes",
    "estimated_refactor_savings_bytes",
    "verified_savings_bytes",
    "origin_build_variant_fingerprint",
    "instantiations",
    "translation_units",
    "source_build_variant_fingerprint",
    "artifact_build_variant_fingerprint",
    "mapping_confidence",
    "clone_confidence",
    "model_confidence",
    "savings_confidence",
    "model_schema_version",
    "estimate_assumptions_json",
    "section",
    "executable",
    "module",
    "duplicated_bytes_normalized",
    "estimated_duplicated_bytes",
    "attribution_basis",
    "shared_dependency_bytes",
    "code_section_bytes",
    "data_segment_bytes",
    "artifact_symbols",
    "definition_path_count",
    "members",
    "attributed_noncanonical_members",
    "assumption_scope",
    "assumption",
    "max_input_bytes",
    "worker_timeout_seconds",
    "worker_memory_limit_bytes",
    "source_map_uri",
    "source_map_local_path",
    "source_map_sources",
    "duplicated_data_bytes",
    "containing_symbols",
    "containing_symbol_bytes",
    "emitted_bodies",
    "max_debug_derived_items",
];

/// The columns one kind of record in the artifact CSV carries.
///
/// A record fills a subset of one wide row, and which subset was written down
/// nowhere: a reader could only find out by running the tool, and a writer
/// could start filling a column meant for something else without anything
/// saying so. This is the one description of that, checked against what the
/// writers actually produce.
#[cfg(test)]
pub(super) struct RecordColumns {
    /// The `record_type` value the record is written under.
    pub(super) record_type: &'static str,
    /// Columns the record carries beyond [`EVERY_RECORD`].
    pub(super) columns: &'static [usize],
}

/// Columns every record carries, whatever kind it is: what it is, which
/// artifact it is about, and what format that artifact was read as.
#[cfg(test)]
pub(super) const EVERY_RECORD: &[usize] = &[column::RECORD_TYPE, column::PATH, column::FORMAT];

/// What each kind of record carries.
///
/// Ordered as `render_csv` writes them. A record that fills a column absent
/// from its entry fails the check that reads this, so a field added to a
/// record has to say which column carries it before it can appear — which is
/// also where a reader looks to find out what a record type means.
#[cfg(test)]
pub(super) const RECORD_COLUMNS: &[RecordColumns] = &[
    RecordColumns {
        record_type: "summary",
        columns: &[
            column::FINGERPRINT,
            column::OBSERVED_BYTES,
            column::DUPLICATED_BYTES,
            column::DUPLICATED_BYTES_NORMALIZED,
            column::RETAINED_BYTES,
            column::SHARED_DEPENDENCY_BYTES,
            column::DUPLICATED_DATA_BYTES,
            column::UPPER_BOUND_SAVINGS_BYTES,
            column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
            column::VERIFIED_SAVINGS_BYTES,
            column::SOURCE_RUN,
            column::MAPPINGS,
            column::MAPPED_SYMBOLS,
            column::UNMAPPED_SYMBOLS,
            column::CODE_SECTION_BYTES,
            column::DATA_SEGMENT_BYTES,
            column::CLONE_CONFIDENCE,
            column::SAVINGS_CONFIDENCE,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "build-variant",
        columns: &[column::FINGERPRINT, column::NAME],
    },
    RecordColumns {
        record_type: "containment",
        columns: &[
            column::MAX_INPUT_BYTES,
            column::WORKER_TIMEOUT_SECONDS,
            column::WORKER_MEMORY_LIMIT_BYTES,
            column::MAX_DEBUG_DERIVED_ITEMS,
        ],
    },
    RecordColumns {
        record_type: "archive-member",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::OFFSET,
            column::SIZE,
            column::DEAD_CODE_STATUS,
        ],
    },
    RecordColumns {
        record_type: "source-map",
        columns: &[
            column::KIND,
            column::SOURCE_MAP_URI,
            column::SOURCE_MAP_LOCAL_PATH,
            column::SOURCE_MAP_SOURCES,
        ],
    },
    RecordColumns {
        record_type: "section",
        columns: &[
            column::KIND,
            column::NAME,
            column::OFFSET,
            column::SIZE,
            column::EXECUTABLE,
        ],
    },
    RecordColumns {
        record_type: "import",
        columns: &[column::KIND, column::NAME, column::MODULE],
    },
    RecordColumns {
        record_type: "relocation",
        columns: &[column::KIND, column::NAME, column::OFFSET, column::SECTION],
    },
    RecordColumns {
        record_type: "data-segment",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::OFFSET,
            column::SIZE,
            column::SECTION,
        ],
    },
    RecordColumns {
        record_type: "duplicate-group",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::MEMBERS,
        ],
    },
    RecordColumns {
        record_type: "duplicate-member",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::OFFSET,
            column::SIZE,
        ],
    },
    RecordColumns {
        record_type: "dead-code",
        columns: &[column::FINGERPRINT, column::DEAD_CODE_STATUS],
    },
    RecordColumns {
        record_type: "retained-size",
        columns: &[column::FINGERPRINT, column::RETAINED_BYTES],
    },
    RecordColumns {
        record_type: "clone-group-attribution",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::ESTIMATED_DUPLICATED_BYTES,
            column::CONTAINING_SYMBOLS,
            column::CONTAINING_SYMBOL_BYTES,
            column::MEMBERS,
            column::ATTRIBUTED_NONCANONICAL_MEMBERS,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::CLONE_CONFIDENCE,
            column::ATTRIBUTION_BASIS,
        ],
    },
    RecordColumns {
        record_type: "multiply-emitted-unit",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::EMITTED_BODIES,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::MAPPING_CONFIDENCE,
        ],
    },
    RecordColumns {
        record_type: "clone-group-savings",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::ESTIMATED_DUPLICATED_BYTES,
            column::ATTRIBUTION_BASIS,
            column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::ARTIFACT_BUILD_VARIANT_FINGERPRINT,
            column::MAPPING_CONFIDENCE,
            column::CLONE_CONFIDENCE,
            column::MODEL_CONFIDENCE,
            column::SAVINGS_CONFIDENCE,
            column::MODEL_SCHEMA_VERSION,
            column::ESTIMATE_ASSUMPTIONS_JSON,
        ],
    },
    RecordColumns {
        record_type: "generic-origin",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::DUPLICATED_BYTES,
            column::RETAINED_BYTES,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::INSTANTIATIONS,
            column::TRANSLATION_UNITS,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "generic-specialization",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::INSTANTIATIONS,
            column::TRANSLATION_UNITS,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "macro-origin",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::ARTIFACT_SYMBOLS,
            column::DEFINITION_PATH_COUNT,
        ],
    },
    RecordColumns {
        record_type: "assumption",
        columns: &[column::ASSUMPTION_SCOPE, column::ASSUMPTION],
    },
];

// Columns are only ever appended, so the published width never shrinks.
const _: () = assert!(ARTIFACT_CSV_HEADER.len() >= super::ARTIFACT_CSV_COLUMNS);

/// Column positions in [`ARTIFACT_CSV_HEADER`], named as the header names them.
pub(super) mod column {
    pub(in crate::artifact) const RECORD_TYPE: usize = 0;
    pub(in crate::artifact) const PATH: usize = 1;
    pub(in crate::artifact) const FORMAT: usize = 2;
    pub(in crate::artifact) const KIND: usize = 3;
    pub(in crate::artifact) const FINGERPRINT: usize = 4;
    pub(in crate::artifact) const NAME: usize = 5;
    pub(in crate::artifact) const OFFSET: usize = 6;
    pub(in crate::artifact) const SIZE: usize = 7;
    pub(in crate::artifact) const DUPLICATED_BYTES: usize = 8;
    pub(in crate::artifact) const RETAINED_BYTES: usize = 9;
    pub(in crate::artifact) const DEAD_CODE_STATUS: usize = 10;
    pub(in crate::artifact) const OBSERVED_BYTES: usize = 11;
    pub(in crate::artifact) const SOURCE_RUN: usize = 12;
    pub(in crate::artifact) const MAPPINGS: usize = 13;
    pub(in crate::artifact) const MAPPED_SYMBOLS: usize = 14;
    pub(in crate::artifact) const UNMAPPED_SYMBOLS: usize = 15;
    pub(in crate::artifact) const UPPER_BOUND_SAVINGS_BYTES: usize = 16;
    pub(in crate::artifact) const ESTIMATED_REFACTOR_SAVINGS_BYTES: usize = 17;
    pub(in crate::artifact) const VERIFIED_SAVINGS_BYTES: usize = 18;
    pub(in crate::artifact) const ORIGIN_BUILD_VARIANT_FINGERPRINT: usize = 19;
    pub(in crate::artifact) const INSTANTIATIONS: usize = 20;
    pub(in crate::artifact) const TRANSLATION_UNITS: usize = 21;
    pub(in crate::artifact) const SOURCE_BUILD_VARIANT_FINGERPRINT: usize = 22;
    pub(in crate::artifact) const ARTIFACT_BUILD_VARIANT_FINGERPRINT: usize = 23;
    pub(in crate::artifact) const MAPPING_CONFIDENCE: usize = 24;
    pub(in crate::artifact) const CLONE_CONFIDENCE: usize = 25;
    pub(in crate::artifact) const MODEL_CONFIDENCE: usize = 26;
    pub(in crate::artifact) const SAVINGS_CONFIDENCE: usize = 27;
    pub(in crate::artifact) const MODEL_SCHEMA_VERSION: usize = 28;
    pub(in crate::artifact) const ESTIMATE_ASSUMPTIONS_JSON: usize = 29;
    pub(in crate::artifact) const SECTION: usize = 30;
    pub(in crate::artifact) const EXECUTABLE: usize = 31;
    pub(in crate::artifact) const MODULE: usize = 32;
    pub(in crate::artifact) const DUPLICATED_BYTES_NORMALIZED: usize = 33;
    pub(in crate::artifact) const ESTIMATED_DUPLICATED_BYTES: usize = 34;
    pub(in crate::artifact) const ATTRIBUTION_BASIS: usize = 35;
    pub(in crate::artifact) const SHARED_DEPENDENCY_BYTES: usize = 36;
    pub(in crate::artifact) const CODE_SECTION_BYTES: usize = 37;
    pub(in crate::artifact) const DATA_SEGMENT_BYTES: usize = 38;
    pub(in crate::artifact) const ARTIFACT_SYMBOLS: usize = 39;
    pub(in crate::artifact) const DEFINITION_PATH_COUNT: usize = 40;
    pub(in crate::artifact) const MEMBERS: usize = 41;
    pub(in crate::artifact) const ATTRIBUTED_NONCANONICAL_MEMBERS: usize = 42;
    pub(in crate::artifact) const ASSUMPTION_SCOPE: usize = 43;
    pub(in crate::artifact) const ASSUMPTION: usize = 44;
    pub(in crate::artifact) const MAX_INPUT_BYTES: usize = 45;
    pub(in crate::artifact) const WORKER_TIMEOUT_SECONDS: usize = 46;
    pub(in crate::artifact) const WORKER_MEMORY_LIMIT_BYTES: usize = 47;
    pub(in crate::artifact) const SOURCE_MAP_URI: usize = 48;
    pub(in crate::artifact) const SOURCE_MAP_LOCAL_PATH: usize = 49;
    pub(in crate::artifact) const SOURCE_MAP_SOURCES: usize = 50;
    pub(in crate::artifact) const DUPLICATED_DATA_BYTES: usize = 51;
    pub(in crate::artifact) const CONTAINING_SYMBOLS: usize = 52;
    pub(in crate::artifact) const CONTAINING_SYMBOL_BYTES: usize = 53;
    pub(in crate::artifact) const EMITTED_BODIES: usize = 54;
    pub(in crate::artifact) const MAX_DEBUG_DERIVED_ITEMS: usize = 55;
}

/// Every comparison CSV column, in the order they are written, under the same
/// union-table rules as [`ARTIFACT_CSV_HEADER`].
pub(super) const COMPARE_CSV_HEADER: &[&str] = &[
    "record_type",
    "before_path",
    "after_path",
    "before_format",
    "after_format",
    "before_fingerprint",
    "after_fingerprint",
    "observed_size_reduction_bytes",
    "duplicated_code_delta_bytes",
    "duplicated_data_delta_bytes",
    "estimated_refactor_savings_bytes",
    "verified_savings_bytes",
    "source_run",
    "clone_group_fingerprint",
    "change_kind",
    "name",
    "fingerprint",
    "symbol_size_delta_bytes",
    "duplicated_bytes_delta",
    "members_delta",
    "warning",
    "absolute_error_bytes",
    "relative_error",
    "before_code_section_bytes",
    "after_code_section_bytes",
    "code_section_delta_bytes",
    "before_data_segment_bytes",
    "after_data_segment_bytes",
    "data_segment_delta_bytes",
    "assumption_scope",
    "assumption",
    "max_input_bytes",
    "worker_timeout_seconds",
    "worker_memory_limit_bytes",
    "artifact_analysis_id",
    "matching_analyses",
    "calibration_record",
];

/// Column positions in [`COMPARE_CSV_HEADER`].
pub(super) mod compare_column {
    pub(in crate::artifact) const RECORD_TYPE: usize = 0;
    pub(in crate::artifact) const BEFORE_PATH: usize = 1;
    pub(in crate::artifact) const AFTER_PATH: usize = 2;
    pub(in crate::artifact) const BEFORE_FORMAT: usize = 3;
    pub(in crate::artifact) const AFTER_FORMAT: usize = 4;
    pub(in crate::artifact) const BEFORE_FINGERPRINT: usize = 5;
    pub(in crate::artifact) const AFTER_FINGERPRINT: usize = 6;
    pub(in crate::artifact) const OBSERVED_SIZE_REDUCTION_BYTES: usize = 7;
    pub(in crate::artifact) const DUPLICATED_CODE_DELTA_BYTES: usize = 8;
    pub(in crate::artifact) const DUPLICATED_DATA_DELTA_BYTES: usize = 9;
    pub(in crate::artifact) const ESTIMATED_REFACTOR_SAVINGS_BYTES: usize = 10;
    pub(in crate::artifact) const VERIFIED_SAVINGS_BYTES: usize = 11;
    pub(in crate::artifact) const SOURCE_RUN: usize = 12;
    pub(in crate::artifact) const CLONE_GROUP_FINGERPRINT: usize = 13;
    pub(in crate::artifact) const CHANGE_KIND: usize = 14;
    pub(in crate::artifact) const NAME: usize = 15;
    pub(in crate::artifact) const FINGERPRINT: usize = 16;
    pub(in crate::artifact) const SYMBOL_SIZE_DELTA_BYTES: usize = 17;
    pub(in crate::artifact) const DUPLICATED_BYTES_DELTA: usize = 18;
    pub(in crate::artifact) const MEMBERS_DELTA: usize = 19;
    pub(in crate::artifact) const WARNING: usize = 20;
    pub(in crate::artifact) const ABSOLUTE_ERROR_BYTES: usize = 21;
    pub(in crate::artifact) const RELATIVE_ERROR: usize = 22;
    pub(in crate::artifact) const BEFORE_CODE_SECTION_BYTES: usize = 23;
    pub(in crate::artifact) const AFTER_CODE_SECTION_BYTES: usize = 24;
    pub(in crate::artifact) const CODE_SECTION_DELTA_BYTES: usize = 25;
    pub(in crate::artifact) const BEFORE_DATA_SEGMENT_BYTES: usize = 26;
    pub(in crate::artifact) const AFTER_DATA_SEGMENT_BYTES: usize = 27;
    pub(in crate::artifact) const DATA_SEGMENT_DELTA_BYTES: usize = 28;
    pub(in crate::artifact) const ASSUMPTION_SCOPE: usize = 29;
    pub(in crate::artifact) const ASSUMPTION: usize = 30;
    pub(in crate::artifact) const MAX_INPUT_BYTES: usize = 31;
    pub(in crate::artifact) const WORKER_TIMEOUT_SECONDS: usize = 32;
    pub(in crate::artifact) const WORKER_MEMORY_LIMIT_BYTES: usize = 33;
    pub(in crate::artifact) const ARTIFACT_ANALYSIS_ID: usize = 34;
    pub(in crate::artifact) const MATCHING_ANALYSES: usize = 35;
    pub(in crate::artifact) const CALIBRATION_RECORD: usize = 36;
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
