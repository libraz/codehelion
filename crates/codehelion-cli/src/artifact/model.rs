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
    pub(super) offset: u64,
    pub(super) size: u64,
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
        let sizes = metrics::classify_sizes_from_duplicates(artifact, &duplicates, &data);
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
            code_section_bytes: artifact
                .sections
                .iter()
                .filter(|section| section.executable)
                .map(|section| section.size)
                .sum(),
            data_segment_bytes: artifact
                .data_segments
                .iter()
                .map(|segment| segment.bytes.len() as u64)
                .sum(),
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
            dead_code: metrics::dead_code_candidates(artifact),
            retained_sizes: metrics::retained_sizes(artifact),
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
    pub(super) observed_size_reduction_bytes: ObservedSizeReductionBytes,
    pub(super) duplicated_code_delta_bytes: i128,
    pub(super) duplicated_data_delta_bytes: Option<i128>,
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
        let before_sizes =
            metrics::classify_sizes_from_duplicates(before, &before_duplicates, &before_data);
        let after_duplicates = metrics::find_duplicates(after);
        let after_data =
            metrics::find_duplicate_data(after, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let after_sizes =
            metrics::classify_sizes_from_duplicates(after, &after_duplicates, &after_data);
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
            "observed_size_reduction_bytes is a measured artifact-byte difference, not a refactoring estimate"
                .to_owned(),
        ];
        if before.format != after.format {
            assumptions.push(
                "the artifact formats differ; size and symbol changes may reflect format changes"
                    .to_owned(),
            );
        }
        let build_variant_warning =
            build_variant_warning(before_variant.as_ref(), after_variant.as_ref());
        if let Some(warning) = &build_variant_warning {
            assumptions.push(warning.clone());
        }
        Self {
            schema_version: ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION,
            before: ComparisonArtifact {
                path: before_path.display().to_string(),
                format: before.format,
                fingerprint: before.fingerprint.to_hex(),
                architecture: before.architecture.clone(),
                skipped_architectures: before.skipped_architectures.clone(),
                build_variant: before_variant,
                sizes: before_sizes.clone(),
            },
            after: ComparisonArtifact {
                path: after_path.display().to_string(),
                format: after.format,
                fingerprint: after.fingerprint.to_hex(),
                architecture: after.architecture.clone(),
                skipped_architectures: after.skipped_architectures.clone(),
                build_variant: after_variant,
                sizes: after_sizes.clone(),
            },
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

pub(super) fn symbol_deltas(before: &ArtifactIr, after: &ArtifactIr) -> Vec<SymbolDelta> {
    let mut before_counts = symbol_counts(before);
    let mut after_counts = symbol_counts(after);
    let mut result = Vec::new();
    for symbol in &after.symbols {
        let Some(count) = after_counts.get_mut(&symbol.fingerprint) else {
            continue;
        };
        if *count == 0 {
            continue;
        }
        if let Some(prior) = before_counts.get_mut(&symbol.fingerprint) {
            if *prior > 0 {
                *prior -= 1;
            } else {
                result.push(SymbolDelta {
                    kind: "added",
                    name: symbol.name.clone(),
                    fingerprint: symbol.fingerprint.to_hex(),
                    size_delta_bytes: i128::from(symbol.size),
                });
            }
        } else {
            result.push(SymbolDelta {
                kind: "added",
                name: symbol.name.clone(),
                fingerprint: symbol.fingerprint.to_hex(),
                size_delta_bytes: i128::from(symbol.size),
            });
        }
        *count -= 1;
    }
    for symbol in &before.symbols {
        let Some(count) = before_counts.get_mut(&symbol.fingerprint) else {
            continue;
        };
        if *count == 0 {
            continue;
        }
        result.push(SymbolDelta {
            kind: "removed",
            name: symbol.name.clone(),
            fingerprint: symbol.fingerprint.to_hex(),
            size_delta_bytes: -i128::from(symbol.size),
        });
        *count -= 1;
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

pub(super) fn modified_named_symbols(before: &ArtifactIr, after: &ArtifactIr) -> usize {
    let names = |artifact: &ArtifactIr| {
        let mut result: BTreeMap<String, BTreeSet<codehelion_artifact::ArtifactFingerprint>> =
            BTreeMap::new();
        for symbol in &artifact.symbols {
            if let Some(name) = symbol.name.as_deref() {
                result
                    .entry(name.to_owned())
                    .or_default()
                    .insert(symbol.fingerprint);
            }
        }
        result
    };
    let before_names = names(before);
    let after_names = names(after);
    before_names
        .iter()
        .filter(|(name, fingerprints)| {
            fingerprints.len() == 1
                && after_names.get(*name).is_some_and(|after_fingerprints| {
                    after_fingerprints.len() == 1 && after_fingerprints != *fingerprints
                })
        })
        .count()
}

pub(super) fn difference(after: u64, before: u64) -> i128 {
    i128::from(after) - i128::from(before)
}
