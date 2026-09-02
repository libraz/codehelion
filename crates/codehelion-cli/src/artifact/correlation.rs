//! Source-to-artifact correlation and evidence aggregation.

use super::{
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCorrelation,
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSource, ArtifactAnalysisUnmappedSourceReason,
    ArtifactAnalysisUnmappedSymbol, ArtifactIr, BTreeMap, BTreeSet, BuildVariantEvidence, Context,
    FilePath, MAX_LINKER_MAP_BYTES, MappingEvidence, MappingEvidenceFact, Result,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION, Serialize, SourceFragmentIdentity, SourceInstantiation,
    SourceResolvedCall, SourceResolvedSymbol, SourceUnitIdentity, Store, bail, fingerprint_hex, fs,
    metrics,
};

/// Mapping rows established by one explicit source-run correlation request.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct CorrelationRows {
    pub(super) mappings: Vec<ArtifactAnalysisMapping>,
    pub(super) unmapped_symbols: Vec<ArtifactAnalysisUnmappedSymbol>,
    pub(super) unmapped_sources: Vec<ArtifactAnalysisUnmappedSource>,
    pub(super) clone_fragments: Vec<SourceFragmentIdentity>,
}

/// Correlation outcome for an explicit source scan.
///
/// The symbol counts and byte sums are all taken over the artifact's
/// symbol-table entries, so `mapped_symbols + unmapped_symbols` equals
/// `artifact_symbols` and the two byte sums add up to the observed symbol
/// bytes. Persisted unmapped rows are deduplicated by stable identity instead,
/// which is a property of the storage schema rather than of this coverage.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ArtifactCorrelationReport {
    pub(super) source_run: i64,
    pub(super) mappings: usize,
    pub(super) artifact_symbols: usize,
    pub(super) mapped_symbols: usize,
    pub(super) mapping_coverage: f64,
    pub(super) mapped_symbol_bytes: u64,
    pub(super) mapped_symbol_bytes_ratio: f64,
    pub(super) unmapped_symbols: usize,
    pub(super) unmapped_symbol_bytes: u64,
    pub(super) unmapped_symbol_reasons: BTreeMap<String, usize>,
    pub(super) source_entities: usize,
    pub(super) unmapped_sources: usize,
    pub(super) unmapped_source_reasons: BTreeMap<String, usize>,
    pub(super) clone_group_attributions: Vec<CloneGroupAttributionReport>,
    pub(super) estimated_refactor_savings: Vec<CloneGroupSavingsReport>,
    pub(super) multiply_emitted_units: Vec<MultiplyEmittedUnitReport>,
    pub(super) generic_origins: Vec<GenericOriginReport>,
    pub(super) macro_origins: Vec<MacroOriginReport>,
}

impl ArtifactCorrelationReport {
    #[allow(clippy::too_many_lines)] // The serialized correlation schema is assembled in one place.
    pub(super) fn from_rows(
        source_run: i64,
        artifact: &ArtifactIr,
        rows: &CorrelationRows,
    ) -> Self {
        let mapped_fingerprints = rows
            .mappings
            .iter()
            .map(|mapping| mapping.artifact_symbol_fingerprint)
            .collect::<BTreeSet<_>>();
        let artifact_symbols = artifact.symbols.len();
        let total_symbol_bytes = artifact
            .symbols
            .iter()
            .map(|symbol| symbol.size)
            .sum::<u64>();
        // Coverage counts one population: the artifact's symbol-table entries.
        // Storage records one unmapped outcome per stable identity, but that
        // deduplication belongs to the write path; letting it reach these
        // fields would report a mapped and an unmapped count that do not add
        // up to the symbols the binary actually contains.
        let unmapped_reasons = rows
            .unmapped_symbols
            .iter()
            .map(|unmapped| (unmapped.artifact_symbol_fingerprint, unmapped.reason))
            .collect::<BTreeMap<_, _>>();
        let mut mapped_symbols = 0;
        let mut mapped_symbol_bytes = 0_u64;
        let mut unmapped_symbols = 0;
        let mut unmapped_symbol_bytes = 0_u64;
        let mut unmapped_symbol_reasons = BTreeMap::new();
        for symbol in &artifact.symbols {
            if mapped_fingerprints.contains(&symbol.fingerprint.as_bytes()) {
                mapped_symbols += 1;
                mapped_symbol_bytes = mapped_symbol_bytes.saturating_add(symbol.size);
                continue;
            }
            unmapped_symbols += 1;
            unmapped_symbol_bytes = unmapped_symbol_bytes.saturating_add(symbol.size);
            if let Some(reason) = unmapped_reasons.get(&symbol.fingerprint.as_bytes()) {
                *unmapped_symbol_reasons
                    .entry(unmapped_reason_label(*reason).to_owned())
                    .or_default() += 1;
            }
        }
        let source_entities = rows
            .mappings
            .iter()
            .map(|mapping| {
                (
                    source_kind_order(mapping.source_kind),
                    mapping.source_fingerprint,
                    mapping.source_instance_fingerprint,
                    mapping.source_build_variant_fingerprint,
                )
            })
            .chain(rows.unmapped_sources.iter().map(|source| {
                (
                    source_kind_order(source.source_kind),
                    source.source_fingerprint,
                    source.source_instance_fingerprint,
                    source.source_build_variant_fingerprint,
                )
            }))
            .collect::<BTreeSet<_>>()
            .len();
        let mut unmapped_source_reasons = BTreeMap::new();
        for source in &rows.unmapped_sources {
            *unmapped_source_reasons
                .entry(unmapped_source_reason_label(source.reason).to_owned())
                .or_default() += 1;
        }
        let mut generic_origins: BTreeMap<_, BTreeMap<String, GenericSpecializationAggregate>> =
            BTreeMap::new();
        for mapping in &rows.mappings {
            if mapping.source_kind != ArtifactAnalysisSourceKind::Unit {
                continue;
            }
            let keys = mapping.evidence.facts.iter().filter_map(|fact| match fact {
                MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units,
                } => Some((
                    definition.clone(),
                    instantiation_key.clone(),
                    translation_units,
                )),
                _ => None,
            });
            for (definition, key, translation_units) in keys {
                let entry = generic_origins
                    .entry((
                        mapping.source_fingerprint,
                        mapping.source_build_variant_fingerprint,
                        definition,
                    ))
                    .or_default();
                let specialization = entry.entry(key).or_default();
                specialization
                    .symbols
                    .insert(mapping.artifact_symbol_fingerprint);
                specialization
                    .translation_units
                    .extend(translation_units.iter().cloned());
            }
        }
        let retained_sizes = if generic_origins.is_empty() {
            None
        } else {
            metrics::retained_sizes(artifact)
        };
        let mut generic_origins: Vec<_> = generic_origins
            .into_iter()
            .map(|((origin, variant, definition), specializations)| {
                let symbols = specializations
                    .values()
                    .flat_map(|specialization| specialization.symbols.iter().copied())
                    .collect::<BTreeSet<_>>();
                let translation_units = specializations
                    .values()
                    .flat_map(|specialization| specialization.translation_units.iter().cloned())
                    .collect::<BTreeSet<_>>();
                let (
                    observed_symbol_bytes,
                    normalized_instruction_duplicated_bytes,
                    retained_size_sum,
                ) = generic_origin_metrics(artifact, &symbols, retained_sizes.as_deref());
                let mut specializations: Vec<_> = specializations
                    .into_iter()
                    .map(
                        |(instantiation_key, aggregate)| GenericSpecializationReport {
                            type_arguments: generic_type_arguments(&instantiation_key),
                            observed_symbol_bytes: observed_symbol_bytes_for(
                                artifact,
                                &aggregate.symbols,
                            ),
                            artifact_symbols: aggregate.symbols.len(),
                            translation_units: aggregate.translation_units.len(),
                            instantiation_key,
                        },
                    )
                    .collect();
                specializations.sort_by(|left, right| {
                    right
                        .observed_symbol_bytes
                        .cmp(&left.observed_symbol_bytes)
                        .then_with(|| left.instantiation_key.cmp(&right.instantiation_key))
                });
                let origin_fingerprint =
                    fingerprint_hex(generic_origin_fingerprint(origin, &definition));
                GenericOriginReport {
                    definition,
                    origin_fingerprint,
                    origin_build_variant_fingerprint: fingerprint_hex(variant.as_bytes()),
                    instantiations: specializations.len(),
                    translation_units: translation_units.len(),
                    artifact_symbols: symbols.len(),
                    observed_symbol_bytes,
                    normalized_instruction_duplicated_bytes,
                    retained_size_sum,
                    specializations,
                }
            })
            .collect();
        generic_origins.sort_by(|left, right| {
            right
                .observed_symbol_bytes
                .cmp(&left.observed_symbol_bytes)
                .then_with(|| left.origin_fingerprint.cmp(&right.origin_fingerprint))
                .then_with(|| {
                    left.origin_build_variant_fingerprint
                        .cmp(&right.origin_build_variant_fingerprint)
                })
                .then_with(|| left.definition.cmp(&right.definition))
        });
        let mut macro_origins: BTreeMap<_, (BTreeSet<String>, BTreeSet<[u8; 16]>)> =
            BTreeMap::new();
        for mapping in &rows.mappings {
            if mapping.source_kind != ArtifactAnalysisSourceKind::Unit {
                continue;
            }
            for definition_path in mapping.evidence.facts.iter().filter_map(|fact| match fact {
                MappingEvidenceFact::MacroOrigin { definition_path } => Some(definition_path),
                _ => None,
            }) {
                let entry = macro_origins
                    .entry((
                        mapping.source_fingerprint,
                        mapping.source_build_variant_fingerprint,
                    ))
                    .or_default();
                entry.0.insert(definition_path.clone());
                entry.1.insert(mapping.artifact_symbol_fingerprint);
            }
        }
        let mut macro_origins: Vec<_> = macro_origins
            .into_iter()
            .map(
                |((origin, variant), (definition_paths, symbols))| MacroOriginReport {
                    origin_fingerprint: fingerprint_hex(origin),
                    origin_build_variant_fingerprint: fingerprint_hex(variant.as_bytes()),
                    definition_paths: definition_paths.into_iter().collect(),
                    artifact_symbols: symbols.len(),
                    observed_symbol_bytes: observed_symbol_bytes_for(artifact, &symbols),
                },
            )
            .collect();
        macro_origins.sort_by(|left, right| {
            right
                .observed_symbol_bytes
                .cmp(&left.observed_symbol_bytes)
                .then_with(|| left.origin_fingerprint.cmp(&right.origin_fingerprint))
        });
        Self {
            source_run,
            mappings: rows.mappings.len(),
            artifact_symbols,
            mapped_symbols,
            mapping_coverage: ratio(mapped_symbols, artifact_symbols),
            mapped_symbol_bytes,
            mapped_symbol_bytes_ratio: ratio_u64(mapped_symbol_bytes, total_symbol_bytes),
            unmapped_symbols,
            unmapped_symbol_bytes,
            unmapped_symbol_reasons,
            source_entities,
            unmapped_sources: rows.unmapped_sources.len(),
            unmapped_source_reasons,
            clone_group_attributions: clone_group_attributions(artifact, rows),
            estimated_refactor_savings: clone_group_savings(rows),
            multiply_emitted_units: multiply_emitted_units(artifact, rows),
            generic_origins,
            macro_origins,
        }
    }

    pub(super) fn snapshot(&self, artifact: &ArtifactIr) -> ArtifactAnalysisCorrelation {
        ArtifactAnalysisCorrelation {
            schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
            source_scan_run_id: self.source_run,
            mapping_count: u64::try_from(self.mappings).unwrap_or(u64::MAX),
            artifact_symbol_count: u64::try_from(self.artifact_symbols).unwrap_or(u64::MAX),
            mapped_symbol_count: u64::try_from(self.mapped_symbols).unwrap_or(u64::MAX),
            artifact_symbol_bytes: artifact.symbols.iter().map(|symbol| symbol.size).sum(),
            mapped_symbol_bytes: self.mapped_symbol_bytes,
        }
    }
}

mod attribution;
mod origin;
mod ratio;
pub(in crate::artifact) mod savings;

pub(super) use attribution::{
    CloneGroupAttributionReport, MultiplyEmittedUnitReport, clone_group_attributions,
    multiply_emitted_units, observed_symbol_bytes_for,
};
pub(super) use origin::{
    GenericOriginReport, GenericSpecializationAggregate, GenericSpecializationReport,
    MacroOriginReport, generic_origin_metrics, generic_type_arguments,
};
pub(in crate::artifact) use ratio::source_kind_order;
use ratio::{ratio, ratio_u64};
use ratio::{unmapped_reason_label, unmapped_source_reason_label};
pub(super) use savings::{
    AttributionBasis, CloneGroupSavingsReport, GroupSizeCategory, RefactorSavingsAssumption,
    clone_group_savings, stored_clone_group_savings,
};

pub(in crate::artifact) mod mapping;

use mapping::generic_origin_fingerprint;
pub(super) use mapping::{correlate_source_run, read_linker_map};

pub(in crate::artifact) mod matching;
