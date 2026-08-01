//! Source-to-artifact correlation and evidence aggregation.

use super::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisMapping, ArtifactAnalysisSavingsConfidence,
    ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason, ArtifactAnalysisUnmappedSource,
    ArtifactAnalysisUnmappedSourceReason, ArtifactAnalysisUnmappedSymbol, ArtifactIr, BTreeMap,
    BTreeSet, BuildVariantEvidence, Context, EstimatedRefactorSavingsBytes, EvidenceConfidence,
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
    pub(super) generic_origins: Vec<GenericOriginReport>,
    pub(super) macro_origins: Vec<MacroOriginReport>,
}

/// Conservative observed bytes attributed to one source clone group.
#[derive(Debug, Clone, Serialize)]
pub(super) struct CloneGroupAttributionReport {
    /// Content-derived stable clone-group identity.
    pub(super) clone_group_fingerprint: String,
    /// Build variant that minted the group's member fingerprints.
    pub(super) source_build_variant_fingerprint: String,
    /// Members recorded for the group under this variant.
    pub(super) members: usize,
    /// Noncanonical members with at least one exact, unambiguous byte split.
    pub(super) attributed_noncanonical_members: usize,
    /// Observed bytes attributable to all noncanonical members, when complete.
    ///
    /// This is an attribution observation, not an estimated refactoring saving.
    pub(super) duplicated_bytes: Option<u64>,
    /// Source clone score kept separate from mapping and model confidence.
    pub(super) clone_confidence: f64,
}

/// Versioned, deliberately conservative refactoring-cost assumptions.
#[derive(Debug, Clone, Serialize)]
pub(super) struct RefactorSavingsModel {
    pub(super) schema_version: &'static str,
    pub(super) retained_copies: u64,
    pub(super) call_overhead_per_replaced_member_bytes: i64,
    pub(super) assumptions: Vec<RefactorSavingsAssumption>,
    pub(super) confidence: EvidenceConfidence,
}

/// One versioned model row. Keeping the coefficients here makes changing a
/// model an explicit data/version change instead of a hidden arithmetic edit.
#[derive(Debug, Clone, Copy)]
pub(super) struct RefactorSavingsModelSpec {
    pub(super) schema_version: &'static str,
    pub(super) retained_copies: u64,
    pub(super) call_overhead_per_replaced_member_bytes: i64,
    pub(super) assumptions: &'static [RefactorSavingsAssumptionSpec],
    pub(super) confidence: EvidenceConfidence,
}

/// Serializable assumptions have a compact static-table counterpart.
#[derive(Debug, Clone, Copy)]
pub(super) enum RefactorSavingsAssumptionSpec {
    SharedImplementationRetainsCopies { copies: u64 },
    CallOverheadPerReplacedMember { bytes: i64 },
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
}

const REFACTOR_SAVINGS_MODELS: &[RefactorSavingsModelSpec] = &[RefactorSavingsModelSpec {
    schema_version: "refactor-savings-model-v1",
    retained_copies: 1,
    call_overhead_per_replaced_member_bytes: 0,
    assumptions: &[
        RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies: 1 },
        RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember { bytes: 0 },
        RefactorSavingsAssumptionSpec::InliningOutcomeUnknown,
        RefactorSavingsAssumptionSpec::LinkerIcfOutcomeUnknown,
    ],
    confidence: EvidenceConfidence::Low,
}];

/// A machine-readable condition behind one refactoring estimate.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum RefactorSavingsAssumption {
    SharedImplementationRetainsCopies { copies: u64 },
    CallOverheadPerReplacedMember { bytes: i64 },
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
}

/// A source/artifact-correlated refactoring estimate for one clone group.
#[derive(Debug, Clone, Serialize)]
pub(super) struct CloneGroupSavingsReport {
    pub(super) clone_group_fingerprint: String,
    pub(super) source_build_variant_fingerprint: String,
    pub(super) artifact_build_variant_fingerprint: String,
    pub(super) duplicated_bytes: u64,
    pub(super) estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes,
    pub(super) mapping_confidence: EvidenceConfidence,
    pub(super) clone_confidence: f64,
    pub(super) model_confidence: EvidenceConfidence,
    pub(super) savings_confidence: EvidenceConfidence,
    pub(super) assumptions: Vec<RefactorSavingsAssumption>,
    pub(super) model_schema_version: &'static str,
}

pub(super) fn stored_clone_group_savings(
    source_scan_run_id: i64,
    estimates: &[CloneGroupSavingsReport],
) -> Result<Vec<ArtifactAnalysisCloneGroupSavings>> {
    estimates
        .iter()
        .map(|estimate| {
            let clone_group_fingerprint = hex_fingerprint(&estimate.clone_group_fingerprint)
                .context("encoding clone-group savings fingerprint")?;
            let source_build_variant_fingerprint =
                hex_fingerprint(&estimate.source_build_variant_fingerprint)
                    .context("encoding source savings build variant")?;
            let artifact_build_variant_fingerprint =
                hex_fingerprint(&estimate.artifact_build_variant_fingerprint)
                    .context("encoding artifact savings build variant")?;
            Ok(ArtifactAnalysisCloneGroupSavings {
                schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_owned(),
                source_scan_run_id,
                clone_group_fingerprint,
                source_build_variant_fingerprint,
                artifact_build_variant_fingerprint,
                duplicated_bytes: estimate.duplicated_bytes,
                estimated_refactor_savings_bytes: estimate.estimated_refactor_savings_bytes.0,
                mapping_confidence: stored_savings_confidence(estimate.mapping_confidence),
                clone_confidence: estimate.clone_confidence,
                model_confidence: stored_savings_confidence(estimate.model_confidence),
                savings_confidence: stored_savings_confidence(estimate.savings_confidence),
                model_schema_version: estimate.model_schema_version.to_owned(),
                assumptions_json: serde_json::to_string(&estimate.assumptions)
                    .context("serializing structured savings assumptions")?,
            })
        })
        .collect()
}

const fn stored_savings_confidence(
    confidence: EvidenceConfidence,
) -> ArtifactAnalysisSavingsConfidence {
    match confidence {
        EvidenceConfidence::High => ArtifactAnalysisSavingsConfidence::High,
        EvidenceConfidence::Medium => ArtifactAnalysisSavingsConfidence::Medium,
        EvidenceConfidence::Low => ArtifactAnalysisSavingsConfidence::Low,
        EvidenceConfidence::Unavailable => ArtifactAnalysisSavingsConfidence::Unavailable,
    }
}

/// Observed artifact symbols attributed to one generic definition origin.
#[derive(Debug, Clone, Serialize)]
pub(super) struct GenericOriginReport {
    /// Compiler-confirmed definition spelling that distinguishes origins with
    /// otherwise identical source content.
    pub(super) definition: String,
    /// Content-derived source unit identity of the generic definition.
    pub(super) origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    pub(super) origin_build_variant_fingerprint: String,
    /// Number of distinct compiler instantiation keys observed for this origin.
    pub(super) instantiations: usize,
    /// Number of translation units that independently observed the origin.
    pub(super) translation_units: usize,
    /// Number of distinct artifact symbols mapped to this origin.
    pub(super) artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    pub(super) observed_symbol_bytes: u64,
    /// Excess observed bytes in equal normalized instruction groups for this origin.
    ///
    /// This is a duplicate observation, not a claimed refactoring saving.
    pub(super) normalized_instruction_duplicated_bytes: u64,
    /// Sum of per-symbol retained sizes when the call graph supports them.
    ///
    /// Retained regions overlap, so this value must not be treated as a total.
    pub(super) retained_size_sum: Option<u64>,
    /// Observed artifact size split by exact compiler-reported specialization.
    pub(super) specializations: Vec<GenericSpecializationReport>,
}

/// Observed artifact symbols attributed to one declarative macro definition.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MacroOriginReport {
    /// Content-derived identity of the source unit containing the macro body.
    pub(super) origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    pub(super) origin_build_variant_fingerprint: String,
    /// Macro definition paths retained as auditable evidence.
    pub(super) definition_paths: Vec<String>,
    /// Number of distinct artifact symbols attributed to this macro body.
    pub(super) artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    pub(super) observed_symbol_bytes: u64,
}

/// One exact generic specialization contributing to an origin's artifact size.
#[derive(Debug, Clone, Serialize)]
pub(super) struct GenericSpecializationReport {
    /// Versioned compiler-reported instantiation key.
    pub(super) instantiation_key: String,
    /// Top-level type or value arguments parsed from the exact key.
    pub(super) type_arguments: Vec<String>,
    /// Number of distinct artifact symbols attributed to this specialization.
    pub(super) artifact_symbols: usize,
    /// Number of translation units that reported this specialization.
    pub(super) translation_units: usize,
    /// Sum of observed sizes of those symbols.
    pub(super) observed_symbol_bytes: u64,
}

/// Compiler observations accumulated for one exact specialization.
#[derive(Debug, Default)]
pub(super) struct GenericSpecializationAggregate {
    pub(super) symbols: BTreeSet<[u8; 16]>,
    pub(super) translation_units: BTreeSet<String>,
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
        let mapped_symbols = artifact
            .symbols
            .iter()
            .filter(|symbol| mapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .count();
        let mapped_symbol_bytes = artifact
            .symbols
            .iter()
            .filter(|symbol| mapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .map(|symbol| symbol.size)
            .sum::<u64>();
        let unmapped_fingerprints = rows
            .unmapped_symbols
            .iter()
            .map(|unmapped| unmapped.artifact_symbol_fingerprint)
            .collect::<BTreeSet<_>>();
        let unmapped_symbol_bytes = artifact
            .symbols
            .iter()
            .filter(|symbol| unmapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .map(|symbol| symbol.size)
            .sum::<u64>();
        let mut unmapped_symbol_reasons = BTreeMap::new();
        for unmapped in &rows.unmapped_symbols {
            *unmapped_symbol_reasons
                .entry(unmapped_reason_label(unmapped.reason).to_owned())
                .or_default() += 1;
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
                    origin_build_variant_fingerprint: fingerprint_hex(variant),
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
                    origin_build_variant_fingerprint: fingerprint_hex(variant),
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
            unmapped_symbols: rows.unmapped_symbols.len(),
            unmapped_symbol_bytes,
            unmapped_symbol_reasons,
            source_entities,
            unmapped_sources: rows.unmapped_sources.len(),
            unmapped_source_reasons,
            clone_group_attributions: clone_group_attributions(rows),
            estimated_refactor_savings: clone_group_savings(rows),
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

pub(super) fn clone_group_attributions(rows: &CorrelationRows) -> Vec<CloneGroupAttributionReport> {
    let mut groups: BTreeMap<_, Vec<&SourceFragmentIdentity>> = BTreeMap::new();
    for fragment in &rows.clone_fragments {
        groups
            .entry((
                fragment.clone_group_fingerprint,
                fragment.build_variant_fingerprint,
            ))
            .or_default()
            .push(fragment);
    }
    groups
        .into_iter()
        .map(|((group_fingerprint, source_variant), members)| {
            let noncanonical = members
                .iter()
                .filter(|member| !member.is_canonical)
                .map(|member| member.finding_id)
                .collect::<BTreeSet<_>>();
            let mut bytes_by_member: BTreeMap<[u8; 16], u64> = BTreeMap::new();
            for mapping in &rows.mappings {
                if mapping.source_kind != ArtifactAnalysisSourceKind::Fragment
                    || mapping.source_build_variant_fingerprint != source_variant
                    || !noncanonical.contains(&mapping.source_instance_fingerprint)
                {
                    continue;
                }
                if let Some(bytes) = mapping.attributed_bytes {
                    let total = bytes_by_member
                        .entry(mapping.source_instance_fingerprint)
                        .or_default();
                    *total = total.saturating_add(bytes);
                }
            }
            let attributed_noncanonical_members = bytes_by_member.len();
            let duplicated_bytes = (attributed_noncanonical_members == noncanonical.len())
                .then(|| bytes_by_member.values().copied().sum());
            CloneGroupAttributionReport {
                clone_group_fingerprint: fingerprint_hex(group_fingerprint),
                source_build_variant_fingerprint: fingerprint_hex(source_variant),
                members: members.len(),
                attributed_noncanonical_members,
                duplicated_bytes,
                clone_confidence: members
                    .first()
                    .map_or(0.0, |member| member.clone_confidence),
            }
        })
        .collect()
}

pub(super) fn refactor_savings_model() -> RefactorSavingsModel {
    let spec = REFACTOR_SAVINGS_MODELS
        .first()
        .copied()
        .unwrap_or(RefactorSavingsModelSpec {
            schema_version: "refactor-savings-model-unavailable",
            retained_copies: 0,
            call_overhead_per_replaced_member_bytes: 0,
            assumptions: &[],
            confidence: EvidenceConfidence::Unavailable,
        });
    RefactorSavingsModel {
        schema_version: spec.schema_version,
        retained_copies: spec.retained_copies,
        call_overhead_per_replaced_member_bytes: spec.call_overhead_per_replaced_member_bytes,
        assumptions: spec
            .assumptions
            .iter()
            .map(|assumption| match assumption {
                RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies } => {
                    RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies: *copies }
                }
                RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember { bytes } => {
                    RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes: *bytes }
                }
                RefactorSavingsAssumptionSpec::InliningOutcomeUnknown => {
                    RefactorSavingsAssumption::InliningOutcomeUnknown
                }
                RefactorSavingsAssumptionSpec::LinkerIcfOutcomeUnknown => {
                    RefactorSavingsAssumption::LinkerIcfOutcomeUnknown
                }
            })
            .collect(),
        confidence: spec.confidence,
    }
}

pub(super) fn clone_group_savings(rows: &CorrelationRows) -> Vec<CloneGroupSavingsReport> {
    let model = refactor_savings_model();
    clone_group_attributions(rows)
        .into_iter()
        .filter_map(|attribution| {
            let duplicated_bytes = attribution.duplicated_bytes?;
            let group_fingerprint = hex_fingerprint(&attribution.clone_group_fingerprint)?;
            let source_variant = hex_fingerprint(&attribution.source_build_variant_fingerprint)?;
            let members = rows
                .clone_fragments
                .iter()
                .filter(|fragment| {
                    fragment.clone_group_fingerprint == group_fingerprint
                        && fragment.build_variant_fingerprint == source_variant
                        && !fragment.is_canonical
                })
                .map(|fragment| fragment.finding_id)
                .collect::<BTreeSet<_>>();
            let artifact_variants = rows
                .mappings
                .iter()
                .filter(|mapping| {
                    mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
                        && mapping.source_build_variant_fingerprint == source_variant
                        && members.contains(&mapping.source_instance_fingerprint)
                        && mapping.attributed_bytes.is_some()
                })
                .map(|mapping| mapping.build_variant_fingerprint)
                .collect::<BTreeSet<_>>();
            let mut artifact_variants = artifact_variants.into_iter();
            let artifact_variant = artifact_variants.next()?;
            if artifact_variants.next().is_some() {
                return None;
            }
            let estimated_refactor_savings_bytes = EstimatedRefactorSavingsBytes(
                estimate_refactor_savings_bytes(duplicated_bytes, members.len(), &model),
            );
            Some(CloneGroupSavingsReport {
                clone_group_fingerprint: attribution.clone_group_fingerprint,
                source_build_variant_fingerprint: attribution.source_build_variant_fingerprint,
                artifact_build_variant_fingerprint: fingerprint_hex(artifact_variant),
                duplicated_bytes,
                estimated_refactor_savings_bytes,
                mapping_confidence: EvidenceConfidence::High,
                clone_confidence: attribution.clone_confidence,
                model_confidence: model.confidence,
                savings_confidence: model.confidence,
                assumptions: model.assumptions.clone(),
                model_schema_version: model.schema_version,
            })
        })
        .collect()
}

pub(super) fn estimate_refactor_savings_bytes(
    duplicated_bytes: u64,
    replaced_members: usize,
    model: &RefactorSavingsModel,
) -> i64 {
    let replaced_members = i128::try_from(replaced_members).unwrap_or(i128::MAX);
    let estimate = i128::from(duplicated_bytes).saturating_sub(
        i128::from(model.call_overhead_per_replaced_member_bytes).saturating_mul(replaced_members),
    );
    match i64::try_from(estimate) {
        Ok(value) => value,
        Err(_) if estimate.is_negative() => i64::MIN,
        Err(_) => i64::MAX,
    }
}

pub(super) fn hex_fingerprint(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

pub(super) fn generic_origin_metrics(
    artifact: &ArtifactIr,
    fingerprints: &BTreeSet<[u8; 16]>,
    retained_sizes: Option<&[metrics::RetainedSize]>,
) -> (u64, u64, Option<u64>) {
    let symbols: Vec<_> = artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .collect();
    let observed_symbol_bytes = symbols
        .iter()
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add);
    let mut normalized_groups: BTreeMap<(&str, &[u8]), Vec<u64>> = BTreeMap::new();
    for symbol in &symbols {
        if let Some(normalized) = &symbol.normalized {
            normalized_groups
                .entry((normalized.version.as_str(), normalized.bytes.as_slice()))
                .or_default()
                .push(symbol.size);
        }
    }
    let normalized_instruction_duplicated_bytes = normalized_groups
        .into_values()
        .filter(|sizes| sizes.len() > 1)
        .map(|sizes| {
            let total = sizes.iter().copied().fold(0_u64, u64::saturating_add);
            total.saturating_sub(sizes.into_iter().max().unwrap_or_default())
        })
        .fold(0_u64, u64::saturating_add);
    let retained_size_sum = retained_sizes.map(|sizes| {
        sizes
            .iter()
            .filter(|size| fingerprints.contains(&size.symbol.as_bytes()))
            .map(|size| size.retained_bytes)
            .fold(0_u64, u64::saturating_add)
    });
    (
        observed_symbol_bytes,
        normalized_instruction_duplicated_bytes,
        retained_size_sum,
    )
}

pub(super) fn observed_symbol_bytes_for(
    artifact: &ArtifactIr,
    fingerprints: &BTreeSet<[u8; 16]>,
) -> u64 {
    artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add)
}

pub(super) fn generic_type_arguments(instantiation_key: &str) -> Vec<String> {
    let Some(start) = instantiation_key.find('<') else {
        return Vec::new();
    };
    let Some(arguments) = instantiation_key
        .strip_suffix('>')
        .and_then(|key| key.get(start + 1..))
    else {
        return Vec::new();
    };
    let mut depth = 0_u32;
    let mut arguments_out = Vec::new();
    let mut argument_start = 0;
    for (index, character) in arguments.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return Vec::new(),
            },
            ',' if depth == 0 => {
                let argument = arguments[argument_start..index].trim();
                if argument.is_empty() {
                    return Vec::new();
                }
                arguments_out.push(argument.to_owned());
                argument_start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Vec::new();
    }
    let argument = arguments[argument_start..].trim();
    if argument.is_empty() {
        return Vec::new();
    }
    arguments_out.push(argument.to_owned());
    arguments_out
}

const fn unmapped_reason_label(reason: ArtifactAnalysisUnmappedReason) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedReason::DebugInfoMissing => "debug_info_missing",
        ArtifactAnalysisUnmappedReason::Stripped => "stripped",
        ArtifactAnalysisUnmappedReason::DemangleFailed => "demangle_failed",
        ArtifactAnalysisUnmappedReason::OutsideSourceScope => "outside_source_scope",
        ArtifactAnalysisUnmappedReason::EvidenceConflict => "evidence_conflict",
    }
}

const fn unmapped_source_reason_label(
    reason: ArtifactAnalysisUnmappedSourceReason,
) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence => "no_artifact_evidence",
        ArtifactAnalysisUnmappedSourceReason::DeadCode => "dead_code",
        ArtifactAnalysisUnmappedSourceReason::InlinedAway => "inlined_away",
        ArtifactAnalysisUnmappedSourceReason::LtoAbsorbed => "lto_absorbed",
        ArtifactAnalysisUnmappedSourceReason::NotCompiledForVariant => "not_compiled_for_variant",
        ArtifactAnalysisUnmappedSourceReason::EvidenceConflict => "evidence_conflict",
    }
}

const fn source_kind_order(kind: ArtifactAnalysisSourceKind) -> u8 {
    match kind {
        ArtifactAnalysisSourceKind::Unit => 0,
        ArtifactAnalysisSourceKind::Fragment => 1,
    }
}

pub(super) fn ratio(numerator: usize, denominator: usize) -> f64 {
    ratio_u64(
        u64::try_from(numerator).unwrap_or(u64::MAX),
        u64::try_from(denominator).unwrap_or(u64::MAX),
    )
}

pub(super) fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
    ratio_u128(u128::from(numerator), u128::from(denominator))
}

pub(super) fn ratio_u128(numerator: u128, denominator: u128) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        const BASIS_POINTS_PER_UNIT: u128 = 10_000;
        let basis_points = numerator
            .saturating_mul(BASIS_POINTS_PER_UNIT)
            .checked_div(denominator)
            .unwrap_or(BASIS_POINTS_PER_UNIT)
            .min(BASIS_POINTS_PER_UNIT);
        let basis_points = u32::try_from(basis_points).unwrap_or(10_000);
        f64::from(basis_points) / 10_000.0
    }
}

pub(in crate::artifact) mod mapping;

use mapping::generic_origin_fingerprint;
pub(super) use mapping::{correlate_source_run, read_linker_map};

pub(in crate::artifact) mod matching;
