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
use codehelion_core::stable_id::CloneGroupFingerprint;
use codehelion_store::artifact::ArtifactAnalysisMappingConfidence;

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

/// Every byte count a report states about one clone group inside an artifact.
///
/// The clone-group population of [`metrics::ReportedSize`]. Kept apart from
/// the artifact-wide categories because the two count over different things:
/// one number is about a binary, the other about a set of members inside it,
/// and a list holding both would let either be read as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupSizeCategory {
    /// Bytes attributable to the noncanonical members, every share observed.
    Duplicated,
    /// The same total when at least one share was divided by source lines.
    EstimatedDuplicated,
    /// Observed size of the symbols holding the members.
    ContainingSymbols,
}

impl metrics::ReportedSize for GroupSizeCategory {
    fn key(self) -> &'static str {
        match self {
            Self::Duplicated => "duplicated_bytes",
            Self::EstimatedDuplicated => "estimated_duplicated_bytes",
            Self::ContainingSymbols => "containing_symbol_bytes",
        }
    }

    fn scope(self) -> metrics::EvidenceScope {
        match self {
            Self::Duplicated => metrics::EvidenceScope::Duplicated,
            Self::EstimatedDuplicated => metrics::EvidenceScope::Estimated,
            // A symbol holds its members and is usually larger than them, so
            // its size bounds what the group occupies rather than measuring it.
            Self::ContainingSymbols => metrics::EvidenceScope::UpperBound,
        }
    }
}

impl GroupSizeCategory {
    /// Every category, in the order a report states them.
    pub(super) const fn all() -> &'static [Self] {
        &[
            Self::Duplicated,
            Self::EstimatedDuplicated,
            Self::ContainingSymbols,
        ]
    }
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
    /// Observed bytes attributable to all noncanonical members, when every one
    /// of those members covers its whole artifact symbol.
    ///
    /// This is an attribution observation, not an estimated refactoring saving.
    /// A member whose share was divided across a symbol's source lines carries
    /// no observation of its own bytes, so one such member leaves this absent
    /// and moves the group's total to [`Self::estimated_duplicated_bytes`].
    pub(super) duplicated_bytes: Option<u64>,
    /// Bytes attributed to all noncanonical members when at least one share was
    /// divided by source lines.
    ///
    /// Line-proportional division is a construction, not a measurement: the
    /// lines say which fragment wrote a symbol, never how many of its bytes
    /// each line became. The value is therefore reported apart from the
    /// observed bucket and never added to it.
    pub(super) estimated_duplicated_bytes: Option<u64>,
    /// Distinct artifact symbols the group's noncanonical members were placed
    /// in, however the correspondence was established.
    ///
    /// A format that carries symbol names but no line frames — a WebAssembly
    /// name section is the common one — settles which symbol holds a member and
    /// nothing finer. Naming the symbols is what such a format can honestly
    /// say, so it is said instead of reporting the group as unreached.
    pub(super) containing_symbols: usize,
    /// Observed size of those symbols, summed once per symbol.
    ///
    /// This is the size of the code the members are part of, not the size of
    /// the members: a member sits inside its symbol and is usually smaller than
    /// it, and two members in one symbol are counted once. It is therefore an
    /// upper bound on what the group occupies and never a duplicated-byte
    /// total, which is why it stays out of [`Self::duplicated_bytes`] and
    /// [`Self::estimated_duplicated_bytes`] rather than filling in for either.
    pub(super) containing_symbol_bytes: Option<u64>,
    /// Source clone score kept separate from mapping and model confidence.
    pub(super) clone_confidence: f64,
}

impl CloneGroupAttributionReport {
    /// Every byte count this attribution states, with the value it holds.
    ///
    /// `None` is "the evidence for this is not there", never zero. Taken apart
    /// exhaustively, so a count added to [`GroupSizeCategory`] stops this
    /// compiling until it says where its number comes from, and every
    /// rendering takes its numbers from here.
    pub(super) fn stated(&self) -> Vec<(GroupSizeCategory, Option<u64>)> {
        GroupSizeCategory::all()
            .iter()
            .copied()
            .map(|category| {
                let bytes = match category {
                    GroupSizeCategory::Duplicated => self.duplicated_bytes,
                    GroupSizeCategory::EstimatedDuplicated => self.estimated_duplicated_bytes,
                    GroupSizeCategory::ContainingSymbols => self.containing_symbol_bytes,
                };
                (category, bytes)
            })
            .collect()
    }
}

/// One source unit the artifact emitted as more than one body.
///
/// Source copies and emitted bodies are different populations. A generic
/// written once is emitted once per instantiation, and a lambda passed to it
/// makes each instantiation a distinct type, so a single source copy can carry
/// a multiple of its own size in the artifact. Consolidating that one copy
/// removes no bodies at all, and the duplicate counts this tool is built on
/// cannot express the difference because there is only ever one copy to count.
///
/// This states the fan-out of the correspondence already established: how many
/// distinct artifact symbols one source unit was mapped to. It needs no
/// template analysis and no debug line information — only that the mapping
/// named a single source unit, so it is available wherever symbol names are.
///
/// Every number here is an observation about the artifact as it stands. None of
/// them is a saving: the bytes are what the artifact spends on this unit today,
/// and whether any of them can be removed is not a question this can answer.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MultiplyEmittedUnitReport {
    /// Content-derived stable identity of the source unit, as `explain` takes.
    pub(super) source_fingerprint: String,
    /// Build variant that minted the source identity.
    pub(super) source_build_variant_fingerprint: String,
    /// Symbol spelling the correspondence matched on, kept as display evidence.
    pub(super) name: Option<String>,
    /// Distinct artifact symbols this one source unit was mapped to.
    pub(super) emitted_bodies: usize,
    /// Observed sizes of those symbols, summed.
    pub(super) observed_symbol_bytes: u64,
    /// Weakest grade among the mappings counted, so a reader can tell a
    /// name-only correspondence from a debug-located one.
    pub(super) mapping_confidence: EvidenceConfidence,
}

/// Versioned, deliberately conservative refactoring-cost assumptions.
///
/// Every coefficient here is one the estimate arithmetic reads. A coefficient
/// the report states but never spends would let an edit move the stated model
/// without moving the number derived from it.
#[derive(Debug, Clone, Serialize)]
pub(super) struct RefactorSavingsModel {
    pub(super) schema_version: &'static str,
    pub(super) call_overhead_per_replaced_member_bytes: i64,
    pub(super) assumptions: Vec<RefactorSavingsAssumption>,
    pub(super) confidence: EvidenceConfidence,
}

/// One versioned model row. Keeping the coefficients here makes changing a
/// model an explicit data/version change instead of a hidden arithmetic edit.
#[derive(Debug, Clone, Copy)]
pub(super) struct RefactorSavingsModelSpec {
    pub(super) schema_version: &'static str,
    pub(super) call_overhead_per_replaced_member_bytes: i64,
    pub(super) assumptions: &'static [RefactorSavingsAssumptionSpec],
    pub(super) confidence: EvidenceConfidence,
}

/// Serializable assumptions have a compact static-table counterpart.
///
/// A variant that restates a model coefficient carries no value of its own:
/// it is filled from the coefficient the estimate spends, so the two cannot be
/// edited apart.
#[derive(Debug, Clone, Copy)]
pub(super) enum RefactorSavingsAssumptionSpec {
    /// The estimate is built from the bytes of the noncanonical members alone,
    /// so this many implementations survive the merge it describes.
    SharedImplementationRetainsCopies {
        copies: u64,
    },
    CallOverheadPerReplacedMember,
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
}

const REFACTOR_SAVINGS_MODELS: &[RefactorSavingsModelSpec] = &[RefactorSavingsModelSpec {
    schema_version: "refactor-savings-model-v1",
    call_overhead_per_replaced_member_bytes: 0,
    assumptions: &[
        RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies: 1 },
        RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember,
        RefactorSavingsAssumptionSpec::InliningOutcomeUnknown,
        RefactorSavingsAssumptionSpec::LinkerIcfOutcomeUnknown,
    ],
    confidence: EvidenceConfidence::Low,
}];

/// A machine-readable condition behind one refactoring estimate.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum RefactorSavingsAssumption {
    SharedImplementationRetainsCopies {
        copies: u64,
    },
    CallOverheadPerReplacedMember {
        bytes: i64,
    },
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
    /// At least one member's bytes were divided across the source lines of its
    /// artifact symbol rather than observed for the member alone.
    AttributionIsLineProportional,
}

/// Which evidence established the bytes one estimate was derived from.
///
/// The number alone cannot say this, and the two are not interchangeable: one
/// is a measurement of a member's own bytes, the other a division of a symbol's
/// bytes across its source lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AttributionBasis {
    /// Every contributing member covered its whole artifact symbol.
    Observed,
    /// At least one member's share was divided across its symbol's source lines.
    LineProportional,
}

impl AttributionBasis {
    /// Whether these bytes were divided rather than observed.
    pub(super) const fn is_estimated(self) -> bool {
        matches!(self, Self::LineProportional)
    }
}

/// A source/artifact-correlated refactoring estimate for one clone group.
#[derive(Debug, Clone, Serialize)]
pub(super) struct CloneGroupSavingsReport {
    pub(super) clone_group_fingerprint: String,
    pub(super) source_build_variant_fingerprint: String,
    pub(super) artifact_build_variant_fingerprint: String,
    pub(super) duplicated_bytes: u64,
    /// Evidence class of [`Self::duplicated_bytes`], so a reader never has to
    /// infer from the model assumptions whether the number was measured.
    pub(super) duplicated_bytes_basis: AttributionBasis,
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

pub(super) fn clone_group_attributions(
    artifact: &ArtifactIr,
    rows: &CorrelationRows,
) -> Vec<CloneGroupAttributionReport> {
    attributed_groups(rows)
        .into_iter()
        .map(|group| {
            let (containing_symbols, containing_bytes) =
                resolved_symbols(artifact, &group.containing);
            CloneGroupAttributionReport {
                clone_group_fingerprint: group.clone_group_fingerprint,
                source_build_variant_fingerprint: group.source_build_variant_fingerprint,
                members: group.members,
                attributed_noncanonical_members: group.attributed_noncanonical_members,
                duplicated_bytes: group.duplicated_bytes,
                estimated_duplicated_bytes: group.estimated_duplicated_bytes,
                containing_symbols,
                containing_symbol_bytes: (containing_symbols > 0).then_some(containing_bytes),
                clone_confidence: group.clone_confidence,
            }
        })
        .collect()
}

/// How many of `fingerprints` this artifact holds, and how many bytes they are.
///
/// A mapping names a symbol of the artifact it was established against, so the
/// names are resolved here rather than counted where they were collected: a
/// report otherwise states a population that the artifact in hand may not
/// contain, and a size of zero would read as a measurement rather than as an
/// absence.
fn resolved_symbols(artifact: &ArtifactIr, fingerprints: &BTreeSet<[u8; 16]>) -> (usize, u64) {
    artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .fold((0, 0_u64), |(count, bytes), symbol| {
            (count + 1, bytes.saturating_add(symbol.size))
        })
}

/// One group's byte attribution, settled before the artifact is consulted.
///
/// The refactoring estimate is built from these numbers and from nothing the
/// artifact supplies. Keeping the two apart is what stops a symbol size from
/// reaching an estimate whose published model does not mention one; the symbols
/// a group sits in travel alongside as [`Self::containing`] and are resolved to
/// bytes only where they are reported as containment.
struct AttributedGroup {
    clone_group_fingerprint: String,
    source_build_variant_fingerprint: String,
    members: usize,
    attributed_noncanonical_members: usize,
    duplicated_bytes: Option<u64>,
    estimated_duplicated_bytes: Option<u64>,
    containing: BTreeSet<[u8; 16]>,
    clone_confidence: f64,
}

fn attributed_groups(rows: &CorrelationRows) -> Vec<AttributedGroup> {
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
            // The canonical member is the copy this accounting keeps rather
            // than counts as duplicated. The writer nominates it from content,
            // so reading its mark here attributes the same bytes to the same
            // occurrence however the scan reached the group's members.
            let noncanonical = members
                .iter()
                .filter(|member| !member.is_canonical)
                .map(|member| *member.finding_id.as_bytes())
                .collect::<BTreeSet<_>>();
            let mut bytes_by_member: BTreeMap<[u8; 16], MemberAttribution> = BTreeMap::new();
            // Where the members sit, which a format without line frames can
            // still settle, is collected beside the bytes they were charged,
            // which only line frames establish. A symbol enters this set once
            // however many members it holds.
            let mut containing: BTreeSet<[u8; 16]> = BTreeSet::new();
            for mapping in group_mappings(rows, source_variant, &noncanonical) {
                if places_one_source_unit(mapping) {
                    containing.insert(mapping.artifact_symbol_fingerprint);
                }
                if let Some(bytes) = mapping.attributed_bytes {
                    let member = bytes_by_member
                        .entry(mapping.source_instance_fingerprint)
                        .or_default();
                    member.total = member.total.saturating_add(bytes);
                    member.whole_symbol_only &= mapping
                        .evidence
                        .attribution_is_whole_symbol()
                        .unwrap_or(false);
                }
            }
            let attributed_noncanonical_members = bytes_by_member.len();
            let complete = attributed_noncanonical_members == noncanonical.len();
            let total = || {
                bytes_by_member
                    .values()
                    .map(|member| member.total)
                    .fold(0_u64, u64::saturating_add)
            };
            let whole_symbol_only = bytes_by_member
                .values()
                .all(|member| member.whole_symbol_only);
            AttributedGroup {
                clone_group_fingerprint: fingerprint_hex(*group_fingerprint.as_bytes()),
                source_build_variant_fingerprint: fingerprint_hex(source_variant),
                members: members.len(),
                attributed_noncanonical_members,
                duplicated_bytes: (complete && whole_symbol_only).then(total),
                estimated_duplicated_bytes: (complete && !whole_symbol_only).then(total),
                containing,
                clone_confidence: members
                    .first()
                    .map_or(0.0, |member| member.clone_confidence),
            }
        })
        .collect()
}

/// Bytes attributed to one noncanonical member, with the evidence class that
/// established them.
#[derive(Debug)]
struct MemberAttribution {
    total: u64,
    whole_symbol_only: bool,
}

impl Default for MemberAttribution {
    fn default() -> Self {
        Self {
            total: 0,
            whole_symbol_only: true,
        }
    }
}

/// Whether this mapping settles the one source unit its symbol came from.
///
/// Both the fan-out count and the containment set answer "which source unit is
/// this symbol", so both need a mapping that named exactly one. An ambiguous
/// mapping named several and chose none: counting it would raise the fan-out of
/// every candidate at once, and would place a group in a symbol that may belong
/// to a different one. Evidence that no longer grades — an unknown schema, a
/// stale recipe version — settles nothing either.
fn places_one_source_unit(mapping: &ArtifactAnalysisMapping) -> bool {
    !matches!(
        mapping.evidence.confidence(),
        None | Some(ArtifactAnalysisMappingConfidence::Ambiguous)
    )
}

/// Source units the artifact emitted as more than one body, widest first.
///
/// The population is whole source units: a fragment is part of a unit, and the
/// question here is how many times a unit was emitted, not how many times a
/// stretch inside one was.
pub(super) fn multiply_emitted_units(
    artifact: &ArtifactIr,
    rows: &CorrelationRows,
) -> Vec<MultiplyEmittedUnitReport> {
    let mut units: BTreeMap<([u8; 16], [u8; 16]), MultiplyEmittedUnit> = BTreeMap::new();
    for mapping in &rows.mappings {
        if mapping.source_kind != ArtifactAnalysisSourceKind::Unit
            || !places_one_source_unit(mapping)
        {
            continue;
        }
        let unit = units
            .entry((
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            ))
            .or_insert_with(|| MultiplyEmittedUnit {
                content: mapping.source_fingerprint,
                name: None,
                symbols: BTreeSet::new(),
                weakest: None,
            });
        unit.symbols.insert(mapping.artifact_symbol_fingerprint);
        // The grade is folded in as each mapping is seen. Asking again per unit
        // afterwards would walk every mapping once for every unit reported,
        // which is the cost of the whole correlation multiplied by the number
        // of units a large artifact repeats.
        unit.weakest = weaker_of(unit.weakest, mapping_grade(mapping));
        if unit.name.is_none() {
            unit.name = mapping.evidence.facts.iter().find_map(|fact| match fact {
                MappingEvidenceFact::SymbolName { source_symbol, .. } => {
                    Some(source_symbol.clone())
                }
                _ => None,
            });
        }
    }
    let mut reports: Vec<_> = units
        .into_iter()
        .filter_map(|((_, variant), unit)| {
            let (emitted_bodies, observed_symbol_bytes) = resolved_symbols(artifact, &unit.symbols);
            // One body is a unit emitted the way reading the source suggests,
            // and there are as many of those as there are functions. Only a
            // unit the artifact repeated says something the source did not.
            (emitted_bodies > 1).then(|| MultiplyEmittedUnitReport {
                source_fingerprint: fingerprint_hex(unit.content),
                source_build_variant_fingerprint: fingerprint_hex(variant),
                name: unit.name,
                emitted_bodies,
                observed_symbol_bytes,
                mapping_confidence: unit.weakest.unwrap_or(EvidenceConfidence::Unavailable),
            })
        })
        .collect();
    reports.sort_by(|left, right| {
        right
            .observed_symbol_bytes
            .cmp(&left.observed_symbol_bytes)
            .then_with(|| right.emitted_bodies.cmp(&left.emitted_bodies))
            .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
            .then_with(|| {
                left.source_build_variant_fingerprint
                    .cmp(&right.source_build_variant_fingerprint)
            })
    });
    reports
}

/// Symbols and display evidence accumulated for one source unit occurrence.
struct MultiplyEmittedUnit {
    content: [u8; 16],
    name: Option<String>,
    symbols: BTreeSet<[u8; 16]>,
    weakest: Option<EvidenceConfidence>,
}

/// The grade one mapping's evidence carries, on the scale a report states.
///
/// This is the same reading [`weakest_mapping_confidence`] takes over a whole
/// row set; it is spelled once here so a running fold and that function cannot
/// come to describe the same evidence differently.
fn mapping_grade(mapping: &ArtifactAnalysisMapping) -> Option<EvidenceConfidence> {
    match mapping.evidence.confidence()? {
        ArtifactAnalysisMappingConfidence::Exact => Some(EvidenceConfidence::High),
        ArtifactAnalysisMappingConfidence::Strong => Some(EvidenceConfidence::Medium),
        ArtifactAnalysisMappingConfidence::Weak => Some(EvidenceConfidence::Low),
        ArtifactAnalysisMappingConfidence::Ambiguous => None,
    }
}

/// The lower of two grades, treating an absent one as nothing to lower to.
const fn weaker_of(
    current: Option<EvidenceConfidence>,
    next: Option<EvidenceConfidence>,
) -> Option<EvidenceConfidence> {
    match (current, next) {
        (Some(current), Some(next)) => {
            if confidence_strength(current) <= confidence_strength(next) {
                Some(current)
            } else {
                Some(next)
            }
        }
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Mappings whose attributed bytes belong to one group under one source variant.
fn group_mappings<'rows>(
    rows: &'rows CorrelationRows,
    source_variant: [u8; 16],
    noncanonical: &'rows BTreeSet<[u8; 16]>,
) -> impl Iterator<Item = &'rows ArtifactAnalysisMapping> + Clone {
    rows.mappings.iter().filter(move |mapping| {
        mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
            && mapping.source_build_variant_fingerprint == source_variant
            && noncanonical.contains(&mapping.source_instance_fingerprint)
    })
}

pub(super) fn refactor_savings_model() -> RefactorSavingsModel {
    let spec = REFACTOR_SAVINGS_MODELS
        .first()
        .copied()
        .unwrap_or(RefactorSavingsModelSpec {
            schema_version: "refactor-savings-model-unavailable",
            call_overhead_per_replaced_member_bytes: 0,
            assumptions: &[],
            confidence: EvidenceConfidence::Unavailable,
        });
    RefactorSavingsModel {
        schema_version: spec.schema_version,
        call_overhead_per_replaced_member_bytes: spec.call_overhead_per_replaced_member_bytes,
        assumptions: spec
            .assumptions
            .iter()
            .map(|assumption| match assumption {
                RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies } => {
                    RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies: *copies }
                }
                RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember => {
                    RefactorSavingsAssumption::CallOverheadPerReplacedMember {
                        bytes: spec.call_overhead_per_replaced_member_bytes,
                    }
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
    attributed_groups(rows)
        .into_iter()
        .filter_map(|attribution| {
            let basis = if attribution.duplicated_bytes.is_some() {
                AttributionBasis::Observed
            } else {
                AttributionBasis::LineProportional
            };
            let duplicated_bytes = attribution
                .duplicated_bytes
                .or(attribution.estimated_duplicated_bytes)?;
            let group_fingerprint = CloneGroupFingerprint::from_bytes(hex_fingerprint(
                &attribution.clone_group_fingerprint,
            )?);
            let source_variant = hex_fingerprint(&attribution.source_build_variant_fingerprint)?;
            let members = rows
                .clone_fragments
                .iter()
                .filter(|fragment| {
                    fragment.clone_group_fingerprint == group_fingerprint
                        && fragment.build_variant_fingerprint == source_variant
                        && !fragment.is_canonical
                })
                .map(|fragment| *fragment.finding_id.as_bytes())
                .collect::<BTreeSet<_>>();
            let contributing = group_mappings(rows, source_variant, &members)
                .filter(|mapping| mapping.attributed_bytes.is_some());
            let artifact_variants = contributing
                .clone()
                .map(|mapping| mapping.build_variant_fingerprint)
                .collect::<BTreeSet<_>>();
            let mut artifact_variants = artifact_variants.into_iter();
            let artifact_variant = artifact_variants.next()?;
            if artifact_variants.next().is_some() {
                return None;
            }
            let mapping_confidence = weakest_mapping_confidence(contributing)?;
            let estimated_refactor_savings_bytes = EstimatedRefactorSavingsBytes(
                estimate_refactor_savings_bytes(duplicated_bytes, members.len(), &model),
            );
            let mut assumptions = model.assumptions.clone();
            if basis.is_estimated() {
                assumptions.push(RefactorSavingsAssumption::AttributionIsLineProportional);
            }
            Some(CloneGroupSavingsReport {
                clone_group_fingerprint: attribution.clone_group_fingerprint,
                source_build_variant_fingerprint: attribution.source_build_variant_fingerprint,
                artifact_build_variant_fingerprint: fingerprint_hex(artifact_variant),
                duplicated_bytes,
                duplicated_bytes_basis: basis,
                estimated_refactor_savings_bytes,
                mapping_confidence,
                clone_confidence: attribution.clone_confidence,
                model_confidence: model.confidence,
                savings_confidence: model.confidence,
                assumptions,
                model_schema_version: model.schema_version,
            })
        })
        .collect()
}

/// Grade one savings row by the weakest mapping that contributed bytes to it.
///
/// A row that reports the strongest grade its correlation reached would say
/// the same thing for a group whose bytes were split exactly and for one whose
/// bytes were divided by source lines, and the two are not the same evidence.
/// A contributing mapping that is ambiguous or unusable removes the row: no
/// grade describes bytes attributed to a candidate that was never chosen.
fn weakest_mapping_confidence<'rows>(
    mappings: impl Iterator<Item = &'rows ArtifactAnalysisMapping>,
) -> Option<EvidenceConfidence> {
    let mut weakest: Option<EvidenceConfidence> = None;
    for mapping in mappings {
        // An ambiguous or ungradable mapping removes the row outright, which is
        // what the `?` does: no grade describes bytes attributed to a candidate
        // that was never chosen.
        weakest = weaker_of(weakest, Some(mapping_grade(mapping)?));
    }
    weakest
}

/// Rank of one confidence grade, highest grade last.
const fn confidence_strength(confidence: EvidenceConfidence) -> u8 {
    match confidence {
        EvidenceConfidence::Unavailable => 0,
        EvidenceConfidence::Low => 1,
        EvidenceConfidence::Medium => 2,
        EvidenceConfidence::High => 3,
    }
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
        ArtifactAnalysisUnmappedReason::DebugInfoUnreadable => "debug_info_unreadable",
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

pub(in crate::artifact) const fn source_kind_order(kind: ArtifactAnalysisSourceKind) -> u8 {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A model row states the coefficients its estimate spends, and only those.
    ///
    /// A stated coefficient the arithmetic never reads would move on its own
    /// when the row is edited, so what a reader reads and what the estimate
    /// returns would drift apart without either one looking wrong.
    #[test]
    fn every_stated_model_coefficient_reaches_the_estimate() {
        let mut model = refactor_savings_model();

        let stated = model
            .assumptions
            .iter()
            .find_map(|assumption| match assumption {
                RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes } => Some(*bytes),
                _ => None,
            })
            .expect("the model states its call overhead");
        assert_eq!(stated, model.call_overhead_per_replaced_member_bytes);

        let baseline = estimate_refactor_savings_bytes(100, 3, &model);
        assert_eq!(baseline, 100 - stated * 3);
        model.call_overhead_per_replaced_member_bytes = stated + 4;
        assert_eq!(
            estimate_refactor_savings_bytes(100, 3, &model),
            baseline - 12,
            "editing the coefficient moves the estimate it is stated for"
        );
    }

    /// The retained-copy count is declared once, by the assumption that reports
    /// it, because the estimate's input already excludes exactly those copies.
    #[test]
    fn the_retained_copy_count_is_declared_once() {
        let model = refactor_savings_model();

        let declared: Vec<_> = model
            .assumptions
            .iter()
            .filter_map(|assumption| match assumption {
                RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies } => {
                    Some(*copies)
                }
                _ => None,
            })
            .collect();

        assert_eq!(declared, vec![1]);
    }
}
