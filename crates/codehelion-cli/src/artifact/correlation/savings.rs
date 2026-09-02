//! Versioned refactoring-savings models and per-clone-group estimates.

use codehelion_core::stable_id::CloneGroupFingerprint;

use super::CorrelationRows;
use super::attribution::{attributed_groups, group_mappings, mapping_grade, weaker_of};
use super::ratio::{hex_build_variant, hex_fingerprint};
use crate::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisMapping, ArtifactAnalysisSavingsConfidence, BTreeSet, Context,
    EstimatedRefactorSavingsBytes, EvidenceConfidence, Result, Serialize, fingerprint_hex, metrics,
};

/// Every byte count a report states about one clone group inside an artifact.
///
/// The clone-group population of [`metrics::ReportedSize`]. Kept apart from
/// the artifact-wide categories because the two count over different things:
/// one number is about a binary, the other about a set of members inside it,
/// and a list holding both would let either be read as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::artifact) enum GroupSizeCategory {
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
    pub(in crate::artifact) const fn all() -> &'static [Self] {
        &[
            Self::Duplicated,
            Self::EstimatedDuplicated,
            Self::ContainingSymbols,
        ]
    }
}

/// Versioned, deliberately conservative refactoring-cost assumptions.
///
/// Every coefficient here is one the estimate arithmetic reads. A coefficient
/// the report states but never spends would let an edit move the stated model
/// without moving the number derived from it.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct RefactorSavingsModel {
    pub(in crate::artifact) schema_version: &'static str,
    pub(in crate::artifact) call_overhead_per_replaced_member_bytes: i64,
    pub(in crate::artifact) assumptions: Vec<RefactorSavingsAssumption>,
    pub(in crate::artifact) confidence: EvidenceConfidence,
}

/// One versioned model row. Keeping the coefficients here makes changing a
/// model an explicit data/version change instead of a hidden arithmetic edit.
#[derive(Debug, Clone, Copy)]
pub(in crate::artifact) struct RefactorSavingsModelSpec {
    pub(in crate::artifact) schema_version: &'static str,
    pub(in crate::artifact) call_overhead_per_replaced_member_bytes: i64,
    pub(in crate::artifact) assumptions: &'static [RefactorSavingsAssumptionSpec],
    pub(in crate::artifact) confidence: EvidenceConfidence,
}

/// Serializable assumptions have a compact static-table counterpart.
///
/// A variant that restates a model coefficient carries no value of its own:
/// it is filled from the coefficient the estimate spends, so the two cannot be
/// edited apart.
#[derive(Debug, Clone, Copy)]
pub(in crate::artifact) enum RefactorSavingsAssumptionSpec {
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
pub(in crate::artifact) enum RefactorSavingsAssumption {
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
pub(in crate::artifact) enum AttributionBasis {
    /// Every contributing member covered its whole artifact symbol.
    Observed,
    /// At least one member's share was divided across its symbol's source lines.
    LineProportional,
}

impl AttributionBasis {
    /// Whether these bytes were divided rather than observed.
    pub(in crate::artifact) const fn is_estimated(self) -> bool {
        matches!(self, Self::LineProportional)
    }
}

/// A source/artifact-correlated refactoring estimate for one clone group.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct CloneGroupSavingsReport {
    pub(in crate::artifact) clone_group_fingerprint: String,
    pub(in crate::artifact) source_build_variant_fingerprint: String,
    pub(in crate::artifact) artifact_build_variant_fingerprint: String,
    pub(in crate::artifact) duplicated_bytes: u64,
    /// Evidence class of [`Self::duplicated_bytes`], so a reader never has to
    /// infer from the model assumptions whether the number was measured.
    pub(in crate::artifact) duplicated_bytes_basis: AttributionBasis,
    pub(in crate::artifact) estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes,
    pub(in crate::artifact) mapping_confidence: EvidenceConfidence,
    pub(in crate::artifact) clone_confidence: f64,
    pub(in crate::artifact) model_confidence: EvidenceConfidence,
    pub(in crate::artifact) savings_confidence: EvidenceConfidence,
    pub(in crate::artifact) assumptions: Vec<RefactorSavingsAssumption>,
    pub(in crate::artifact) model_schema_version: &'static str,
}

pub(in crate::artifact) fn stored_clone_group_savings(
    source_scan_run_id: i64,
    estimates: &[CloneGroupSavingsReport],
) -> Result<Vec<ArtifactAnalysisCloneGroupSavings>> {
    estimates
        .iter()
        .map(|estimate| {
            let clone_group_fingerprint = hex_fingerprint(&estimate.clone_group_fingerprint)
                .context("encoding clone-group savings fingerprint")?;
            let source_build_variant_fingerprint =
                hex_build_variant(&estimate.source_build_variant_fingerprint)
                    .context("encoding source savings build variant")?;
            let artifact_build_variant_fingerprint =
                hex_build_variant(&estimate.artifact_build_variant_fingerprint)
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

pub(in crate::artifact) fn refactor_savings_model() -> RefactorSavingsModel {
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

pub(in crate::artifact) fn clone_group_savings(
    rows: &CorrelationRows,
) -> Vec<CloneGroupSavingsReport> {
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
            let source_variant = hex_build_variant(&attribution.source_build_variant_fingerprint)?;
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
                artifact_build_variant_fingerprint: fingerprint_hex(artifact_variant.as_bytes()),
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
pub(super) const fn confidence_strength(confidence: EvidenceConfidence) -> u8 {
    match confidence {
        EvidenceConfidence::Unavailable => 0,
        EvidenceConfidence::Low => 1,
        EvidenceConfidence::Medium => 2,
        EvidenceConfidence::High => 3,
    }
}

pub(in crate::artifact) fn estimate_refactor_savings_bytes(
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
