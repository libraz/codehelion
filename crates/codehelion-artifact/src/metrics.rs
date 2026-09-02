//! Format-neutral duplicate grouping over [`ArtifactIr`].
//!
//! Exact and normalized equality are equivalence relations, so their groups
//! are keyed directly by content rather than by a transitive similarity graph.
//! Near-match grouping is deliberately a later operation: it must use the
//! source engine's complete-linkage policy instead of union-find.

mod callgraph;
mod duplicates;

use serde::{Deserialize, Serialize};

use crate::ArtifactIr;

pub use callgraph::{
    CallGraph, DeadCodeReport, LocalDispatch, RetainedSize, dead_code_candidates, local_dispatch,
    retained_sizes,
};
pub use duplicates::{
    DEFAULT_MIN_DUPLICATE_DATA_BYTES, DuplicateGroup, DuplicateMember, DuplicateReport,
    find_duplicate_data, find_duplicates,
};

/// A model-derived estimate of a refactoring's byte impact.
///
/// Estimates may be negative when required call overhead outweighs the
/// duplicate bytes attributed to the proposed refactoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EstimatedRefactorSavingsBytes(pub i64);

/// A before/after reduction verified for one controlled refactoring.
///
/// A verified change may be negative when the controlled change grows the
/// artifact, so it cannot be represented by an unsigned observed count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerifiedSavingsBytes(pub i64);

/// Size categories kept separate in artifact reports.
///
/// A `None` value means the current parser evidence cannot establish the
/// category. In particular, retained and shared-dependency sizes require a
/// resolved call graph, which not every format backend can provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeClassification {
    /// Complete byte length observed directly from the input.
    pub observed_bytes: u64,
    /// Excess bytes in exact duplicate code groups.
    pub duplicated_bytes: u64,
    /// Excess bytes in code groups that are equal only after normalization,
    /// when a normalizer exists for this architecture.
    ///
    /// Kept apart from [`Self::duplicated_bytes`] rather than added to it:
    /// normalized equality is reached through a rewriting rule, so it is
    /// weaker evidence than byte equality and cannot stand in the same
    /// column. It feeds no savings value for the same reason.
    pub duplicated_bytes_normalized: Option<u64>,
    /// Bytes retained by call-graph reachability, when calculated.
    pub retained_bytes: Option<u64>,
    /// Bytes shared by several dependency closures, when calculated.
    pub shared_dependency_bytes: Option<u64>,
    /// Excess bytes in exact duplicate data groups, when regions were
    /// independently established rather than inferred from whole sections.
    pub duplicated_data_bytes: Option<u64>,
    /// A theoretical maximum from directly observed exact duplication.
    ///
    /// This counts [`Self::duplicated_bytes`] alone: exact duplication among
    /// code symbols. Duplication that only normalization makes visible, and
    /// duplication among data segments, are deliberately outside it, so it is
    /// not an upper bound over everything this report calls duplicated.
    ///
    /// This is explicitly not a claim that a linker or refactoring can remove
    /// the bytes without changing behaviour or layout.
    pub upper_bound_savings_bytes: Option<u64>,
    /// A source-informed refactoring estimate, unavailable before mapping.
    pub estimated_refactor_savings_bytes: Option<EstimatedRefactorSavingsBytes>,
    /// A before/after measured reduction, unavailable for one artifact.
    pub verified_savings_bytes: Option<VerifiedSavingsBytes>,
    /// Confidence in the duplicate observation. Exact byte equality is a
    /// direct observation, while normalized equality stays separate in the
    /// duplicate report.
    pub clone_confidence: EvidenceConfidence,
    /// Confidence in a possible size reduction. This is unavailable before
    /// source mapping and a measured refactoring supply actual evidence.
    pub savings_confidence: EvidenceConfidence,
    /// Conditions and omissions that qualify the derived categories.
    pub assumptions: Vec<String>,
}

/// What a reported byte count is evidence of.
///
/// Six kinds, kept apart because a reader acts differently on each: a number
/// read off the input, a count of excess among things found equal, a total
/// reached by following call edges, a ceiling, a model output, and a
/// before/after measurement of a controlled change. Mixing any two of them
/// turns a number nobody measured into one a reader takes as measured, which
/// is the one way these categories have gone wrong.
///
/// Carried by [`ReportedSize`], so a byte count cannot be reported without
/// saying which of the six it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceScope {
    /// Read directly off the input.
    Observed,
    /// Excess among occurrences found equal, counting every copy past the one
    /// a reader would keep.
    Duplicated,
    /// A total reached by following the call edges the parser established.
    Retained,
    /// A ceiling on what something could occupy or free, and never a claim
    /// that it can be freed.
    UpperBound,
    /// A model output, derived rather than measured.
    Estimated,
    /// The difference between two artifacts that differ in one controlled way.
    Verified,
}

/// One kind of byte count a report states, whatever population it counts over.
///
/// Implemented once per population — the artifact as a whole, one clone group
/// inside it — because the two count different things and a single list of
/// them would let a value of one be read as a value of the other. What the
/// populations share is this: every category names itself and declares the
/// evidence behind it, so adding one is not possible without answering both.
pub trait ReportedSize: Copy {
    /// Field name under which every rendering states this category.
    fn key(self) -> &'static str;

    /// What the number is evidence of.
    fn scope(self) -> EvidenceScope;
}

/// Every byte count a report states about one artifact as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeCategory {
    /// The artifact's own length.
    Observed,
    /// Excess in byte-identical code groups.
    Duplicated,
    /// Excess in code groups equal only after normalization.
    DuplicatedNormalized,
    /// Bytes held by call-graph reachability.
    Retained,
    /// Bytes several dependency closures share.
    SharedDependency,
    /// Excess in byte-identical data groups.
    DuplicatedData,
    /// The ceiling built from directly observed exact duplication.
    UpperBoundSavings,
    /// A source-informed refactoring estimate.
    EstimatedRefactorSavings,
    /// A measured before/after reduction.
    VerifiedSavings,
}

impl ReportedSize for SizeCategory {
    fn key(self) -> &'static str {
        match self {
            Self::Observed => "observed_bytes",
            Self::Duplicated => "duplicated_bytes",
            Self::DuplicatedNormalized => "duplicated_bytes_normalized",
            Self::Retained => "retained_bytes",
            Self::SharedDependency => "shared_dependency_bytes",
            Self::DuplicatedData => "duplicated_data_bytes",
            Self::UpperBoundSavings => "upper_bound_savings_bytes",
            Self::EstimatedRefactorSavings => "estimated_refactor_savings_bytes",
            Self::VerifiedSavings => "verified_savings_bytes",
        }
    }

    fn scope(self) -> EvidenceScope {
        match self {
            Self::Observed => EvidenceScope::Observed,
            Self::Duplicated | Self::DuplicatedNormalized | Self::DuplicatedData => {
                EvidenceScope::Duplicated
            }
            Self::Retained | Self::SharedDependency => EvidenceScope::Retained,
            Self::UpperBoundSavings => EvidenceScope::UpperBound,
            Self::EstimatedRefactorSavings => EvidenceScope::Estimated,
            Self::VerifiedSavings => EvidenceScope::Verified,
        }
    }
}

impl SizeCategory {
    /// Every category, in the order a report states them.
    ///
    /// The list every rendering walks. A category left out of it would be one
    /// no reader ever sees, so [`SizeClassification::stated`] is built from
    /// this and nothing states its categories a second way.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Observed,
            Self::Duplicated,
            Self::DuplicatedNormalized,
            Self::Retained,
            Self::SharedDependency,
            Self::DuplicatedData,
            Self::UpperBoundSavings,
            Self::EstimatedRefactorSavings,
            Self::VerifiedSavings,
        ]
    }

    /// What a reader has to know about this number beyond its name, when
    /// there is such a thing.
    #[must_use]
    pub const fn qualification(self) -> Option<&'static str> {
        match self {
            Self::Duplicated => Some("byte-identical groups only"),
            Self::DuplicatedNormalized => Some("weaker evidence: equal after normalization"),
            Self::UpperBoundSavings => Some("duplicate code only; upper bound, not guaranteed"),
            Self::EstimatedRefactorSavings => {
                Some("per-clone-group estimates appear under source correlation")
            }
            Self::VerifiedSavings => Some("requires a controlled artifact compare calibration"),
            Self::Observed | Self::Retained | Self::SharedDependency | Self::DuplicatedData => None,
        }
    }
}

/// The duplication the upper bound is built from.
///
/// One list rather than a sentence about one: [`upper_bound_excludes`] derives
/// what is left out from it, so a duplicated category added later appears in
/// what a report says about the bound without anyone editing that sentence.
pub const UPPER_BOUND_COUNTS: &[SizeCategory] = &[SizeCategory::Duplicated];

/// The duplication the upper bound leaves out.
///
/// Every category counting duplication that [`UPPER_BOUND_COUNTS`] does not
/// take. Normalized equality is reached through a rewriting rule and duplicate
/// data is not code, so neither belongs in a bound over observed duplicate
/// code — but which categories those are is read off the list rather than
/// written down twice.
#[must_use]
pub fn upper_bound_excludes() -> Vec<SizeCategory> {
    SizeCategory::all()
        .iter()
        .copied()
        .filter(|category| {
            category.scope() == EvidenceScope::Duplicated && !UPPER_BOUND_COUNTS.contains(category)
        })
        .collect()
}

impl SizeClassification {
    /// Every category this classification states, with the value it holds.
    ///
    /// `None` is "the evidence for this is not there", never zero. Taken apart
    /// exhaustively, so a category added to [`SizeCategory`] stops this
    /// compiling until it says where its number comes from — and every
    /// rendering walks this rather than listing the fields again.
    #[must_use]
    pub fn stated(&self) -> Vec<(SizeCategory, Option<i128>)> {
        SizeCategory::all()
            .iter()
            .copied()
            .map(|category| {
                let bytes = match category {
                    SizeCategory::Observed => Some(i128::from(self.observed_bytes)),
                    SizeCategory::Duplicated => Some(i128::from(self.duplicated_bytes)),
                    SizeCategory::DuplicatedNormalized => {
                        self.duplicated_bytes_normalized.map(i128::from)
                    }
                    SizeCategory::Retained => self.retained_bytes.map(i128::from),
                    SizeCategory::SharedDependency => self.shared_dependency_bytes.map(i128::from),
                    SizeCategory::DuplicatedData => self.duplicated_data_bytes.map(i128::from),
                    SizeCategory::UpperBoundSavings => {
                        self.upper_bound_savings_bytes.map(i128::from)
                    }
                    SizeCategory::EstimatedRefactorSavings => self
                        .estimated_refactor_savings_bytes
                        .map(|value| i128::from(value.0)),
                    SizeCategory::VerifiedSavings => {
                        self.verified_savings_bytes.map(|value| i128::from(value.0))
                    }
                };
                (category, bytes)
            })
            .collect()
    }
}

/// Evidence strength reported without turning an observation into a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceConfidence {
    /// Direct parser-observed facts establish the value.
    High,
    /// The result uses a conservative inference with known incompleteness.
    Medium,
    /// The result has substantial unresolved evidence.
    Low,
    /// The evidence necessary to calculate the value is absent.
    Unavailable,
}

/// Derive the size categories supported by the currently observed IR.
#[must_use]
pub fn classify_sizes(artifact: &ArtifactIr) -> SizeClassification {
    let duplicates = find_duplicates(artifact);
    let duplicate_data = find_duplicate_data(artifact, DEFAULT_MIN_DUPLICATE_DATA_BYTES);
    classify_sizes_from_duplicates(artifact, &duplicates, &duplicate_data)
}

/// Derive size categories while reusing duplicate groups already calculated
/// for another report surface.
///
/// This builds the local call graph for `artifact`. A caller that also asks
/// for [`dead_code_candidates`] or [`retained_sizes`] builds one
/// [`CallGraph`] instead and asks it for all three.
#[must_use]
pub fn classify_sizes_from_duplicates(
    artifact: &ArtifactIr,
    duplicates: &DuplicateReport,
    duplicate_data: &[DuplicateGroup],
) -> SizeClassification {
    CallGraph::from_ir(artifact).classify_sizes_from_duplicates(duplicates, duplicate_data)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        ArtifactDataSegment, ArtifactFingerprint, ArtifactFormat, ArtifactSymbol,
        NormalizedInstructions,
    };
    use proptest::prelude::*;

    /// One code symbol, shared by every test in this module tree.
    pub(super) fn symbol(offset: u64, code: &[u8], normalized: Option<&[u8]>) -> ArtifactSymbol {
        ArtifactSymbol {
            fingerprint: ArtifactFingerprint::from_content("test-symbol", &offset.to_le_bytes()),
            name: None,
            exported: false,
            section: Some(1),
            offset,
            size: code.len() as u64,
            size_inferred: false,
            code: code.to_vec(),
            normalized: normalized.map(|bytes| NormalizedInstructions {
                version: "test-normal-v1".to_owned(),
                bytes: bytes.to_vec(),
            }),
            // Grouping within one artifact reads the exact code bytes, which
            // are present here, rather than the cross-artifact body identity.
            body_fingerprint: None,
            inline_stack: Vec::new(),
        }
    }

    /// The size categories carry both duplicate totals, and the savings value
    /// stays built from the byte-identical one alone.
    ///
    /// A reader who came for size reads the categories and stops there, so a
    /// total that only appears in the duplicate listing above is a total they
    /// never see. Adding it into the upper bound instead would put an
    /// inference behind a number that says it is an observation.
    #[test]
    fn size_categories_carry_normalized_duplication_without_folding_it_into_savings() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.observed_bytes = 100;
        artifact.symbols = vec![
            symbol(30, &[1, 2], Some(&[9])),
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[1, 3], Some(&[9])),
            symbol(40, &[5], None),
        ];

        let duplicates = find_duplicates(&artifact);
        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.duplicated_bytes, duplicates.exact[0].duplicated_bytes);
        assert_eq!(
            sizes.duplicated_bytes_normalized,
            Some(duplicates.normalized[0].duplicated_bytes)
        );
        assert_eq!(
            sizes.upper_bound_savings_bytes,
            Some(sizes.duplicated_bytes),
            "the upper bound stays built from byte-identical duplication alone"
        );
        assert!(
            sizes
                .assumptions
                .iter()
                .any(|line| line == "duplicated_bytes counts byte-identical groups only"),
            "{:?}",
            sizes.assumptions
        );
    }

    /// Without a normalizer the total is absent rather than zero, and says so.
    #[test]
    fn normalized_duplication_is_unavailable_rather_than_zero_without_a_normalizer() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Elf, b"input");
        artifact.observed_bytes = 100;
        artifact.symbols = vec![
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[3, 4], Some(&[9])),
        ];

        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.duplicated_bytes_normalized, None);
        assert!(
            sizes.assumptions.iter().any(|line| line
                == "duplicated_bytes_normalized needs a normalizer for this architecture"),
            "{:?}",
            sizes.assumptions
        );
    }

    #[test]
    fn size_categories_separate_observed_data_and_unavailable_estimates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input bytes");
        artifact.capabilities.independent_data_segments = true;
        artifact.symbols = vec![symbol(10, &[1, 2, 3], None), symbol(20, &[1, 2, 3], None)];
        let bytes = vec![7; 16];
        artifact.data_segments = vec![
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"one"),
                section: None,
                offset: 100,
                bytes: bytes.clone(),
            },
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"two"),
                section: None,
                offset: 200,
                bytes,
            },
        ];
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.observed_bytes, 11);
        assert_eq!(sizes.duplicated_bytes, 3);
        assert_eq!(sizes.duplicated_data_bytes, Some(16));
        assert_eq!(sizes.upper_bound_savings_bytes, Some(3));
        assert!(sizes.estimated_refactor_savings_bytes.is_none());
        assert!(sizes.verified_savings_bytes.is_none());
        assert_eq!(sizes.clone_confidence, EvidenceConfidence::High);
        assert_eq!(sizes.savings_confidence, EvidenceConfidence::Unavailable);
        assert!(sizes.duplicated_bytes >= sizes.upper_bound_savings_bytes.unwrap_or(u64::MAX));
    }

    proptest! {
        #[test]
        fn size_categories_keep_exact_duplicate_bounds_for_disjoint_regions(
            lengths in prop::collection::vec(16_usize..128, 0..24),
        ) {
            let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"");
            artifact.capabilities.independent_data_segments = true;
            let mut offset = 0_u64;
            for (index, length) in lengths.iter().copied().enumerate() {
                let bytes = vec![u8::try_from(index).unwrap_or(u8::MAX); length];
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes: bytes.clone(),
                });
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes,
                });
                offset += length as u64;
            }
            artifact.observed_bytes = offset;
            let sizes = classify_sizes(&artifact);
            prop_assert!(sizes.duplicated_bytes <= sizes.observed_bytes);
            prop_assert!(sizes.duplicated_bytes_normalized.is_none_or(|value| value <= sizes.observed_bytes));
            prop_assert!(sizes.duplicated_data_bytes.is_some_and(|value| value <= sizes.observed_bytes));
            prop_assert_eq!(
                sizes.upper_bound_savings_bytes,
                Some(sizes.duplicated_bytes)
            );
            prop_assert!(
                sizes.estimated_refactor_savings_bytes.is_none()
                    && sizes.verified_savings_bytes.is_none()
            );
        }
    }
}
