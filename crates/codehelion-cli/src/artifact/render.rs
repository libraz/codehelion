//! Human-readable and CSV artifact report rendering.

use super::correlation::{self, AttributionBasis, RefactorSavingsAssumption};
use super::metrics;
use super::model::{self, column};

mod compare;
mod csv;
mod text;

pub(super) use compare::{render_compare_csv, render_compare_text};
pub(super) use csv::render_csv;
pub(super) use text::render_text;

pub(super) const fn artifact_import_kind_label(
    kind: codehelion_artifact::ArtifactImportKind,
) -> &'static str {
    match kind {
        codehelion_artifact::ArtifactImportKind::Function => "function",
        codehelion_artifact::ArtifactImportKind::Table => "table",
        codehelion_artifact::ArtifactImportKind::Memory => "memory",
        codehelion_artifact::ArtifactImportKind::Global => "global",
        codehelion_artifact::ArtifactImportKind::Tag => "tag",
        codehelion_artifact::ArtifactImportKind::Other => "other",
    }
}

/// Name the evidence behind one attributed byte count wherever it is printed.
pub(super) const fn attribution_basis_label(basis: AttributionBasis) -> &'static str {
    match basis {
        AttributionBasis::Observed => "observed attributed",
        AttributionBasis::LineProportional => "line-proportional estimated",
    }
}

/// The CSV spelling of the same evidence class.
pub(super) const fn attribution_basis_field(basis: AttributionBasis) -> &'static str {
    match basis {
        AttributionBasis::Observed => "observed",
        AttributionBasis::LineProportional => "line_proportional_estimate",
    }
}

pub(super) fn refactor_savings_assumption_text(assumption: &RefactorSavingsAssumption) -> String {
    match assumption {
        RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies } => {
            format!("shared implementation retains {copies} copy/copies")
        }
        RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes } => {
            format!("call overhead is {bytes} bytes per replaced member")
        }
        RefactorSavingsAssumption::InliningOutcomeUnknown => {
            "compiler inlining outcome is unknown".to_owned()
        }
        RefactorSavingsAssumption::LinkerIcfOutcomeUnknown => {
            "linker ICF outcome is unknown".to_owned()
        }
        RefactorSavingsAssumption::AttributionIsLineProportional => {
            "at least one member's bytes were divided across its symbol's source lines rather than observed".to_owned()
        }
    }
}

pub(super) fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

/// One stated size category's value, or the word for evidence that is absent.
///
/// The absence is spelled the same way whatever the category, because "the
/// evidence for this is not there" is one fact and a reader comparing two
/// lines should not have to tell two spellings of it apart.
pub(super) fn stated_bytes(value: Option<i128>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

/// The column one clone-group byte count is written to.
///
/// Taken apart exhaustively for the same reason the artifact-wide mapping is:
/// a count added to the attribution stops this compiling until it is given a
/// column of its own, rather than sharing one with a count of another kind.
pub(super) const fn attribution_column(category: correlation::GroupSizeCategory) -> usize {
    match category {
        correlation::GroupSizeCategory::Duplicated => column::DUPLICATED_BYTES,
        correlation::GroupSizeCategory::EstimatedDuplicated => column::ESTIMATED_DUPLICATED_BYTES,
        correlation::GroupSizeCategory::ContainingSymbols => column::CONTAINING_SYMBOL_BYTES,
    }
}

/// The summary column one size category is written to.
///
/// Taken apart exhaustively: a category added to the classification stops this
/// compiling until it is given a column, which is what stops a number reaching
/// the text and JSON views while the record a consumer parses leaves it out.
/// Columns are only ever appended, so a new category takes a new one.
pub(super) const fn summary_column(category: metrics::SizeCategory) -> usize {
    match category {
        metrics::SizeCategory::Observed => column::OBSERVED_BYTES,
        metrics::SizeCategory::Duplicated => column::DUPLICATED_BYTES,
        metrics::SizeCategory::DuplicatedNormalized => column::DUPLICATED_BYTES_NORMALIZED,
        metrics::SizeCategory::Retained => column::RETAINED_BYTES,
        metrics::SizeCategory::SharedDependency => column::SHARED_DEPENDENCY_BYTES,
        metrics::SizeCategory::DuplicatedData => column::DUPLICATED_DATA_BYTES,
        metrics::SizeCategory::UpperBoundSavings => column::UPPER_BOUND_SAVINGS_BYTES,
        metrics::SizeCategory::EstimatedRefactorSavings => column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
        metrics::SizeCategory::VerifiedSavings => column::VERIFIED_SAVINGS_BYTES,
    }
}
