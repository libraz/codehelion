//! Human-readable and CSV artifact report rendering.

use std::borrow::Cow;
use std::collections::HashMap;

use codehelion_artifact::short_name::short_name;

use super::correlation::{self, AttributionBasis, RefactorSavingsAssumption};
use super::metrics;
use super::model::{ArtifactReport, ReportFact, column};
use super::{Context, Result, Write, csv};
use crate::report::render::format::noun_form_of;

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
            format!(
                "shared implementation retains {}",
                counted(*copies, "copy", "copies")
            )
        }
        RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes } => {
            format!(
                "call overhead is {} per replaced member",
                counted(*bytes, "byte", "bytes")
            )
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

/// Write each of `facts` into `row`, under the column `header` names for it.
pub(super) fn write_fact_columns<R>(
    facts: &[ReportFact<R>],
    report: &R,
    header: &[&str],
    row: &mut [String],
) -> Result<()> {
    for fact in facts {
        let index = header
            .iter()
            .position(|column| *column == fact.column)
            .with_context(|| format!("the CSV header has no {} column", fact.column))?;
        row[index] = (fact.value)(report).map_or_else(String::new, |value| csv(&value));
    }
    Ok(())
}

/// Write each of `facts` the report has as one `label: value` line.
pub(super) fn render_fact_lines<R>(
    facts: &[ReportFact<R>],
    report: &R,
    out: &mut impl Write,
) -> Result<()> {
    for fact in facts {
        if let Some(value) = (fact.value)(report) {
            writeln!(out, "{}: {value}", fact.label)?;
        }
    }
    Ok(())
}

/// Say how many entries a capped list left to the JSON output.
pub(super) fn render_omitted(
    total: usize,
    listed: usize,
    singular: &str,
    plural: &str,
    indent: &str,
    out: &mut impl Write,
) -> Result<()> {
    let omitted = total.saturating_sub(listed);
    if omitted > 0 {
        writeln!(
            out,
            "{indent}{omitted} more {}",
            noun(omitted, singular, plural)
        )?;
    }
    Ok(())
}

/// The singular or plural noun for `count`, judged by its magnitude.
pub(super) fn noun<'a>(count: impl TryInto<i128>, singular: &'a str, plural: &'a str) -> &'a str {
    let magnitude = count.try_into().map_or(u128::MAX, i128::unsigned_abs);
    noun_form_of(
        u64::try_from(magnitude).unwrap_or(u64::MAX),
        singular,
        plural,
    )
}

/// `1 symbol` / `3 symbols`.
pub(super) fn counted(
    count: impl TryInto<i128> + Copy + std::fmt::Display,
    singular: &str,
    plural: &str,
) -> String {
    format!("{count} {}", noun(count, singular, plural))
}

/// `+1 member` / `-3 members`, the noun following the magnitude.
pub(super) fn signed_counted(delta: i128, singular: &str, plural: &str) -> String {
    format!("{delta:+} {}", noun(delta, singular, plural))
}

/// Symbol names by fingerprint, for lists that identify symbols by fingerprint only.
///
/// Symbols can share a fingerprint, so each entry holds the distinct full names
/// in file order; a fingerprint with no named symbol maps to an empty list.
pub(super) fn symbol_names(report: &ArtifactReport) -> HashMap<&str, Vec<&str>> {
    let mut names: HashMap<&str, Vec<&str>> = HashMap::with_capacity(report.symbols.len());
    for symbol in &report.symbols {
        let entry = names.entry(symbol.fingerprint.as_str()).or_default();
        if let Some(name) = symbol.name.as_deref()
            && !entry.contains(&name)
        {
            entry.push(name);
        }
    }
    names
}

/// The names behind one fingerprint as a text report prints them: each
/// shortened unless `verbose`, joined with ` | `, or `<unnamed>` when none.
pub(super) fn listed_names(
    names: &HashMap<&str, Vec<&str>>,
    fingerprint: &str,
    verbose: bool,
) -> String {
    match names.get(fingerprint).map(Vec::as_slice) {
        None | Some([]) => display_name(None, verbose).into_owned(),
        Some(found) => found
            .iter()
            .map(|name| display_name(Some(name), verbose))
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

/// The names behind one fingerprint in full, joined with ` | `, or empty.
pub(super) fn joined_names(names: &HashMap<&str, Vec<&str>>, fingerprint: &str) -> String {
    names
        .get(fingerprint)
        .map_or_else(String::new, |found| found.join(" | "))
}

/// A symbol name as a text report prints it: shortened unless `verbose`, and
/// `<unnamed>` when the symbol has none.
pub(super) fn display_name(name: Option<&str>, verbose: bool) -> Cow<'_, str> {
    match name {
        Some(name) if verbose => Cow::Borrowed(name),
        Some(name) => short_name(name),
        None => Cow::Borrowed("<unnamed>"),
    }
}
