//! Statements qualifying the sizes one report and one comparison state.

use super::{ArtifactComparisonReport, ArtifactReport};
use crate::artifact::{BTreeSet, metrics};

/// Where in a report one qualifying statement belongs.
///
/// Text prints a statement under the block whose numbers it qualifies, CSV
/// names that block in a column, and JSON carries it inside that block. The
/// scope is what lets three renderings place one statement without any of them
/// inventing a fourth statement, dropping one, or printing one twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::artifact) enum AssumptionScope {
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
    pub(in crate::artifact) const fn field(self) -> &'static str {
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
pub(in crate::artifact) struct ReportAssumption<'a> {
    /// The reported block this statement qualifies.
    pub(in crate::artifact) scope: AssumptionScope,
    /// The statement itself, as the report carries it.
    pub(in crate::artifact) text: &'a str,
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
pub(super) const CONTAINER_WIDE_OBSERVED_BYTES: &str = "observed byte counts cover the whole container, including the skipped architecture slices; only section, symbol and duplicate counts are limited to the selected architecture";

/// A verified saving belongs to one refactoring only under a controlled pair.
pub(super) const VERIFIED_SAVINGS_NEEDS_CONTROL: &str = "verified_savings_bytes attributes the whole observed artifact difference to the calibrated clone group, which holds only when the two artifacts differ in nothing else; this comparison establishes the artifact format and the build variant and nothing further";

/// State what the reported size fields leave out, beside what their derivation
/// already assumed.
///
/// These reach every rendering because they are added while the report is
/// built: JSON serializes them from the same vector text and CSV read.
pub(in crate::artifact) fn qualify_sizes(
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
pub(in crate::artifact) fn report_assumptions(
    report: &ArtifactReport,
) -> Vec<ReportAssumption<'_>> {
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
pub(in crate::artifact) fn comparison_assumptions(
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
pub(in crate::artifact) const fn dead_code_unavailability(report: &ArtifactReport) -> &'static str {
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
pub(in crate::artifact) fn retained_size_unavailability(report: &ArtifactReport) -> Vec<&str> {
    report
        .sizes
        .assumptions
        .iter()
        .filter(|text| text.starts_with(WITHDRAWN_SIZE_PREFIX))
        .map(String::as_str)
        .collect()
}
