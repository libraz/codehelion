//! Human-readable notes for incomplete scans and grouping ceilings.
//!
//! Each returns the sentence alone. Whether it reaches the reader as a note or
//! as a warning is the caller's to decide, because the same fact is a
//! different weight in a report than it is in a comparison rendered inside
//! one.

use super::{BTreeSet, FunnelCause, FunnelDrop, FunnelStage, is_search_truncation};

/// How many items the funnel attributes to one cause, across every stage.
fn dropped_for(funnel: &[FunnelStage], cause: FunnelCause) -> u64 {
    funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| drop.cause == cause.name())
        .map(|drop| drop.count)
        .fold(0, u64::saturating_add)
}

/// What the exhausted candidate-pair ceiling cost, in the run's own numbers.
///
/// How much was skipped, not only that something was: a ceiling that trimmed
/// a hundred low-signal candidates and one that left nine tenths of the
/// corpus uncompared both read as "exhausted", and only one of them is a
/// result worth acting on.
///
/// The figure covers the stages the ceiling actually stopped. A pass that
/// finished its own search is not part of what was cut short, and counting it
/// in would dilute the share into saying less than it does.
pub(super) fn budget_note(funnel: &[FunnelStage]) -> String {
    // Summed over whichever stages recorded the ceiling firing, rather than
    // over stage names written down here: each pass holds its own allowance,
    // and a list of names would let a pass added later go uncounted and read
    // as complete.
    let budgeted = funnel.iter().filter(|stage| {
        stage
            .dropped
            .iter()
            .any(|drop| drop.cause == FunnelCause::PairBudget.name())
    });
    let (examined, skipped) = budgeted.fold((0u64, 0u64), |(examined, skipped), stage| {
        let dropped: u64 = stage
            .dropped
            .iter()
            .filter(|drop| drop.cause == FunnelCause::PairBudget.name())
            .map(|drop| drop.count)
            .sum();
        (
            examined.saturating_add(stage.passed),
            skipped.saturating_add(dropped),
        )
    });
    let total = examined.saturating_add(skipped);
    if total == 0 {
        return "the candidate-pair budget was exhausted; results may be incomplete".to_string();
    }
    format!(
        "the candidate-pair budget stopped the search after {examined} of {total} candidate \
         pairs; the {skipped} left unexamined may hold duplication this report does not list"
    )
}

/// The ceiling causes that cut candidate search in this run.
///
/// Counts are deliberately not collapsed across kinds: a dropped posting,
/// bucket, class, and pair are different units. The note states only what the
/// funnel establishes — that the search was truncated and findings may be
/// absent — while the verbose funnel retains each exact count.
pub fn search_truncation_note(funnel: &[FunnelStage]) -> String {
    let causes: BTreeSet<String> = funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| is_search_truncation(&drop.cause))
        .map(FunnelDrop::label)
        .collect();
    let listed = causes.into_iter().collect::<Vec<_>>().join(", ");
    format!(
        "candidate search was truncated by {listed}; duplication the tree contains may be missing from this report"
    )
}

/// Files whose parser stopped at the structural depth ceiling.
///
/// This is distinct from ordinary recovery: malformed source carries its
/// uncertainty in `unparsed`, while a depth ceiling is an explicit limit on
/// how far the scan intentionally read.
pub(super) fn depth_truncation_files(funnel: &[FunnelStage]) -> Option<u64> {
    let files = dropped_for(funnel, FunnelCause::DepthLimit);
    (files > 0).then_some(files)
}

/// Block bodies the Fast fragment cut left alone at its nesting ceiling.
///
/// The same kind of fact as [`depth_truncation_files`] and stated the same
/// way, but counted in blocks rather than files: the Fast pipeline lexes whole
/// files and stops descending into the bodies below its extraction depth, so
/// what was left out is a set of blocks inside files that were read in full.
/// Reporting these as files would say a part of the tree went unread when it
/// did not.
pub(super) fn nesting_truncation_bodies(funnel: &[FunnelStage]) -> Option<u64> {
    let bodies = dropped_for(funnel, FunnelCause::NestingLimit);
    (bodies > 0).then_some(bodies)
}

/// What a cut kept from being reported, appended to the note about the cut.
///
/// Two units the cut put in different pieces were never weighed against each
/// other, so a relation between them is not carried out as a pair — it would
/// restate the same set once per crossing, and a set large enough to be cut is
/// large enough for that to be the whole report. The count says how much was
/// held back, which is the difference between a coarser answer and a quieter
/// one. Empty when nothing was held back, so the note stays one sentence in
/// the case where the cut cost nothing.
pub(super) fn severed_note(funnel: &[FunnelStage]) -> String {
    let severed = dropped_for(funnel, FunnelCause::TheCeilingCutTheSet);
    if severed == 0 {
        return String::new();
    }
    format!(", and {severed} verified pair(s) across the cut are counted rather than listed")
}
