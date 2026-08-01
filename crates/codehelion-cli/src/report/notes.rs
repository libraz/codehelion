//! Human-readable notes for incomplete scans and grouping ceilings.

use super::{BTreeSet, FunnelDrop, FunnelStage, is_search_truncation};

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
    let budgeted = funnel
        .iter()
        .filter(|stage| stage.dropped.iter().any(|drop| drop.cause == "pair_budget"));
    let (examined, skipped) = budgeted.fold((0u64, 0u64), |(examined, skipped), stage| {
        let dropped: u64 = stage
            .dropped
            .iter()
            .filter(|drop| drop.cause == "pair_budget")
            .map(|drop| drop.count)
            .sum();
        (
            examined.saturating_add(stage.passed),
            skipped.saturating_add(dropped),
        )
    });
    let total = examined.saturating_add(skipped);
    if total == 0 {
        return "  note: the candidate-pair budget was exhausted; results may be incomplete"
            .to_string();
    }
    format!(
        "  note: the candidate-pair budget stopped the search after {examined} of {total} \
         candidate pairs; the {skipped} left unexamined may hold duplication this report does \
         not list"
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
        "  note: candidate search was truncated by {listed}; duplication the tree contains may be missing from this report"
    )
}

/// Files whose parser stopped at the structural depth ceiling.
///
/// This is distinct from ordinary recovery: malformed source carries its
/// uncertainty in `unparsed`, while a depth ceiling is an explicit limit on
/// how far the scan intentionally read.
pub(super) fn depth_truncation_files(funnel: &[FunnelStage]) -> Option<u64> {
    let files: u64 = funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| drop.cause == "depth_limit")
        .map(|drop| drop.count)
        .sum();
    (files > 0).then_some(files)
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
    let severed: u64 = funnel
        .iter()
        .flat_map(|stage| stage.dropped.iter())
        .filter(|drop| drop.cause == "the_ceiling_cut_the_set")
        .map(|drop| drop.count)
        .sum();
    if severed == 0 {
        return String::new();
    }
    format!(", and {severed} verified pair(s) across the cut are counted rather than listed")
}
