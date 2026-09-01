//! Matching of detector findings against corpus labels, and the accuracy and
//! stability metrics derived from that matching.
//!
//! # Matching semantics
//!
//! A labelled fragment set (a [`LabelPair`](crate::labels::LabelPair) or a
//! [`NonClone`](crate::labels::NonClone), each with exactly two
//! fragments) is *covered* by a [`Finding`] when, for **every** labelled
//! fragment, the finding contains at least one fragment whose
//! [`Fragment::overlap`] with it is greater than or equal to the match
//! threshold.
//!
//! A labelled clone pair has a second way to be answered for, because the
//! report keeps one finding per duplication and shows the shorter cuts of one
//! duplication inside the longest rather than beside it. [`confirms`] is the
//! question a label asks — did the report point a reader at this duplication —
//! and it takes either a finding with the label's bounds or a longer finding
//! holding both labelled regions in members of its own.
//!
//! # True/false positives
//!
//! [`evaluate`] assumes a fully-labelled synthetic corpus: every genuine clone
//! is a labelled `clone_pair`. Under that assumption a finding is a **true
//! positive** when it covers at least one `clone_pair`, and a **false
//! positive** otherwise. On partially-labelled real code this over-counts false
//! positives, so [`Metrics::precision_overall`] is meaningful only against a
//! complete label set.
//!
//! Real code cannot be labelled that way — nobody enumerates every clone in a
//! tree before measuring one. [`adjudicate`] is the measure for that case: it
//! scores only the findings a label speaks about, and counts the rest as
//! [unjudged](Adjudication::unjudged) rather than guessing. What it reports is
//! "of the findings someone has ruled on, how many were right", which is a
//! statement a partial label set can support.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::detected::DetectedSiblingGroup;
use crate::labels::LabelSet;
use crate::schema::{CloneType, DetectionResult, Finding, Fragment, SiblingBasis};

mod adjudication;
mod stability;

pub use adjudication::{
    Adjudication, AxisSplit, BandSplit, RankedVerdicts, ReasonSplit, SizeSplit, Verdict,
    WidthFamily, adjudicate, confirms, verdict,
};
pub use stability::{Stability, stability, stability_by_rule};

/// Default line-overlap threshold at or above which two fragments are
/// considered the same code region.
pub const DEFAULT_MATCH_THRESHOLD: f64 = 0.5;

/// Whether `finding` covers the labelled `fragments` at `threshold`.
///
/// See the [module documentation](self) for the exact "covers" semantics.
#[must_use]
pub fn covers(finding: &Finding, fragments: &[Fragment], threshold: f64) -> bool {
    covers_fragments(&finding.fragments, fragments, threshold)
}

/// Whether every labelled fragment is covered by a reported fragment.
fn covers_fragments(
    reported_fragments: &[Fragment],
    labelled_fragments: &[Fragment],
    threshold: f64,
) -> bool {
    !labelled_fragments.is_empty()
        && labelled_fragments.iter().all(|labelled| {
            reported_fragments
                .iter()
                .any(|reported| reported.overlap(labelled) >= threshold)
        })
}

/// Whether `finding` covers the labelled clone `pair` at `threshold`.
#[must_use]
pub fn matches_pair(finding: &Finding, pair: &crate::labels::LabelPair, threshold: f64) -> bool {
    covers(finding, &pair.fragments, threshold)
}

/// Accuracy metrics for one detection run against a label set.
#[derive(Debug, Clone, PartialEq)]
pub struct Metrics {
    /// Fraction of all `clone_pairs` covered by at least one finding.
    ///
    /// `None` when there are no labelled pairs.
    pub recall_overall: Option<f64>,
    /// Per-type recall, keyed by [`CloneType`], for every type present in the
    /// labels.
    pub recall_by_type: BTreeMap<CloneType, f64>,
    /// True positives divided by the number of findings, or `None` when no
    /// finding was reported.
    pub precision_overall: Option<f64>,
    /// Findings per 1000 lines of analysed code, or `None` when `loc` is `0`.
    pub findings_per_kloc: Option<f64>,
    /// False positives per 1000 lines of analysed code, or `None` when `loc`
    /// is `0`.
    pub false_positives_per_kloc: Option<f64>,
    /// Precision among the top-`k` findings ranked by score (descending, ties
    /// broken by `id` ascending), or `None` when the selected top set is
    /// empty.
    pub precision_at_k: Option<f64>,
    /// Number of findings that cover a labelled `non_clone`; each is a clear
    /// false positive.
    pub non_clone_hits: usize,
    /// Total number of findings evaluated.
    pub total_findings: usize,
    /// Number of findings classified as true positives.
    pub true_positives: usize,
    /// Number of findings classified as false positives.
    pub false_positives: usize,
    /// The `k` used for [`precision_at_k`](Self::precision_at_k).
    pub top_k: usize,
}

/// Metrics for supplemental sibling evidence, kept separate from primary
/// clone precision and recall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingMetrics {
    /// Known mirror labels recovered by their owning primary group and sibling
    /// overlap.
    pub known_mirrors_recovered: usize,
    /// Number of known mirror labels in the corpus.
    pub known_mirrors_total: usize,
    /// All retained signature-channel sibling entries in the report.
    pub signature_siblings_total: usize,
}

/// Score known mirror labels against rich sibling evidence.
#[must_use]
pub fn evaluate_siblings(
    sibling_groups: &[DetectedSiblingGroup],
    labels: &LabelSet,
    threshold: f64,
) -> SiblingMetrics {
    let known_mirrors_recovered = labels
        .known_siblings
        .iter()
        .filter(|known| {
            sibling_groups.iter().any(|group| {
                covers_fragments(&group.owner_members, &known.primary_fragments, threshold)
                    && group.siblings.iter().any(|sibling| {
                        sibling.basis == known.basis
                            && sibling.member.overlap(&known.sibling) >= threshold
                    })
            })
        })
        .count();
    let signature_siblings_total = sibling_groups
        .iter()
        .flat_map(|group| &group.siblings)
        .filter(|sibling| sibling.basis == SiblingBasis::Signature)
        .count();
    SiblingMetrics {
        known_mirrors_recovered,
        known_mirrors_total: labels.known_siblings.len(),
        signature_siblings_total,
    }
}

impl fmt::Display for SiblingMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "known mirrors recovered     {} / {}",
            self.known_mirrors_recovered, self.known_mirrors_total
        )?;
        write!(
            f,
            "signature-derived siblings  {}",
            self.signature_siblings_total
        )
    }
}

/// Measured ratio `num / den`, or `None` when `den` is zero.
#[allow(clippy::cast_precision_loss)] // Corpus counts are far below f64's exact range.
fn ratio(num: usize, den: usize) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

/// `count` scaled to a per-1000-lines rate, or `None` when `loc` is zero.
#[allow(clippy::cast_precision_loss)] // Corpus counts are far below f64's exact range.
fn per_kloc(count: usize, loc: u32) -> Option<f64> {
    if loc == 0 {
        None
    } else {
        Some(count as f64 / f64::from(loc) * 1000.0)
    }
}

/// Score `results` against `labels`.
///
/// `loc` is the analysed line count used for the per-KLOC rates, `threshold`
/// the overlap threshold for the "covers" relation, and `top_k` the cut-off for
/// [`Metrics::precision_at_k`].
#[must_use]
pub fn evaluate(
    results: &DetectionResult,
    labels: &LabelSet,
    loc: u32,
    threshold: f64,
    top_k: usize,
) -> Metrics {
    let total_findings = results.findings.len();

    // Classify each finding: a true positive covers at least one clone pair.
    let is_true_positive: Vec<bool> = results
        .findings
        .iter()
        .map(|finding| {
            labels
                .clone_pairs
                .iter()
                .any(|pair| matches_pair(finding, pair, threshold))
        })
        .collect();
    let true_positives = is_true_positive.iter().filter(|&&tp| tp).count();
    let false_positives = total_findings - true_positives;

    // Recall, overall and per type.
    let mut per_type_total: BTreeMap<CloneType, usize> = BTreeMap::new();
    let mut per_type_covered: BTreeMap<CloneType, usize> = BTreeMap::new();
    let mut covered_pairs = 0usize;
    for pair in &labels.clone_pairs {
        let covered = results
            .findings
            .iter()
            .any(|finding| matches_pair(finding, pair, threshold));
        *per_type_total.entry(pair.clone_type).or_insert(0) += 1;
        let covered_entry = per_type_covered.entry(pair.clone_type).or_insert(0);
        if covered {
            covered_pairs += 1;
            *covered_entry += 1;
        }
    }
    let recall_overall = ratio(covered_pairs, labels.clone_pairs.len());
    let recall_by_type = per_type_total
        .iter()
        .filter_map(|(&clone_type, &total)| {
            let covered = per_type_covered.get(&clone_type).copied().unwrap_or(0);
            ratio(covered, total).map(|recall| (clone_type, recall))
        })
        .collect();

    let precision_overall = ratio(true_positives, total_findings);
    let findings_per_kloc = per_kloc(total_findings, loc);
    let false_positives_per_kloc = per_kloc(false_positives, loc);

    // Precision among the top-k findings, ranked by score then id.
    let mut order: Vec<usize> = (0..total_findings).collect();
    order.sort_by(|&i, &j| {
        let (fi, fj) = (&results.findings[i], &results.findings[j]);
        fj.score
            .partial_cmp(&fi.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| fi.id.cmp(&fj.id))
    });
    let k = top_k.min(total_findings);
    let tp_in_k = order
        .iter()
        .take(k)
        .filter(|&&i| is_true_positive[i])
        .count();
    let precision_at_k = ratio(tp_in_k, k);

    let non_clone_hits = results
        .findings
        .iter()
        .filter(|finding| {
            labels
                .non_clones
                .iter()
                .any(|non_clone| covers(finding, &non_clone.fragments, threshold))
        })
        .count();

    Metrics {
        recall_overall,
        recall_by_type,
        precision_overall,
        findings_per_kloc,
        false_positives_per_kloc,
        precision_at_k,
        non_clone_hits,
        total_findings,
        true_positives,
        false_positives,
        top_k,
    }
}

/// Evaluate every registered semantic rule explicitly named by the labels.
///
/// A rule contributes only findings that name it and labels that name it. This
/// keeps an unlabelled rule from changing another rule's precision, while
/// retaining the normal [`evaluate`] semantics inside each labelled slice.
/// Rules with no labelled positive or negative examples are intentionally not
/// returned: their precision and recall have no corpus basis yet.
#[must_use]
pub fn evaluate_by_rule(
    results: &DetectionResult,
    labels: &LabelSet,
    loc: u32,
    threshold: f64,
    top_k: usize,
) -> BTreeMap<String, Metrics> {
    let rule_ids: BTreeSet<&str> = labels
        .clone_pairs
        .iter()
        .filter_map(|pair| pair.rule_id.as_deref())
        .chain(
            labels
                .non_clones
                .iter()
                .filter_map(|non_clone| non_clone.rule_id.as_deref()),
        )
        .collect();

    rule_ids
        .into_iter()
        .map(|rule_id| {
            let scoped_results = DetectionResult {
                schema_version: results.schema_version,
                language: results.language.clone(),
                findings: results
                    .findings
                    .iter()
                    .filter(|finding| finding.rule_ids.iter().any(|id| id == rule_id))
                    .cloned()
                    .collect(),
                withheld: Vec::new(),
            };
            let scoped_labels = LabelSet {
                schema_version: labels.schema_version,
                language: labels.language.clone(),
                files: labels.files.clone(),
                clone_pairs: labels
                    .clone_pairs
                    .iter()
                    .filter(|pair| pair.rule_id.as_deref() == Some(rule_id))
                    .cloned()
                    .collect(),
                non_clones: labels
                    .non_clones
                    .iter()
                    .filter(|non_clone| non_clone.rule_id.as_deref() == Some(rule_id))
                    .cloned()
                    .collect(),
                known_siblings: Vec::new(),
            };
            (
                rule_id.to_string(),
                evaluate(&scoped_results, &scoped_labels, loc, threshold, top_k),
            )
        })
        .collect()
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "recall (overall)          {}",
            display_measure(self.recall_overall)
        )?;
        for (clone_type, recall) in &self.recall_by_type {
            writeln!(f, "  recall {:<19} {recall:.4}", clone_type.as_str())?;
        }
        writeln!(
            f,
            "precision (overall)       {}",
            display_measure(self.precision_overall)
        )?;
        writeln!(
            f,
            "precision@{:<15} {}",
            self.top_k,
            display_measure(self.precision_at_k)
        )?;
        writeln!(
            f,
            "findings / kLOC           {}",
            display_measure(self.findings_per_kloc)
        )?;
        writeln!(
            f,
            "false positives / kLOC    {}",
            display_measure(self.false_positives_per_kloc)
        )?;
        writeln!(
            f,
            "true / false positives    {} / {}  (of {})",
            self.true_positives, self.false_positives, self.total_findings
        )?;
        write!(f, "non-clone hits            {}", self.non_clone_hits)
    }
}

/// Format a measured value without presenting an absent denominator as zero.
fn display_measure(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |measure| format!("{measure:.4}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
