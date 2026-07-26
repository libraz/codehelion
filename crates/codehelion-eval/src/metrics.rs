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

use crate::labels::LabelSet;
use crate::schema::{CloneType, DetectionResult, Finding, Fragment};

/// Default line-overlap threshold at or above which two fragments are
/// considered the same code region.
pub const DEFAULT_MATCH_THRESHOLD: f64 = 0.5;

/// Whether `finding` covers the labelled `fragments` at `threshold`.
///
/// See the [module documentation](self) for the exact "covers" semantics.
#[must_use]
pub fn covers(finding: &Finding, fragments: &[Fragment], threshold: f64) -> bool {
    fragments.iter().all(|labelled| {
        finding
            .fragments
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
    /// `0.0` when there are no labelled pairs.
    pub recall_overall: f64,
    /// Per-type recall, keyed by [`CloneType`], for every type present in the
    /// labels.
    pub recall_by_type: BTreeMap<CloneType, f64>,
    /// True positives divided by the number of findings. `0.0` when there are
    /// no findings.
    pub precision_overall: f64,
    /// Findings per 1000 lines of analysed code. `0.0` when `loc` is `0`.
    pub findings_per_kloc: f64,
    /// False positives per 1000 lines of analysed code. `0.0` when `loc` is
    /// `0`.
    pub false_positives_per_kloc: f64,
    /// Precision among the top-`k` findings ranked by score (descending, ties
    /// broken by `id` ascending). `0.0` when there are no findings.
    pub precision_at_k: f64,
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

/// Ratio `num / den`, or `0.0` when `den` is zero.
#[allow(clippy::cast_precision_loss)] // Corpus counts are far below f64's exact range.
fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// `count` scaled to a per-1000-lines rate, or `0.0` when `loc` is zero.
#[allow(clippy::cast_precision_loss)] // Corpus counts are far below f64's exact range.
fn per_kloc(count: usize, loc: u32) -> f64 {
    if loc == 0 {
        0.0
    } else {
        count as f64 / f64::from(loc) * 1000.0
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
        .map(|(&clone_type, &total)| {
            let covered = per_type_covered.get(&clone_type).copied().unwrap_or(0);
            (clone_type, ratio(covered, total))
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
    let precision_at_k = if k == 0 {
        0.0
    } else {
        let tp_in_k = order
            .iter()
            .take(k)
            .filter(|&&i| is_true_positive[i])
            .count();
        ratio(tp_in_k, k)
    };

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

/// What a partial label set says about one detection run.
///
/// Every finding falls into exactly one of confirmed / refuted / conflicting /
/// unjudged, so the four counts sum to the number of findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjudication {
    /// Findings covering a labelled `clone_pair` and no labelled `non_clone`.
    pub confirmed: usize,
    /// Findings covering a labelled `non_clone` and no labelled `clone_pair`.
    pub refuted: usize,
    /// Findings covering both, which means the labels disagree with each other
    /// rather than with the detector. Non-zero is a corpus defect.
    pub conflicting: usize,
    /// Findings no label speaks about. Counted, never guessed at.
    pub unjudged: usize,
}

impl Adjudication {
    /// Findings a label ruled on either way.
    #[must_use]
    pub const fn judged(&self) -> usize {
        self.confirmed + self.refuted
    }

    /// Confirmed findings over judged ones; `0.0` when nothing was judged.
    ///
    /// Unjudged findings are outside both the numerator and the denominator:
    /// an unlabelled finding is an unasked question, not a wrong answer.
    #[must_use]
    pub fn precision(&self) -> f64 {
        ratio(self.confirmed, self.judged())
    }
}

/// Rule `results` against `labels`, scoring only what the labels speak about.
///
/// `threshold` is the overlap threshold for the "covers" relation, as in
/// [`evaluate`].
#[must_use]
pub fn adjudicate(results: &DetectionResult, labels: &LabelSet, threshold: f64) -> Adjudication {
    let mut adjudication = Adjudication {
        confirmed: 0,
        refuted: 0,
        conflicting: 0,
        unjudged: 0,
    };
    for finding in &results.findings {
        match verdict(finding, labels, threshold) {
            Verdict::Conflicting => adjudication.conflicting += 1,
            Verdict::Confirmed => adjudication.confirmed += 1,
            Verdict::Refuted => adjudication.refuted += 1,
            Verdict::Unjudged => adjudication.unjudged += 1,
        }
    }
    adjudication
}

/// How well a ranking puts the real duplication first.
///
/// A report is read from the top, so where a finding sits decides whether it
/// is read at all. Precision over the whole result set says nothing about
/// that: two orderings of the same findings score identically on it and are
/// worth entirely different amounts to a reader.
///
/// Accumulates across corpora, because a single labelled project has too few
/// judged findings for a cut-off of fifty to mean anything. Findings the
/// labels do not speak about are left out of the ordering entirely rather than
/// counted against it — an unlabelled finding is an unasked question, and
/// including it would let a ranking look better by burying its unjudged
/// findings at the bottom.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RankedVerdicts {
    /// Every judged finding, as `(score, was it confirmed)`.
    entries: Vec<(f64, bool)>,
}

impl RankedVerdicts {
    /// Add every judged finding in `results`, scored by `score`.
    ///
    /// `score` reads a finding and returns the value the ranking under test
    /// would order by, higher first. Passing a different one is how two
    /// rankings are compared over the same verdicts.
    pub fn record(
        &mut self,
        results: &DetectionResult,
        labels: &LabelSet,
        threshold: f64,
        score: impl Fn(&Finding) -> f64,
    ) {
        for finding in &results.findings {
            match verdict(finding, labels, threshold) {
                Verdict::Confirmed => self.entries.push((score(finding), true)),
                Verdict::Refuted => self.entries.push((score(finding), false)),
                Verdict::Conflicting | Verdict::Unjudged => {}
            }
        }
    }

    /// Judged findings recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Share of the top `k` that a label confirmed; `0.0` when nothing was
    /// recorded. `k` past the end scores every entry.
    ///
    /// Ties are broken pessimistically — a refuted finding sorts ahead of a
    /// confirmed one at the same score — so a ranking cannot be credited for
    /// an order it did not actually express.
    #[must_use]
    pub fn precision_at(&self, k: usize) -> f64 {
        let mut ordered = self.entries.clone();
        ordered.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let top = &ordered[..k.min(ordered.len())];
        ratio(
            top.iter().filter(|(_, confirmed)| *confirmed).count(),
            top.len(),
        )
    }

    /// Mean average precision: the precision at every position a confirmed
    /// finding occupies, averaged.
    ///
    /// The measure to compare two rankings on, because it reads the whole
    /// order rather than one cut-off, and a cut-off chosen after seeing the
    /// results is a way of choosing a winner rather than of measuring one.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Corpus counts are far below f64's exact range.
    pub fn mean_average_precision(&self) -> f64 {
        let mut ordered = self.entries.clone();
        ordered.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let mut hits = 0usize;
        let mut total = 0.0;
        for (position, (_, confirmed)) in ordered.iter().enumerate() {
            if *confirmed {
                hits += 1;
                total += ratio(hits, position + 1);
            }
        }
        if hits == 0 { 0.0 } else { total / hits as f64 }
    }
}

/// What the labels say about a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Covers a labelled `clone_pair` and no labelled `non_clone`.
    Confirmed,
    /// Covers a labelled `non_clone` and no labelled `clone_pair`.
    Refuted,
    /// Covers both, which is the labels disagreeing with each other.
    Conflicting,
    /// No label speaks about it.
    Unjudged,
}

/// Rule one finding against `labels` at `threshold`.
#[must_use]
pub fn verdict(finding: &Finding, labels: &LabelSet, threshold: f64) -> Verdict {
    let is_clone = labels
        .clone_pairs
        .iter()
        .any(|pair| matches_pair(finding, pair, threshold));
    let is_non_clone = labels
        .non_clones
        .iter()
        .any(|non_clone| covers(finding, &non_clone.fragments, threshold));
    match (is_clone, is_non_clone) {
        (true, true) => Verdict::Conflicting,
        (true, false) => Verdict::Confirmed,
        (false, true) => Verdict::Refuted,
        (false, false) => Verdict::Unjudged,
    }
}

/// How large the judged findings are, measured in lines of their smallest
/// member and split by verdict.
///
/// This exists to keep one recurring question answerable from data rather than
/// from intuition: whether a length floor could drop the lookalikes without
/// dropping real clones. Length is the most obvious knob a clone detector has,
/// and the two populations have to be looked at together to see that it does
/// not sort them — see [`Self::confirmed_within_refuted_range`].
///
/// The smallest member is the right end to measure, because a group is only as
/// convincing as its least substantial instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SizeSplit {
    /// Smallest member of each confirmed finding, in lines, ascending.
    pub confirmed: Vec<u32>,
    /// Smallest member of each refuted finding, in lines, ascending.
    pub refuted: Vec<u32>,
}

impl SizeSplit {
    /// Add every judged finding in `results` to the split.
    ///
    /// Accumulates, so one split can span several corpora. Findings that are
    /// unjudged or conflicting are left out: neither is a statement about what
    /// a clone is worth.
    pub fn record(&mut self, results: &DetectionResult, labels: &LabelSet, threshold: f64) {
        for finding in &results.findings {
            let Some(smallest) = finding.fragments.iter().map(Fragment::line_count).min() else {
                continue;
            };
            match verdict(finding, labels, threshold) {
                Verdict::Confirmed => self.confirmed.push(smallest),
                Verdict::Refuted => self.refuted.push(smallest),
                Verdict::Conflicting | Verdict::Unjudged => {}
            }
        }
        self.confirmed.sort_unstable();
        self.refuted.sort_unstable();
    }

    /// How many confirmed findings are no larger than the largest refuted one.
    ///
    /// This is what a length floor high enough to remove every refuted finding
    /// would take with it. Zero would mean the two populations separate by
    /// length and a floor is worth calibrating; anything else is the price of
    /// one, and says the shortest real clones are as short as the shortest
    /// lookalikes.
    #[must_use]
    pub fn confirmed_within_refuted_range(&self) -> usize {
        let Some(&largest) = self.refuted.last() else {
            return 0;
        };
        self.confirmed.iter().filter(|&&n| n <= largest).count()
    }
}

impl fmt::Display for SizeSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let span = |sizes: &[u32]| match (sizes.first(), sizes.last()) {
            (Some(low), Some(high)) => format!("{low}-{high} lines (n={})", sizes.len()),
            _ => "none".to_string(),
        };
        writeln!(f, "smallest member, confirmed  {}", span(&self.confirmed))?;
        writeln!(f, "smallest member, refuted    {}", span(&self.refuted))?;
        write!(
            f,
            "confirmed inside that range {} — the cost of a length floor that \
             removed every refuted finding",
            self.confirmed_within_refuted_range()
        )
    }
}

impl fmt::Display for Adjudication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "precision (judged only)   {:.4}", self.precision())?;
        writeln!(
            f,
            "confirmed / refuted       {} / {}  (of {} judged)",
            self.confirmed,
            self.refuted,
            self.judged()
        )?;
        writeln!(f, "unjudged                  {}", self.unjudged)?;
        write!(f, "conflicting labels        {}", self.conflicting)
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "recall (overall)          {:.4}", self.recall_overall)?;
        for (clone_type, recall) in &self.recall_by_type {
            writeln!(f, "  recall {:<19} {recall:.4}", clone_type.as_str())?;
        }
        writeln!(f, "precision (overall)       {:.4}", self.precision_overall)?;
        writeln!(f, "precision@{:<15} {:.4}", self.top_k, self.precision_at_k)?;
        writeln!(f, "findings / kLOC           {:.4}", self.findings_per_kloc)?;
        writeln!(
            f,
            "false positives / kLOC    {:.4}",
            self.false_positives_per_kloc
        )?;
        writeln!(
            f,
            "true / false positives    {} / {}  (of {})",
            self.true_positives, self.false_positives, self.total_findings
        )?;
        write!(f, "non-clone hits            {}", self.non_clone_hits)
    }
}

/// Run-to-run stability of two detection results over the same input.
///
/// Finding identity is the sorted set of `(file, start_line, end_line)`
/// fragments, never the detector-assigned `id` (which may vary across runs).
#[derive(Debug, Clone, PartialEq)]
pub struct Stability {
    /// Whether both runs reported exactly the same set of findings.
    pub identical: bool,
    /// Jaccard similarity of the two finding-key sets. `1.0` when both runs are
    /// empty.
    pub jaccard: f64,
    /// `1.0 - jaccard`: the fraction of findings that changed.
    pub churn: f64,
}

/// Canonical, id-independent key for a finding: its fragments as sorted tuples.
type FindingKey = Vec<(String, u32, u32)>;

fn key_set(result: &DetectionResult) -> BTreeSet<FindingKey> {
    result
        .findings
        .iter()
        .map(|finding| {
            let mut key: FindingKey = finding
                .fragments
                .iter()
                .map(|fragment| {
                    (
                        fragment.file.clone(),
                        fragment.start_line,
                        fragment.end_line,
                    )
                })
                .collect();
            key.sort();
            key
        })
        .collect()
}

/// Compare the finding sets of two runs `a` and `b` over the same input.
#[must_use]
pub fn stability(a: &DetectionResult, b: &DetectionResult) -> Stability {
    let keys_a = key_set(a);
    let keys_b = key_set(b);
    let intersection = keys_a.intersection(&keys_b).count();
    let union = keys_a.union(&keys_b).count();
    let jaccard = if union == 0 {
        1.0
    } else {
        ratio(intersection, union)
    };
    Stability {
        identical: keys_a == keys_b,
        jaccard,
        churn: 1.0 - jaccard,
    }
}

impl fmt::Display for Stability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "identical                 {}", self.identical)?;
        writeln!(f, "jaccard                   {:.4}", self.jaccard)?;
        write!(f, "churn                     {:.4}", self.churn)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::labels::{LabelPair, NonClone};

    fn fragment(file: &str, start: u32, end: u32) -> Fragment {
        Fragment {
            file: file.to_string(),
            start_line: start,
            end_line: end,
        }
    }

    fn finding(id: &str, score: f64, fragments: Vec<Fragment>) -> Finding {
        Finding {
            size_tokens: 0,
            id: id.to_string(),
            clone_type: CloneType::Type2,
            score,
            fragments,
        }
    }

    /// Hand-crafted self-test: 2 clone pairs, 3 findings. Exactly 1 pair is
    /// covered, exactly 2 findings are true positives, 1 is a false positive.
    fn self_test_inputs() -> (DetectionResult, LabelSet) {
        let results = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            findings: vec![
                // Covers pair A exactly -> true positive.
                finding(
                    "f-001",
                    0.9,
                    vec![fragment("x.rs", 1, 10), fragment("y.rs", 1, 10)],
                ),
                // Overlaps pair A ~0.818 -> true positive.
                finding(
                    "f-002",
                    0.8,
                    vec![fragment("x.rs", 2, 11), fragment("y.rs", 2, 11)],
                ),
                // Covers nothing labelled as a clone -> false positive, and it
                // covers the non-clone region.
                finding(
                    "f-003",
                    0.95,
                    vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
                ),
            ],
        };
        let labels = LabelSet {
            schema_version: 0,
            language: "rust".to_string(),
            files: vec!["x.rs".to_string(), "y.rs".to_string()],
            clone_pairs: vec![
                LabelPair {
                    id: "cp-001".to_string(),
                    clone_type: CloneType::Type2,
                    fragments: vec![fragment("x.rs", 1, 10), fragment("y.rs", 1, 10)],
                },
                LabelPair {
                    id: "cp-002".to_string(),
                    clone_type: CloneType::Type3,
                    fragments: vec![fragment("x.rs", 100, 110), fragment("y.rs", 100, 110)],
                },
            ],
            non_clones: vec![NonClone {
                id: "nc-001".to_string(),
                reason: "unrelated".to_string(),
                fragments: vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
            }],
        };
        (results, labels)
    }

    #[test]
    fn evaluate_matches_hand_computed_values() {
        let (results, labels) = self_test_inputs();
        let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 3);

        assert!((metrics.recall_overall - 0.5).abs() < 1e-9);
        assert!((metrics.precision_overall - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(metrics.true_positives, 2);
        assert_eq!(metrics.false_positives, 1);

        // 3 findings / 100 LOC * 1000 = 30; 1 FP / 100 * 1000 = 10.
        assert!((metrics.findings_per_kloc - 30.0).abs() < 1e-9);
        assert!((metrics.false_positives_per_kloc - 10.0).abs() < 1e-9);

        // Per-type recall: type-2 pair covered (1.0), type-3 pair not (0.0).
        assert!((metrics.recall_by_type[&CloneType::Type2] - 1.0).abs() < 1e-9);
        assert!(metrics.recall_by_type[&CloneType::Type3].abs() < 1e-9);

        // One finding lands on the non-clone region.
        assert_eq!(metrics.non_clone_hits, 1);

        // Top-3 precision equals overall precision here.
        assert!((metrics.precision_at_k - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn precision_at_k_ranks_by_score() {
        let (results, labels) = self_test_inputs();
        // Ranked by score: f-003 (0.95, FP), f-001 (0.9, TP), f-002 (0.8, TP).
        // Top-2 contains one TP -> 0.5.
        let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 2);
        assert!((metrics.precision_at_k - 0.5).abs() < 1e-9);
    }

    #[test]
    fn adjudication_scores_only_what_the_labels_speak_about() {
        let (results, labels) = self_test_inputs();
        // f-001 and f-002 cover clone pair A; f-003 covers the non-clone.
        let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
        assert_eq!(ruled.confirmed, 2);
        assert_eq!(ruled.refuted, 1);
        assert_eq!(ruled.conflicting, 0);
        assert_eq!(ruled.unjudged, 0);
        assert!((ruled.precision() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn an_unlabelled_finding_counts_against_nothing() {
        let (mut results, labels) = self_test_inputs();
        // A finding in a region no label mentions: not a wrong answer, an
        // unasked question. `evaluate` would call it a false positive.
        results.findings.push(finding(
            "f-004",
            0.7,
            vec![fragment("x.rs", 500, 510), fragment("y.rs", 500, 510)],
        ));

        let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
        assert_eq!(ruled.unjudged, 1);
        assert_eq!(ruled.judged(), 3);
        assert!(
            (ruled.precision() - 2.0 / 3.0).abs() < 1e-9,
            "precision is unchanged by a finding nobody ruled on"
        );

        let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 4);
        assert!(
            (metrics.precision_overall - 0.5).abs() < 1e-9,
            "the fully-labelled measure charges the same finding as a miss"
        );
    }

    #[test]
    fn a_finding_both_labels_claim_is_a_corpus_defect() {
        let (results, mut labels) = self_test_inputs();
        // Label the region f-003 reports as a clone as well as a non-clone.
        labels.clone_pairs.push(LabelPair {
            id: "cp-003".to_string(),
            clone_type: CloneType::Type1,
            fragments: vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
        });

        let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
        assert_eq!(ruled.conflicting, 1);
        assert_eq!(ruled.refuted, 0, "a conflict is neither verdict");
        assert_eq!(ruled.confirmed, 2);
    }

    #[test]
    fn nothing_judged_is_not_perfect_precision() {
        let (results, _) = self_test_inputs();
        let empty = LabelSet {
            schema_version: 0,
            language: "rust".to_string(),
            files: vec![],
            clone_pairs: vec![],
            non_clones: vec![],
        };
        let ruled = adjudicate(&results, &empty, DEFAULT_MATCH_THRESHOLD);
        assert_eq!(ruled.judged(), 0);
        assert_eq!(ruled.unjudged, 3);
        assert!(ruled.precision().abs() < f64::EPSILON);
    }

    #[test]
    fn the_size_split_measures_the_smallest_member_of_each_judged_finding() {
        let (results, labels) = self_test_inputs();
        let mut split = SizeSplit::default();
        split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);

        // f-001 and f-002 are confirmed, f-003 refuted; every fragment above
        // spans 10 or 11 lines.
        assert_eq!(split.confirmed, vec![10, 10]);
        assert_eq!(split.refuted, vec![11]);
    }

    #[test]
    fn a_split_that_separates_by_length_costs_nothing() {
        let split = SizeSplit {
            confirmed: vec![20, 30, 40],
            refuted: vec![3, 4, 5],
        };
        assert_eq!(
            split.confirmed_within_refuted_range(),
            0,
            "no confirmed finding is as short as the longest lookalike, so a \
             floor at 6 lines removes the lookalikes for free"
        );
    }

    #[test]
    fn a_split_that_overlaps_prices_the_floor_in_real_clones() {
        let split = SizeSplit {
            confirmed: vec![4, 9, 40],
            refuted: vec![3, 4, 12],
        };
        assert_eq!(
            split.confirmed_within_refuted_range(),
            2,
            "a floor above 12 lines takes the 4- and 9-line clones with it"
        );
    }

    #[test]
    fn nothing_refuted_leaves_a_floor_unpriced() {
        let split = SizeSplit {
            confirmed: vec![4, 9],
            refuted: vec![],
        };
        assert_eq!(
            split.confirmed_within_refuted_range(),
            0,
            "with no lookalikes to remove there is no floor to price"
        );
    }

    #[test]
    fn stability_identical_runs() {
        let (results, _) = self_test_inputs();
        let s = stability(&results, &results);
        assert!(s.identical);
        assert!((s.jaccard - 1.0).abs() < 1e-9);
        assert!(s.churn.abs() < 1e-9);
    }

    #[test]
    fn stability_disjoint_runs() {
        let a = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            findings: vec![finding("f-a", 1.0, vec![fragment("x.rs", 1, 10)])],
        };
        let b = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            findings: vec![finding("f-b", 1.0, vec![fragment("x.rs", 50, 60)])],
        };
        let s = stability(&a, &b);
        assert!(!s.identical);
        assert!(s.jaccard.abs() < 1e-9);
        assert!((s.churn - 1.0).abs() < 1e-9);
    }

    #[test]
    fn stability_partial_overlap_has_known_jaccard() {
        // Shared key K2; A also has K1, B also has K3 -> intersection 1, union 3.
        let k1 = vec![fragment("x.rs", 1, 10)];
        let k2 = vec![fragment("y.rs", 1, 10)];
        let k3 = vec![fragment("z.rs", 1, 10)];
        let a = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            findings: vec![finding("a1", 1.0, k1), finding("a2", 1.0, k2.clone())],
        };
        let b = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            // Different id and clone_type for the shared key: identity is by
            // fragments only.
            findings: vec![
                Finding {
                    size_tokens: 0,
                    id: "b2".to_string(),
                    clone_type: CloneType::Type1,
                    score: 1.0,
                    fragments: k2,
                },
                finding("b3", 1.0, k3),
            ],
        };
        let s = stability(&a, &b);
        assert!(!s.identical);
        assert!((s.jaccard - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn stability_empty_runs_are_identical() {
        let empty = DetectionResult {
            schema_version: 0,
            language: "rust".to_string(),
            findings: vec![],
        };
        let s = stability(&empty, &empty);
        assert!(s.identical);
        assert!((s.jaccard - 1.0).abs() < 1e-9);
    }
}
