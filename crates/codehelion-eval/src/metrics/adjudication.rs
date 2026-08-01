use std::collections::BTreeMap;
use std::fmt;

use crate::labels::LabelSet;
use crate::schema::{Axes, DetectionResult, Finding, Fragment};

use super::{covers, display_measure, matches_pair, ratio};

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
    /// Of the confirmed, those the report put forward rather than filed below
    /// the findings that carry behaviour.
    pub actionable_confirmed: usize,
    /// Of the refuted, those the report put forward.
    pub actionable_refuted: usize,
}

impl Adjudication {
    /// Findings a label ruled on either way.
    #[must_use]
    pub const fn judged(&self) -> usize {
        self.confirmed + self.refuted
    }

    /// Confirmed findings over judged ones, or `None` when nothing was judged.
    ///
    /// Unjudged findings are outside both the numerator and the denominator:
    /// an unlabelled finding is an unasked question, not a wrong answer.
    #[must_use]
    pub fn precision(&self) -> Option<f64> {
        ratio(self.confirmed, self.judged())
    }

    /// Precision over the findings the report put forward.
    ///
    /// The report keeps some findings without asking for them to be read
    /// first, and a reader who stops at the fold never meets those. Overall
    /// precision counts them all the same, which credits or blames the tool
    /// for rows nobody reached. This is the figure the fold was drawn to
    /// improve, so it is the one that says whether drawing it worked.
    #[must_use]
    pub fn actionable_precision(&self) -> Option<f64> {
        ratio(
            self.actionable_confirmed,
            self.actionable_confirmed + self.actionable_refuted,
        )
    }
}

/// Rule `results` against `labels`, scoring only what the labels speak about.
///
/// `threshold` is the overlap threshold for the "covers" relation, as in
/// [`evaluate`](crate::metrics::evaluate).
#[must_use]
pub fn adjudicate(results: &DetectionResult, labels: &LabelSet, threshold: f64) -> Adjudication {
    let mut adjudication = Adjudication {
        confirmed: 0,
        refuted: 0,
        conflicting: 0,
        unjudged: 0,
        actionable_confirmed: 0,
        actionable_refuted: 0,
    };
    for finding in &results.findings {
        match verdict(finding, labels, threshold) {
            Verdict::Conflicting => adjudication.conflicting += 1,
            Verdict::Confirmed => {
                adjudication.confirmed += 1;
                adjudication.actionable_confirmed += usize::from(finding.actionable);
            }
            Verdict::Refuted => {
                adjudication.refuted += 1;
                adjudication.actionable_refuted += usize::from(finding.actionable);
            }
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

    /// Share of the top `k` that a label confirmed, or `None` when nothing was
    /// recorded. `k` past the end scores every entry.
    ///
    /// Ties are broken pessimistically — a refuted finding sorts ahead of a
    /// confirmed one at the same score — so a ranking cannot be credited for
    /// an order it did not actually express.
    #[must_use]
    pub fn precision_at(&self, k: usize) -> Option<f64> {
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
                total += hits as f64 / (position + 1) as f64;
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

/// What each confidence band is worth, as the share of its findings the
/// verdicts confirmed.
///
/// The band says how far past the acceptance threshold a pair's composite
/// similarity sits. Whether that predicts a finding worth reporting is a
/// separate question, and the only way to answer it is to count. It is
/// answered here rather than left to the band's name, which reads like a
/// prediction and is not one.
///
/// Findings the detector never scored — split pairs and fragment runs — are
/// counted under their own key, so the table accounts for every judged
/// finding rather than quietly dropping the unbanded ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BandSplit {
    /// Confirmed and refuted counts per band, keyed by the band's name.
    pub bands: BTreeMap<String, (usize, usize)>,
}

impl BandSplit {
    /// Name a finding without a band is counted under.
    const UNSCORED: &'static str = "(unscored)";

    /// Add every judged finding in `results` to the split.
    ///
    /// Accumulates, so one split can span several corpora.
    pub fn record(&mut self, results: &DetectionResult, labels: &LabelSet, threshold: f64) {
        for finding in &results.findings {
            let band = finding
                .band
                .clone()
                .unwrap_or_else(|| Self::UNSCORED.into());
            let entry = self.bands.entry(band).or_insert((0, 0));
            match verdict(finding, labels, threshold) {
                Verdict::Confirmed => entry.0 += 1,
                Verdict::Refuted => entry.1 += 1,
                Verdict::Conflicting | Verdict::Unjudged => {}
            }
        }
    }
}

impl fmt::Display for BandSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<12}{:>10}{:>9}{:>11}",
            "band", "confirmed", "refuted", "precision"
        )?;
        // Strongest band first, whatever order the names sort in: the point of
        // the table is the trend across bands, and it is unreadable if the
        // rows arrive alphabetically.
        let order = ["high", "medium", "low", Self::UNSCORED];
        let ranked = order
            .iter()
            .filter_map(|name| self.bands.get_key_value(*name))
            .chain(
                self.bands
                    .iter()
                    .filter(|(name, _)| !order.contains(&name.as_str())),
            );
        for (name, &(confirmed, refuted)) in ranked {
            let judged = confirmed + refuted;
            #[allow(clippy::cast_precision_loss)] // counts this size are exact in f64
            let precision = if judged == 0 {
                0.0
            } else {
                confirmed as f64 / judged as f64
            };
            writeln!(f, "{name:<12}{confirmed:>10}{refuted:>9}{precision:>11.4}")?;
        }
        Ok(())
    }
}

/// How much of each class of lookalike still reaches the report.
///
/// Precision says how many findings were wrong; this says what they were wrong
/// about. The two lead to different work: a class the report still shows in
/// numbers is a rule waiting to be written, while a class it no longer shows is
/// one already answered, and the aggregate cannot tell them apart.
///
/// Counted over labels rather than over findings. A finding can cover more than
/// one labelled lookalike, so attributing findings to classes would count the
/// same finding under several names and total to more than there are findings.
/// A label, in contrast, was either reached or it was not.
///
/// A class whose labels are no longer reached is kept in the table at zero. The
/// verdicts stay after the report stops showing them, and a row that reads zero
/// is where a class coming back would appear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReasonSplit {
    /// Per class: labels a finding put forward, labels any finding reached, and
    /// labels recorded.
    pub reasons: BTreeMap<String, (usize, usize, usize)>,
}

impl ReasonSplit {
    /// Add every labelled lookalike in `labels` to the split.
    ///
    /// Accumulates, so one split can span several corpora.
    pub fn record(&mut self, results: &DetectionResult, labels: &LabelSet, threshold: f64) {
        for non_clone in &labels.non_clones {
            let reaching = || {
                results
                    .findings
                    .iter()
                    .filter(|finding| covers(finding, &non_clone.fragments, threshold))
            };
            let entry = self
                .reasons
                .entry(non_clone.reason.clone())
                .or_insert((0, 0, 0));
            entry.0 += usize::from(reaching().any(|finding| finding.actionable));
            entry.1 += usize::from(reaching().next().is_some());
            entry.2 += 1;
        }
    }

    /// The classes the report still puts forward, the most of them first.
    #[must_use]
    pub fn still_reported(&self) -> Vec<(&str, usize, usize, usize)> {
        let mut rows: Vec<_> = self
            .reasons
            .iter()
            .map(|(reason, &(forward, reached, total))| (reason.as_str(), forward, reached, total))
            .collect();
        rows.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.0.cmp(b.0))
        });
        rows
    }
}

impl fmt::Display for ReasonSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<28}{:>13}{:>10}{:>10}",
            "lookalike class", "put forward", "shown", "labelled"
        )?;
        for (reason, forward, reached, total) in self.still_reported() {
            writeln!(f, "{reason:<28}{forward:>13}{reached:>10}{total:>10}")?;
        }
        writeln!(
            f,
            "put forward is what a reader meets first; shown counts the classes \
             filed below them too"
        )
    }
}

/// How far a rule reads off the [substitution
/// witness](codehelion_core::substitution::Witness) gets, and what it costs.
///
/// The rule: every name that differs between two occurrences differs by the
/// same integer width, and no constant changed. That is a set of routines
/// written once per width — the shape a typed language forces on a library and
/// the commonest thing this detector is wrong about — and it is invisible to
/// every measure the report carries, because normalization erased the names
/// before anything looked at them.
///
/// Recorded rather than acted on. What a rule of this kind has to clear is not
/// a precision figure but a counterexample: nothing it reaches may be a clone
/// somebody confirmed, and that has to hold on a project it was not read from.
/// Both numbers are here so the first can be checked on every run and the
/// second by holding a case out.
///
/// Which findings the rule reaches is read from the result rather than worked
/// out again here, so what is scored is the rule the detector applies. Only the
/// gap is measured from the sources, and a finding the gap could not be read
/// from is counted apart: it is still reached, and its verdict still counts.
///
/// The rule says nothing about how much work one occurrence does that the other
/// does not: a routine written for the wider type routinely has a step the
/// narrower one has no need of. Bounding that would mean choosing a number, and
/// three separate attempts to find a number that tells these two populations
/// apart have come to nothing. [`Self::most_edits`] is what stands in for it —
/// not a bound but the largest gap the rule has been seen to span, so a rule
/// that starts reaching further apart says so instead of doing it quietly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WidthFamily {
    /// Confirmed findings the rule reaches. Every one is a counterexample.
    pub confirmed: usize,
    /// Refuted findings the rule reaches.
    pub refuted: usize,
    /// Findings the rule reached whose gap could not be read here.
    pub unalignable: usize,
    /// Judged findings the rule was asked about and did not reach.
    pub untouched: usize,
    /// The most unpaired tokens any finding the rule reached carried.
    pub most_edits: usize,
}

impl WidthFamily {
    /// Add every judged finding in `results`, asking `witness` how far apart
    /// the ones the detector reached actually are.
    ///
    /// Which findings the rule reaches is read from the result, so this scores
    /// the rule the detector applies rather than a second implementation of it.
    /// The witness is only for the gap, and it comes from the caller because it
    /// takes the source the finding was read from, which scoring does not
    /// otherwise open.
    pub fn record(
        &mut self,
        results: &DetectionResult,
        labels: &LabelSet,
        threshold: f64,
        mut witness: impl FnMut(&Finding) -> Option<codehelion_core::substitution::Witness>,
    ) {
        // Both lists, because acting on the rule moves everything it reaches
        // out of the first one. A measurement that only read what the report
        // shows would answer "nothing" the moment the rule was turned on.
        for finding in results.findings.iter().chain(&results.withheld) {
            let confirmed = match verdict(finding, labels, threshold) {
                Verdict::Confirmed => true,
                Verdict::Refuted => false,
                Verdict::Conflicting | Verdict::Unjudged => continue,
            };
            if !finding.width_family {
                self.untouched += 1;
                continue;
            }
            match witness(finding) {
                Some(witness) => self.most_edits = self.most_edits.max(witness.edits),
                None => self.unalignable += 1,
            }
            if confirmed {
                self.confirmed += 1;
            } else {
                self.refuted += 1;
            }
        }
    }
}

impl fmt::Display for WidthFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "written once per width: {} refuted reached, {} confirmed reached, \
             {} not reached, {} reached with no gap read, widest gap {} token(s)",
            self.refuted, self.confirmed, self.untouched, self.unalignable, self.most_edits
        )
    }
}

/// Where the judged findings sit on each similarity axis, split by verdict.
///
/// The sibling of [`SizeSplit`], for the other obvious knob. Length is the
/// first thing anyone reaches for when precision is short; a similarity floor
/// is the second, and it is more tempting because the detector already
/// computes the numbers. The question is the same one — would a floor drop the
/// lookalikes without dropping real clones — and so is the way to answer it:
/// look at both populations on one axis and see whether they separate.
///
/// [`Self::floor_that_costs_nothing`] is the answer in one number per axis. A
/// floor above the lowest confirmed finding is a floor that hides real
/// duplication, so the highest usable one is that finding's value, and what it
/// removes is what the axis is worth as a filter.
///
/// An axis a finding was not scored on is left out of that axis and counted in
/// no other: a split pair has no similarity, and treating its absence as zero
/// would put it under every floor.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AxisSplit {
    /// Per axis name, the values of the confirmed findings, ascending.
    confirmed: BTreeMap<&'static str, Vec<f64>>,
    /// The same for the refuted ones.
    refuted: BTreeMap<&'static str, Vec<f64>>,
}

impl AxisSplit {
    /// Add every judged finding in `results` to the split.
    ///
    /// Accumulates, so one split can span several corpora.
    pub fn record(&mut self, results: &DetectionResult, labels: &LabelSet, threshold: f64) {
        for finding in &results.findings {
            let side = match verdict(finding, labels, threshold) {
                Verdict::Confirmed => &mut self.confirmed,
                Verdict::Refuted => &mut self.refuted,
                Verdict::Conflicting | Verdict::Unjudged => continue,
            };
            for (name, value) in finding.axes.named() {
                if let Some(value) = value {
                    side.entry(name).or_default().push(value);
                }
            }
        }
        for values in self.confirmed.values_mut().chain(self.refuted.values_mut()) {
            values.sort_by(f64::total_cmp);
        }
    }

    /// The highest floor on `axis` that removes no confirmed finding, and how
    /// many refuted ones it would remove.
    ///
    /// `None` where no finding was scored on the axis at all. A count of zero
    /// says the axis is worthless as a filter: the lowest real clone sits at or
    /// below every lookalike, so nothing can be cut without cutting it.
    #[must_use]
    pub fn floor_that_costs_nothing(&self, axis: &str) -> Option<(f64, usize)> {
        let &floor = self.confirmed.get(axis)?.first()?;
        let removed = self
            .refuted
            .get(axis)
            .map_or(0, |values| values.iter().filter(|&&v| v < floor).count());
        Some((floor, removed))
    }

    /// The axes anything was scored on, in report order.
    #[must_use]
    pub fn axes(&self) -> Vec<&'static str> {
        Axes::default()
            .named()
            .iter()
            .map(|&(name, _)| name)
            .filter(|name| self.confirmed.contains_key(name) || self.refuted.contains_key(name))
            .collect()
    }
}

impl fmt::Display for AxisSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<14}{:>18}{:>18}{:>8}{:>13}",
            "axis", "confirmed", "refuted", "floor", "it removes"
        )?;
        let span = |values: Option<&Vec<f64>>| match values.map(Vec::as_slice) {
            Some([first, .., last]) => {
                format!("{first:.2}-{last:.2} (n={})", values.map_or(0, Vec::len))
            }
            Some([only]) => format!("{only:.2} (n=1)"),
            _ => "none".to_owned(),
        };
        for axis in self.axes() {
            let (floor, removed) = self.floor_that_costs_nothing(axis).map_or_else(
                || ("-".to_owned(), "-".to_owned()),
                |(floor, removed)| (format!("{floor:.2}"), removed.to_string()),
            );
            writeln!(
                f,
                "{axis:<14}{:>18}{:>18}{floor:>8}{removed:>13}",
                span(self.confirmed.get(axis)),
                span(self.refuted.get(axis)),
            )?;
        }
        write!(
            f,
            "the floor is the lowest confirmed finding; what it removes is what \
             the axis is worth as a filter"
        )
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
        writeln!(
            f,
            "precision (judged only)   {}",
            display_measure(self.precision())
        )?;
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
