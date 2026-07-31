//! Structural-mode weighted verification: the precise judgment of a candidate
//! pair.
//!
//! The candidate stages ([`crate::candidate`], [`crate::near_match`]) propose
//! pairs cheaply and over-approximate; this stage decides. It compares two
//! units across several independent dimensions, keeps every dimension's score
//! rather than collapsing to one opaque number (AGENTS.md §22), and only then
//! forms a composite and a clone classification.
//!
//! The dimensions:
//!
//! - **lexical** — how much of the aligned statements' text matches verbatim;
//!   separates a verbatim copy from a renamed one;
//! - **structural** — the statement-summary alignment (a rename-invariant LCS)
//!   folded with the characteristic-vector cosine and the subtree overlap;
//! - **control flow** — the approximate control-flow profiles (a syntactic
//!   approximation, refined by a real CFG in Semantic mode);
//! - **type** — how much the two units' resolved types agree, as
//!   [`crate::types::TypeEvidence`]. Unavailable in Structural mode, which
//!   resolves no types: the dimension is then `None` and the classification's
//!   confidence is penalised accordingly rather than guessing. Supplying
//!   evidence for both sides is what lifts that penalty, and only a compiler
//!   can supply it;
//! - **api** — how much the two call surfaces overlap. Semantic mode uses
//!   compiler-resolved targets when both units have them; otherwise it retains
//!   Structural mode's call-name comparison. It is unavailable when neither
//!   unit calls anything, since two empty call surfaces are an absence of
//!   evidence rather than agreement.
//!
//! Alignment is a by-product: the LCS backtrace records which statements
//! matched and which are unique to each side, which is the diff `explain`
//! shows. The composite weights are configurable and versioned
//! ([`WEIGHT_VERSION`]); changing them changes findings, so the version travels
//! with the detector identity (AGENTS.md §2-4). Everything here is a pure
//! function of its inputs.
//!
//! # What the composite can and cannot separate
//!
//! The acceptance threshold is what separates clones from lookalikes, and the
//! labelled corpora bound how well it can: functions written to share a
//! skeleton while computing different things score up to 0.69, and the weakest
//! pair that is a real copy scores 0.71.
//! [`VerifyConfig::type3_min_composite`] sits between them.
//!
//! Two properties of that gap are worth stating, because they decide where
//! future accuracy work belongs.
//!
//! First, **lexical is the dimension that discriminates**. Lookalikes agree on
//! shape by construction — that is what makes them lookalikes — so structural
//! and control-flow agreement is high for both populations and only lexical
//! agreement pulls them apart. Weighting shape more heavily than text therefore
//! costs precision rather than buying it, and no reweighting of these five
//! dimensions separates the two populations by more than a hair unless lexical
//! is the one carrying the weight.
//!
//! Second, **a unit can be a genuine clone and still not be worth reporting**.
//! Two one-line accessors are copies of each other by every measure in this
//! module, and they score accordingly. Suppressing them is
//! [`crate::boilerplate`]'s job, not this one's: lowering a similarity score to
//! hide a triviality would corrupt the evidence the score exists to carry.

use crate::clone_class::CloneClass;
use crate::features::{ApiCallFeature, CfgFeature, SubtreeFeature, UnitFeatures};
use crate::frontend::Token;
use crate::ir::{IrNode, Shape, StatementSummary};
use crate::types::{ApiEvidence, TypeEvidence};

/// Version of the composite-weight recipe and judgment rules. Bump it when any
/// weight default or classification rule changes, since findings change with
/// it. Recorded as a detector version.
pub const WEIGHT_VERSION: &str = "structural-verify-v5";

/// Relative weights of the similarity dimensions in the composite score.
///
/// A dimension that is unavailable for a pair (a `None` type similarity in
/// Structural mode) drops out and the remaining weights renormalise, so the
/// composite is always a weighted mean over the dimensions that were actually
/// measured.
#[derive(Debug, Clone, PartialEq)]
pub struct Weights {
    /// Weight of the lexical dimension.
    pub lexical: f64,
    /// Weight of the structural dimension.
    pub structural: f64,
    /// Weight of the control-flow dimension.
    pub control_flow: f64,
    /// Weight of the type dimension, applied only when it is available.
    pub type_similarity: f64,
    /// Weight of the api dimension.
    pub api: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            lexical: 0.20,
            structural: 0.45,
            control_flow: 0.20,
            type_similarity: 0.15,
            api: 0.15,
        }
    }
}

/// Tuning for verification. Thresholds are provisional and calibrated against
/// the mutation corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyConfig {
    /// Composite-score weights.
    pub weights: Weights,
    /// Smallest composite a Type-3 pair must reach to be a clone at all.
    ///
    /// Calibrated against the labelled corpora: the pairs deliberately built
    /// to share a skeleton while computing different things reach 0.69, and
    /// the weakest pair that is a real copy reaches 0.71. The threshold sits
    /// in that gap.
    ///
    /// The gap is narrow, and which side an unlabelled pair falls on is
    /// decided almost entirely by lexical agreement — the lookalikes reach
    /// 0.77 there while the weakest real copy reaches 0.91. A composite near
    /// this threshold is therefore weak evidence by construction, which is
    /// what the low confidence band exists to say.
    pub type3_min_composite: f64,
    /// Composite at or above which a Type-3 finding is high confidence.
    pub high_confidence: f64,
    /// Composite at or above which a Type-3 finding is medium confidence.
    ///
    /// Kept above [`Self::type3_min_composite`], or the low band could never
    /// be reached and a finding sitting just over the acceptance threshold
    /// would be reported as confidently as one well clear of it.
    pub medium_confidence: f64,
    /// Tolerance for treating a similarity as exactly `1.0`.
    pub exact_epsilon: f64,
    /// How far the statement alignment may stray from the diagonal that joins
    /// the two sequences' ends, in statements.
    ///
    /// The band bounds the alignment's cost at `O(min(n, m) * band)` instead
    /// of `O(n * m)`. Widening it can only raise a pair's similarity, so the
    /// banded result is a lower bound: a real clone, whose alignment hugs that
    /// diagonal, is measured exactly, while a pair that would need to wander
    /// further is scored no higher than it deserves.
    pub alignment_band: usize,
    /// Largest alignment table, in cells.
    ///
    /// The band alone bounds the table for units of comparable length; this
    /// bounds it for a pair whose lengths also differ widely, by narrowing the
    /// band further until the table fits. Narrowing only weakens the lower
    /// bound, so nothing is dropped — such a pair cannot align well enough to
    /// be a clone in any case.
    pub max_alignment_cells: usize,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            type3_min_composite: 0.70,
            high_confidence: 0.85,
            medium_confidence: 0.75,
            exact_epsilon: 1e-9,
            // Wide enough that the gapped clones the mode targets — copies
            // with statements inserted or removed — align exactly.
            alignment_band: 64,
            // 4M cells is ~16 MiB of table, reached only by a pair of units
            // in the tens of thousands of statements with lengths far apart.
            max_alignment_cells: 4_000_000,
        }
    }
}

/// How far past the acceptance threshold a finding's composite similarity
/// sits.
///
/// It bands one number and says nothing beyond it. In particular it is not a
/// prediction that the finding is worth acting on, and over hand-labelled real
/// code it runs the other way: the shapes that are alike without being worth
/// reporting — one routine per integer width, one accessor per variant — are
/// alike almost exactly, so they land in the top band. The labelled corpora
/// print the band's measured precision beside this ordering rather than
/// leaving the names to imply one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The two agree well clear of the threshold.
    High,
    /// The two agree, with room between the score and the threshold.
    Medium,
    /// The two agree just past the threshold.
    Low,
}

impl Confidence {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Lower `High` to `Medium`, leaving the other bands unchanged; used to
    /// penalise a Type-3 finding for which no type evidence was available.
    const fn without_type_evidence(self) -> Self {
        match self {
            Self::High | Self::Medium => Self::Medium,
            Self::Low => Self::Low,
        }
    }
}

/// The per-dimension similarity scores and their composite.
///
/// Every dimension stays visible: the composite is a convenience, never a
/// replacement for the breakdown.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SimilarityBreakdown {
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement (a syntactic approximation).
    pub control_flow: f64,
    /// Type agreement, or `None` when types are unavailable (Structural mode).
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit calls
    /// anything and there is therefore nothing to compare.
    pub api: Option<f64>,
    /// Weighted mean of the available dimensions.
    pub composite: f64,
}

/// The statement alignment behind a verdict: the diff `explain` renders.
///
/// Indices are into the two units' statement sequences as passed to
/// [`verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Alignment {
    /// Matched statement index pairs, in order.
    pub matched: Vec<(usize, usize)>,
    /// Indices of statements present only in the first unit.
    pub only_a: Vec<usize>,
    /// Indices of statements present only in the second unit.
    pub only_b: Vec<usize>,
}

impl Alignment {
    /// The same alignment read from the other unit's side.
    ///
    /// An alignment is monotone in both coordinates, so swapping each matched
    /// pair leaves the sequence ordered.
    fn mirrored(self) -> Self {
        Self {
            matched: self.matched.into_iter().map(|(i, j)| (j, i)).collect(),
            only_a: self.only_b,
            only_b: self.only_a,
        }
    }
}

/// One unit's inputs to verification: its flattened statement sequence, the
/// token stream those statements span, and its extracted features.
#[derive(Debug, Clone, Copy)]
pub struct UnitView<'a> {
    /// The unit's statements, flattened in pre-order (see
    /// [`statement_sequence`]).
    pub statements: &'a [StatementSummary],
    /// The whole token stream of the file the statements came from. A
    /// statement span indexes this, so it must be the same stream the
    /// summaries were built against.
    pub tokens: &'a [Token],
    /// The unit's extracted features.
    pub features: &'a UnitFeatures,
    /// The types a compiler resolved inside the unit, when one did.
    ///
    /// `None` in the modes that run no compiler, which is a different claim
    /// from empty evidence: absent means nobody looked, and empty means
    /// somebody looked and found nothing to compare.
    pub types: Option<&'a TypeEvidence>,
    /// The call targets a compiler resolved inside the unit, when both sides
    /// of a comparison can use them. Missing targets deliberately retain the
    /// Structural call-name comparison rather than claiming disagreement.
    pub apis: Option<&'a ApiEvidence>,
}

/// The outcome of verifying a candidate pair.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// The clone class, or `None` when the pair is not a clone.
    pub class: Option<CloneClass>,
    /// Confidence of the classification; `Some` exactly when `class` is.
    pub confidence: Option<Confidence>,
    /// The similarity breakdown.
    pub breakdown: SimilarityBreakdown,
    /// The statement alignment.
    pub alignment: Alignment,
}

/// Flatten a unit subtree into its statement summaries, in pre-order: each
/// block contributes its direct statements before its nested blocks do.
#[must_use]
pub fn statement_sequence(unit: &IrNode, tokens: &[Token]) -> Vec<StatementSummary> {
    let mut out = Vec::new();
    collect_statements(unit, tokens, &mut out);
    out
}

fn collect_statements(node: &IrNode, tokens: &[Token], out: &mut Vec<StatementSummary>) {
    if matches!(node.shape, Shape::Block) {
        out.extend(node.statement_summaries(tokens));
    }
    for child in &node.children {
        collect_statements(child, tokens, out);
    }
}

/// Verify a candidate pair, producing its similarity breakdown, alignment and
/// clone classification.
///
/// The verdict is a property of the pair, not of the order the two units were
/// passed in: several alignments can be equally long, and which one the
/// recurrence settles on depends on which unit leads, so the same two units
/// would otherwise score differently depending on which of them a group picked
/// as its medoid. The pair is therefore ordered by content before measuring,
/// and the alignment is mirrored back so the caller still reads it as
/// `(a, b)`.
#[must_use]
pub fn verify(a: &UnitView<'_>, b: &UnitView<'_>, config: &VerifyConfig) -> Verdict {
    if order_key(b) < order_key(a) {
        let mut verdict = measure(b, a, config);
        verdict.alignment = verdict.alignment.mirrored();
        return verdict;
    }
    measure(a, b, config)
}

/// Content-derived ordering key of one unit.
///
/// Nothing positional enters it: a unit's key must not change because the unit
/// moved within its file.
const fn order_key(unit: &UnitView<'_>) -> (usize, [u8; 16], [u8; 16], u8) {
    (
        unit.statements.len(),
        *unit.features.cfg.hash.as_bytes(),
        *unit.features.api.multiset_hash.as_bytes(),
        unit.features.shape_tag,
    )
}

/// Measure and classify one ordered pair.
fn measure(a: &UnitView<'_>, b: &UnitView<'_>, config: &VerifyConfig) -> Verdict {
    let (lcs, alignment) = align(a.statements, b.statements, config);
    let seq_sim = sequence_similarity(lcs, a.statements.len(), b.statements.len());
    let lexical = lexical_similarity(a, b, &alignment);
    let structural = mean3(
        seq_sim,
        a.features.vector.cosine_similarity(&b.features.vector),
        subtree_jaccard(&a.features.subtrees, &b.features.subtrees),
    );
    let control_flow = cfg_similarity(&a.features.cfg, &b.features.cfg);
    let api = a
        .apis
        .zip(b.apis)
        .and_then(|(a, b)| ApiEvidence::agreement(a, b))
        .or_else(|| api_similarity(&a.features.api, &b.features.api));
    // Absent unless a compiler resolved types for both sides. Structural mode
    // resolves none, and the dimension is then missing rather than zero: a
    // zero would say the two units' types disagree, which nothing measured.
    let type_similarity = a
        .types
        .zip(b.types)
        .and_then(|(a, b)| TypeEvidence::agreement(a, b));

    let composite = composite(
        &config.weights,
        lexical,
        structural,
        control_flow,
        type_similarity,
        api,
    );
    let breakdown = SimilarityBreakdown {
        lexical,
        structural,
        control_flow,
        type_similarity,
        api,
        composite,
    };

    let (class, confidence) = classify(&breakdown, config);
    Verdict {
        class,
        confidence,
        breakdown,
        alignment,
    }
}

/// Classify a breakdown into a clone class and confidence, or `None` when the
/// pair falls below the Type-3 threshold.
fn classify(
    breakdown: &SimilarityBreakdown,
    config: &VerifyConfig,
) -> (Option<CloneClass>, Option<Confidence>) {
    let eps = config.exact_epsilon;
    let exact = |value: f64| (1.0 - value).abs() <= eps;

    // Identical structure: the statement alignment, the shape vector and the
    // subtree set all agree completely.
    if exact(breakdown.structural) {
        // A Type-1 claim says the copies differ only in whitespace and
        // comments. A statement summary keeps just its leading tokens, so a
        // rename further into a statement leaves `lexical` exact; the call
        // surface is the dimension that carries identifier text, and a
        // difference there is evidence of renaming that outranks the silence
        // of the head tokens. Type-2 is then the claim the evidence supports.
        return if exact(breakdown.lexical) && breakdown.api.is_none_or(exact) {
            (Some(CloneClass::Type1), Some(Confidence::High))
        } else {
            (Some(CloneClass::Type2), Some(Confidence::High))
        };
    }
    if breakdown.composite >= config.type3_min_composite {
        let band = if breakdown.composite >= config.high_confidence {
            Confidence::High
        } else if breakdown.composite >= config.medium_confidence {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        // Type-3 leans on structure without type evidence: penalise the band.
        let band = if breakdown.type_similarity.is_none() {
            band.without_type_evidence()
        } else {
            band
        };
        return (Some(CloneClass::Type3), Some(band));
    }
    (None, None)
}

/// The composite: a weighted mean over the dimensions that were measured. A
/// `None` type similarity drops out and the remaining weights renormalise.
fn composite(
    weights: &Weights,
    lexical: f64,
    structural: f64,
    control_flow: f64,
    type_similarity: Option<f64>,
    api: Option<f64>,
) -> f64 {
    let mut acc = 0.0;
    let mut total = 0.0;
    let mut add = |value: f64, weight: f64| {
        acc = value.mul_add(weight, acc);
        total += weight;
    };
    add(lexical, weights.lexical);
    add(structural, weights.structural);
    add(control_flow, weights.control_flow);
    if let Some(api) = api {
        add(api, weights.api);
    }
    if let Some(type_sim) = type_similarity {
        add(type_sim, weights.type_similarity);
    }
    if total > 0.0 { acc / total } else { 0.0 }
}

/// The band of `second` indices row `ia` of the alignment table covers, as an
/// offset range around `ia` itself.
///
/// The range normally contains both `0` (the table's start corner sits on
/// `jb == ia`) and `len_b - len_a` (its end corner), with the configured slack
/// either way, so the trivial paths are never banded out. When that range
/// alone would exceed the cell budget — two very large units of very different
/// lengths — it is narrowed around the start corner instead. A narrower band
/// only weakens the lower bound the alignment reports; it never invents a
/// match.
struct Band {
    /// How far `jb` may lag `ia`.
    back: usize,
    /// How far `jb` may lead `ia`.
    forward: usize,
}

impl Band {
    fn new(len_a: usize, len_b: usize, config: &VerifyConfig) -> Self {
        let slack = config.alignment_band;
        // The end corner sits at `jb - ia == len_b - len_a`, so the longer
        // side gets the length difference on top of the slack.
        let mut back = slack.saturating_add(len_a.saturating_sub(len_b));
        let mut forward = slack.saturating_add(len_b.saturating_sub(len_a));
        let allowed = (config.max_alignment_cells / (len_a + 1)).max(1);
        if back + forward + 1 > allowed {
            // Keep the diagonals nearest the start corner, where the
            // backtrace begins.
            back = back.min((allowed - 1) / 2);
            forward = forward.min(allowed - 1 - back);
        }
        Self { back, forward }
    }

    /// Number of cells per row.
    const fn width(&self) -> usize {
        self.back + self.forward + 1
    }

    /// First `jb` row `ia` covers.
    const fn first(&self, ia: usize) -> usize {
        ia.saturating_sub(self.back)
    }

    /// Last `jb` row `ia` covers, given a `second` of length `len_b`.
    const fn last(&self, ia: usize, len_b: usize) -> usize {
        let end = ia.saturating_add(self.forward);
        if end < len_b { end } else { len_b - 1 }
    }

    /// Index of `(ia, jb)` in the banded table, or `None` when `jb` lies
    /// outside row `ia`'s band.
    fn index(&self, ia: usize, jb: usize) -> Option<usize> {
        let offset = (jb + self.back).checked_sub(ia)?;
        (offset < self.width()).then(|| ia * self.width() + offset)
    }
}

/// The longest common subsequence of two statement sequences under
/// rename-invariant equality — equal shape tag and native kind — with its
/// alignment. Returns the LCS length and the matched/unmatched indices.
///
/// The search is banded: only alignments staying within
/// [`VerifyConfig::alignment_band`] statements of the diagonal joining the two
/// sequences' ends are considered, and the band narrows further if the table
/// would exceed [`VerifyConfig::max_alignment_cells`]. Since every considered
/// alignment is a real common subsequence, the result is a lower bound on the
/// true LCS — never an overestimate — and it is exact for the copy-with-edits
/// shapes the mode targets.
fn align(
    first: &[StatementSummary],
    second: &[StatementSummary],
    config: &VerifyConfig,
) -> (usize, Alignment) {
    let (len_a, len_b) = (first.len(), second.len());
    let band = Band::new(len_a, len_b, config);
    // Row-major banded table: row `ia` holds the cells whose `jb` lies inside
    // the band around `ia`. Out-of-band cells read as zero, which is the
    // identity for the maximum below, so a path that would leave the band is
    // simply not taken.
    let mut dp = vec![0u32; (len_a + 1) * band.width()];
    let at = |dp: &[u32], ia: usize, jb: usize| -> u32 {
        if ia > len_a || jb > len_b {
            return 0;
        }
        band.index(ia, jb).map_or(0, |index| dp[index])
    };
    if len_b > 0 {
        for ia in (0..len_a).rev() {
            for jb in (band.first(ia)..=band.last(ia, len_b)).rev() {
                let value = if summaries_align(&first[ia], &second[jb]) {
                    at(&dp, ia + 1, jb + 1) + 1
                } else {
                    at(&dp, ia + 1, jb).max(at(&dp, ia, jb + 1))
                };
                // `jb` came from row `ia`'s own band, so the cell exists.
                if let Some(index) = band.index(ia, jb) {
                    dp[index] = value;
                }
            }
        }
    }

    let mut alignment = Alignment::default();
    let (mut ia, mut jb) = (0, 0);
    while ia < len_a && jb < len_b {
        if summaries_align(&first[ia], &second[jb]) {
            alignment.matched.push((ia, jb));
            ia += 1;
            jb += 1;
        } else if at(&dp, ia + 1, jb) >= at(&dp, ia, jb + 1) {
            alignment.only_a.push(ia);
            ia += 1;
        } else {
            alignment.only_b.push(jb);
            jb += 1;
        }
    }
    while ia < len_a {
        alignment.only_a.push(ia);
        ia += 1;
    }
    while jb < len_b {
        alignment.only_b.push(jb);
        jb += 1;
    }
    (at(&dp, 0, 0).try_into().unwrap_or(usize::MAX), alignment)
}

/// Two statements align when their shape and native kind match; identifier and
/// literal texts are ignored, so a consistent rename still aligns.
fn summaries_align(a: &StatementSummary, b: &StatementSummary) -> bool {
    a.shape_tag == b.shape_tag && a.native_kind == b.native_kind
}

/// Structural sequence similarity: the LCS as a fraction of the two lengths.
fn sequence_similarity(lcs: usize, n: usize, m: usize) -> f64 {
    if n == 0 && m == 0 {
        return 1.0;
    }
    ratio(2 * lcs, n + m)
}

/// Lexical agreement: the mean, over aligned statement pairs, of how much of
/// their text matches verbatim. `1.0` when every aligned pair reads the same
/// (a verbatim copy); lower when identifiers or literals were changed.
///
/// A compound statement spans its whole body, so the statements nested inside
/// it are measured both on their own and again as part of it. That is
/// deliberate: whether a loop's body was copied wholesale is the evidence that
/// separates a copy from a routine that merely has a loop in the same place,
/// and weighting a construct by how much code it encloses is what makes that
/// evidence count. Comparing each statement's own text instead — a loop header
/// without its body — measurably fails to tell the two apart, because
/// lookalikes share those headers exactly.
fn lexical_similarity(a: &UnitView<'_>, b: &UnitView<'_>, alignment: &Alignment) -> f64 {
    if alignment.matched.is_empty() {
        return 0.0;
    }
    let mut total = 0.0;
    for &(i, j) in &alignment.matched {
        total += text_agreement(
            a.statements[i].tokens(a.tokens),
            b.statements[j].tokens(b.tokens),
        );
    }
    total / ratio_denominator(alignment.matched.len())
}

/// Fraction of token positions that carry the same text, over the longer of
/// the two statements so that extra text counts against the match.
fn text_agreement(a: &[Token], b: &[Token]) -> f64 {
    let longest = a.len().max(b.len());
    if longest == 0 {
        return 1.0;
    }
    let equal = a.iter().zip(b).filter(|(x, y)| x.text == y.text).count();
    ratio(equal, longest)
}

/// Control-flow agreement. Identical control-op hashes score `1.0`; otherwise
/// the score falls with the normalised difference of the shape statistics
/// (op count, loop depth, branch count) — a syntactic approximation.
fn cfg_similarity(a: &CfgFeature, b: &CfgFeature) -> f64 {
    if a.hash == b.hash {
        return 1.0;
    }
    let diff = a.op_count.abs_diff(b.op_count)
        + a.max_loop_depth.abs_diff(b.max_loop_depth)
        + a.branch_count.abs_diff(b.branch_count);
    let scale = (a.op_count + a.max_loop_depth + a.branch_count)
        .max(b.op_count + b.max_loop_depth + b.branch_count);
    if scale == 0 {
        return 1.0;
    }
    1.0 - ratio(diff as usize, scale as usize)
}

/// Jaccard similarity of two subtree-hash sets. `1.0` when both are empty.
fn subtree_jaccard(a: &[SubtreeFeature], b: &[SubtreeFeature]) -> f64 {
    let mut sa: Vec<[u8; 16]> = a.iter().map(|s| *s.hash.as_bytes()).collect();
    let mut sb: Vec<[u8; 16]> = b.iter().map(|s| *s.hash.as_bytes()).collect();
    sa.sort_unstable();
    sa.dedup();
    sb.sort_unstable();
    sb.dedup();
    set_jaccard(&sa, &sb)
}

/// Api agreement: Jaccard of the two call-name multisets, treated as sets of
/// distinct callee names.
///
/// `None` when neither unit calls anything: the dimension then has nothing to
/// compare, and reporting that as perfect agreement would hand every call-free
/// pair the dimension's full weight on no evidence at all.
fn api_similarity(a: &ApiCallFeature, b: &ApiCallFeature) -> Option<f64> {
    let mut sa: Vec<&str> = a
        .names
        .iter()
        .map(crate::frontend::Lexeme::as_str)
        .collect();
    let mut sb: Vec<&str> = b
        .names
        .iter()
        .map(crate::frontend::Lexeme::as_str)
        .collect();
    if sa.is_empty() && sb.is_empty() {
        return None;
    }
    sa.sort_unstable();
    sa.dedup();
    sb.sort_unstable();
    sb.dedup();
    Some(set_jaccard(&sa, &sb))
}

/// Jaccard of two sorted, deduplicated slices. `1.0` when both are empty.
fn set_jaccard<T: Ord>(a: &[T], b: &[T]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (mut i, mut j, mut inter) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - inter;
    ratio(inter, union)
}

/// Arithmetic mean of three scores.
fn mean3(a: f64, b: f64, c: f64) -> f64 {
    (a + b + c) / 3.0
}

/// Lossless `usize` ratio via `u32`, `0.0` when the denominator is zero.
fn ratio(numer: usize, denom: usize) -> f64 {
    let n = u32::try_from(numer).unwrap_or(u32::MAX);
    let d = u32::try_from(denom).unwrap_or(u32::MAX);
    if d == 0 {
        0.0
    } else {
        f64::from(n) / f64::from(d)
    }
}

/// `count` as an `f64` denominator, never zero (callers guard emptiness).
fn ratio_denominator(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX)).max(1.0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::features::{
        ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, SubtreeFeature,
        UnitFeatures, WindowFeature,
    };
    use crate::frontend::Lexeme;
    use crate::ir::ByteRange;
    use crate::types::{ApiEvidence, TypeTag};

    /// A statement with no text of its own. Enough for the tests that only
    /// exercise alignment, which reads shapes and never the tokens.
    fn summary(shape_tag: u8) -> StatementSummary {
        StatementSummary {
            shape_tag,
            native_kind: None,
            token_start: 0,
            token_end: 0,
        }
    }

    /// A statement sequence and the token stream it spans, built together: a
    /// statement's span is only meaningful against the stream it was cut from,
    /// so a test that cares about text has to own both.
    struct Statements {
        tokens: Vec<Token>,
        summaries: Vec<StatementSummary>,
    }

    impl Statements {
        fn view<'a>(&'a self, features: &'a UnitFeatures) -> UnitView<'a> {
            UnitView {
                statements: &self.summaries,
                tokens: &self.tokens,
                features,
                types: None,
                apis: None,
            }
        }

        fn view_typed<'a>(
            &'a self,
            features: &'a UnitFeatures,
            types: &'a TypeEvidence,
        ) -> UnitView<'a> {
            UnitView {
                types: Some(types),
                ..self.view(features)
            }
        }

        fn view_with_apis<'a>(
            &'a self,
            features: &'a UnitFeatures,
            apis: &'a ApiEvidence,
        ) -> UnitView<'a> {
            UnitView {
                apis: Some(apis),
                ..self.view(features)
            }
        }
    }

    /// Build statements from `(shape tag, token texts)` pairs, laying the
    /// tokens out consecutively.
    fn statements(spec: &[(u8, &[&str])]) -> Statements {
        let mut built = Statements {
            tokens: Vec::new(),
            summaries: Vec::new(),
        };
        for &(shape_tag, texts) in spec {
            let token_start = built.tokens.len();
            for text in texts {
                let start_byte = built.tokens.len() * 8;
                built.tokens.push(Token {
                    kind: crate::frontend::TokenKind::Identifier,
                    text: Lexeme::from(*text),
                    span: crate::frontend::SourceSpan {
                        start_byte,
                        end_byte: start_byte + text.len(),
                        start_line: 1,
                        start_column: 1,
                    },
                });
            }
            built.summaries.push(StatementSummary {
                shape_tag,
                native_kind: None,
                token_start,
                token_end: built.tokens.len(),
            });
        }
        built
    }

    /// Features with a chosen characteristic vector, subtree-hash set, cfg hash
    /// and api names, enough to drive each dimension.
    fn features(vector_counts: [u32; 23], subtrees: &[u8], cfg: u8, api: &[&str]) -> UnitFeatures {
        let subtrees = subtrees
            .iter()
            .map(|&seed| SubtreeFeature {
                hash: FeatureHash::from_bytes([seed; 16]),
                node_count: 6,
                range: ByteRange { start: 0, end: 8 },
            })
            .collect();
        UnitFeatures {
            name: None,
            shape_tag: 1,
            range: ByteRange { start: 0, end: 100 },
            windows: Vec::<WindowFeature>::new(),
            subtrees,
            vector: CharacteristicVector {
                counts: vector_counts,
                max_depth: 4,
                node_count: vector_counts.iter().sum(),
            },
            cfg: CfgFeature {
                hash: FeatureHash::from_bytes([cfg; 16]),
                skeleton_hash: FeatureHash::from_bytes([cfg; 16]),
                op_count: 5,
                skeleton_ops: 5,
                max_loop_depth: 1,
                branch_count: 1,
            },
            api: ApiCallFeature {
                names: api.iter().map(|n| Lexeme::from(*n)).collect(),
                sequence_hash: FeatureHash::from_bytes([0; 16]),
                multiset_hash: FeatureHash::from_bytes([0; 16]),
            },
        }
    }

    fn counts(fill: u32) -> [u32; 23] {
        let mut c = [0u32; 23];
        c[1] = fill;
        c[6] = fill / 2;
        c
    }

    #[test]
    fn identical_units_are_a_type1_clone() {
        let stmts = statements(&[(3, &["if", "x"]), (12, &["let", "y"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &["push", "len"]);
        let view = stmts.view(&feats);
        let verdict = verify(&view, &view, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type1));
        assert_eq!(verdict.confidence, Some(Confidence::High));
        assert!((verdict.breakdown.composite - 1.0).abs() < 1e-9);
        assert!(verdict.alignment.only_a.is_empty());
        assert!(verdict.alignment.only_b.is_empty());
    }

    #[test]
    fn same_structure_but_renamed_heads_is_a_type2_clone() {
        let a = statements(&[(3, &["if", "acc"]), (12, &["let", "count"])]);
        let b = statements(&[(3, &["if", "state"]), (12, &["let", "seen"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
        let va = a.view(&feats);
        let vb = b.view(&feats);
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type2));
        assert!(verdict.breakdown.lexical < 1.0);
        assert!((verdict.breakdown.structural - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_rename_past_the_opening_tokens_still_shows_in_the_text() {
        // The two statements open identically and diverge only afterwards.
        // Reading a fixed number of leading tokens would call this pair
        // verbatim and hand it a Type-1 classification, which asserts the two
        // units differ in nothing but whitespace — a claim this pair does not
        // support. The whole statement is compared for exactly this reason.
        let a = statements(&[(12, &["let", "total", "=", "first", "+", "second"])]);
        let b = statements(&[(12, &["let", "total", "=", "first", "-", "third"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &[]);
        let verdict = verify(&a.view(&feats), &b.view(&feats), &VerifyConfig::default());
        assert!(
            verdict.breakdown.lexical < 1.0,
            "the divergence past the opening tokens must show, got {}",
            verdict.breakdown.lexical
        );
        assert_ne!(verdict.class, Some(CloneClass::Type1));
        // Four of the six tokens still agree, so this is a near-copy, not a
        // pair with nothing in common.
        assert!((verdict.breakdown.lexical - 4.0 / 6.0).abs() < 1e-9);
    }

    #[test]
    fn a_compound_statement_is_compared_over_everything_it_encloses() {
        // A statement's span covers its body, so two loops that open the same
        // way but enclose different code do not read as the same statement.
        let a = statements(&[(7, &["for", "row", "in", "rows", "total", "+=", "row"])]);
        let b = statements(&[(7, &["for", "row", "in", "rows", "widest", "=", "row"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &[]);
        let verdict = verify(&a.view(&feats), &b.view(&feats), &VerifyConfig::default());
        // The four header tokens and the trailing operand agree; the two the
        // body differs in do not. Had only the header been read, the pair
        // would have scored a verbatim match on a body that was rewritten.
        assert!(
            (verdict.breakdown.lexical - 5.0 / 7.0).abs() < 1e-9,
            "five of the seven tokens agree, got {}",
            verdict.breakdown.lexical
        );
    }

    #[test]
    fn a_renamed_call_surface_is_type2_however_quiet_the_heads_are() {
        // Both sides read identically and their structure is identical, so
        // the only dimension carrying the rename is the call surface. This is
        // the case the api dimension exists for: the statements cannot show a
        // difference the features do.
        let stmts = statements(&[(3, &["let", "x", "=", "y"])]);
        let fa = features(counts(4), &[1, 2, 3], 9, &["abs", "min"]);
        let fb = features(counts(4), &[1, 2, 3], 9, &["signum", "rem_euclid"]);
        let va = stmts.view(&fa);
        let vb = stmts.view(&fb);
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert!((verdict.breakdown.lexical - 1.0).abs() < 1e-9);
        assert!((verdict.breakdown.structural - 1.0).abs() < 1e-9);
        assert_eq!(verdict.breakdown.api, Some(0.0));
        assert_eq!(verdict.class, Some(CloneClass::Type2));
    }

    #[test]
    fn two_call_free_units_have_no_api_dimension_rather_than_a_perfect_one() {
        // Neither unit calls anything, so there is no call surface to compare.
        // Scoring that as agreement would hand the dimension's whole weight to
        // every pair of call-free units on no evidence, which is exactly the
        // shape of code — small helpers — where a false positive is cheapest
        // to produce.
        let a = statements(&[(12, &["let", "total"]), (4, &["return"])]);
        let b = statements(&[(12, &["let", "count"]), (4, &["return"])]);
        let fa = features(counts(4), &[1, 2, 3], 9, &[]);
        let fb = features(counts(5), &[1, 2, 4], 8, &[]);
        let va = a.view(&fa);
        let vb = b.view(&fb);
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.breakdown.api, None);

        // The composite is the mean over what was measured, so the absent
        // dimension does not quietly pull the score towards 1.0.
        let weights = Weights::default();
        let measured = weights.lexical + weights.structural + weights.control_flow;
        let expected = weights.lexical.mul_add(
            verdict.breakdown.lexical,
            weights.structural.mul_add(
                verdict.breakdown.structural,
                weights.control_flow * verdict.breakdown.control_flow,
            ),
        ) / measured;
        assert!((verdict.breakdown.composite - expected).abs() < 1e-9);
    }

    #[test]
    fn a_call_free_verbatim_copy_is_still_a_type1_clone() {
        // An absent dimension is not evidence against the strong claim: with
        // nothing to compare, it cannot contradict identical structure and
        // identical heads.
        let stmts = statements(&[(12, &["let", "total"]), (4, &["return"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &[]);
        let view = stmts.view(&feats);
        let verdict = verify(&view, &view, &VerifyConfig::default());
        assert_eq!(verdict.breakdown.api, None);
        assert_eq!(verdict.class, Some(CloneClass::Type1));
        assert!((verdict.breakdown.composite - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_pair_scores_the_same_whichever_unit_leads() {
        // `a` opens with a `let` the other side lacks and continues with `let`s
        // that repeat, so two alignments are equally long: one skips `a`'s
        // opening statement and matches the repeated ones verbatim, the other
        // matches the opening statement and pays for its differing head. Which
        // one the recurrence settles on follows the order of the arguments, so
        // the lexical dimension moves with it.
        let a = statements(&[
            (12, &["let", "seen"]),
            (12, &["let", "total"]),
            (12, &["let", "total"]),
            (12, &["let", "total"]),
        ]);
        let b = statements(&[
            (4, &["return", "total"]),
            (12, &["let", "total"]),
            (12, &["let", "total"]),
        ]);
        let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push"]);
        let fb = features(counts(5), &[1, 2, 3], 8, &["push"]);
        let va = a.view(&fa);
        let vb = b.view(&fb);
        let forward = verify(&va, &vb, &VerifyConfig::default());
        let backward = verify(&vb, &va, &VerifyConfig::default());
        assert_eq!(forward.breakdown, backward.breakdown);
        assert_eq!(forward.class, backward.class);
        assert_eq!(forward.confidence, backward.confidence);
        // The alignment is reported from the caller's side either way.
        assert_eq!(forward.alignment.only_a, backward.alignment.only_b);
        assert_eq!(forward.alignment.only_b, backward.alignment.only_a);
        let mirrored: Vec<(usize, usize)> = backward
            .alignment
            .matched
            .iter()
            .map(|&(i, j)| (j, i))
            .collect();
        assert_eq!(forward.alignment.matched, mirrored);
    }

    #[test]
    fn a_gapped_edit_is_a_type3_clone_and_the_gap_shows_in_the_alignment() {
        // b has one extra leading statement; the rest align.
        let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
        let b = statements(&[
            (11, &["loop"]),
            (3, &["if"]),
            (12, &["let"]),
            (4, &["return"]),
        ]);
        let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
        let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
        let va = a.view(&fa);
        let vb = b.view(&fb);
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type3));
        // The type dimension is unavailable, so a Type-3 is capped at medium.
        assert_ne!(verdict.confidence, Some(Confidence::High));
        assert_eq!(verdict.alignment.only_b, vec![0]);
        assert_eq!(verdict.alignment.matched.len(), 3);
        assert!(verdict.breakdown.type_similarity.is_none());
    }

    /// The same pair with a compiler's answer about its types. The dimension
    /// appears, and the cap that stood in for it is lifted: the band was
    /// lowered because nothing had looked, not because something had looked and
    /// disagreed.
    #[test]
    fn resolved_types_supply_the_dimension_that_was_standing_in_for_them() {
        let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
        let b = statements(&[
            (11, &["loop"]),
            (3, &["if"]),
            (12, &["let"]),
            (4, &["return"]),
        ]);
        let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
        let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
        let same = TypeEvidence::from_tags([TypeTag::Integer, TypeTag::Sequence]);

        let untyped = verify(&a.view(&fa), &b.view(&fb), &VerifyConfig::default());
        let typed = verify(
            &a.view_typed(&fa, &same),
            &b.view_typed(&fb, &same),
            &VerifyConfig::default(),
        );
        assert_eq!(typed.class, Some(CloneClass::Type3));
        assert_eq!(typed.breakdown.type_similarity, Some(1.0));
        assert_eq!(typed.confidence, Some(Confidence::High));
        assert_ne!(untyped.confidence, typed.confidence);
    }

    /// Evidence that disagrees is evidence: it lowers the composite rather than
    /// leaving the dimension out, which is the whole difference between a
    /// measurement and its absence.
    #[test]
    fn types_that_disagree_are_not_the_same_as_types_nobody_resolved() {
        let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
        let b = statements(&[
            (11, &["loop"]),
            (3, &["if"]),
            (12, &["let"]),
            (4, &["return"]),
        ]);
        let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
        let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
        let numbers = TypeEvidence::from_tags([TypeTag::Integer, TypeTag::Integer]);
        let maps = TypeEvidence::from_tags([TypeTag::Mapping, TypeTag::Mapping]);

        let untyped = verify(&a.view(&fa), &b.view(&fb), &VerifyConfig::default());
        let disagreeing = verify(
            &a.view_typed(&fa, &numbers),
            &b.view_typed(&fb, &maps),
            &VerifyConfig::default(),
        );
        assert_eq!(disagreeing.breakdown.type_similarity, Some(0.0));
        assert!(
            disagreeing.breakdown.composite < untyped.breakdown.composite,
            "{} !< {}",
            disagreeing.breakdown.composite,
            untyped.breakdown.composite
        );
    }

    /// Compiler identities distinguish calls that the Structural lexer sees
    /// under the same source spelling. The fallback remains useful when only
    /// one side was resolved, so an unavailable helper does not turn evidence
    /// into a synthetic mismatch.
    #[test]
    fn resolved_api_targets_refine_call_names_without_penalising_missing_data() {
        let a = statements(&[(3, &["run"])]);
        let b = statements(&[(3, &["run"])]);
        let features = features(counts(1), &[1], 1, &["run"]);
        let left = ApiEvidence::from_targets(["static:crate::left::run".to_string()]);
        let right = ApiEvidence::from_targets(["static:crate::right::run".to_string()]);

        let structural = verify(
            &a.view(&features),
            &b.view(&features),
            &VerifyConfig::default(),
        );
        let semantic = verify(
            &a.view_with_apis(&features, &left),
            &b.view_with_apis(&features, &right),
            &VerifyConfig::default(),
        );
        let partial = verify(
            &a.view_with_apis(&features, &left),
            &b.view(&features),
            &VerifyConfig::default(),
        );
        assert_eq!(structural.breakdown.api, Some(1.0));
        assert_eq!(semantic.breakdown.api, Some(0.0));
        assert_eq!(partial.breakdown.api, Some(1.0));
    }

    /// A sequence of `len` statements whose shapes cycle, so that alignment is
    /// a real search rather than a run of identical statements.
    fn sequence(len: usize) -> Vec<StatementSummary> {
        (0..len)
            .map(|index| summary(u8::try_from(index % 7).unwrap_or(0)))
            .collect()
    }

    #[test]
    fn the_band_recovers_the_exact_alignment_of_a_gapped_copy() {
        // A copy with a run of statements inserted in the middle: the edit is
        // well inside the band, so the banded search finds the whole original
        // sequence, exactly as an unbounded one would.
        let a = sequence(400);
        let mut b = a.clone();
        for extra in 0..16 {
            b.insert(200 + extra, summary(9));
        }
        let (lcs, alignment) = align(&a, &b, &VerifyConfig::default());
        assert_eq!(lcs, a.len());
        assert_eq!(alignment.matched.len(), a.len());
        assert!(alignment.only_a.is_empty());
        assert_eq!(alignment.only_b.len(), 16);
    }

    #[test]
    fn a_narrower_band_never_reports_more_than_a_wider_one() {
        // The gap is wider than the narrow band, so the narrow search cannot
        // follow the alignment across it; what it reports stays a real common
        // subsequence, never an overestimate.
        let a = sequence(200);
        let mut b = a.clone();
        for extra in 0..80 {
            b.insert(100 + extra, summary(9));
        }
        let narrow = VerifyConfig {
            alignment_band: 4,
            ..VerifyConfig::default()
        };
        let (narrow_lcs, _) = align(&a, &b, &narrow);
        let (wide_lcs, _) = align(&a, &b, &VerifyConfig::default());
        assert_eq!(wide_lcs, a.len());
        assert!(
            narrow_lcs <= wide_lcs,
            "narrow band reported {narrow_lcs}, above the wider band's {wide_lcs}"
        );
    }

    #[test]
    fn the_cell_ceiling_bounds_a_pair_of_very_different_lengths() {
        // Lengths far enough apart that the diagonal span alone would dominate
        // the table; the ceiling narrows the band instead of letting it grow.
        let a = sequence(64);
        let b = sequence(4096);
        let config = VerifyConfig {
            max_alignment_cells: 8_000,
            ..VerifyConfig::default()
        };
        let band = Band::new(a.len(), b.len(), &config);
        assert!(
            (a.len() + 1) * band.width() <= config.max_alignment_cells,
            "table of {} cells exceeds the ceiling",
            (a.len() + 1) * band.width()
        );
        // The band still covers the start corner, so the search begins where
        // the backtrace does.
        assert_eq!(band.first(0), 0);
        // And it still produces a real alignment.
        let (lcs, alignment) = align(&a, &b, &config);
        assert!(lcs <= a.len());
        assert_eq!(alignment.matched.len() + alignment.only_a.len(), a.len());
    }

    #[test]
    fn unrelated_units_are_not_a_clone() {
        let a = statements(&[(3, &["if"]), (4, &["return"])]);
        let b = statements(&[(12, &["let"]), (10, &["match"])]);
        let fa = features(counts(4), &[1, 2], 9, &["push"]);
        let fb = features(counts(1), &[7, 8], 5, &["draw"]);
        // Give the vectors nothing in common.
        let mut cb = [0u32; 23];
        cb[10] = 4;
        let fb = UnitFeatures {
            vector: CharacteristicVector {
                counts: cb,
                ..fb.vector
            },
            ..fb
        };
        let va = a.view(&fa);
        let vb = b.view(&fb);
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, None);
        assert_eq!(verdict.confidence, None);
    }

    #[test]
    fn the_composite_renormalises_when_type_is_absent() {
        // With type absent, the composite is the weighted mean of the other
        // four dimensions; here all are 1.0 so it must be exactly 1.0.
        let value = composite(&Weights::default(), 1.0, 1.0, 1.0, None, Some(1.0));
        assert!((value - 1.0).abs() < 1e-9);
        // Present type similarity participates.
        let value = composite(&Weights::default(), 1.0, 1.0, 1.0, Some(0.0), Some(1.0));
        assert!(value < 1.0);
    }

    #[test]
    fn cfg_similarity_is_one_on_equal_hashes_and_falls_otherwise() {
        let base = CfgFeature {
            hash: FeatureHash::from_bytes([1; 16]),
            skeleton_hash: FeatureHash::from_bytes([1; 16]),
            op_count: 5,
            skeleton_ops: 5,
            max_loop_depth: 1,
            branch_count: 1,
        };
        assert!((cfg_similarity(&base, &base) - 1.0).abs() < 1e-9);
        let other = CfgFeature {
            hash: FeatureHash::from_bytes([2; 16]),
            skeleton_hash: FeatureHash::from_bytes([2; 16]),
            op_count: 10,
            skeleton_ops: 10,
            max_loop_depth: 2,
            branch_count: 3,
        };
        let sim = cfg_similarity(&base, &other);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn set_jaccard_handles_empty_and_partial_overlap() {
        assert!((set_jaccard::<u8>(&[], &[]) - 1.0).abs() < 1e-9);
        assert!((set_jaccard(&[1, 2, 3], &[2, 3, 4]) - 0.5).abs() < 1e-9);
        assert!(set_jaccard(&[1, 2], &[3, 4]).abs() < 1e-9);
    }

    #[test]
    fn verification_is_deterministic() {
        let a = statements(&[(3, &["if"]), (12, &["let"])]);
        let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
        let view = a.view(&feats);
        let cfg = VerifyConfig::default();
        assert_eq!(verify(&view, &view, &cfg), verify(&view, &view, &cfg));
    }
}
