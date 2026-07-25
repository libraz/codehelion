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
//! - **lexical** — how much of the aligned statements' leading tokens match
//!   verbatim; separates a verbatim copy from a renamed one;
//! - **structural** — the statement-summary alignment (a rename-invariant LCS)
//!   folded with the characteristic-vector cosine and the subtree overlap;
//! - **control flow** — the approximate control-flow profiles (a syntactic
//!   approximation, refined by a real CFG in Semantic mode);
//! - **type** — unavailable in Structural mode: there are no resolved types, so
//!   this dimension is `None` and the classification's confidence is penalised
//!   accordingly rather than guessing;
//! - **api** — how much the two call-name multisets overlap.
//!
//! Alignment is a by-product: the LCS backtrace records which statements
//! matched and which are unique to each side, which is the diff `explain`
//! shows. The composite weights are configurable and versioned
//! ([`WEIGHT_VERSION`]); changing them changes findings, so the version travels
//! with the detector identity (AGENTS.md §2-4). Everything here is a pure
//! function of its inputs.

use crate::clone_class::CloneClass;
use crate::features::{ApiCallFeature, CfgFeature, SubtreeFeature, UnitFeatures};
use crate::frontend::Token;
use crate::ir::{IrNode, Shape, StatementSummary};

/// Version of the composite-weight recipe and judgment rules. Bump it when any
/// weight default or classification rule changes, since findings change with
/// it. Recorded as a detector version.
pub const WEIGHT_VERSION: &str = "structural-verify-v0";

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
    pub type3_min_composite: f64,
    /// Composite at or above which a Type-3 finding is high confidence.
    pub high_confidence: f64,
    /// Composite at or above which a Type-3 finding is medium confidence.
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
            type3_min_composite: 0.60,
            high_confidence: 0.85,
            medium_confidence: 0.70,
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

/// Confidence band of a clone finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Strong evidence.
    High,
    /// Moderate evidence.
    Medium,
    /// Weak evidence, near the acceptance threshold.
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
    /// Call-name multiset agreement.
    pub api: f64,
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

/// One unit's inputs to verification: its flattened statement sequence and its
/// extracted features.
#[derive(Debug, Clone, Copy)]
pub struct UnitView<'a> {
    /// The unit's statements, flattened in pre-order (see
    /// [`statement_sequence`]).
    pub statements: &'a [StatementSummary],
    /// The unit's extracted features.
    pub features: &'a UnitFeatures,
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
#[must_use]
pub fn verify(a: &UnitView<'_>, b: &UnitView<'_>, config: &VerifyConfig) -> Verdict {
    let (lcs, alignment) = align(a.statements, b.statements, config);
    let seq_sim = sequence_similarity(lcs, a.statements.len(), b.statements.len());
    let lexical = lexical_similarity(a.statements, b.statements, &alignment);
    let structural = mean3(
        seq_sim,
        a.features.vector.cosine_similarity(&b.features.vector),
        subtree_jaccard(&a.features.subtrees, &b.features.subtrees),
    );
    let control_flow = cfg_similarity(&a.features.cfg, &b.features.cfg);
    let api = api_similarity(&a.features.api, &b.features.api);
    // No resolved types in Structural mode: the dimension is absent, not zero.
    let type_similarity = None;

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
        return if exact(breakdown.lexical) {
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
    api: f64,
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
    add(api, weights.api);
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

/// Lexical agreement: the mean, over aligned statement pairs, of how many
/// leading tokens match verbatim. `1.0` when every aligned pair's head tokens
/// are identical (a verbatim copy); lower when identifiers were renamed.
fn lexical_similarity(
    a: &[StatementSummary],
    b: &[StatementSummary],
    alignment: &Alignment,
) -> f64 {
    if alignment.matched.is_empty() {
        return 0.0;
    }
    let mut total = 0.0;
    for &(i, j) in &alignment.matched {
        total += head_agreement(&a[i].head, &b[j].head);
    }
    total / ratio_denominator(alignment.matched.len())
}

/// Fraction of leading-token positions that carry the same text.
fn head_agreement(a: &[crate::frontend::Lexeme], b: &[crate::frontend::Lexeme]) -> f64 {
    let longest = a.len().max(b.len());
    if longest == 0 {
        return 1.0;
    }
    let equal = a.iter().zip(b).filter(|(x, y)| x == y).count();
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
/// distinct callee names. `1.0` when neither unit calls anything.
fn api_similarity(a: &ApiCallFeature, b: &ApiCallFeature) -> f64 {
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
    sa.sort_unstable();
    sa.dedup();
    sb.sort_unstable();
    sb.dedup();
    set_jaccard(&sa, &sb)
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

    fn summary(shape_tag: u8, head: &[&str]) -> StatementSummary {
        StatementSummary {
            shape_tag,
            native_kind: None,
            head: head.iter().map(|t| Lexeme::from(*t)).collect(),
        }
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
                op_count: 5,
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
        let stmts = vec![summary(3, &["if", "x"]), summary(12, &["let", "y"])];
        let feats = features(counts(4), &[1, 2, 3], 9, &["push", "len"]);
        let view = UnitView {
            statements: &stmts,
            features: &feats,
        };
        let verdict = verify(&view, &view, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type1));
        assert_eq!(verdict.confidence, Some(Confidence::High));
        assert!((verdict.breakdown.composite - 1.0).abs() < 1e-9);
        assert!(verdict.alignment.only_a.is_empty());
        assert!(verdict.alignment.only_b.is_empty());
    }

    #[test]
    fn same_structure_but_renamed_heads_is_a_type2_clone() {
        let a = vec![summary(3, &["if", "acc"]), summary(12, &["let", "count"])];
        let b = vec![summary(3, &["if", "state"]), summary(12, &["let", "seen"])];
        let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
        let va = UnitView {
            statements: &a,
            features: &feats,
        };
        let vb = UnitView {
            statements: &b,
            features: &feats,
        };
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type2));
        assert!(verdict.breakdown.lexical < 1.0);
        assert!((verdict.breakdown.structural - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_gapped_edit_is_a_type3_clone_and_the_gap_shows_in_the_alignment() {
        // b has one extra leading statement; the rest align.
        let a = vec![
            summary(3, &["if"]),
            summary(12, &["let"]),
            summary(4, &["return"]),
        ];
        let b = vec![
            summary(11, &["loop"]),
            summary(3, &["if"]),
            summary(12, &["let"]),
            summary(4, &["return"]),
        ];
        let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
        let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
        let va = UnitView {
            statements: &a,
            features: &fa,
        };
        let vb = UnitView {
            statements: &b,
            features: &fb,
        };
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, Some(CloneClass::Type3));
        // The type dimension is unavailable, so a Type-3 is capped at medium.
        assert_ne!(verdict.confidence, Some(Confidence::High));
        assert_eq!(verdict.alignment.only_b, vec![0]);
        assert_eq!(verdict.alignment.matched.len(), 3);
        assert!(verdict.breakdown.type_similarity.is_none());
    }

    /// A sequence of `len` statements whose shapes cycle, so that alignment is
    /// a real search rather than a run of identical statements.
    fn sequence(len: usize) -> Vec<StatementSummary> {
        (0..len)
            .map(|index| summary(u8::try_from(index % 7).unwrap_or(0), &["let"]))
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
            b.insert(200 + extra, summary(9, &["loop"]));
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
            b.insert(100 + extra, summary(9, &["loop"]));
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
        let a = vec![summary(3, &["if"]), summary(4, &["return"])];
        let b = vec![summary(12, &["let"]), summary(10, &["match"])];
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
        let va = UnitView {
            statements: &a,
            features: &fa,
        };
        let vb = UnitView {
            statements: &b,
            features: &fb,
        };
        let verdict = verify(&va, &vb, &VerifyConfig::default());
        assert_eq!(verdict.class, None);
        assert_eq!(verdict.confidence, None);
    }

    #[test]
    fn the_composite_renormalises_when_type_is_absent() {
        // With type absent, the composite is the weighted mean of the other
        // four dimensions; here all are 1.0 so it must be exactly 1.0.
        let value = composite(&Weights::default(), 1.0, 1.0, 1.0, None, 1.0);
        assert!((value - 1.0).abs() < 1e-9);
        // Present type similarity participates.
        let value = composite(&Weights::default(), 1.0, 1.0, 1.0, Some(0.0), 1.0);
        assert!(value < 1.0);
    }

    #[test]
    fn cfg_similarity_is_one_on_equal_hashes_and_falls_otherwise() {
        let base = CfgFeature {
            hash: FeatureHash::from_bytes([1; 16]),
            op_count: 5,
            max_loop_depth: 1,
            branch_count: 1,
        };
        assert!((cfg_similarity(&base, &base) - 1.0).abs() < 1e-9);
        let other = CfgFeature {
            hash: FeatureHash::from_bytes([2; 16]),
            op_count: 10,
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
        let a = vec![summary(3, &["if"]), summary(12, &["let"])];
        let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
        let view = UnitView {
            statements: &a,
            features: &feats,
        };
        let cfg = VerifyConfig::default();
        assert_eq!(verify(&view, &view, &cfg), verify(&view, &view, &cfg));
    }
}
