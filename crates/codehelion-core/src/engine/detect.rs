//! The two detection passes.
//!
//! The raw pass finds Type-1 clones: winnowed k-gram fingerprints over raw
//! tokens seed candidate positions, every seed is verified token-by-token,
//! then extended to a maximal equal run that never crosses a function
//! boundary. Runs nested inside a larger run of the same file pair are
//! dropped.
//!
//! The fragment pass finds Type-2 clones: candidate fragments (bodies, loop
//! and branch bodies, statement runs) are normalized scope-locally and grouped
//! by whole-fragment content. Equal normal forms with unequal raw text are
//! renamed copies. Verbatim fragment matches are left to the raw pass, which
//! reports them at maximal extent.
//!
//! Candidate-explosion control happens before pairing, not after: fingerprints
//! whose posting list exceeds the cap are dropped (and counted), and a global
//! pair budget bounds the quadratic pairing step. Fingerprints are paired
//! rarest-first, so when the budget runs out the low-signal, high-frequency
//! candidates are the ones sacrificed — and the report says so.

#![allow(clippy::redundant_pub_crate)] // internal helpers reached from the engine root

use std::collections::BTreeMap;

use crate::frontend::Token;

use super::fingerprint::{
    ContentDigest, kgram_hashes, norm_sequence_digest, norm_sequence_hash, raw_sequence_digest,
    raw_sequence_hash, raw_token_hash, winnow,
};
use super::normalize::{NormToken, normalize_into};
use super::segment::{self, SegmentId};
use super::{CloneClass, ClonePair, EngineConfig, EngineStats, InputFile, Instance};

/// Remaining candidate-pair allowance shared by both passes.
pub(crate) struct PairBudget {
    remaining: usize,
    exhausted: bool,
}

impl PairBudget {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    /// Take one complete candidate class from the budget.
    ///
    /// Pairing only a prefix of a class would turn a seven-instance clone
    /// into an arbitrary three-instance group when the budget runs out. The
    /// passes visit classes shortest-first, so the first class that does not
    /// fit is no more expensive than any remaining class and ends pairing.
    const fn take_list(&mut self, wanted: usize) -> bool {
        if wanted > self.remaining {
            self.exhausted = true;
            return false;
        }
        self.remaining -= wanted;
        true
    }

    pub(crate) const fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Pairs a posting list or fragment class of `len` members holds.
const fn pairs_within(len: usize) -> usize {
    len.saturating_mul(len.saturating_sub(1)) / 2
}

/// Raw token equality: kind and text, ignoring position.
fn tokens_eq(a: &Token, b: &Token) -> bool {
    a.kind == b.kind && a.text == b.text
}

/// A fingerprint occurrence: `(file index, token position)`.
type Posting = (usize, usize);

/// A fragment occurrence: `(file index, token start, token end)`.
type FragmentRef = (usize, usize, usize);

/// One pairing class of the raw pass: `(size, hash, postings)`.
type RawClass<'a> = (usize, u64, &'a [(u64, Posting)]);

/// One pairing class of the fragment pass: `(size, key, members)`.
type FragmentClass = (usize, u64, ContentDigest, Vec<FragmentRef>);

/// A verified Type-2 candidate, before nested-pair filtering.
#[derive(Debug, Clone, Copy)]
struct FragmentMatch {
    key: u64,
    digest: ContentDigest,
    a: FragmentRef,
    b: FragmentRef,
    score: f64,
}

impl FragmentMatch {
    /// Whether `self` is nested inside `other` on both sides.
    fn nested_in(&self, other: &Self) -> bool {
        if self.a == other.a && self.b == other.b {
            return false; // the same match is not "nested"
        }
        let (fa, sa, ea) = self.a;
        let (fb, sb, eb) = self.b;
        let (ofa, osa, oea) = other.a;
        let (ofb, osb, oeb) = other.b;
        ofa == fa && ofb == fb && osa <= sa && ea <= oea && osb <= sb && eb <= oeb
    }
}

/// A maximal matched run between two files (possibly the same file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Run {
    file_a: usize,
    file_b: usize,
    a_start: usize,
    b_start: usize,
    len: usize,
}

/// Build one instance, resolving line range and enclosing-unit anchor.
fn instance(
    files: &[InputFile<'_>],
    anchors: &[Vec<Option<usize>>],
    file: usize,
    token_start: usize,
    token_end: usize,
) -> Instance {
    let tokens = files[file].tokens;
    let first = &tokens[token_start];
    let last = &tokens[token_end - 1];
    let newlines = u32::try_from(last.text.matches('\n').count()).unwrap_or(0);
    Instance {
        file,
        token_start,
        token_end,
        start_line: first.span.start_line,
        end_line: last.span.start_line.saturating_add(newlines),
        unit: anchors[file][token_start],
    }
}

/// Extend a verified seed to a maximal equal run within one segment per side.
fn extend(
    a: &[Token],
    b: &[Token],
    seg_a: &[SegmentId],
    seg_b: &[SegmentId],
    ai: usize,
    bi: usize,
    k: usize,
) -> (usize, usize, usize) {
    let sa = seg_a[ai];
    let sb = seg_b[bi];
    let mut start_a = ai;
    let mut start_b = bi;
    while start_a > 0
        && start_b > 0
        && seg_a[start_a - 1] == sa
        && seg_b[start_b - 1] == sb
        && tokens_eq(&a[start_a - 1], &b[start_b - 1])
    {
        start_a -= 1;
        start_b -= 1;
    }
    let mut end_a = ai + k;
    let mut end_b = bi + k;
    while end_a < a.len()
        && end_b < b.len()
        && seg_a[end_a] == sa
        && seg_b[end_b] == sb
        && tokens_eq(&a[end_a], &b[end_b])
    {
        end_a += 1;
        end_b += 1;
    }
    (start_a, start_b, end_a - start_a)
}

/// An offline two-dimensional range index for the second half of a run pair.
///
/// The outer sweep admits only runs whose first span begins no later than the
/// current one. Each Fenwick node covers a prefix of second-span starts and
/// stores a second Fenwick tree of first-span ends, whose values are the
/// greatest matching second-span end. A query consequently answers all three
/// remaining containment conditions without scanning a file-pair bucket.
struct ContainmentIndex {
    /// Sorted unique second-span starts.
    second_starts: Vec<usize>,
    /// Per outer Fenwick node, sorted unique first-span ends that can enter it.
    first_ends: Vec<Vec<usize>>,
    /// Per outer Fenwick node, a max Fenwick tree over reversed first-end
    /// positions. Reversing turns an `end >= threshold` query into a prefix.
    greatest_second_end: Vec<Vec<usize>>,
}

impl ContainmentIndex {
    fn for_runs(runs: &[Run]) -> Self {
        let mut second_starts: Vec<usize> = runs.iter().map(|run| run.b_start).collect();
        second_starts.sort_unstable();
        second_starts.dedup();
        let mut first_ends = vec![Vec::new(); second_starts.len() + 1];
        for run in runs {
            let mut node = second_starts.partition_point(|&start| start < run.b_start) + 1;
            let first_end = run.a_start + run.len;
            while node < first_ends.len() {
                first_ends[node].push(first_end);
                node += lowbit(node);
            }
        }
        for ends in &mut first_ends {
            ends.sort_unstable();
            ends.dedup();
        }
        let greatest_second_end = first_ends
            .iter()
            .map(|ends| vec![0; ends.len() + 1])
            .collect();
        Self {
            second_starts,
            first_ends,
            greatest_second_end,
        }
    }

    /// Record a possible outer run.
    fn insert(&mut self, run: Run) {
        let mut node = self
            .second_starts
            .partition_point(|&start| start < run.b_start)
            + 1;
        let first_end = run.a_start + run.len;
        let second_end = run.b_start + run.len;
        while node < self.first_ends.len() {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < first_end);
            let values = &mut self.greatest_second_end[node];
            let mut position = reversed;
            while position < values.len() {
                values[position] = values[position].max(second_end);
                position += lowbit(position);
            }
            node += lowbit(node);
        }
    }

    /// Whether an already inserted run contains `run` on both spans.
    fn contains(&self, run: Run) -> bool {
        let first_end = run.a_start + run.len;
        let second_end = run.b_start + run.len;
        let mut node = self
            .second_starts
            .partition_point(|&start| start <= run.b_start);
        while node > 0 {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < first_end);
            let values = &self.greatest_second_end[node];
            let mut position = reversed;
            let mut greatest = 0;
            while position > 0 {
                greatest = greatest.max(values[position]);
                position -= lowbit(position);
            }
            if greatest >= second_end {
                return true;
            }
            node -= lowbit(node);
        }
        false
    }
}

/// Least significant set bit of a one-based Fenwick index.
const fn lowbit(index: usize) -> usize {
    index & index.wrapping_neg()
}

/// Drop duplicate runs, then every run nested inside a larger run of the
/// same file pair.
///
/// Nesting is only possible between runs of the same `(file_a, file_b)` pair.
/// A start-offset sweep plus [`ContainmentIndex`] finds a covering pair in
/// O(m log² m), preserving the old two-span containment rule without a
/// quadratic scan through a generated-code bucket.
fn drop_nested(mut all: Vec<Run>) -> Vec<Run> {
    all.sort_unstable();
    all.dedup();
    let mut kept = Vec::new();
    for bucket in all.chunk_by(|a, b| (a.file_a, a.file_b) == (b.file_a, b.file_b)) {
        let mut ordered = bucket.to_vec();
        ordered.sort_by_key(|run| {
            (
                run.a_start,
                std::cmp::Reverse(run.a_start + run.len),
                run.b_start,
                std::cmp::Reverse(run.b_start + run.len),
            )
        });
        let mut index = ContainmentIndex::for_runs(&ordered);
        for run in ordered {
            if !index.contains(run) {
                index.insert(run);
                kept.push(run);
            }
        }
    }
    kept.sort_unstable();
    kept
}

/// Drop every match nested inside a larger match of the same file pair.
///
/// [`FragmentMatch::nested_in`] can only hold between matches of the same
/// file pair, so matches are bucketed by that pair first and the pairwise
/// containment check runs inside each bucket instead of scanning all matches.
fn drop_nested_matches(matches: Vec<FragmentMatch>) -> Vec<FragmentMatch> {
    let mut buckets: BTreeMap<(usize, usize), Vec<FragmentMatch>> = BTreeMap::new();
    for m in matches {
        buckets.entry((m.a.0, m.b.0)).or_default().push(m);
    }
    let mut kept: Vec<FragmentMatch> = Vec::new();
    for bucket in buckets.values() {
        kept.extend(
            bucket
                .iter()
                .filter(|m| !bucket.iter().any(|o| m.nested_in(o)))
                .copied(),
        );
    }
    kept
}

/// The Type-1 pass: raw fingerprints, verified seeds, maximal runs.
pub(crate) fn raw_pass(
    files: &[InputFile<'_>],
    segments: &[Vec<SegmentId>],
    anchors: &[Vec<Option<usize>>],
    config: &EngineConfig,
    stats: &mut EngineStats,
    budget: &mut PairBudget,
) -> Vec<ClonePair> {
    let k = config.min_clone_tokens;

    // Winnowed fingerprint index over per-segment token runs, kept as one
    // flat posting list instead of a tree of per-hash vectors: with millions
    // of fingerprints the per-hash allocations dominate peak memory. The
    // stable sort groups equal hashes while preserving discovery order
    // within each group, exactly as the per-hash vectors did.
    let mut flat: Vec<(u64, Posting)> = Vec::new();
    for (fi, file) in files.iter().enumerate() {
        let hashes: Vec<u64> = file.tokens.iter().map(raw_token_hash).collect();
        let seg = &segments[fi];
        let mut start = 0usize;
        for i in 1..=file.tokens.len() {
            if i != file.tokens.len() && seg[i] == seg[start] {
                continue;
            }
            if i - start >= k {
                let grams = kgram_hashes(&hashes[start..i], k);
                for (h, gi) in winnow(&grams, config.winnow_window) {
                    flat.push((h, (fi, start + gi)));
                    stats.raw_fingerprints += 1;
                }
            }
            start = i;
        }
    }
    flat.sort_by_key(|&(h, _)| h);

    // Stop-fingerprint suppression before any pairing.
    let mut kept: Vec<RawClass<'_>> = Vec::new();
    for postings in flat.chunk_by(|a, b| a.0 == b.0) {
        stats.raw_distinct += 1;
        if postings.len() > config.posting_cap {
            stats.stop_fingerprints += 1;
            stats.stop_postings += postings.len();
        } else {
            kept.push((postings.len(), postings[0].0, postings));
        }
    }
    // Rarest fingerprints first: highest signal per candidate pair.
    kept.sort_by_key(|&(len, h, _)| (len, h));
    stats.raw_pairs_available += kept
        .iter()
        .map(|&(len, _, _)| pairs_within(len))
        .sum::<usize>();

    let mut runs: Vec<Run> = Vec::new();
    'seeding: for &(_, _, postings) in &kept {
        if !budget.take_list(pairs_within(postings.len())) {
            break 'seeding;
        }
        for x in 0..postings.len() {
            for y in (x + 1)..postings.len() {
                stats.seed_candidates += 1;
                let (mut fa, mut pa) = postings[x].1;
                let (mut fb, mut pb) = postings[y].1;
                if (fb, pb) < (fa, pa) {
                    std::mem::swap(&mut fa, &mut fb);
                    std::mem::swap(&mut pa, &mut pb);
                }
                if fa == fb && pb - pa < k {
                    continue; // overlapping window in one file
                }
                let a = files[fa].tokens;
                let b = files[fb].tokens;
                if pa + k > a.len() || pb + k > b.len() {
                    continue;
                }
                // Verify against hash collisions before extending.
                if !(0..k).all(|d| tokens_eq(&a[pa + d], &b[pb + d])) {
                    continue;
                }
                let (a_start, b_start, len) = extend(a, b, &segments[fa], &segments[fb], pa, pb, k);
                if fa == fb && a_start + len > b_start {
                    continue; // self-overlapping repetition
                }
                runs.push(Run {
                    file_a: fa,
                    file_b: fb,
                    a_start,
                    b_start,
                    len,
                });
            }
        }
    }

    let mut pairs: Vec<ClonePair> = drop_nested(runs)
        .into_iter()
        .map(|r| {
            let slice = &files[r.file_a].tokens[r.a_start..r.a_start + r.len];
            ClonePair {
                content_key: raw_sequence_hash(slice),
                content_digest: raw_sequence_digest(slice),
                clone_type: CloneClass::Type1,
                score: 1.0,
                a: instance(files, anchors, r.file_a, r.a_start, r.a_start + r.len),
                b: instance(files, anchors, r.file_b, r.b_start, r.b_start + r.len),
            }
        })
        .collect();
    pairs.sort_by_key(pair_order);
    pairs
}

/// Index every candidate fragment by its normalized content.
///
/// The result is one flat list sorted by class key; the stable sort keeps
/// members of one class in emission order. One list allocation replaces a
/// tree with a vector per class, which at millions of fragments is the
/// difference between one arena-sized block and pathological heap churn.
fn fragment_classes(
    files: &[InputFile<'_>],
    config: &EngineConfig,
    stats: &mut EngineStats,
) -> Vec<(u64, FragmentRef)> {
    let mut flat: Vec<(u64, FragmentRef)> = Vec::new();
    let mut norm: Vec<NormToken<'_>> = Vec::new();
    for (fi, file) in files.iter().enumerate() {
        let braces = segment::brace_pairs(file.tokens);
        for fragment in segment::fragments(
            file.tokens,
            file.units,
            &braces,
            config.min_clone_tokens,
            config.max_statement_window,
        ) {
            stats.fragments += 1;
            let slice = &file.tokens[fragment.start..fragment.end];
            normalize_into(slice, config.literals, &mut norm);
            let key = norm_sequence_hash(&norm);
            flat.push((key, (fi, fragment.start, fragment.end)));
        }
    }
    flat.sort_by_key(|&(key, _)| key);
    flat
}

/// Verify a class against hash collisions: every member must normalize
/// identically to the first. Mismatches are evicted and counted.
fn verified_members<'a>(
    files: &[InputFile<'a>],
    members: &[(u64, FragmentRef)],
    config: &EngineConfig,
    stats: &mut EngineStats,
    reference: &mut Vec<NormToken<'a>>,
    candidate: &mut Vec<NormToken<'a>>,
) -> Vec<FragmentRef> {
    let (fi, s, e) = members[0].1;
    normalize_into(&files[fi].tokens[s..e], config.literals, reference);
    members
        .iter()
        .filter(|&&(_, (fi, s, e))| {
            normalize_into(&files[fi].tokens[s..e], config.literals, candidate);
            let same = candidate == reference;
            if !same {
                stats.hash_collisions += 1;
            }
            same
        })
        .map(|&(_, member)| member)
        .collect()
}

/// The Type-2 pass: scope-normalized fragments grouped by content.
pub(crate) fn fragment_pass(
    files: &[InputFile<'_>],
    anchors: &[Vec<Option<usize>>],
    config: &EngineConfig,
    stats: &mut EngineStats,
    budget: &mut PairBudget,
) -> Vec<ClonePair> {
    // Classes ordered rarest-first, class-size cap applied before pairing.
    let flat = fragment_classes(files, config, stats);
    let mut kept: Vec<FragmentClass> = Vec::new();
    let mut reference: Vec<NormToken<'_>> = Vec::new();
    let mut candidate: Vec<NormToken<'_>> = Vec::new();
    for members in flat.chunk_by(|a, b| a.0 == b.0) {
        let verified = verified_members(
            files,
            members,
            config,
            stats,
            &mut reference,
            &mut candidate,
        );
        if verified.len() < 2 {
            continue;
        }
        if verified.len() > config.posting_cap {
            stats.class_cap_dropped += 1;
            continue;
        }
        kept.push((
            verified.len(),
            members[0].0,
            norm_sequence_digest(&reference),
            verified,
        ));
    }
    stats.fragment_classes = kept.len();
    kept.sort_by_key(|&(len, key, digest, _)| (len, key, digest));
    stats.fragment_pairs_available += kept
        .iter()
        .map(|&(len, _, _, _)| pairs_within(len))
        .sum::<usize>();

    let mut matches: Vec<FragmentMatch> = Vec::new();
    'pairing: for (_, key, digest, verified) in kept {
        if !budget.take_list(pairs_within(verified.len())) {
            break 'pairing;
        }
        for x in 0..verified.len() {
            for y in (x + 1)..verified.len() {
                stats.fragment_candidates += 1;
                let (fa, sa, ea) = verified[x];
                let (fb, sb, eb) = verified[y];
                if fa == fb && sa < eb && sb < ea {
                    continue; // overlapping ranges in one file
                }
                let a = &files[fa].tokens[sa..ea];
                let b = &files[fb].tokens[sb..eb];
                let raw_eq = a
                    .iter()
                    .zip(b.iter())
                    .filter(|(ta, tb)| tokens_eq(ta, tb))
                    .count();
                if raw_eq == a.len() {
                    continue; // verbatim: the raw pass reports it maximally
                }
                #[allow(clippy::cast_precision_loss)] // token counts are small
                let score = raw_eq as f64 / a.len() as f64;
                matches.push(FragmentMatch {
                    key,
                    digest,
                    a: verified[x],
                    b: verified[y],
                    score,
                });
            }
        }
    }

    // Drop matches nested inside a larger match of the same file pair.
    let mut pairs: Vec<ClonePair> = drop_nested_matches(matches)
        .into_iter()
        .map(|m| ClonePair {
            content_key: m.key,
            content_digest: m.digest,
            clone_type: CloneClass::Type2,
            score: m.score,
            a: instance(files, anchors, m.a.0, m.a.1, m.a.2),
            b: instance(files, anchors, m.b.0, m.b.1, m.b.2),
        })
        .collect();
    pairs.sort_by_key(pair_order);
    pairs
}

/// Deterministic pair ordering key, independent of discovery order.
const fn pair_order(pair: &ClonePair) -> (usize, usize, usize, usize, u64, ContentDigest) {
    (
        pair.a.file,
        pair.a.token_start,
        pair.b.file,
        pair.b.token_start,
        pair.content_key,
        pair.content_digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{SourceSpan, TokenKind};

    fn token(kind: TokenKind, text: &str) -> Token {
        Token {
            kind,
            text: text.into(),
            span: SourceSpan {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_column: 1,
            },
        }
    }

    #[test]
    fn hash_collision_members_do_not_reach_fragment_pairing() {
        let first = [token(TokenKind::Punctuation, "+")];
        let second = [token(TokenKind::Punctuation, "-")];
        let files = [
            InputFile {
                tokens: &first,
                units: &[],
            },
            InputFile {
                tokens: &second,
                units: &[],
            },
        ];
        let members = [(7, (0, 0, 1)), (7, (1, 0, 1))];
        let mut stats = EngineStats::default();
        let mut reference = Vec::new();
        let mut candidate = Vec::new();
        let verified = verified_members(
            &files,
            &members,
            &EngineConfig::default(),
            &mut stats,
            &mut reference,
            &mut candidate,
        );
        assert_eq!(verified, vec![(0, 0, 1)]);
        assert_eq!(stats.hash_collisions, 1);
        assert!(verified.len() < 2, "no pair may consume the pair budget");
    }

    #[test]
    fn a_clone_at_the_configured_minimum_is_seeded_below_the_winnow_window() {
        let first = [
            token(TokenKind::Keyword, "return"),
            token(TokenKind::Identifier, "value"),
            token(TokenKind::Punctuation, ";"),
        ];
        let second = first.clone();
        let files = [
            InputFile {
                tokens: &first,
                units: &[],
            },
            InputFile {
                tokens: &second,
                units: &[],
            },
        ];
        let config = EngineConfig {
            min_clone_tokens: 3,
            winnow_window: 4,
            ..EngineConfig::default()
        };
        let segments = [vec![0; 3], vec![0; 3]];
        let anchors = [vec![None; 3], vec![None; 3]];
        let mut stats = EngineStats::default();
        let mut budget = PairBudget::new(config.pair_budget);
        let pairs = raw_pass(
            &files,
            &segments,
            &anchors,
            &config,
            &mut stats,
            &mut budget,
        );
        assert_eq!(pairs.len(), 1, "{pairs:#?}");
        assert_eq!(pairs[0].clone_type, CloneClass::Type1);
        assert_eq!(pairs[0].a.token_end - pairs[0].a.token_start, 3);
    }

    const fn run(file_a: usize, file_b: usize, a_start: usize, b_start: usize, len: usize) -> Run {
        Run {
            file_a,
            file_b,
            a_start,
            b_start,
            len,
        }
    }

    #[test]
    fn nested_runs_are_dropped_within_their_file_pair_only() {
        let outer = run(0, 1, 0, 0, 30);
        let inner = run(0, 1, 5, 5, 10);
        let other_pair = run(0, 2, 5, 5, 10); // same geometry, different pair
        let kept = drop_nested([outer, inner, other_pair].into_iter().collect());
        assert!(kept.contains(&outer));
        assert!(!kept.contains(&inner), "nested run must be dropped");
        assert!(
            kept.contains(&other_pair),
            "containment across file pairs must not fire"
        );
    }

    #[test]
    fn cross_diagonal_nested_runs_are_still_dropped() {
        // Contained on both sides but at different pair offsets.
        let outer = run(0, 1, 0, 0, 30);
        let inner = run(0, 1, 2, 12, 10);
        let kept = drop_nested([outer, inner].into_iter().collect());
        assert_eq!(kept, vec![outer]);
    }

    /// The former implementation is deliberately kept here as a test oracle:
    /// the sweep may change its data structure, never the two-span predicate.
    fn quadratic_drop_nested(mut all: Vec<Run>) -> Vec<Run> {
        all.sort_unstable();
        all.dedup();
        all.chunk_by(|a, b| (a.file_a, a.file_b) == (b.file_a, b.file_b))
            .flat_map(|bucket| {
                bucket.iter().filter(|run| {
                    !bucket.iter().any(|outer| {
                        *outer != **run
                            && outer.a_start <= run.a_start
                            && run.a_start + run.len <= outer.a_start + outer.len
                            && outer.b_start <= run.b_start
                            && run.b_start + run.len <= outer.b_start + outer.len
                    })
                })
            })
            .copied()
            .collect()
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "each generated value is masked below usize::MAX before conversion"
    )]
    fn containment_sweep_keeps_the_quadratic_predicates_exact_result() {
        // Include crossing diagonals, different file pairs, and equal starts
        // in many deterministic shapes. The quadratic oracle makes this a
        // semantic comparison, not merely a timing claim.
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for _case in 0..32 {
            let mut runs = Vec::new();
            for _ in 0..96 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let file_a = usize::try_from((state >> 8) & 1).unwrap();
                let file_b = usize::try_from((state >> 16) & 1).unwrap() + 1;
                let a_start = usize::try_from((state >> 24) % 64).unwrap();
                let b_start = usize::try_from((state >> 32) % 64).unwrap();
                let len = usize::try_from((state >> 40) % 16).unwrap() + 1;
                runs.push(run(file_a, file_b, a_start, b_start, len));
            }
            assert_eq!(drop_nested(runs.clone()), quadratic_drop_nested(runs));
        }
    }

    const fn fragment(key: u64, a: FragmentRef, b: FragmentRef) -> FragmentMatch {
        FragmentMatch {
            key,
            digest: ContentDigest::from_bytes([0; 16]),
            a,
            b,
            score: 0.5,
        }
    }

    #[test]
    fn nested_matches_are_dropped_within_their_file_pair_only() {
        let outer = fragment(1, (0, 0, 30), (1, 0, 30));
        let inner = fragment(2, (0, 5, 15), (1, 5, 15));
        let other_pair = fragment(3, (0, 5, 15), (2, 5, 15));
        let kept = drop_nested_matches(vec![outer, inner, other_pair]);
        let keys: Vec<u64> = kept.iter().map(|m| m.key).collect();
        assert!(keys.contains(&1));
        assert!(!keys.contains(&2), "nested match must be dropped");
        assert!(
            keys.contains(&3),
            "containment across file pairs must not fire"
        );
    }

    #[test]
    fn identical_coordinates_do_not_drop_each_other() {
        let a = fragment(1, (0, 0, 30), (1, 0, 30));
        let b = fragment(2, (0, 0, 30), (1, 0, 30));
        let kept = drop_nested_matches(vec![a, b]);
        assert_eq!(kept.len(), 2, "equal spans are duplicates, not nesting");
    }
}
