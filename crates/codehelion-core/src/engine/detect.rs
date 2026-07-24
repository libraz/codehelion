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

use std::collections::{BTreeMap, BTreeSet};

use crate::frontend::Token;

use super::fingerprint::{
    kgram_hashes, norm_sequence_hash, raw_sequence_hash, raw_token_hash, winnow,
};
use super::normalize::normalize;
use super::segment::{self, SegmentId};
use super::{ClonePair, CloneType, EngineConfig, EngineStats, InputFile, Instance};

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

    /// Take one candidate from the budget; `false` means stop pairing.
    const fn take(&mut self) -> bool {
        if self.remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        true
    }

    pub(crate) const fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Raw token equality: kind and text, ignoring position.
fn tokens_eq(a: &Token, b: &Token) -> bool {
    a.kind == b.kind && a.text == b.text
}

/// A fingerprint occurrence: `(file index, token position)`.
type Posting = (usize, usize);

/// A fragment occurrence: `(file index, token start, token end)`.
type FragmentRef = (usize, usize, usize);

/// A verified Type-2 candidate, before nested-pair filtering.
#[derive(Debug, Clone, Copy)]
struct FragmentMatch {
    key: u64,
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

/// Drop every run nested inside a larger run of the same file pair.
fn drop_nested(runs: BTreeSet<Run>) -> Vec<Run> {
    let all: Vec<Run> = runs.into_iter().collect();
    all.iter()
        .filter(|r| {
            !all.iter().any(|o| {
                *o != **r
                    && o.file_a == r.file_a
                    && o.file_b == r.file_b
                    && o.a_start <= r.a_start
                    && r.a_start + r.len <= o.a_start + o.len
                    && o.b_start <= r.b_start
                    && r.b_start + r.len <= o.b_start + o.len
            })
        })
        .copied()
        .collect()
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

    // Winnowed fingerprint index over per-segment token runs.
    let mut index: BTreeMap<u64, Vec<Posting>> = BTreeMap::new();
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
                    index.entry(h).or_default().push((fi, start + gi));
                    stats.raw_fingerprints += 1;
                }
            }
            start = i;
        }
    }
    stats.raw_distinct = index.len();

    // Stop-fingerprint suppression before any pairing.
    let mut kept: Vec<(usize, u64, Vec<Posting>)> = Vec::new();
    for (h, postings) in index {
        if postings.len() > config.posting_cap {
            stats.stop_fingerprints += 1;
            stats.stop_postings += postings.len();
        } else {
            kept.push((postings.len(), h, postings));
        }
    }
    // Rarest fingerprints first: highest signal per candidate pair.
    kept.sort_by_key(|&(len, h, _)| (len, h));

    let mut runs: BTreeSet<Run> = BTreeSet::new();
    'seeding: for (_, _, postings) in &kept {
        for x in 0..postings.len() {
            for y in (x + 1)..postings.len() {
                if !budget.take() {
                    break 'seeding;
                }
                stats.seed_candidates += 1;
                let (mut fa, mut pa) = postings[x];
                let (mut fb, mut pb) = postings[y];
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
                runs.insert(Run {
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
                clone_type: CloneType::Type1,
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
fn fragment_classes(
    files: &[InputFile<'_>],
    config: &EngineConfig,
    stats: &mut EngineStats,
) -> BTreeMap<u64, Vec<FragmentRef>> {
    let mut classes: BTreeMap<u64, Vec<FragmentRef>> = BTreeMap::new();
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
            let key = norm_sequence_hash(&normalize(slice, config.literals));
            classes
                .entry(key)
                .or_default()
                .push((fi, fragment.start, fragment.end));
        }
    }
    classes
}

/// Verify a class against hash collisions: every member must normalize
/// identically to the first. Mismatches are evicted and counted.
fn verified_members(
    files: &[InputFile<'_>],
    members: &[FragmentRef],
    config: &EngineConfig,
    stats: &mut EngineStats,
) -> Vec<FragmentRef> {
    let (fi, s, e) = members[0];
    let reference = normalize(&files[fi].tokens[s..e], config.literals);
    members
        .iter()
        .filter(|&&(fi, s, e)| {
            let same = normalize(&files[fi].tokens[s..e], config.literals) == reference;
            if !same {
                stats.hash_collisions += 1;
            }
            same
        })
        .copied()
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
    let mut kept: Vec<(usize, u64, Vec<FragmentRef>)> = Vec::new();
    for (key, members) in fragment_classes(files, config, stats) {
        if members.len() < 2 {
            continue;
        }
        if members.len() > config.posting_cap {
            stats.class_cap_dropped += 1;
            continue;
        }
        kept.push((members.len(), key, members));
    }
    stats.fragment_classes = kept.len();
    kept.sort_by_key(|&(len, key, _)| (len, key));

    let mut matches: Vec<FragmentMatch> = Vec::new();
    'pairing: for (_, key, members) in &kept {
        let verified = verified_members(files, members, config, stats);
        for x in 0..verified.len() {
            for y in (x + 1)..verified.len() {
                if !budget.take() {
                    break 'pairing;
                }
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
                    key: *key,
                    a: verified[x],
                    b: verified[y],
                    score,
                });
            }
        }
    }

    // Drop matches nested inside a larger match of the same file pair.
    let mut pairs: Vec<ClonePair> = matches
        .iter()
        .filter(|m| !matches.iter().any(|o| m.nested_in(o)))
        .map(|m| ClonePair {
            content_key: m.key,
            clone_type: CloneType::Type2,
            score: m.score,
            a: instance(files, anchors, m.a.0, m.a.1, m.a.2),
            b: instance(files, anchors, m.b.0, m.b.1, m.b.2),
        })
        .collect();
    pairs.sort_by_key(pair_order);
    pairs
}

/// Deterministic pair ordering key, independent of discovery order.
const fn pair_order(pair: &ClonePair) -> (usize, usize, usize, usize, u64) {
    (
        pair.a.file,
        pair.a.token_start,
        pair.b.file,
        pair.b.token_start,
        pair.content_key,
    )
}
