//! Folding overlapping seed matches back into maximal shared statement runs.
//!
//! Statement windows slide with stride 1 over every block, so a shared run of
//! `n` statements does not surface as one match — it surfaces as a fan of
//! overlapping window matches, one per offset and per window length. Reporting
//! those raw would bury a single duplicated block under a dozen findings that
//! all describe the same code.
//!
//! This stage reverses the sliding: seed matches that describe the same shared
//! run are folded into the maximal run they jointly cover, so a duplicated
//! block is one region no matter how many windows detected it.
//!
//! # Why folding is sound
//!
//! A window match means the two windows' statement summaries are equal
//! statement for statement. Two matches fold only when they agree on
//! *alignment* — the same enclosing blocks on both sides and the same offset
//! between them — and their runs touch. Under those conditions the equalities
//! compose: if `a[0..4] == b[2..6]` and `a[2..6] == b[4..8]` then
//! `a[0..6] == b[2..8]`, because each statement of the union is covered by at
//! least one of the two matches at the same relative position. No similarity is
//! re-estimated here and nothing is approximated: the folded region is exactly
//! as much of an exact match as the seeds it came from.
//!
//! Gapped runs — a shared block interrupted by an edited statement — are *not*
//! bridged here. Bridging a gap makes the region an approximate match, so it
//! belongs behind the judge rather than in a fold that claims exactness.
//!
//! # What a window hash does not see
//!
//! A statement summary is its shape, its native kind and its leading token
//! kinds — deliberately shallow, so the index stays cheap. A loop whose body is
//! one line therefore summarises exactly like a loop whose body is forty, and
//! two runs can match on summaries while covering wildly different amounts of
//! code. That is not a duplicate of anything, so a seed whose two sides differ
//! in source length by more than [`MaximalConfig::max_extent_ratio`] is dropped
//! and counted: the size gap is the direct evidence that the summary hid the
//! difference.
//!
//! # Nesting
//!
//! An inner block's run sits inside its enclosing statement, so a duplicated
//! loop body is also detected as part of the duplicated loop. The larger region
//! is the one worth reporting, so a region whose source spans are contained in
//! another region's on both sides is absorbed into it and counted.
//!
//! Output is deterministic: regions are keyed and ordered by content position
//! alone, and the fold never depends on the order seeds arrive in.

use std::collections::BTreeMap;

use crate::candidate::{CandidatePair, StatementRun};
use crate::features::FeatureKind;
use crate::ir::ByteRange;

/// Default minimum reportable region length, in statements: the shortest
/// window length, so the floor never silently discards a run the seed layer
/// could detect.
pub const DEFAULT_MIN_STATEMENTS: u32 = 4;

/// Default largest source-length ratio between a seed's two sides.
///
/// Generous on purpose: consistent renaming moves source length by a few
/// percent, so anything near this factor means the summaries agreed over
/// unequal amounts of code.
pub const DEFAULT_MAX_EXTENT_RATIO: f64 = 2.0;

/// Tuning for region consolidation.
#[derive(Debug, Clone, PartialEq)]
pub struct MaximalConfig {
    /// Shortest run, in statements, that is still reported. Shorter regions
    /// are dropped and counted in [`RegionStats::below_minimum`].
    pub min_statements: u32,
    /// Largest ratio between the source lengths of a seed's two sides before
    /// the seed is dropped as a summary-level coincidence.
    pub max_extent_ratio: f64,
}

impl Default for MaximalConfig {
    fn default() -> Self {
        Self {
            min_statements: DEFAULT_MIN_STATEMENTS,
            max_extent_ratio: DEFAULT_MAX_EXTENT_RATIO,
        }
    }
}

/// One side of a clone region: where the shared run sits in one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionSide {
    /// Index of the file in the analysed slice.
    pub file: usize,
    /// Index of the enclosing unit in the file's units.
    pub unit: usize,
    /// The statement run the region covers.
    pub run: StatementRun,
    /// Source bytes the run covers; reporting only.
    pub range: ByteRange,
}

/// A maximal shared statement run between two units.
///
/// The two sides hold the same statement summaries, statement for statement,
/// so `a.run.length == b.run.length` always.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CloneRegion {
    /// The lower side, by fragment order.
    pub a: RegionSide,
    /// The higher side.
    pub b: RegionSide,
    /// How many seed matches folded into this region.
    pub seeds: usize,
}

/// What consolidation saw and dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionStats {
    /// Statement-window seed matches offered to the fold.
    pub seeds: usize,
    /// Seeds dropped because their two sides cover very different amounts of
    /// source, so the summaries matched over unequal code.
    pub divergent_extent: usize,
    /// Regions the seeds folded into, before the drops below.
    pub folded: usize,
    /// Regions absorbed by a region containing them on both sides.
    pub absorbed: usize,
    /// Regions whose two sides overlap each other in one block, so the
    /// "clone" is a run overlapping itself rather than two instances.
    pub self_overlapping: usize,
    /// Regions shorter than [`MaximalConfig::min_statements`].
    pub below_minimum: usize,
    /// Regions emitted.
    pub regions: usize,
}

/// The consolidation stage's output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionSet {
    /// Maximal regions, deterministically ordered.
    pub regions: Vec<CloneRegion>,
    /// What the stage saw and dropped.
    pub stats: RegionStats,
}

/// How two runs are aligned: the enclosing blocks and the offset between them.
/// Seeds sharing an alignment describe one shared run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Alignment {
    a_file: usize,
    a_unit: usize,
    a_block: u32,
    b_file: usize,
    b_unit: usize,
    b_block: u32,
    /// `b.start - a.start`, which is constant along one shared run.
    shift: i64,
}

/// A run being grown, with the source bytes and seed count folded so far.
#[derive(Debug, Clone, Copy)]
struct Growing {
    a_start: u32,
    a_end: u32,
    a_bytes: ByteRange,
    b_bytes: ByteRange,
    seeds: usize,
}

/// Fold statement-window seed matches into maximal shared runs.
///
/// Subtree seeds are ignored: a subtree is a tree region, not a run of
/// sibling statements, so it has no adjacency to grow along. It still does its
/// job upstream, where it proposes the unit pair.
///
/// The result is a pure function of the input.
#[must_use]
pub fn consolidate(pairs: &[CandidatePair], config: &MaximalConfig) -> RegionSet {
    let mut stats = RegionStats::default();
    let mut runs: BTreeMap<Alignment, Vec<(StatementRun, ByteRange, StatementRun, ByteRange)>> =
        BTreeMap::new();

    for pair in pairs {
        if pair.kind != FeatureKind::StatementWindow {
            continue;
        }
        let (Some(a_run), Some(b_run)) = (pair.a.run, pair.b.run) else {
            continue;
        };
        stats.seeds += 1;
        let a_bytes = ByteRange {
            start: pair.a.start_byte,
            end: pair.a.end_byte,
        };
        let b_bytes = ByteRange {
            start: pair.b.start_byte,
            end: pair.b.end_byte,
        };
        if diverges(a_bytes, b_bytes, config.max_extent_ratio) {
            stats.divergent_extent += 1;
            continue;
        }
        let alignment = Alignment {
            a_file: pair.a.file,
            a_unit: pair.a.unit,
            a_block: a_run.block,
            b_file: pair.b.file,
            b_unit: pair.b.unit,
            b_block: b_run.block,
            shift: i64::from(b_run.start) - i64::from(a_run.start),
        };
        runs.entry(alignment)
            .or_default()
            .push((a_run, a_bytes, b_run, b_bytes));
    }

    let mut folded: Vec<CloneRegion> = Vec::new();
    for (alignment, mut seeds) in runs {
        seeds.sort_by_key(|&(a_run, _, _, _)| (a_run.start, a_run.length));
        let mut current: Option<Growing> = None;
        for (a_run, a_bytes, _, b_bytes) in seeds {
            // Touching or overlapping the run grown so far: extend it.
            let extends = current.is_some_and(|growing| a_run.start <= growing.a_end);
            if let (true, Some(growing)) = (extends, current.as_mut()) {
                growing.a_end = growing.a_end.max(a_run.end());
                growing.a_bytes = union(growing.a_bytes, a_bytes);
                growing.b_bytes = union(growing.b_bytes, b_bytes);
                growing.seeds += 1;
                continue;
            }
            if let Some(done) = current.take() {
                folded.push(emit(&alignment, &done));
            }
            current = Some(Growing {
                a_start: a_run.start,
                a_end: a_run.end(),
                a_bytes,
                b_bytes,
                seeds: 1,
            });
        }
        if let Some(done) = current {
            folded.push(emit(&alignment, &done));
        }
    }
    stats.folded = folded.len();

    // Order by coverage first so containment is decided by the larger region,
    // then by position so the choice among equals is deterministic.
    folded.sort_by_key(|region| {
        (
            std::cmp::Reverse(u64::from(region.a.run.length)),
            region.a,
            region.b,
        )
    });

    let mut kept: Vec<CloneRegion> = Vec::new();
    for region in folded {
        if region.a.run.length < config.min_statements {
            stats.below_minimum += 1;
            continue;
        }
        if overlaps_itself(&region) {
            stats.self_overlapping += 1;
            continue;
        }
        if kept.iter().any(|outer| contains(outer, &region)) {
            stats.absorbed += 1;
            continue;
        }
        kept.push(region);
    }

    kept.sort_unstable();
    stats.regions = kept.len();
    RegionSet {
        regions: kept,
        stats,
    }
}

/// Turn a grown run and its alignment into a region.
fn emit(alignment: &Alignment, grown: &Growing) -> CloneRegion {
    let length = grown.a_end - grown.a_start;
    let b_start = u32::try_from(i64::from(grown.a_start) + alignment.shift).unwrap_or(0);
    CloneRegion {
        a: RegionSide {
            file: alignment.a_file,
            unit: alignment.a_unit,
            run: StatementRun {
                block: alignment.a_block,
                start: grown.a_start,
                length,
            },
            range: grown.a_bytes,
        },
        b: RegionSide {
            file: alignment.b_file,
            unit: alignment.b_unit,
            run: StatementRun {
                block: alignment.b_block,
                start: b_start,
                length,
            },
            range: grown.b_bytes,
        },
        seeds: grown.seeds,
    }
}

/// Whether a region's two sides are the same stretch of source, which happens
/// when a repetitive block matches a shifted copy of itself, or when a nested
/// unit's run matches the enclosing unit's copy of it. Either way there is one
/// stretch of code, not two instances of one.
const fn overlaps_itself(region: &CloneRegion) -> bool {
    region.a.file == region.b.file && intersects(region.a.range, region.b.range)
}

/// Whether two byte ranges share at least one byte.
const fn intersects(a: ByteRange, b: ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

/// Whether `outer` covers `inner` on both sides, in the same files.
const fn contains(outer: &CloneRegion, inner: &CloneRegion) -> bool {
    outer.a.file == inner.a.file
        && outer.b.file == inner.b.file
        && covers(outer.a.range, inner.a.range)
        && covers(outer.b.range, inner.b.range)
}

/// Whether two matched sides cover source lengths further apart than `ratio`.
/// A zero-length side is never divergent: there is nothing to compare.
fn diverges(a: ByteRange, b: ByteRange, ratio: f64) -> bool {
    let (short, long) = {
        let (a, b) = (a.len(), b.len());
        if a <= b { (a, b) } else { (b, a) }
    };
    if short == 0 {
        return false;
    }
    #[allow(clippy::cast_precision_loss)]
    let measured = long as f64 / short as f64;
    measured > ratio
}

const fn covers(outer: ByteRange, inner: ByteRange) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

const fn union(a: ByteRange, b: ByteRange) -> ByteRange {
    ByteRange {
        start: if a.start < b.start { a.start } else { b.start },
        end: if a.end > b.end { a.end } else { b.end },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::candidate::FragmentRef;
    use crate::features::FeatureHash;

    /// A window seed at a statement offset, with byte anchors derived from the
    /// offset so ranges stay ordered and non-overlapping between statements.
    fn window(file: usize, unit: usize, block: u32, start: u32, length: u32) -> FragmentRef {
        FragmentRef {
            file,
            unit,
            start_byte: usize::try_from(start).unwrap() * 10,
            end_byte: usize::try_from(start + length).unwrap() * 10,
            extent: length,
            run: Some(StatementRun {
                block,
                start,
                length,
            }),
        }
    }

    fn seed(a: FragmentRef, b: FragmentRef) -> CandidatePair {
        CandidatePair {
            kind: FeatureKind::StatementWindow,
            hash: FeatureHash::from_bytes([1; 16]),
            a,
            b,
        }
    }

    #[test]
    fn overlapping_seeds_fold_into_one_run() {
        // Three stride-1 windows of length four covering statements 0..6 in
        // one unit and 2..8 in the other.
        let pairs: Vec<CandidatePair> = (0..3)
            .map(|i| seed(window(0, 0, 0, i, 4), window(1, 0, 0, i + 2, 4)))
            .collect();
        let set = consolidate(&pairs, &MaximalConfig::default());

        assert_eq!(set.regions.len(), 1);
        let region = set.regions[0];
        assert_eq!(region.a.run.start, 0);
        assert_eq!(region.a.run.length, 6);
        assert_eq!(region.b.run.start, 2);
        assert_eq!(region.b.run.length, 6);
        assert_eq!(region.a.range, ByteRange { start: 0, end: 60 });
        assert_eq!(region.b.range, ByteRange { start: 20, end: 80 });
        assert_eq!(region.seeds, 3);
        assert_eq!(set.stats.seeds, 3);
        assert_eq!(set.stats.regions, 1);
    }

    #[test]
    fn a_gap_between_seeds_leaves_two_runs() {
        // Statements 0..4 and 8..12 match; 4..8 does not. Bridging the gap
        // would claim an exact match over statements the seeds never covered.
        let pairs = vec![
            seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
            seed(window(0, 0, 0, 8, 4), window(1, 0, 0, 8, 4)),
        ];
        let set = consolidate(&pairs, &MaximalConfig::default());
        assert_eq!(set.regions.len(), 2);
        assert!(set.regions.iter().all(|region| region.a.run.length == 4));
    }

    #[test]
    fn seeds_at_different_alignments_stay_apart() {
        // The same statements on side a match two different stretches on side
        // b. Those are two shared runs, not one long one.
        let pairs = vec![
            seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
            seed(window(0, 0, 0, 1, 4), window(1, 0, 0, 9, 4)),
        ];
        let set = consolidate(&pairs, &MaximalConfig::default());
        assert_eq!(set.regions.len(), 2);
        assert!(set.regions.iter().all(|region| region.seeds == 1));
    }

    #[test]
    fn a_run_contained_in_a_longer_one_is_absorbed() {
        // A length-8 match and a length-4 match inside it, at the same
        // alignment but in different blocks, so the fold cannot merge them.
        let pairs = vec![
            seed(window(0, 0, 0, 0, 8), window(1, 0, 0, 0, 8)),
            seed(window(0, 0, 1, 2, 4), window(1, 0, 1, 2, 4)),
        ];
        let set = consolidate(&pairs, &MaximalConfig::default());
        assert_eq!(set.regions.len(), 1);
        assert_eq!(set.regions[0].a.run.length, 8);
        assert_eq!(set.stats.folded, 2);
        assert_eq!(set.stats.absorbed, 1);
    }

    #[test]
    fn a_run_matching_a_shifted_copy_of_itself_is_dropped() {
        // One block of repeated statements: window 0..4 equals window 1..5.
        // Reporting that as two instances would double-count one stretch.
        let pairs = vec![seed(window(0, 0, 0, 0, 4), window(0, 0, 0, 1, 4))];
        let set = consolidate(&pairs, &MaximalConfig::default());
        assert!(set.regions.is_empty());
        assert_eq!(set.stats.self_overlapping, 1);
    }

    #[test]
    fn two_runs_in_one_unit_that_do_not_touch_are_kept() {
        let pairs = vec![seed(window(0, 0, 0, 0, 4), window(0, 0, 1, 20, 4))];
        let set = consolidate(&pairs, &MaximalConfig::default());
        assert_eq!(set.regions.len(), 1);
        assert_eq!(set.stats.self_overlapping, 0);
    }

    #[test]
    fn a_seed_whose_sides_cover_unequal_code_is_dropped() {
        // Same four statement summaries, but one side spans three times the
        // source: a loop with a long body summarises like a loop with a short
        // one, and the size gap is what gives that away.
        let mut a = window(0, 0, 0, 0, 4);
        let mut b = window(1, 0, 0, 0, 4);
        a.end_byte = a.start_byte + 100;
        b.end_byte = b.start_byte + 300;
        let set = consolidate(&[seed(a, b)], &MaximalConfig::default());
        assert!(set.regions.is_empty());
        assert_eq!(set.stats.seeds, 1);
        assert_eq!(set.stats.divergent_extent, 1);

        // The gate is a configured ratio, not a fixed rule.
        let lenient = MaximalConfig {
            max_extent_ratio: 4.0,
            ..MaximalConfig::default()
        };
        assert_eq!(consolidate(&[seed(a, b)], &lenient).regions.len(), 1);
    }

    #[test]
    fn the_minimum_length_drops_short_runs_and_counts_them() {
        let pairs = vec![seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4))];
        let config = MaximalConfig {
            min_statements: 5,
            ..MaximalConfig::default()
        };
        let set = consolidate(&pairs, &config);
        assert!(set.regions.is_empty());
        assert_eq!(set.stats.below_minimum, 1);
    }

    #[test]
    fn subtree_seeds_do_not_enter_the_fold() {
        let mut pair = seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4));
        pair.kind = FeatureKind::Subtree;
        pair.a.run = None;
        pair.b.run = None;
        let set = consolidate(&[pair], &MaximalConfig::default());
        assert!(set.regions.is_empty());
        assert_eq!(set.stats.seeds, 0);
    }

    #[test]
    fn folding_does_not_depend_on_seed_order() {
        let forward = vec![
            seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
            seed(window(0, 0, 0, 1, 4), window(1, 0, 0, 1, 4)),
            seed(window(0, 0, 0, 2, 4), window(1, 0, 0, 2, 4)),
        ];
        let mut backward = forward.clone();
        backward.reverse();
        assert_eq!(
            consolidate(&forward, &MaximalConfig::default()),
            consolidate(&backward, &MaximalConfig::default())
        );
    }
}
