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
//! # One duplication, not every pair of its copies
//!
//! A run copied into `n` places matches pairwise `n * (n - 1) / 2` times, and
//! every one of those pairs describes the same duplication. The stage therefore
//! also reports [`SharedRegion`]s: one entry per duplicated run holding all of
//! its occurrences.
//!
//! # Nesting
//!
//! An inner block's run sits inside its enclosing statement, so a duplicated
//! loop body is also detected as part of the duplicated loop. The larger region
//! is the one worth reporting, so a region whose source spans are contained in
//! another region's on both sides is absorbed into it and counted. Containment
//! is indexed per file pair with a first-span sweep and two-dimensional Fenwick
//! query, so a bucket of `m` folded regions costs `O(m log² m)`, not `O(m²)`.
//!
//! Output is deterministic: regions are keyed and ordered by content position
//! alone, and the fold never depends on the order seeds arrive in.

use std::collections::BTreeMap;

use crate::candidate::{CandidatePair, StatementRun};
use crate::features::FeatureKind;
use crate::ir::ByteRange;

/// Version of the maximal-region folding and containment rules.
///
/// This changes which structural findings survive when the folding, extent, or
/// containment policy changes, so it is recorded in the detector contract.
pub const MAXIMAL_VERSION: &str = "maximal-v1";

/// Default minimum reportable region length, in statements: the shortest
/// window length, so the floor never silently discards a run the seed layer
/// could detect.
///
/// It is deliberately not raised past that. Length looks like the obvious way
/// to shed lookalikes, but the labelled corpora say it does not sort them: a
/// helper copied verbatim into two files is five lines, while a routine written
/// once per concrete type is eighty tokens and still nothing anyone should
/// merge. Calibrated on all but one project, a floor either sits low enough to
/// remove nothing or high enough to take that project's clearest true copy.
/// What the short lookalikes have in common is that their bodies follow from
/// their signatures, and that is not a length.
///
/// Taken from the seed layer rather than written out again, so the two cannot
/// drift apart. Below the shortest window the setting has nothing to apply to:
/// a run shorter than any window indexed never becomes a seed, so lowering the
/// floor recovers nothing. Above it the floor discards runs the seeds did find.
pub const DEFAULT_MIN_STATEMENTS: u32 = shortest_window();

/// The shortest statement window the seed layer indexes.
// The window lengths are small literals written next to this, so the cast
// cannot lose anything; there is no const `TryFrom` to say so instead.
#[allow(clippy::cast_possible_truncation)]
const fn shortest_window() -> u32 {
    let mut shortest = usize::MAX;
    let mut index = 0;
    while index < crate::features::WINDOW_LENGTHS.len() {
        if crate::features::WINDOW_LENGTHS[index] < shortest {
            shortest = crate::features::WINDOW_LENGTHS[index];
        }
        index += 1;
    }
    shortest as u32
}

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

/// One duplicated run and every place it occurs.
///
/// A run copied into `n` places produces `n * (n - 1) / 2` pairwise matches
/// that all describe the same duplication, so the pairs are collapsed into the
/// occurrence set they imply. Every occurrence in the set holds the same
/// statement summaries as every other, not merely as its neighbours: see
/// [`consolidate`] for why grouping by transitive closure is sound here and
/// would not be for an approximate match.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SharedRegion {
    /// Where the run occurs, at least twice, in ascending order.
    pub occurrences: Vec<RegionSide>,
    /// Length of the run, in statements; the same at every occurrence.
    pub statements: u32,
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
    /// Pairwise regions emitted.
    pub regions: usize,
    /// Occurrence sets the pairwise regions collapse into: the number of
    /// distinct duplicated runs.
    pub shared: usize,
}

/// The consolidation stage's output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionSet {
    /// Maximal pairwise regions, deterministically ordered: the evidence the
    /// occurrence sets are built from.
    pub regions: Vec<CloneRegion>,
    /// One entry per duplicated run, holding every place it occurs.
    pub shared: Vec<SharedRegion>,
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
        let (a_bytes, b_bytes) = pair_ranges(pair);
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

    // Containment can only hold between regions over the same two files. Keep
    // those candidates together, then answer each two-span containment query
    // through an offline index rather than scanning a generated-code bucket.
    let mut buckets: BTreeMap<(usize, usize), Vec<CloneRegion>> = BTreeMap::new();
    for region in folded {
        if region.a.run.length < config.min_statements {
            stats.below_minimum += 1;
            continue;
        }
        if overlaps_itself(&region) {
            stats.self_overlapping += 1;
            continue;
        }
        buckets
            .entry((region.a.file, region.b.file))
            .or_default()
            .push(region);
    }

    let mut kept: Vec<CloneRegion> = Vec::new();
    for bucket in buckets.into_values() {
        let (bucket, absorbed) = remove_contained(bucket);
        stats.absorbed += absorbed;
        kept.extend(bucket);
    }
    kept.sort_unstable();
    stats.regions = kept.len();
    let shared = share(&kept);
    stats.shared = shared.len();
    RegionSet {
        regions: kept,
        shared,
        stats,
    }
}

/// The source byte spans carried by a candidate pair.
const fn pair_ranges(pair: &CandidatePair) -> (ByteRange, ByteRange) {
    (
        ByteRange {
            start: pair.a.start_byte,
            end: pair.a.end_byte,
        },
        ByteRange {
            start: pair.b.start_byte,
            end: pair.b.end_byte,
        },
    )
}

/// Remove regions covered on both spans by an earlier region in one file pair.
fn remove_contained(mut regions: Vec<CloneRegion>) -> (Vec<CloneRegion>, usize) {
    // Sweep the first span from left to right. For equal starts, put the
    // widest span first, so a pair of equal regions leaves one canonical
    // representative instead of removing both.
    regions.sort_by_key(|region| {
        (
            region.a.range.start,
            std::cmp::Reverse(region.a.range.end),
            region.b.range.start,
            std::cmp::Reverse(region.b.range.end),
            region.a,
            region.b,
        )
    });
    let mut index = ContainmentIndex::for_regions(&regions);
    let mut kept = Vec::with_capacity(regions.len());
    let mut absorbed = 0;
    for region in regions {
        if index.contains(&region) {
            absorbed += 1;
        } else {
            index.insert(&region);
            kept.push(region);
        }
    }
    (kept, absorbed)
}

/// Offline two-dimensional range index for the second half of a clone region.
///
/// The outer sweep supplies the first-span start condition. Each Fenwick node
/// covers a prefix of second-span starts and holds another Fenwick tree over
/// first-span ends. Its value is the greatest second-span end seen there, so a
/// query proves all remaining containment conditions in `O(log² m)`.
struct ContainmentIndex {
    /// Sorted unique starts of the second span.
    second_starts: Vec<usize>,
    /// Per outer Fenwick node, the possible ends of the first span.
    first_ends: Vec<Vec<usize>>,
    /// Per outer Fenwick node, maximum second-span ends by reversed first end.
    greatest_second_ends: Vec<Vec<usize>>,
}

impl ContainmentIndex {
    fn for_regions(regions: &[CloneRegion]) -> Self {
        let mut second_starts: Vec<usize> =
            regions.iter().map(|region| region.b.range.start).collect();
        second_starts.sort_unstable();
        second_starts.dedup();

        let mut first_ends = vec![Vec::new(); second_starts.len() + 1];
        for region in regions {
            let mut node = second_starts.partition_point(|&start| start < region.b.range.start) + 1;
            while node < first_ends.len() {
                first_ends[node].push(region.a.range.end);
                node += lowbit(node);
            }
        }
        for ends in &mut first_ends {
            ends.sort_unstable();
            ends.dedup();
        }
        let greatest_second_ends = first_ends
            .iter()
            .map(|ends| vec![0; ends.len() + 1])
            .collect();

        Self {
            second_starts,
            first_ends,
            greatest_second_ends,
        }
    }

    /// Record one earlier region from the first-span sweep.
    fn insert(&mut self, region: &CloneRegion) {
        let mut node = self
            .second_starts
            .partition_point(|&start| start < region.b.range.start)
            + 1;
        while node < self.first_ends.len() {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < region.a.range.end);
            let values = &mut self.greatest_second_ends[node];
            let mut position = reversed;
            while position < values.len() {
                values[position] = values[position].max(region.b.range.end);
                position += lowbit(position);
            }
            node += lowbit(node);
        }
    }

    /// Whether an earlier region covers both spans of `region`.
    fn contains(&self, region: &CloneRegion) -> bool {
        let mut node = self
            .second_starts
            .partition_point(|&start| start <= region.b.range.start);
        while node > 0 {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < region.a.range.end);
            let values = &self.greatest_second_ends[node];
            let mut greatest = 0;
            let mut position = reversed;
            while position > 0 {
                greatest = greatest.max(values[position]);
                position -= lowbit(position);
            }
            if greatest >= region.b.range.end {
                return true;
            }
            node -= lowbit(node);
        }
        false
    }
}

/// Least significant set bit of a one-based Fenwick index.
const fn lowbit(index: usize) -> usize {
    index.isolate_lowest_one()
}

/// Collapse pairwise regions into one entry per duplicated run.
///
/// Grouping is the transitive closure over the pairwise matches — plain
/// connected components, which is exactly what clone grouping must *not* use
/// for approximate matches, because similarity is not transitive and chaining
/// fuses unrelated code. It is correct here for the opposite reason: these
/// matches are statement-for-statement equalities, and equality is transitive,
/// so a component really is a set of mutually equal runs. An occurrence's
/// extent is part of its identity, so a run that matches one neighbour over
/// six statements and another over four contributes two occurrences and lands
/// in two sets, each internally consistent.
///
/// A set can hold occurrences that overlap each other, because the closure
/// reaches them through a third occurrence they both match. Whether those are
/// one stretch of code or two is not decidable from statement summaries, so it
/// is left to content confirmation downstream.
fn share(regions: &[CloneRegion]) -> Vec<SharedRegion> {
    let mut index: BTreeMap<RegionSide, usize> = BTreeMap::new();
    for region in regions {
        let next = index.len();
        index.entry(region.a).or_insert(next);
        let next = index.len();
        index.entry(region.b).or_insert(next);
    }
    let mut parent: Vec<usize> = (0..index.len()).collect();
    for region in regions {
        let (Some(&a), Some(&b)) = (index.get(&region.a), index.get(&region.b)) else {
            continue;
        };
        join(&mut parent, a, b);
    }

    let mut sets: BTreeMap<usize, Vec<RegionSide>> = BTreeMap::new();
    for (&side, &node) in &index {
        sets.entry(find(&mut parent, node)).or_default().push(side);
    }
    let mut shared: Vec<SharedRegion> = sets
        .into_values()
        .filter(|occurrences| occurrences.len() >= 2)
        .map(|mut occurrences| {
            occurrences.sort_unstable();
            let statements = occurrences.first().map_or(0, |side| side.run.length);
            SharedRegion {
                occurrences,
                statements,
            }
        })
        .collect();
    shared.sort_unstable();
    shared
}

const fn find(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

fn join(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    if a != b {
        parent[a.max(b)] = a.min(b);
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
#[must_use]
pub const fn intersects(a: ByteRange, b: ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

/// Whether one run picks up exactly where the other stops, in the same block
/// of the same unit.
///
/// Two runs that tile one stretch of code are that stretch's period, not two
/// copies of it. A hand-unrolled loop repeats one operation by construction,
/// and the second half is not a site anyone can be sent to: the duplication is
/// the whole block, and the whole block is already where the reader is looking.
///
/// The question is asked in statements rather than bytes so that a blank line
/// or a comment between the two halves cannot change the answer, and it is
/// asked inside one block because adjacency across units means nothing — two
/// functions are two sites however the file happens to lay them out.
#[must_use]
pub const fn adjoins(a: &RegionSide, b: &RegionSide) -> bool {
    a.file == b.file
        && a.unit == b.unit
        && a.run.block == b.run.block
        && (a.run.end() == b.run.start || b.run.end() == a.run.start)
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

const fn union(a: ByteRange, b: ByteRange) -> ByteRange {
    ByteRange {
        start: if a.start < b.start { a.start } else { b.start },
        end: if a.end > b.end { a.end } else { b.end },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
