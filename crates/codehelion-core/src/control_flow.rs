//! Structural-mode candidate generation from the control-flow skeleton.
//!
//! The other two candidate stages both describe a unit by the *pieces* it is
//! made of: [`crate::candidate`] indexes statement windows and subtrees and
//! pairs units that share one exactly, and [`crate::near_match`] treats those
//! same pieces as a set and pairs units whose sets overlap. Both lose the same
//! edit, and lose it hardest where code is smallest.
//!
//! Inserting a statement rewrites every piece that encloses it. In a short
//! function almost every piece encloses almost everything: the body block, the
//! loop, the whole unit. A copy with two statements added can therefore share
//! *no* window and *no* subtree with its original, so the exact stage proposes
//! nothing and the set stage sees two disjoint sets — while a reader would call
//! them the same function. The loss is not a threshold that could be relaxed;
//! there is no overlap left to find.
//!
//! What such an edit does leave untouched is the shape of the control flow. A
//! statement that is not a loop, a branch, a match or a jump does not appear in
//! [`crate::features::CfgFeature::skeleton_hash`] at all, so a unit and its
//! gapped copy hash to the same skeleton. This stage indexes that hash and
//! pairs the units that share one. It is an exact-match index like the seed
//! layer, not an approximation: units either have the same skeleton or they do
//! not.
//!
//! A skeleton says much less than a subtree does — it is why this stage
//! proposes rather than concludes, and every pair it emits is judged by
//! [`crate::verify`] like any other. Three controls keep what it proposes
//! bounded (AGENTS.md invariant 10), and each counts what it drops:
//!
//! - **a minimum skeleton size** — a unit with fewer than
//!   [`ControlFlowConfig::min_ops`] control operations has a skeleton so common
//!   that sharing it is no evidence at all, and is not indexed;
//! - **high-frequency suppression** — a skeleton shared by more than
//!   [`ControlFlowConfig::posting_cap`] units is common structure rather than a
//!   family of copies, and its whole posting list is dropped;
//! - **a length-ratio gate and a global pair budget** — as in the near-match
//!   stage, a pair spanning too great a size difference is not a gapped copy,
//!   and posting lists are paired rarest-first so exhaustion sacrifices the
//!   lowest-signal candidates.
//!
//! As in [`crate::candidate`], the budget stops between posting lists and never
//! inside one: a list compared only in part reaches grouping as a family whose
//! members disagree, and comes back out as the stray pairs the ceiling allowed
//! rather than as the one group it is. What a list costs is counted after the
//! length-ratio gate, so a list of widely differing sizes is charged for the
//! few pairs it really contributes.
//!
//! Output is a pure function of the input: the index is ordered, pairing is
//! deterministic, and the emitted pairs are sorted.

use std::collections::BTreeMap;

use crate::features::{FeatureHash, FileFeatures, UnitRef};

/// Default smallest skeleton size, in control operations, for a unit to be
/// indexed.
///
/// Four operations is one control construct nested inside another — a branch
/// inside a loop, say — which is the point at which a skeleton starts to
/// distinguish one function from the next. Below it the skeletons of unrelated
/// code coincide constantly, and the posting cap would be doing all the work.
pub const DEFAULT_MIN_OPS: u32 = 4;

/// Default largest unit-size ratio a pair may span.
pub const DEFAULT_MAX_LENGTH_RATIO: f64 = 3.0;

/// Default posting-list cap; longer lists are common structure and dropped.
pub const DEFAULT_POSTING_CAP: usize = 256;

/// Default global candidate-pair upper bound.
pub const DEFAULT_PAIR_BUDGET: usize = 2_000_000;

/// Tuning for control-flow candidate generation.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlFlowConfig {
    /// Units whose skeleton holds fewer operations than this are not indexed.
    pub min_ops: u32,
    /// Largest ratio of unit sizes (in nodes) a pair may span.
    pub max_length_ratio: f64,
    /// Longest posting list that still enters pairing; longer ones are dropped
    /// as common structure and counted.
    pub posting_cap: usize,
    /// Upper bound on candidate pairs emitted.
    pub pair_budget: usize,
}

impl Default for ControlFlowConfig {
    fn default() -> Self {
        Self {
            min_ops: DEFAULT_MIN_OPS,
            max_length_ratio: DEFAULT_MAX_LENGTH_RATIO,
            posting_cap: DEFAULT_POSTING_CAP,
            pair_budget: DEFAULT_PAIR_BUDGET,
        }
    }
}

/// A control-flow candidate: two units with the same control-flow skeleton.
/// Canonical: `a < b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlFlowPair {
    /// The lower unit.
    pub a: UnitRef,
    /// The higher unit.
    pub b: UnitRef,
    /// The skeleton hash the two share.
    pub hash: FeatureHash,
}

/// Counters describing what control-flow generation saw and dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlFlowStats {
    /// Units across all files.
    pub units: usize,
    /// Units indexed (cleared `min_ops`).
    pub indexed_units: usize,
    /// Units skipped for having too small a skeleton.
    pub skipped_shallow: usize,
    /// Distinct skeletons in the index.
    pub distinct_skeletons: usize,
    /// Skeletons dropped for exceeding the posting cap.
    pub stop_skeletons: usize,
    /// Units dropped with them.
    pub stop_postings: usize,
    /// Pairs dropped by the length-ratio gate.
    pub filtered_by_size: usize,
    /// Candidate pairs emitted.
    pub candidate_pairs: usize,
    /// Whether the pair budget ran out before all posting lists were paired.
    pub budget_exhausted: bool,
    /// Candidate pairs in lists the pair budget refused after their
    /// length-ratio gate was evaluated.
    pub budget_dropped: usize,
}

/// The control-flow stage's output: candidate unit pairs plus funnel counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowSet {
    /// Candidate pairs, deterministically ordered by `(a, b)`.
    pub pairs: Vec<ControlFlowPair>,
    /// What the stage saw and dropped.
    pub stats: ControlFlowStats,
}

/// Generate control-flow candidate unit pairs across `files`.
///
/// The result is a pure function of the input: file order only moves the `file`
/// indices inside the unit references.
#[must_use]
pub fn generate(files: &[FileFeatures], config: &ControlFlowConfig) -> ControlFlowSet {
    let mut index: BTreeMap<FeatureHash, Vec<UnitRef>> = BTreeMap::new();
    let mut stats = ControlFlowStats::default();

    for (file, features) in files.iter().enumerate() {
        stats.units += features.units.len();
        for (unit, unit_features) in features.units.iter().enumerate() {
            if unit_features.cfg.skeleton_ops < config.min_ops {
                stats.skipped_shallow += 1;
                continue;
            }
            index
                .entry(unit_features.cfg.skeleton_hash)
                .or_default()
                .push(UnitRef {
                    file,
                    unit,
                    node_count: unit_features.vector.node_count,
                });
        }
    }
    stats.indexed_units = index.values().map(Vec::len).sum();
    stats.distinct_skeletons = index.len();

    // Posting lists eligible for pairing: at least two units and within the
    // high-frequency cap. Everything else is dropped and counted.
    let mut eligible: Vec<(&FeatureHash, &Vec<UnitRef>)> = Vec::new();
    for (hash, postings) in &index {
        if postings.len() > config.posting_cap {
            stats.stop_skeletons += 1;
            stats.stop_postings += postings.len();
        } else if postings.len() >= 2 {
            eligible.push((hash, postings));
        }
    }
    // Rarest-first: a skeleton shared by two units says far more than one
    // shared by fifty, so budget exhaustion sacrifices the common ones.
    eligible.sort_by(|a, b| a.1.len().cmp(&b.1.len()).then_with(|| a.0.cmp(b.0)));

    let mut pairs = Vec::new();
    let mut remaining = config.pair_budget;
    for (index, &(hash, postings)) in eligible.iter().enumerate() {
        // Charge the closed-form upper bound before entering the quadratic
        // length-ratio loop. Lists are shortest-first, so a later list cannot
        // fit after this one fails; stopping here makes the budget bound work.
        let possible = postings
            .len()
            .saturating_mul(postings.len().saturating_sub(1))
            / 2;
        if possible > remaining {
            stats.budget_exhausted = true;
            stats.budget_dropped = eligible[index..].iter().fold(0, |total, (_, list)| {
                total.saturating_add(list.len().saturating_mul(list.len().saturating_sub(1)) / 2)
            });
            break;
        }
        remaining -= possible;
        let mut filtered = 0usize;
        for (i, &a) in postings.iter().enumerate() {
            for &b in &postings[i + 1..] {
                if a.within_length_ratio(b, config.max_length_ratio) {
                } else {
                    filtered += 1;
                }
            }
        }
        stats.filtered_by_size += filtered;
        for (i, &a) in postings.iter().enumerate() {
            for &b in &postings[i + 1..] {
                if a.within_length_ratio(b, config.max_length_ratio) {
                    let (a, b) = if a <= b { (a, b) } else { (b, a) };
                    pairs.push(ControlFlowPair { a, b, hash: *hash });
                }
            }
        }
    }

    // Sort into a stable output order independent of the rarest-first walk.
    pairs.sort();
    stats.candidate_pairs = pairs.len();
    ControlFlowSet { pairs, stats }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::features::{
        ApiCallFeature, CfgFeature, CharacteristicVector, SubtreeFeature, UnitFeatures,
        WindowFeature,
    };
    use crate::ir::ByteRange;

    fn hash(seed: u8) -> FeatureHash {
        FeatureHash::from_bytes([seed; 16])
    }

    /// A unit with the given skeleton hash, op count and node count. The
    /// window and subtree sets are left empty: this stage never reads them,
    /// which is the whole point of having it.
    fn unit(skeleton: u8, op_count: u32, node_count: u32) -> UnitFeatures {
        UnitFeatures {
            name: None,
            shape_tag: 1,
            range: ByteRange { start: 0, end: 100 },
            windows: Vec::<WindowFeature>::new(),
            subtrees: Vec::<SubtreeFeature>::new(),
            vector: CharacteristicVector {
                node_count,
                ..CharacteristicVector::default()
            },
            cfg: CfgFeature {
                hash: hash(skeleton),
                skeleton_hash: hash(skeleton),
                op_count,
                skeleton_ops: op_count,
                max_loop_depth: 1,
                branch_count: 1,
            },
            api: ApiCallFeature {
                names: Vec::new(),
                sequence_hash: hash(0),
                multiset_hash: hash(0),
            },
        }
    }

    fn file(units: Vec<UnitFeatures>) -> FileFeatures {
        FileFeatures { units }
    }

    #[test]
    fn two_units_sharing_a_skeleton_are_a_candidate_pair() {
        // Neither unit has a single window or subtree in common with the
        // other — they have none at all — and they still pair.
        let files = vec![file(vec![unit(1, 4, 20)]), file(vec![unit(1, 4, 24)])];
        let set = generate(&files, &ControlFlowConfig::default());
        assert_eq!(set.pairs.len(), 1);
        assert_eq!(set.pairs[0].hash, hash(1));
        assert_eq!((set.pairs[0].a.file, set.pairs[0].b.file), (0, 1));
        assert_eq!(set.stats.indexed_units, 2);
        assert!(!set.stats.budget_exhausted);
    }

    #[test]
    fn different_skeletons_do_not_pair() {
        let files = vec![file(vec![unit(1, 4, 20), unit(2, 4, 20)])];
        let set = generate(&files, &ControlFlowConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.distinct_skeletons, 2);
    }

    #[test]
    fn a_skeleton_too_small_to_mean_anything_is_not_indexed() {
        // Three control ops, one below the minimum: two units that would
        // otherwise pair are left out, and the skip is counted.
        let files = vec![file(vec![unit(1, 3, 20), unit(1, 3, 20)])];
        let set = generate(&files, &ControlFlowConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.skipped_shallow, 2);
        assert_eq!(set.stats.indexed_units, 0);
    }

    #[test]
    fn a_size_mismatched_pair_is_rejected_and_counted() {
        // Same skeleton, sizes 10 and 40: ratio 4 exceeds the cap of 3.
        let files = vec![file(vec![unit(1, 4, 10), unit(1, 4, 40)])];
        let set = generate(&files, &ControlFlowConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.filtered_by_size, 1);
    }

    #[test]
    fn a_common_skeleton_is_dropped_whole_and_counted() {
        let files = vec![file(vec![
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(1, 4, 20),
        ])];
        let config = ControlFlowConfig {
            posting_cap: 3,
            ..ControlFlowConfig::default()
        };
        let set = generate(&files, &config);
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.stop_skeletons, 1);
        assert_eq!(set.stats.stop_postings, 4);
    }

    #[test]
    fn the_pair_budget_refuses_a_list_it_cannot_pair_whole() {
        // One skeleton over four units => C(4,2) = 6 pairs, budget 2. Taking
        // two of them would hand grouping four units compared to each other in
        // part, which reads there as four units that disagree.
        let files = vec![file(vec![
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(1, 4, 20),
        ])];
        let config = ControlFlowConfig {
            pair_budget: 2,
            ..ControlFlowConfig::default()
        };
        let set = generate(&files, &config);
        assert!(set.pairs.is_empty());
        assert!(set.stats.budget_exhausted);
        assert_eq!(set.stats.budget_dropped, 6);
    }

    #[test]
    fn a_refused_list_stops_before_later_quadratic_work() {
        // Rarest-first meets the three-unit list first. Its C(3,2) work bound
        // exceeds the allowance, so the longer list is never walked even
        // though its length-ratio gate would have left one pair.
        let files = vec![file(vec![
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(1, 4, 20),
            unit(2, 4, 20),
            unit(2, 4, 20),
            unit(2, 4, 100),
            unit(2, 4, 400),
        ])];
        let config = ControlFlowConfig {
            pair_budget: 1,
            ..ControlFlowConfig::default()
        };
        let set = generate(&files, &config);
        assert!(set.pairs.is_empty());
        assert!(set.stats.budget_exhausted);
        assert_eq!(set.stats.filtered_by_size, 0);
        assert_eq!(set.stats.budget_dropped, 9);
    }

    #[test]
    fn generation_is_deterministic() {
        let files = vec![
            file(vec![unit(1, 4, 20), unit(2, 5, 30)]),
            file(vec![unit(1, 4, 22), unit(2, 5, 31)]),
        ];
        let a = generate(&files, &ControlFlowConfig::default());
        let b = generate(&files, &ControlFlowConfig::default());
        assert_eq!(a, b);
        assert_eq!(a.pairs.len(), 2);
    }
}
