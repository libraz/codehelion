//! Structural-mode candidate generation: the inverted-index seed layer.
//!
//! Verifying every pair of fragments in a corpus is quadratic and hopeless at
//! scale, so detection never starts from pairs. It starts from an inverted
//! index: statement-window and subtree feature hashes ([`crate::features`])
//! map to the fragments that produced them, and only fragments that landed in
//! the same posting list — an exact structural match under the feature recipe
//! — become candidate pairs. The approximate near-match layer (characteristic
//! vector nearest-neighbour, `MinHash`/LSH) plugs in behind the same
//! candidate-emitting interface later; this layer is the exact-match seed.
//!
//! Candidate-explosion control is a first-class concern, not an afterthought
//! (AGENTS.md invariant 10). Two controls act here, both before any pair
//! leaves the stage, and both count what they drop into [`CandidateStats`]
//! rather than letting it vanish:
//!
//! - **high-frequency suppression** — a hash whose posting list exceeds
//!   [`CandidateConfig::posting_cap`] is boilerplate-shaped noise that would
//!   dominate the pair budget; it is dropped whole and counted;
//! - **a global candidate upper bound** — posting lists are paired
//!   rarest-first, so when [`CandidateConfig::pair_budget`] runs out the
//!   high-frequency, low-signal lists are the ones sacrificed, and the set
//!   records that it was truncated.
//!
//! Output is a pure function of the input: the emitted pairs are sorted
//! deterministically, so file order only moves the `file` indices inside the
//! fragment references and never changes which pairs appear or in what order.

use std::collections::BTreeMap;

use crate::features::{FeatureHash, FeatureKind, FileFeatures};

/// Default posting-list cap. Provisional; the corpus funnel measurement
/// calibrates it against real high-frequency structure.
pub const DEFAULT_POSTING_CAP: usize = 256;

/// Default global candidate-pair upper bound. Provisional, as above.
pub const DEFAULT_PAIR_BUDGET: usize = 2_000_000;

/// Tuning for candidate generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfig {
    /// Longest posting list that still enters pairing; longer ones are dropped
    /// as high-frequency noise and counted.
    pub posting_cap: usize,
    /// Upper bound on candidate pairs emitted. Pairing is rarest-first, so
    /// exhaustion sacrifices the lowest-signal candidates.
    pub pair_budget: usize,
}

impl Default for CandidateConfig {
    fn default() -> Self {
        Self {
            posting_cap: DEFAULT_POSTING_CAP,
            pair_budget: DEFAULT_PAIR_BUDGET,
        }
    }
}

/// Where a statement-window fragment sits in its unit's statement sequences.
///
/// This is position, not identity: it lets adjacent window matches be folded
/// back into one maximal statement run ([`crate::maximal`]), and it never
/// enters a fingerprint (AGENTS.md invariant 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatementRun {
    /// Ordinal of the enclosing block within the unit, in walk order.
    pub block: u32,
    /// Index of the run's first statement within that block.
    pub start: u32,
    /// Length of the run, in statements.
    pub length: u32,
}

impl StatementRun {
    /// Index one past the run's last statement.
    #[must_use]
    pub const fn end(self) -> u32 {
        self.start.saturating_add(self.length)
    }
}

/// One occurrence of a hashed fragment (a statement window or a subtree) at a
/// source location. `file` indexes the slice given to [`generate`]; `unit`
/// indexes that file's [`FileFeatures::units`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FragmentRef {
    /// Index of the file in the input slice.
    pub file: usize,
    /// Index of the enclosing unit in the file's units.
    pub unit: usize,
    /// Anchor: first byte the fragment covers.
    pub start_byte: usize,
    /// Anchor: one past the last byte the fragment covers.
    pub end_byte: usize,
    /// Kind-specific size: window length or subtree node count.
    pub extent: u32,
    /// The statement run this fragment covers, for a statement window. `None`
    /// for a subtree, which is a tree region rather than a run of siblings.
    pub run: Option<StatementRun>,
}

/// An exact-hash candidate pair: two fragments that share one feature hash.
///
/// The pair is canonical: `a < b` by fragment reference, so the same two
/// fragments never appear in both orders.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidatePair {
    /// Which feature family the shared hash came from.
    pub kind: FeatureKind,
    /// The shared feature hash.
    pub hash: FeatureHash,
    /// The lower fragment.
    pub a: FragmentRef,
    /// The higher fragment.
    pub b: FragmentRef,
}

/// Counters describing what candidate generation saw and dropped: the head of
/// the detection funnel, recorded for the `doctor`/verbose view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateStats {
    /// Units across all files.
    pub units: usize,
    /// Window and subtree occurrences indexed.
    pub fragments: usize,
    /// Distinct feature hashes in the index.
    pub distinct_fingerprints: usize,
    /// Distinct hashes dropped for exceeding the posting cap.
    pub stop_fingerprints: usize,
    /// Occurrences dropped with them.
    pub stop_postings: usize,
    /// Candidate pairs emitted.
    pub candidate_pairs: usize,
    /// Whether the pair budget ran out before all posting lists were paired.
    pub budget_exhausted: bool,
}

/// The candidate stage's output: exact-hash pairs plus funnel statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSet {
    /// Candidate pairs, deterministically ordered.
    pub pairs: Vec<CandidatePair>,
    /// What the stage saw and dropped.
    pub stats: CandidateStats,
}

/// A remaining candidate-pair allowance; mirrors the Fast engine's budget.
struct PairBudget {
    remaining: usize,
    exhausted: bool,
}

impl PairBudget {
    const fn new(limit: usize) -> Self {
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
}

/// Generate exact-hash candidate pairs across `files`.
///
/// The result is a pure function of the input: file order only affects the
/// `file` indices inside fragment references, and the emitted pairs are sorted
/// deterministically.
#[must_use]
pub fn generate(files: &[FileFeatures], config: &CandidateConfig) -> CandidateSet {
    let mut index: BTreeMap<(FeatureKind, FeatureHash), Vec<FragmentRef>> = BTreeMap::new();
    let mut stats = CandidateStats::default();

    for (file, features) in files.iter().enumerate() {
        stats.units += features.units.len();
        for (unit, unit_features) in features.units.iter().enumerate() {
            for window in &unit_features.windows {
                push_occurrence(
                    &mut index,
                    FeatureKind::StatementWindow,
                    window.hash,
                    FragmentRef {
                        file,
                        unit,
                        start_byte: window.range.start,
                        end_byte: window.range.end,
                        extent: clamp_u32(window.length),
                        run: Some(StatementRun {
                            block: window.block,
                            start: window.offset,
                            length: clamp_u32(window.length),
                        }),
                    },
                );
                stats.fragments += 1;
            }
            for subtree in &unit_features.subtrees {
                push_occurrence(
                    &mut index,
                    FeatureKind::Subtree,
                    subtree.hash,
                    FragmentRef {
                        file,
                        unit,
                        start_byte: subtree.range.start,
                        end_byte: subtree.range.end,
                        extent: clamp_u32(subtree.node_count),
                        run: None,
                    },
                );
                stats.fragments += 1;
            }
        }
    }
    stats.distinct_fingerprints = index.len();

    // Posting lists eligible for pairing: at least two occurrences and within
    // the high-frequency cap. Everything else is dropped and counted.
    let mut eligible: Vec<(&(FeatureKind, FeatureHash), &Vec<FragmentRef>)> = Vec::new();
    for (key, postings) in &index {
        if postings.len() > config.posting_cap {
            stats.stop_fingerprints += 1;
            stats.stop_postings += postings.len();
        } else if postings.len() >= 2 {
            eligible.push((key, postings));
        }
    }
    // Rarest-first: shortest lists carry the highest signal, so when the
    // budget runs out the frequent lists are the ones left unpaired. The key
    // tiebreak keeps the order total and deterministic.
    eligible.sort_by(|a, b| a.1.len().cmp(&b.1.len()).then_with(|| a.0.cmp(b.0)));

    let mut budget = PairBudget::new(config.pair_budget);
    let mut pairs = Vec::new();
    'lists: for (&(kind, hash), postings) in eligible {
        for (i, &a) in postings.iter().enumerate() {
            for &b in &postings[i + 1..] {
                if !budget.take() {
                    break 'lists;
                }
                let (a, b) = if a <= b { (a, b) } else { (b, a) };
                pairs.push(CandidatePair { kind, hash, a, b });
            }
        }
    }

    // Sort into a stable output order independent of the rarest-first walk.
    pairs.sort();
    stats.candidate_pairs = pairs.len();
    stats.budget_exhausted = budget.exhausted;
    CandidateSet { pairs, stats }
}

fn push_occurrence(
    index: &mut BTreeMap<(FeatureKind, FeatureHash), Vec<FragmentRef>>,
    kind: FeatureKind,
    hash: FeatureHash,
    fragment: FragmentRef,
) {
    index.entry((kind, hash)).or_default().push(fragment);
}

fn clamp_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
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

    /// A unit carrying the given window hashes and subtree hashes, each with a
    /// distinct byte anchor so fragments stay distinguishable.
    fn unit_with(windows: &[u8], subtrees: &[u8]) -> UnitFeatures {
        let windows = windows
            .iter()
            .enumerate()
            .map(|(i, &seed)| WindowFeature {
                hash: hash(seed),
                length: 4,
                range: ByteRange {
                    start: i * 10,
                    end: i * 10 + 8,
                },
                block: 0,
                offset: u32::try_from(i).unwrap(),
            })
            .collect();
        let subtrees = subtrees
            .iter()
            .enumerate()
            .map(|(i, &seed)| SubtreeFeature {
                hash: hash(seed),
                node_count: 6,
                range: ByteRange {
                    start: 100 + i * 10,
                    end: 100 + i * 10 + 8,
                },
            })
            .collect();
        UnitFeatures {
            name: None,
            shape_tag: 1,
            range: ByteRange { start: 0, end: 200 },
            windows,
            subtrees,
            vector: CharacteristicVector::default(),
            cfg: CfgFeature {
                hash: hash(0),
                op_count: 0,
                max_loop_depth: 0,
                branch_count: 0,
            },
            api: ApiCallFeature {
                names: Vec::new(),
                sequence_hash: hash(0),
                multiset_hash: hash(0),
            },
        }
    }

    fn file_with(units: Vec<UnitFeatures>) -> FileFeatures {
        FileFeatures { units }
    }

    #[test]
    fn a_shared_hash_across_two_files_is_one_candidate_pair() {
        let files = vec![
            file_with(vec![unit_with(&[7], &[])]),
            file_with(vec![unit_with(&[7], &[])]),
        ];
        let set = generate(&files, &CandidateConfig::default());
        assert_eq!(set.pairs.len(), 1);
        let pair = &set.pairs[0];
        assert_eq!(pair.kind, FeatureKind::StatementWindow);
        assert_eq!(pair.hash, hash(7));
        assert_eq!(pair.a.file, 0);
        assert_eq!(pair.b.file, 1);
        assert_eq!(set.stats.fragments, 2);
        assert_eq!(set.stats.distinct_fingerprints, 1);
        assert_eq!(set.stats.candidate_pairs, 1);
        assert!(!set.stats.budget_exhausted);
    }

    #[test]
    fn a_singleton_hash_yields_no_pair() {
        let files = vec![file_with(vec![unit_with(&[7], &[8])])];
        let set = generate(&files, &CandidateConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.distinct_fingerprints, 2);
        assert_eq!(set.stats.stop_fingerprints, 0);
    }

    #[test]
    fn window_and_subtree_hashes_do_not_cross_match() {
        // Same 16 bytes, but one is a window hash and one a subtree hash: they
        // key on different families and never pair.
        let files = vec![file_with(vec![unit_with(&[9], &[9])])];
        let set = generate(&files, &CandidateConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.distinct_fingerprints, 2);
    }

    #[test]
    fn a_high_frequency_hash_is_dropped_whole_and_counted() {
        // Four occurrences of hash 5, cap of 3: the whole list is stopped.
        let files = vec![file_with(vec![
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
        ])];
        let config = CandidateConfig {
            posting_cap: 3,
            ..CandidateConfig::default()
        };
        let set = generate(&files, &config);
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.stop_fingerprints, 1);
        assert_eq!(set.stats.stop_postings, 4);
        assert_eq!(set.stats.candidate_pairs, 0);
    }

    #[test]
    fn the_pair_budget_truncates_and_records_it() {
        // One hash with four occurrences => C(4,2) = 6 pairs, budget 2.
        let files = vec![file_with(vec![
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
            unit_with(&[5], &[]),
        ])];
        let config = CandidateConfig {
            posting_cap: 64,
            pair_budget: 2,
        };
        let set = generate(&files, &config);
        assert_eq!(set.pairs.len(), 2);
        assert!(set.stats.budget_exhausted);
        assert_eq!(set.stats.candidate_pairs, 2);
    }

    #[test]
    fn generation_is_deterministic() {
        let files = vec![
            file_with(vec![unit_with(&[7, 8], &[20])]),
            file_with(vec![unit_with(&[8], &[20, 21])]),
        ];
        let a = generate(&files, &CandidateConfig::default());
        let b = generate(&files, &CandidateConfig::default());
        assert_eq!(a, b);
        // Hash 8 (2 occurrences) and hash 20 (2 occurrences) each pair once.
        assert_eq!(a.pairs.len(), 2);
    }
}
