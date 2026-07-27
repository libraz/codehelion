//! Structural-mode near-match candidate generation: `MinHash` + LSH.
//!
//! The exact-hash seed layer ([`crate::candidate`]) finds fragments whose
//! structure is *identical* under the feature recipe — Type-1 and Type-2
//! clones. Type-3 clones differ: statements inserted, deleted or reordered, so
//! no single hash matches end to end, but most of the two units' structural
//! fingerprints still coincide. This layer finds those units by set
//! similarity.
//!
//! Each unit becomes a shingle set — the union of its statement-window and
//! subtree feature hashes. A `MinHash` signature estimates the Jaccard
//! similarity of any two sets from a fixed-length vector, and Locality-
//! Sensitive Hashing bands those signatures so that only unit pairs likely to
//! be similar are ever examined, sidestepping the quadratic all-pairs compare.
//!
//! LSH is probabilistic, so it is used only to *propose* pairs; every proposed
//! pair must then clear two deterministic gates before it is emitted, which is
//! also what keeps the output a pure function of the input:
//!
//! - a **length-ratio** pre-filter drops pairs whose unit sizes differ by more
//!   than [`NearMatchConfig::max_length_ratio`] — a large and a small unit are
//!   not a Type-3 pair however their shingles happened to band;
//! - an **estimated-Jaccard** gate drops pairs whose signature similarity is
//!   below [`NearMatchConfig::min_estimated_jaccard`], so a spurious band
//!   collision between dissimilar units never survives.
//!
//! Candidate-explosion control matches the seed layer (AGENTS.md invariant
//! 10): an LSH bucket larger than the posting cap is high-frequency structure
//! and is dropped whole and counted, and a global pair budget bounds the
//! distinct pairs examined, spent smallest-bucket-first so exhaustion drops
//! the lowest-signal candidates. Everything dropped is counted in
//! [`NearMatchStats`].
//!
//! This design deliberately subsumes the separate size-bucket and
//! prefix-filtering prefilters: LSH banding partitions the search, and the
//! length-ratio gate bounds size divergence, which together already bound the
//! candidate set without a second size index.

use std::collections::{BTreeMap, BTreeSet};

use crate::features::{FileFeatures, UnitFeatures, UnitRef};

/// Default number of `MinHash` permutations per signature.
pub const DEFAULT_NUM_HASHES: usize = 128;

/// Default number of LSH bands; rows per band is `num_hashes / bands`.
///
/// Two rows per band puts the LSH S-curve crossover (~`(1/bands)^(1/rows)`)
/// well below [`DEFAULT_MIN_ESTIMATED_JACCARD`], so LSH proposes every pair the
/// acceptance gate would keep and the gate, not LSH, sets precision. The
/// recall/candidate-count trade-off is calibrated against the corpus.
pub const DEFAULT_BANDS: usize = 64;

/// Default largest unit-size ratio a pair may span.
pub const DEFAULT_MAX_LENGTH_RATIO: f64 = 3.0;

/// Default smallest shingle-set size a unit needs to be signed. Below this a
/// `MinHash` estimate is too noisy to trust.
pub const DEFAULT_MIN_SHINGLES: usize = 4;

/// Default smallest estimated Jaccard a pair must reach to be emitted. Type-3
/// edits routinely land here.
///
/// Not calibrated against the corpus, and not for want of trying: every value
/// from 0.1 to one no estimate can reach leaves every corpus this project has
/// reporting exactly the same groups. Turning the stage off does too. What
/// this gate is worth is therefore unmeasured rather than measured and small —
/// the stage exists for gapped clones the exact seeds miss, and the largest
/// case here is under half a million lines.
pub const DEFAULT_MIN_ESTIMATED_JACCARD: f64 = 0.3;

/// Default LSH-bucket cap; larger buckets are high-frequency and dropped.
pub const DEFAULT_POSTING_CAP: usize = 256;

/// Default global candidate-pair upper bound.
pub const DEFAULT_PAIR_BUDGET: usize = 2_000_000;

/// Tuning for near-match candidate generation. Defaults are provisional and
/// calibrated against the corpus with the funnel measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct NearMatchConfig {
    /// Number of `MinHash` permutations per signature.
    pub num_hashes: usize,
    /// Number of LSH bands. Rows per band is `num_hashes / bands`; a higher
    /// band count raises recall at the cost of more candidate pairs.
    pub bands: usize,
    /// Units with fewer distinct shingles than this are not signed.
    pub min_shingles: usize,
    /// Largest ratio of unit sizes (in nodes) a pair may span.
    pub max_length_ratio: f64,
    /// Smallest estimated Jaccard a pair must reach to be emitted.
    pub min_estimated_jaccard: f64,
    /// Longest LSH bucket that still enters pairing; longer ones are dropped
    /// as high-frequency structure and counted.
    pub posting_cap: usize,
    /// Upper bound on distinct candidate pairs examined.
    pub pair_budget: usize,
}

impl Default for NearMatchConfig {
    fn default() -> Self {
        Self {
            num_hashes: DEFAULT_NUM_HASHES,
            bands: DEFAULT_BANDS,
            min_shingles: DEFAULT_MIN_SHINGLES,
            max_length_ratio: DEFAULT_MAX_LENGTH_RATIO,
            min_estimated_jaccard: DEFAULT_MIN_ESTIMATED_JACCARD,
            posting_cap: DEFAULT_POSTING_CAP,
            pair_budget: DEFAULT_PAIR_BUDGET,
        }
    }
}

impl NearMatchConfig {
    /// Rows per band, at least one, never more than the signature length.
    fn rows(&self) -> usize {
        (self.num_hashes / self.bands.max(1)).max(1)
    }
}

/// A near-match candidate: two units whose structural shingle sets overlap
/// enough to be a possible Type-3 clone. Canonical: `a < b`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NearMatchPair {
    /// The lower unit.
    pub a: UnitRef,
    /// The higher unit.
    pub b: UnitRef,
    /// `MinHash`-estimated Jaccard similarity of the two shingle sets.
    pub estimated_jaccard: f64,
}

/// Counters describing what near-match generation saw and dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NearMatchStats {
    /// Units across all files.
    pub units: usize,
    /// Units signed (cleared `min_shingles`).
    pub signed_units: usize,
    /// Units skipped for having too few shingles.
    pub skipped_small: usize,
    /// LSH buckets with at least two members.
    pub buckets: usize,
    /// Buckets dropped for exceeding the posting cap.
    pub stop_buckets: usize,
    /// Bucket members dropped with them.
    pub stop_bucket_members: usize,
    /// Distinct pairs proposed by LSH before the deterministic gates.
    pub proposed_pairs: usize,
    /// Pairs dropped by the length-ratio gate.
    pub filtered_by_size: usize,
    /// Pairs dropped by the estimated-Jaccard gate.
    pub filtered_by_jaccard: usize,
    /// Candidate pairs emitted.
    pub candidate_pairs: usize,
    /// Whether the pair budget ran out before all buckets were paired.
    pub budget_exhausted: bool,
}

/// The near-match stage's output: candidate unit pairs plus funnel statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct NearMatchSet {
    /// Candidate pairs, deterministically ordered by `(a, b)`.
    pub pairs: Vec<NearMatchPair>,
    /// What the stage saw and dropped.
    pub stats: NearMatchStats,
}

/// Generate near-match candidate unit pairs across `files`.
///
/// The result is a pure function of the input: the `MinHash` permutations are
/// fixed, LSH bucketing is deterministic, and the emitted pairs are sorted, so
/// file order only moves the `file` indices inside the unit references.
#[must_use]
pub fn generate(files: &[FileFeatures], config: &NearMatchConfig) -> NearMatchSet {
    let seeds = permutation_seeds(config.num_hashes);
    let mut stats = NearMatchStats::default();

    // Sign every unit large enough to trust; carry its reference and signature.
    let mut signed: Vec<(UnitRef, Vec<u64>)> = Vec::new();
    for (file, features) in files.iter().enumerate() {
        stats.units += features.units.len();
        for (unit, unit_features) in features.units.iter().enumerate() {
            let shingles = shingles_of(unit_features);
            if shingles.len() < config.min_shingles {
                stats.skipped_small += 1;
                continue;
            }
            let unit_ref = UnitRef {
                file,
                unit,
                node_count: unit_features.vector.node_count,
            };
            signed.push((unit_ref, signature(&shingles, &seeds)));
        }
    }
    stats.signed_units = signed.len();

    let proposed = propose_pairs(&signed, config, &mut stats);
    stats.proposed_pairs = proposed.len();

    // Apply the deterministic gates. `proposed` is already sorted, so output
    // ordering is stable without re-sorting.
    let mut pairs = Vec::new();
    for (ai, bi) in proposed {
        let (ref_a, sig_a) = &signed[ai];
        let (ref_b, sig_b) = &signed[bi];
        if !ref_a.within_length_ratio(*ref_b, config.max_length_ratio) {
            stats.filtered_by_size += 1;
            continue;
        }
        let estimated = estimated_jaccard(sig_a, sig_b);
        if estimated < config.min_estimated_jaccard {
            stats.filtered_by_jaccard += 1;
            continue;
        }
        pairs.push(NearMatchPair {
            a: *ref_a,
            b: *ref_b,
            estimated_jaccard: estimated,
        });
    }
    stats.candidate_pairs = pairs.len();
    NearMatchSet { pairs, stats }
}

/// Propose candidate index pairs (into `signed`) via LSH banding, applying the
/// bucket cap and pair budget. Returns distinct `(a, b)` index pairs with
/// `a < b`, sorted.
fn propose_pairs(
    signed: &[(UnitRef, Vec<u64>)],
    config: &NearMatchConfig,
    stats: &mut NearMatchStats,
) -> Vec<(usize, usize)> {
    let rows = config.rows();
    let bands = config.num_hashes / rows;

    // band key -> member unit indices. The band index is folded into the key,
    // so two units collide here only when they share the same rows of the same
    // band.
    let mut buckets: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, (_, sig)) in signed.iter().enumerate() {
        for band in 0..bands {
            let start = band * rows;
            let key = band_key(band, &sig[start..start + rows]);
            buckets.entry(key).or_default().push(index);
        }
    }

    // Bucket lists, smallest first: rarest buckets carry the highest signal, so
    // budget exhaustion drops the largest (lowest-signal) buckets.
    let mut lists: Vec<&Vec<usize>> = buckets
        .values()
        .filter(|members| members.len() >= 2)
        .collect();
    lists.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut remaining = config.pair_budget;
    'lists: for members in lists {
        stats.buckets += 1;
        if members.len() > config.posting_cap {
            stats.stop_buckets += 1;
            stats.stop_bucket_members += members.len();
            continue;
        }
        for (i, &a) in members.iter().enumerate() {
            for &b in &members[i + 1..] {
                let pair = if a <= b { (a, b) } else { (b, a) };
                if seen.contains(&pair) {
                    continue;
                }
                if remaining == 0 {
                    stats.budget_exhausted = true;
                    break 'lists;
                }
                remaining -= 1;
                seen.insert(pair);
            }
        }
    }

    seen.into_iter().collect()
}

/// The union of a unit's window and subtree feature hashes, folded to `u64`
/// shingles, sorted and deduplicated. The kind is mixed in so a window hash
/// and a subtree hash with the same bytes stay distinct shingles.
fn shingles_of(unit: &UnitFeatures) -> Vec<u64> {
    const WINDOW_DOMAIN: u64 = 0x5749_4e44_4f57_0000; // "WINDOW"
    const SUBTREE_DOMAIN: u64 = 0x5355_4254_5245_0000; // "SUBTRE"
    let mut shingles: Vec<u64> = Vec::with_capacity(unit.windows.len() + unit.subtrees.len());
    for window in &unit.windows {
        shingles.push(fold_hash(window.hash.as_bytes()) ^ WINDOW_DOMAIN);
    }
    for subtree in &unit.subtrees {
        shingles.push(fold_hash(subtree.hash.as_bytes()) ^ SUBTREE_DOMAIN);
    }
    shingles.sort_unstable();
    shingles.dedup();
    shingles
}

/// Fold a 16-byte feature hash to a `u64` shingle base. The two halves are
/// mixed with distinct multipliers and a finalizer, so distinct hashes stay
/// distinct even when their bytes are symmetric.
fn fold_hash(bytes: &[u8; 16]) -> u64 {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&bytes[..8]);
    hi.copy_from_slice(&bytes[8..]);
    let a = u64::from_le_bytes(lo);
    let b = u64::from_le_bytes(hi);
    let mut z = a.wrapping_mul(0xff51_afd7_ed55_8ccd) ^ b.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    z = (z ^ (z >> 33)).wrapping_mul(0xff51_afd7_ed55_8ccd);
    z ^ (z >> 29)
}

/// The `MinHash` signature of a shingle set: the per-permutation minimum.
fn signature(shingles: &[u64], seeds: &[u64]) -> Vec<u64> {
    seeds
        .iter()
        .map(|&seed| {
            shingles
                .iter()
                .map(|&shingle| permute(shingle, seed))
                .min()
                .unwrap_or(u64::MAX)
        })
        .collect()
}

/// Estimated Jaccard similarity: the fraction of signature positions that
/// agree. Signatures always share a length here.
fn estimated_jaccard(a: &[u64], b: &[u64]) -> f64 {
    let equal = a.iter().zip(b).filter(|(x, y)| x == y).count();
    frac(equal, a.len())
}

/// Lossless `usize` ratio via `u32`, `0.0` when the denominator is zero.
fn frac(numer: usize, denom: usize) -> f64 {
    let n = u32::try_from(numer).unwrap_or(u32::MAX);
    let d = u32::try_from(denom).unwrap_or(u32::MAX);
    if d == 0 {
        0.0
    } else {
        f64::from(n) / f64::from(d)
    }
}

/// A deterministic table of `count` permutation seeds from a fixed constant,
/// so signatures never depend on run-time randomness.
fn permutation_seeds(count: usize) -> Vec<u64> {
    let mut state = 0x1234_5678_9abc_def0u64;
    (0..count).map(|_| splitmix64(&mut state)).collect()
}

/// `SplitMix64`: a deterministic seed generator.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// One `MinHash` permutation of a shingle: a strong finalizer of `x ^ seed`.
const fn permute(x: u64, seed: u64) -> u64 {
    let mut z = x ^ seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A band's key: the band index folded together with its signature rows.
fn band_key(band: usize, rows: &[u64]) -> u64 {
    let mut z = 0xcbf2_9ce4_8422_2325u64 ^ (band as u64).wrapping_mul(0x1_0000_01b3);
    for &row in rows {
        z = (z ^ row).wrapping_mul(0x0000_0100_0000_01b3);
    }
    z ^ (z >> 32)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::features::{
        ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, SubtreeFeature,
        UnitFeatures, WindowFeature,
    };
    use crate::ir::ByteRange;

    /// A unit whose shingle set is exactly the given window and subtree hash
    /// seeds, with a chosen node count for the length-ratio gate.
    fn unit(windows: &[u8], subtrees: &[u8], node_count: u32) -> UnitFeatures {
        let windows = windows
            .iter()
            .map(|&seed| WindowFeature {
                hash: FeatureHash::from_bytes([seed; 16]),
                length: 4,
                range: ByteRange { start: 0, end: 8 },
                block: 0,
                offset: 0,
            })
            .collect();
        let subtrees = subtrees
            .iter()
            .map(|&seed| SubtreeFeature {
                hash: FeatureHash::from_bytes([seed; 16]),
                node_count: 6,
                range: ByteRange { start: 0, end: 8 },
            })
            .collect();
        let vector = CharacteristicVector {
            node_count,
            ..CharacteristicVector::default()
        };
        UnitFeatures {
            name: None,
            shape_tag: 1,
            range: ByteRange { start: 0, end: 100 },
            windows,
            subtrees,
            vector,
            cfg: CfgFeature {
                hash: FeatureHash::from_bytes([0; 16]),
                skeleton_hash: FeatureHash::from_bytes([0; 16]),
                op_count: 0,
                skeleton_ops: 0,
                max_loop_depth: 0,
                branch_count: 0,
            },
            api: ApiCallFeature {
                names: Vec::new(),
                sequence_hash: FeatureHash::from_bytes([0; 16]),
                multiset_hash: FeatureHash::from_bytes([0; 16]),
            },
        }
    }

    fn file(units: Vec<UnitFeatures>) -> FileFeatures {
        FileFeatures { units }
    }

    #[test]
    fn identical_units_are_a_candidate_with_full_similarity() {
        let files = vec![
            file(vec![unit(&[1, 2, 3, 4], &[5, 6], 20)]),
            file(vec![unit(&[1, 2, 3, 4], &[5, 6], 20)]),
        ];
        let set = generate(&files, &NearMatchConfig::default());
        assert_eq!(set.pairs.len(), 1);
        assert!((set.pairs[0].estimated_jaccard - 1.0).abs() < f64::EPSILON);
        assert_eq!(set.stats.signed_units, 2);
        assert!(!set.stats.budget_exhausted);
    }

    #[test]
    fn a_high_overlap_pair_is_proposed_and_its_estimate_is_accurate() {
        // Sets share five of seven shingles: true Jaccard = 5/9.
        let a = unit(&[1, 2, 3, 4, 5], &[6, 7], 20);
        let b = unit(&[1, 2, 3, 4, 5], &[8, 9], 20);
        let files = vec![file(vec![a, b])];
        let config = NearMatchConfig {
            min_estimated_jaccard: 0.3,
            ..NearMatchConfig::default()
        };
        let set = generate(&files, &config);
        assert_eq!(set.pairs.len(), 1, "a high-overlap pair must surface");
        // True Jaccard 5/9 ~= 0.556; a 128-hash estimate lands close.
        let true_jaccard = 5.0 / 9.0;
        assert!(
            (set.pairs[0].estimated_jaccard - true_jaccard).abs() < 0.15,
            "estimate {} too far from {true_jaccard}",
            set.pairs[0].estimated_jaccard
        );
    }

    #[test]
    fn disjoint_units_are_rejected_by_the_jaccard_gate() {
        let files = vec![file(vec![
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[10, 11, 12, 13], &[14, 15], 20),
        ])];
        let set = generate(&files, &NearMatchConfig::default());
        assert!(
            set.pairs.is_empty(),
            "disjoint units must not be candidates"
        );
        // Even if LSH proposed nothing, the estimate gate would have caught it.
        assert_eq!(set.stats.candidate_pairs, 0);
    }

    #[test]
    fn the_length_ratio_gate_drops_size_mismatched_pairs() {
        // Identical shingles, but sizes 10 vs 40: ratio 4 exceeds the cap of 3.
        let files = vec![file(vec![
            unit(&[1, 2, 3, 4], &[5, 6], 10),
            unit(&[1, 2, 3, 4], &[5, 6], 40),
        ])];
        let set = generate(&files, &NearMatchConfig::default());
        assert!(set.pairs.is_empty());
        assert_eq!(set.stats.filtered_by_size, 1);
        assert_eq!(set.stats.filtered_by_jaccard, 0);
    }

    #[test]
    fn a_unit_with_too_few_shingles_is_not_signed() {
        let files = vec![file(vec![unit(&[1, 2], &[], 20), unit(&[1, 2], &[], 20)])];
        let set = generate(&files, &NearMatchConfig::default());
        assert_eq!(set.stats.signed_units, 0);
        assert_eq!(set.stats.skipped_small, 2);
        assert!(set.pairs.is_empty());
    }

    #[test]
    fn a_high_frequency_bucket_is_dropped_and_counted() {
        // Four identical units, bucket cap 3: every band bucket holds all four
        // and is stopped, so no pair survives.
        let files = vec![file(vec![
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[1, 2, 3, 4], &[5, 6], 20),
        ])];
        let config = NearMatchConfig {
            posting_cap: 3,
            ..NearMatchConfig::default()
        };
        let set = generate(&files, &config);
        assert!(set.pairs.is_empty());
        assert!(set.stats.stop_buckets > 0);
        assert_eq!(set.stats.candidate_pairs, 0);
    }

    #[test]
    fn the_pair_budget_truncates_and_records_it() {
        let files = vec![file(vec![
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[1, 2, 3, 4], &[5, 6], 20),
            unit(&[1, 2, 3, 4], &[5, 6], 20),
        ])];
        let config = NearMatchConfig {
            pair_budget: 1,
            ..NearMatchConfig::default()
        };
        let set = generate(&files, &config);
        assert_eq!(set.stats.proposed_pairs, 1);
        assert!(set.stats.budget_exhausted);
    }

    #[test]
    fn generation_is_deterministic() {
        let files = vec![
            file(vec![unit(&[1, 2, 3, 4], &[5, 6], 20)]),
            file(vec![unit(&[1, 2, 3, 5], &[5, 6], 22)]),
        ];
        let a = generate(&files, &NearMatchConfig::default());
        let b = generate(&files, &NearMatchConfig::default());
        assert_eq!(a, b);
    }
}
