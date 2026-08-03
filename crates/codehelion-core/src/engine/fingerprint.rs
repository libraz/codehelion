//! Deterministic content hashing: token hashes, rolling k-grams, winnowing.
//!
//! Every hash here is a pure function of token content (kind tags and
//! normalized or raw text). No process randomness, no position, no file
//! identity enters any hash, so runs are reproducible and equal content always
//! collides intentionally. The 64-bit FNV hashes are used only for candidate
//! indexing. Grouping uses a domain-separated 128-bit BLAKE3 digest, so an
//! attacker-controlled FNV collision cannot combine unrelated findings.

use crate::frontend::Token;

use super::normalize::{NormAtom, NormToken};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Collision-resistant identity of one matched token sequence for grouping.
///
/// This is deliberately separate from the 64-bit FNV candidate key. The
/// latter keeps the index compact; this digest protects the user-visible
/// equivalence relation after candidates have been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ContentDigest([u8; 16]);

impl ContentDigest {
    #[cfg(test)]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Incremental FNV-1a over bytes.
#[derive(Debug, Clone, Copy)]
struct Fnv(u64);

impl Fnv {
    const fn new() -> Self {
        Self(FNV_OFFSET)
    }

    const fn byte(mut self, b: u8) -> Self {
        self.0 ^= b as u64;
        self.0 = self.0.wrapping_mul(FNV_PRIME);
        self
    }

    fn bytes(mut self, bytes: &[u8]) -> Self {
        for &b in bytes {
            self = self.byte(b);
        }
        self
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

/// Hash one raw token: kind tag plus raw text.
#[must_use]
pub fn raw_token_hash(token: &Token) -> u64 {
    Fnv::new()
        .byte(token.kind.tag())
        .bytes(token.text.as_bytes())
        .finish()
}

/// Hash one normalized token: kind tag, atom discriminant, atom payload.
#[must_use]
pub fn norm_token_hash(token: &NormToken<'_>) -> u64 {
    let h = Fnv::new().byte(token.tag);
    match token.atom {
        NormAtom::Renamed(n) => h.byte(1).bytes(&n.to_le_bytes()),
        NormAtom::Text(text) => h.byte(2).bytes(text.as_bytes()),
        NormAtom::Literal(class) => h.byte(3).byte(class),
    }
    .finish()
}

/// Content key of a raw token sequence: the fold of its per-token hashes.
#[must_use]
pub fn raw_sequence_hash(tokens: &[Token]) -> u64 {
    tokens
        .iter()
        .fold(Fnv::new(), |h, t| h.bytes(&raw_token_hash(t).to_le_bytes()))
        .finish()
}

/// Content key of a normalized token sequence.
#[must_use]
pub fn norm_sequence_hash(tokens: &[NormToken<'_>]) -> u64 {
    tokens
        .iter()
        .fold(Fnv::new(), |h, t| {
            h.bytes(&norm_token_hash(t).to_le_bytes())
        })
        .finish()
}

/// Collision-resistant grouping identity of a raw token sequence.
#[must_use]
pub(crate) fn raw_sequence_digest(tokens: &[Token]) -> ContentDigest {
    let mut hasher = sequence_digest_hasher("codehelion/group/raw/v1", tokens.len());
    for token in tokens {
        hasher.update(&[token.kind.tag()]);
        write_bytes(&mut hasher, token.text.as_bytes());
    }
    finish_digest(&hasher)
}

/// Collision-resistant grouping identity of a normalized token sequence.
#[must_use]
pub(crate) fn norm_sequence_digest(tokens: &[NormToken<'_>]) -> ContentDigest {
    let mut hasher = sequence_digest_hasher("codehelion/group/normalized/v1", tokens.len());
    for token in tokens {
        hasher.update(&[token.tag]);
        match token.atom {
            NormAtom::Renamed(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_le_bytes());
            }
            NormAtom::Text(text) => {
                hasher.update(&[2]);
                write_bytes(&mut hasher, text.as_bytes());
            }
            NormAtom::Literal(class) => {
                hasher.update(&[3, class]);
            }
        }
    }
    finish_digest(&hasher)
}

fn sequence_digest_hasher(domain: &str, token_count: usize) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    write_bytes(&mut hasher, domain.as_bytes());
    hasher.update(&u64::try_from(token_count).unwrap_or(u64::MAX).to_le_bytes());
    hasher
}

fn write_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn finish_digest(hasher: &blake3::Hasher) -> ContentDigest {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    ContentDigest(bytes)
}

/// Rolling polynomial hashes of every k-gram of `units` (mod 2^64):
/// `gram(i) = units[i]·B^(k-1) + … + units[i+k-1]`.
///
/// Returns an empty vector when the input is shorter than `k`.
#[must_use]
pub fn kgram_hashes(units: &[u64], k: usize) -> Vec<u64> {
    const B: u64 = FNV_PRIME;
    if k == 0 || units.len() < k {
        return Vec::new();
    }
    let pow = B.wrapping_pow(u32::try_from(k - 1).unwrap_or(u32::MAX));
    let mut out = Vec::with_capacity(units.len() - k + 1);
    let mut h: u64 = 0;
    for &u in &units[..k] {
        h = h.wrapping_mul(B).wrapping_add(u);
    }
    out.push(h);
    for i in k..units.len() {
        h = h
            .wrapping_sub(units[i - k].wrapping_mul(pow))
            .wrapping_mul(B)
            .wrapping_add(units[i]);
        out.push(h);
    }
    out
}

/// Winnowing: select fingerprints from k-gram hashes.
///
/// Over every window of `w` consecutive hashes the minimum is selected
/// (rightmost on ties). Inputs shorter than one window select their global
/// minimum, so short segments are still fingerprinted.
///
/// Returns deduplicated `(hash, gram index)` pairs in ascending index order.
/// The selection guarantees that any shared token run of at least `w + k - 1`
/// tokens produces at least one shared fingerprint.
#[must_use]
pub fn winnow(hashes: &[u64], w: usize) -> Vec<(u64, usize)> {
    use std::collections::VecDeque;

    if hashes.is_empty() || w == 0 {
        return Vec::new();
    }
    if hashes.len() < w {
        let mut best = 0usize;
        for (i, &h) in hashes.iter().enumerate() {
            if h <= hashes[best] {
                best = i;
            }
        }
        return vec![(hashes[best], best)];
    }

    let mut candidates = VecDeque::with_capacity(w);
    let mut picks = Vec::with_capacity(hashes.len().div_ceil(w));
    for (index, &hash) in hashes.iter().enumerate() {
        // Remove equal values too: a later equal minimum is the required
        // rightmost representative and outlives every earlier one.
        while candidates
            .back()
            .is_some_and(|&previous| hashes[previous] >= hash)
        {
            candidates.pop_back();
        }
        candidates.push_back(index);

        if index + 1 < w {
            continue;
        }
        let start = index + 1 - w;
        while candidates.front().is_some_and(|&previous| previous < start) {
            candidates.pop_front();
        }
        let best = *candidates.front().unwrap_or(&index);
        if picks.last().is_none_or(|&(_, previous)| previous != best) {
            picks.push((hashes[best], best));
        }
    }
    picks
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn kgram_count_and_rolling_consistency() {
        let units: Vec<u64> = (0..40u64).map(|i| i.wrapping_mul(0x9e37_79b9)).collect();
        let k = 5;
        let hashes = kgram_hashes(&units, k);
        assert_eq!(hashes.len(), units.len() - k + 1);
        // Each rolled hash equals a direct recomputation over its window.
        for (i, &h) in hashes.iter().enumerate() {
            let direct = units[i..i + k]
                .iter()
                .fold(0u64, |acc, &u| acc.wrapping_mul(FNV_PRIME).wrapping_add(u));
            assert_eq!(h, direct, "gram {i}");
        }
    }

    #[test]
    fn kgram_short_input_is_empty() {
        assert!(kgram_hashes(&[1, 2, 3], 4).is_empty());
        assert!(kgram_hashes(&[], 1).is_empty());
    }

    #[test]
    fn winnow_covers_every_window() {
        let hashes: Vec<u64> = (0..100u64).map(|i| i.wrapping_mul(0x517c_c1b7)).collect();
        let w = 4;
        let picks = winnow(&hashes, w);
        // Every window of w consecutive grams contains at least one pick.
        let picked: std::collections::BTreeSet<usize> = picks.iter().map(|&(_, i)| i).collect();
        for start in 0..=(hashes.len() - w) {
            assert!(
                (start..start + w).any(|i| picked.contains(&i)),
                "window at {start} has no pick"
            );
        }
    }

    #[test]
    fn winnow_short_input_selects_global_min() {
        let hashes = [50u64, 10, 30];
        let picks = winnow(&hashes, 8);
        assert_eq!(picks, vec![(10, 1)]);
    }

    #[test]
    fn winnow_is_deterministic() {
        let hashes: Vec<u64> = (0..64u64).map(|i| i ^ (i << 3)).collect();
        assert_eq!(winnow(&hashes, 4), winnow(&hashes, 4));
    }

    #[test]
    fn winnow_matches_window_rescanning_for_ties_and_every_window_size() {
        fn reference(hashes: &[u64], w: usize) -> Vec<(u64, usize)> {
            use std::collections::BTreeSet;

            if hashes.is_empty() || w == 0 {
                return Vec::new();
            }
            let mut picks = BTreeSet::new();
            for start in 0..hashes.len().saturating_sub(w).saturating_add(1) {
                let end = (start + w).min(hashes.len());
                let best = (start..end).min_by_key(|&index| (hashes[index], usize::MAX - index));
                if let Some(best) = best {
                    picks.insert((best, hashes[best]));
                }
            }
            picks
                .into_iter()
                .map(|(index, hash)| (hash, index))
                .collect()
        }

        let hashes = [9, 4, 4, 7, 2, 2, 2, 5, 1, 1, 8, 3];
        for w in 0..=hashes.len() + 2 {
            assert_eq!(winnow(&hashes, w), reference(&hashes, w), "window {w}");
        }
    }

    #[test]
    fn sequence_hash_distinguishes_order_and_content() {
        use crate::engine::normalize::{NormAtom, NormToken};
        let a = [
            NormToken {
                tag: 1,
                atom: NormAtom::Renamed(0),
            },
            NormToken {
                tag: 4,
                atom: NormAtom::Text("+"),
            },
        ];
        let b = [
            NormToken {
                tag: 4,
                atom: NormAtom::Text("+"),
            },
            NormToken {
                tag: 1,
                atom: NormAtom::Renamed(0),
            },
        ];
        assert_ne!(norm_sequence_hash(&a), norm_sequence_hash(&b));
        // Deterministic: the same input always hashes the same.
        assert_eq!(norm_sequence_hash(&a), norm_sequence_hash(&a));
    }
}
