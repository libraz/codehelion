//! Clone-pair grouping and noise scoring.
//!
//! Pairs whose matched content is identical (same content key) form one clone
//! group; instances are deduplicated and the canonical instance is chosen by a
//! deterministic tie-break. Exact-content equivalence classes trivially
//! satisfy the constraint that every member match the canonical instance, so
//! this interface can later be re-implemented with medoid-based grouping for
//! near-match clones without changing callers.
//!
//! Each group carries two noise signals instead of being silently dropped:
//! low content entropy (degenerate repetition such as long literal tables) and
//! high instance degree (idiomatic boilerplate that recurs all over a
//! codebase). Thresholds only set a suppression marker; reporting stays
//! honest about what was found.

use std::collections::BTreeMap;

use super::fingerprint::norm_token_hash;
use super::normalize::normalize;
use super::{CloneGroup, ClonePair, CloneType, EngineConfig, InputFile, Instance, SuppressReason};

/// Shannon entropy, in bits, of the normalized-token distribution of a slice.
#[allow(clippy::cast_precision_loss)] // token counts are far below 2^52
fn entropy_bits(files: &[InputFile<'_>], instance: &Instance, config: &EngineConfig) -> f64 {
    let slice = &files[instance.file].tokens[instance.token_start..instance.token_end];
    let normalized = normalize(slice, config.literals);
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for token in &normalized {
        *counts.entry(norm_token_hash(token)).or_insert(0) += 1;
    }
    let total = normalized.len();
    if total == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Group clone pairs into clone groups by matched content.
///
/// Instances are deduplicated across pairs, members are sorted, and the
/// canonical instance is the first member under `(file, token range)` order.
/// Groups come back sorted by their canonical instance, so output order does
/// not depend on input order.
#[must_use]
pub fn group_pairs(
    pairs: &[ClonePair],
    files: &[InputFile<'_>],
    config: &EngineConfig,
) -> Vec<CloneGroup> {
    let mut by_key: BTreeMap<u64, Vec<&ClonePair>> = BTreeMap::new();
    for pair in pairs {
        by_key.entry(pair.content_key).or_default().push(pair);
    }

    let mut groups: Vec<CloneGroup> = by_key
        .into_iter()
        .map(|(content_key, pairs)| {
            let mut members: Vec<Instance> = Vec::new();
            for pair in &pairs {
                for candidate in [&pair.a, &pair.b] {
                    if !members.iter().any(|m| {
                        (m.file, m.token_start, m.token_end)
                            == (candidate.file, candidate.token_start, candidate.token_end)
                    }) {
                        members.push(candidate.clone());
                    }
                }
            }
            members.sort_by_key(|m| (m.file, m.token_start, m.token_end));

            let clone_type = if pairs.iter().any(|p| p.clone_type == CloneType::Type2) {
                CloneType::Type2
            } else {
                CloneType::Type1
            };
            let score = pairs.iter().map(|p| p.score).fold(f64::INFINITY, f64::min);
            let entropy = entropy_bits(files, &members[0], config);
            let degree = members.len();
            let suppressed = if degree > config.degree_cap {
                Some(SuppressReason::HighFrequency)
            } else if entropy < config.entropy_floor {
                Some(SuppressReason::LowEntropy)
            } else {
                None
            };
            CloneGroup {
                content_key,
                clone_type,
                score,
                members,
                entropy_bits: entropy,
                suppressed,
            }
        })
        .collect();

    groups.sort_by_key(|g| {
        let c = &g.members[0];
        (c.file, c.token_start, c.token_end, g.content_key)
    });
    groups
}
