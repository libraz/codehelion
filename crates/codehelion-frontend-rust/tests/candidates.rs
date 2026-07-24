//! Candidate generation over real parsed Rust: the exact-hash seed layer end
//! to end. Two verbatim-equal functions must surface as candidate fragment
//! pairs through the inverted index, a renamed copy must still surface because
//! the features are rename-invariant, and two unrelated functions must not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use codehelion_core::candidate::{self, CandidateConfig};
use codehelion_core::features::{self, FileFeatures};
use codehelion_core::ir::StructuralFrontend;
use codehelion_frontend_rust::ir::RustStructuralFrontend;

/// A function with enough body to clear the window and subtree minimums.
const ALPHA: &str = "\
fn alpha(data: &[u32]) -> u32 {
    let mut acc = 0u32;
    let mut count = 0u32;
    for value in data {
        if *value > 10 {
            acc = acc.wrapping_add(*value);
        } else {
            acc = acc.wrapping_sub(1);
        }
        count += 1;
    }
    return acc + count;
}
";

/// `ALPHA` with every identifier and literal changed, callees kept: a Type-2
/// copy whose structural features are byte-identical.
const ALPHA_RENAMED: &str = "\
fn beta(feed: &[u32]) -> u32 {
    let mut state = 3u32;
    let mut seen = 7u32;
    for item in feed {
        if *item > 99 {
            state = state.wrapping_add(*item);
        } else {
            state = state.wrapping_sub(2);
        }
        seen += 4;
    }
    return state + seen;
}
";

/// A structurally unrelated function.
const GAMMA: &str = "\
fn gamma(name: &str) -> usize {
    let trimmed = name.trim();
    let width = trimmed.chars().count();
    width.saturating_mul(2)
}
";

fn features_of(source: &str) -> FileFeatures {
    features::extract(&RustStructuralFrontend.parse(source))
}

#[test]
fn two_verbatim_functions_surface_as_candidate_pairs() {
    let files = vec![features_of(ALPHA), features_of(ALPHA)];
    let set = candidate::generate(&files, &CandidateConfig::default());

    assert!(
        !set.pairs.is_empty(),
        "identical functions must share fragment hashes"
    );
    // Every emitted pair bridges the two files; none is intra-file here.
    assert!(set.pairs.iter().all(|p| p.a.file != p.b.file));
    assert_eq!(set.stats.candidate_pairs, set.pairs.len());
    assert!(!set.stats.budget_exhausted);
}

#[test]
fn a_renamed_copy_still_surfaces_through_rename_invariant_hashes() {
    let files = vec![features_of(ALPHA), features_of(ALPHA_RENAMED)];
    let set = candidate::generate(&files, &CandidateConfig::default());
    assert!(
        !set.pairs.is_empty(),
        "a consistently renamed copy must still share structural hashes"
    );
    assert!(set.pairs.iter().all(|p| p.a.file != p.b.file));
}

#[test]
fn unrelated_functions_produce_no_candidates() {
    let files = vec![features_of(ALPHA), features_of(GAMMA)];
    let set = candidate::generate(&files, &CandidateConfig::default());
    assert!(
        set.pairs.is_empty(),
        "unrelated functions must not seed candidate pairs"
    );
}
