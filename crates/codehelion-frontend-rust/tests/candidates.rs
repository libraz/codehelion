//! Candidate generation over real parsed Rust: the exact-hash seed layer end
//! to end. Two verbatim-equal functions must surface as candidate fragment
//! pairs through the inverted index, a renamed copy must still surface because
//! the features are rename-invariant, and two unrelated functions must not.
//!
//! The near-match and control-flow layers are exercised here too, on the case
//! that separates them: a short function with statements inserted, where the
//! shingle layers have nothing left to overlap and the skeleton is all that
//! survives.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use codehelion_core::candidate::{self, CandidateConfig};
use codehelion_core::control_flow::{self, ControlFlowConfig};
use codehelion_core::features::{self, FileFeatures};
use codehelion_core::ir::StructuralFrontend;
use codehelion_core::near_match::{self, NearMatchConfig};
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
    acc = acc.wrapping_mul(3);
    count = count.wrapping_add(acc);
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
    state = state.wrapping_mul(8);
    seen = seen.wrapping_add(state);
    return state + seen;
}
";

/// `ALPHA` with an extra statement inserted before the return: a Type-3 edit
/// that shifts some windows but keeps most subtrees, so the shingle sets still
/// overlap enough to clear the near-match gate.
const ALPHA_TYPE3: &str = "\
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
    acc = acc.wrapping_mul(3);
    count = count.wrapping_add(acc);
    let extra = acc ^ count;
    return acc + count + extra;
}
";

/// A three-statement function: too short for a statement window, and small
/// enough that every subtree big enough to be indexed spans the loop.
const SHORT: &str = "\
fn sum_even(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        if value % 2 == 0 {
            total += value;
        }
    }
    total
}
";

/// `SHORT` with two statements added, one of them inside the loop. Every
/// subtree of the original encloses the loop, so the edit rewrites all of
/// them: the two functions have no window and no subtree in common at all.
const SHORT_TYPE3: &str = "\
fn sum_even(values: &[i32]) -> i32 {
    let mut total = 0;
    let mut seen = 0;
    for value in values {
        seen += 1;
        if value % 3 != 1 {
            total += value * 2;
        }
    }
    let _ = seen;
    total
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

#[test]
fn a_type3_edit_surfaces_as_a_near_match_but_an_unrelated_function_does_not() {
    let files = vec![
        features_of(ALPHA),
        features_of(ALPHA_TYPE3),
        features_of(GAMMA),
    ];
    let set = near_match::generate(&files, &NearMatchConfig::default());

    // The gapped edit pairs with the original; the unrelated function does not
    // pair with either.
    assert_eq!(set.pairs.len(), 1, "exactly the Type-3 pair must surface");
    let pair = &set.pairs[0];
    assert_eq!((pair.a.file, pair.b.file), (0, 1));
    assert!(
        pair.estimated_jaccard >= NearMatchConfig::default().min_estimated_jaccard,
        "estimate {} below the gate",
        pair.estimated_jaccard
    );
}

#[test]
fn a_short_gapped_copy_shares_no_feature_with_its_original() {
    // The premise the control-flow layer exists for. If this ever stops
    // holding, the layer is no longer covering the case it was added for and
    // the test below is passing for the wrong reason.
    let original = features_of(SHORT);
    let gapped = features_of(SHORT_TYPE3);
    let hashes = |file: &FileFeatures| {
        let unit = &file.units[0];
        let windows: Vec<_> = unit.windows.iter().map(|w| w.hash).collect();
        let subtrees: Vec<_> = unit.subtrees.iter().map(|s| s.hash).collect();
        (windows, subtrees)
    };
    let (original_windows, original_subtrees) = hashes(&original);
    let (gapped_windows, gapped_subtrees) = hashes(&gapped);
    assert!(
        !original_subtrees.is_empty() && !gapped_subtrees.is_empty(),
        "both functions must have subtrees, or they share none for a dull reason"
    );
    assert!(
        original_windows.iter().all(|h| !gapped_windows.contains(h)),
        "the two share a statement window"
    );
    assert!(
        original_subtrees
            .iter()
            .all(|h| !gapped_subtrees.contains(h)),
        "the two share a subtree"
    );
}

#[test]
fn a_short_gapped_copy_surfaces_through_its_control_flow_skeleton() {
    let files = vec![
        features_of(SHORT),
        features_of(SHORT_TYPE3),
        features_of(GAMMA),
        features_of(ALPHA),
    ];

    // Neither shingle layer can propose the pair: they have nothing to work
    // from, whatever the thresholds are set to.
    let generous = NearMatchConfig {
        min_shingles: 1,
        min_estimated_jaccard: 0.0,
        ..NearMatchConfig::default()
    };
    let near = near_match::generate(&files, &generous);
    assert!(
        !near
            .pairs
            .iter()
            .any(|pair| (pair.a.file, pair.b.file) == (0, 1)),
        "the shingle layer proposed the pair after all"
    );
    assert!(
        !candidate::generate(&files, &CandidateConfig::default())
            .pairs
            .iter()
            .any(|pair| (pair.a.file, pair.b.file) == (0, 1)),
        "the exact-seed layer proposed the pair after all"
    );

    // The skeleton layer does, and pairs it with nothing else: the unrelated
    // function is too shallow to index, and the long function branches
    // differently.
    let set = control_flow::generate(&files, &ControlFlowConfig::default());
    assert_eq!(
        set.pairs.len(),
        1,
        "exactly the gapped pair must surface, got {:?}",
        set.pairs
    );
    assert_eq!((set.pairs[0].a.file, set.pairs[0].b.file), (0, 1));
}

#[test]
fn a_copy_that_only_adds_a_call_keeps_its_skeleton() {
    // A call is an operation a unit performs, not a fork in the path through
    // it. The full control-op sequence moves when one is added; the skeleton
    // the candidate layer indexes does not.
    let with_call = SHORT_TYPE3.replace("let _ = seen;", "drop(seen);");
    let plain = features_of(SHORT_TYPE3);
    let calling = features_of(&with_call);
    let (plain, calling) = (&plain.units[0].cfg, &calling.units[0].cfg);
    assert_ne!(
        plain.hash, calling.hash,
        "the full control-op sequence must record the call"
    );
    assert_eq!(
        plain.skeleton_hash, calling.skeleton_hash,
        "the skeleton must not"
    );
    assert_eq!(plain.op_count + 1, calling.op_count);
    assert_eq!(plain.skeleton_ops, calling.skeleton_ops);
}
