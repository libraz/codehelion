//! Feature-extraction regression over real parsed Rust: the rename-invariance
//! contract end to end. Sources that differ only in identifier names and
//! literal values must yield identical windows, subtrees, control-flow
//! profiles and characteristic vectors; only a renamed callee may move the
//! API-call hashes, and a genuine statement insertion must move the windows
//! and the control-op count while shifting the characteristic vector by a
//! small bounded amount.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use codehelion_core::features::{self, FeatureHash, FileFeatures, SubtreeFeature, UnitFeatures};
use codehelion_core::ir::StructuralFrontend;
use codehelion_frontend_rust::ir::RustStructuralFrontend;

/// The baseline function: six top-block statements, one loop, one branch and
/// four method calls.
const BASE: &str = "\
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

/// `BASE` with every identifier renamed and every literal changed; the
/// callee names are kept identical.
const RENAMED: &str = "\
fn beta(feed: &[u32]) -> u32 {
    let mut state = 9u32;
    let mut seen = 5u32;
    for item in feed {
        if *item > 42 {
            state = state.wrapping_add(*item);
        } else {
            state = state.wrapping_sub(7);
        }
        seen += 3;
    }
    state = state.wrapping_mul(8);
    seen = seen.wrapping_add(state);
    return state + seen;
}
";

/// `BASE` with one callee renamed (`wrapping_sub` -> `saturating_sub`) and
/// nothing else changed.
const CALLEE_RENAMED: &str = "\
fn alpha(data: &[u32]) -> u32 {
    let mut acc = 0u32;
    let mut count = 0u32;
    for value in data {
        if *value > 10 {
            acc = acc.wrapping_add(*value);
        } else {
            acc = acc.saturating_sub(1);
        }
        count += 1;
    }
    acc = acc.wrapping_mul(3);
    count = count.wrapping_add(acc);
    return acc + count;
}
";

/// `BASE` with one extra assignment statement (carrying one call) inserted
/// before the return.
const INSERTED: &str = "\
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
    acc = acc.wrapping_add(count);
    return acc + count;
}
";

fn features_of(source: &str) -> FileFeatures {
    features::extract(&RustStructuralFrontend.parse(source))
}

fn only_unit(features: &FileFeatures) -> &UnitFeatures {
    assert_eq!(features.units.len(), 1, "each source holds one function");
    &features.units[0]
}

fn window_hashes(unit: &UnitFeatures) -> Vec<FeatureHash> {
    let mut hashes: Vec<FeatureHash> = unit.windows.iter().map(|window| window.hash).collect();
    hashes.sort_unstable();
    hashes
}

fn subtree_hashes(unit: &UnitFeatures) -> Vec<FeatureHash> {
    let mut hashes: Vec<FeatureHash> = unit.subtrees.iter().map(|subtree| subtree.hash).collect();
    hashes.sort_unstable();
    hashes
}

/// The subtree feature covering the whole unit: the one with the most nodes.
fn root_subtree(unit: &UnitFeatures) -> &SubtreeFeature {
    unit.subtrees
        .iter()
        .max_by_key(|subtree| subtree.node_count)
        .expect("the unit subtree must qualify for a fingerprint")
}

#[test]
fn identifier_and_literal_renames_leave_every_feature_unchanged() {
    let base = features_of(BASE);
    let renamed = features_of(RENAMED);
    let unit = only_unit(&base);
    let renamed_unit = only_unit(&renamed);

    assert!(!unit.windows.is_empty(), "the body must produce windows");
    assert_eq!(window_hashes(unit), window_hashes(renamed_unit));
    assert_eq!(subtree_hashes(unit), subtree_hashes(renamed_unit));
    assert_eq!(root_subtree(unit).hash, root_subtree(renamed_unit).hash);
    assert_eq!(unit.cfg, renamed_unit.cfg);
    assert_eq!(unit.vector, renamed_unit.vector);
    // The callee names were kept identical, so the API profile matches too.
    assert_eq!(unit.api, renamed_unit.api);
}

#[test]
fn a_renamed_callee_moves_only_the_api_hashes() {
    let base = features_of(BASE);
    let edited = features_of(CALLEE_RENAMED);
    let unit = only_unit(&base);
    let edited_unit = only_unit(&edited);

    assert_eq!(window_hashes(unit), window_hashes(edited_unit));
    assert_eq!(subtree_hashes(unit), subtree_hashes(edited_unit));
    assert_eq!(unit.cfg, edited_unit.cfg);
    assert_eq!(unit.vector, edited_unit.vector);
    assert_ne!(unit.api.sequence_hash, edited_unit.api.sequence_hash);
    assert_ne!(unit.api.multiset_hash, edited_unit.api.multiset_hash);
}

#[test]
fn an_inserted_statement_shifts_windows_and_cfg_boundedly() {
    let base = features_of(BASE);
    let edited = features_of(INSERTED);
    let unit = only_unit(&base);
    let edited_unit = only_unit(&edited);

    assert_ne!(window_hashes(unit), window_hashes(edited_unit));
    // The inserted assignment carries exactly one call op.
    assert_eq!(edited_unit.cfg.op_count, unit.cfg.op_count + 1);
    // One Assign node plus one Call node: the vector moves by 2, no more.
    assert_eq!(unit.vector.l1_distance(&edited_unit.vector), 2);
}

#[test]
fn extraction_is_deterministic_across_parses() {
    assert_eq!(features_of(BASE), features_of(BASE));
}
