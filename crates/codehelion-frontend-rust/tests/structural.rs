//! The structural pipeline end to end over real parsed Rust: two verbatim
//! copies and a renamed copy of one function must land in one clone group, a
//! gapped edit joins as a Type-3 near-clone, and an unrelated function stays
//! out — exercising candidate extraction, near-match, verification and medoid
//! grouping together, with real stable fingerprints as the grouping keys.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

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
    return acc + count;
}
";

// A verbatim copy of alpha under a different name (Type-1 structure).
const ALPHA_COPY: &str = "\
fn alpha_copy(data: &[u32]) -> u32 {
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
    return acc + count;
}
";

// A consistently renamed copy (Type-2 structure).
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
    return state + seen;
}
";

// A gapped edit: one extra statement (Type-3).
const ALPHA_TYPE3: &str = "\
fn gamma(data: &[u32]) -> u32 {
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
    let extra = acc ^ count;
    return acc + count + extra;
}
";

// An unrelated function.
const UNRELATED: &str = "\
fn label(name: &str) -> usize {
    let trimmed = name.trim();
    let width = trimmed.chars().count();
    for _ in 0..width {
        if width > 3 {
            return width;
        }
    }
    return width.saturating_mul(2);
}
";

fn parse_all(sources: &[&str]) -> Vec<SyntaxIrFile> {
    sources
        .iter()
        .map(|source| RustStructuralFrontend.parse(source))
        .collect()
}

fn variant() -> BuildVariant {
    BuildVariant::structural(LanguageSelection::default())
}

#[test]
fn verbatim_and_renamed_copies_group_together() {
    // One file per function keeps the mapping simple: unit i is file i.
    let files = parse_all(&[ALPHA, ALPHA_COPY, ALPHA_RENAMED, UNRELATED]);
    let report = structural::analyze(&files, &variant(), &StructuralConfig::default());

    assert_eq!(report.units.len(), 4, "one unit per file");
    // The three copies (units 0, 1, 2) form a single cohesive group; the
    // unrelated function (unit 3) is not in it.
    let group = report
        .groups
        .groups
        .iter()
        .find(|g| g.members.contains(&0))
        .expect("alpha is grouped with its copies");
    assert!(group.members.contains(&1), "verbatim copy joins");
    assert!(group.members.contains(&2), "renamed copy joins");
    assert!(
        !group.members.contains(&3),
        "the unrelated function stays out"
    );
    assert_eq!(report.stats.units, 4);
    assert!(report.stats.verified_pairs >= 2);

    // Every group carries a parallel detail: a stable clone id and one
    // medoid-to-member breakdown per member.
    assert_eq!(report.details.len(), report.groups.groups.len());
    let group_index = report
        .groups
        .groups
        .iter()
        .position(|g| g.members.contains(&0))
        .unwrap();
    let detail = &report.details[group_index];
    assert_eq!(
        detail.member_breakdowns.len(),
        report.groups.groups[group_index].members.len()
    );
    // The medoid entry (member 0) is a perfect self-match.
    assert!((detail.member_breakdowns[0].composite - 1.0).abs() < 1e-9);
    // Type absent in Structural mode: every breakdown leaves it unmeasured.
    assert!(
        detail
            .member_breakdowns
            .iter()
            .all(|b| b.type_similarity.is_none())
    );
}

#[test]
fn a_type3_edit_is_grouped_as_a_near_clone() {
    let files = parse_all(&[ALPHA, ALPHA_TYPE3, UNRELATED]);
    let report = structural::analyze(&files, &variant(), &StructuralConfig::default());
    let group = report
        .groups
        .groups
        .iter()
        .find(|g| g.members.contains(&0))
        .expect("alpha is grouped with its gapped edit");
    assert!(
        group.members.contains(&1),
        "the Type-3 edit joins alpha's group"
    );
    assert!(!group.members.contains(&2));
}

#[test]
fn analysis_is_deterministic() {
    let files = parse_all(&[ALPHA, ALPHA_COPY, ALPHA_RENAMED, UNRELATED]);
    let first = structural::analyze(&files, &variant(), &StructuralConfig::default());
    let second = structural::analyze(&files, &variant(), &StructuralConfig::default());
    assert_eq!(first, second);
}
