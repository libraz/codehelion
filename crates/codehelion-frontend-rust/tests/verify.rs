//! Verification over real parsed Rust: the precise judgment end to end. A
//! verbatim copy is Type-1, a consistently renamed copy Type-2, a gapped edit
//! Type-3 with the gap visible in the alignment, and an unrelated function no
//! clone at all — driving `statement_sequence` and `verify` on real IR.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use codehelion_core::clone_class::CloneClass;
use codehelion_core::features::{self, UnitFeatures};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::stable_id::FragmentFingerprint;
use codehelion_core::verify::{self, UnitView, VerifyConfig};
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

const ALPHA_RENAMED: &str = "\
fn beta(feed: &[u32]) -> u32 {
    let mut acc = 0u32;
    let mut count = 0u32;
    for value in feed {
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
    let extra = acc ^ count;
    return acc + count + extra;
}
";

const GAMMA: &str = "\
fn gamma(name: &str) -> usize {
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

struct Prepared {
    ir: SyntaxIrFile,
    features: UnitFeatures,
}

fn prepare(source: &str) -> Prepared {
    let ir = RustStructuralFrontend.parse(source);
    let mut features = features::extract(&ir);
    assert_eq!(features.units.len(), 1, "each source holds one function");
    let features = features.units.remove(0);
    Prepared { ir, features }
}

fn view(prepared: &Prepared) -> UnitView<'_> {
    // The function is the first (only) root of the parsed file.
    let statements = leak(verify::statement_sequence(
        &prepared.ir.roots[0],
        &prepared.ir.tokens,
    ));
    UnitView {
        statements,
        tokens: &prepared.ir.tokens,
        content: FragmentFingerprint::from_bytes([0; 16]),
        features: &prepared.features,
        types: None,
        apis: None,
    }
}

/// Persist the flattened statements for the borrow the view needs; test-only.
fn leak(
    statements: Vec<codehelion_core::ir::StatementSummary>,
) -> &'static [codehelion_core::ir::StatementSummary] {
    Box::leak(statements.into_boxed_slice())
}

#[test]
fn a_verbatim_copy_is_a_type1_clone() {
    let alpha = prepare(ALPHA);
    let verdict = verify::verify(&view(&alpha), &view(&alpha), &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type1));
    assert!(verdict.alignment.only_a.is_empty());
    assert!(verdict.alignment.only_b.is_empty());
}

#[test]
fn a_consistently_renamed_copy_is_a_type2_clone() {
    let alpha = prepare(ALPHA);
    let renamed = prepare(ALPHA_RENAMED);
    let verdict = verify::verify(&view(&alpha), &view(&renamed), &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type2));
    assert!(verdict.breakdown.lexical < 1.0, "renamed heads differ");
}

#[test]
fn a_gapped_edit_is_a_type3_clone_with_the_inserted_statement_in_the_alignment() {
    let alpha = prepare(ALPHA);
    let edited = prepare(ALPHA_TYPE3);
    let verdict = verify::verify(&view(&alpha), &view(&edited), &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type3));
    // The inserted `let extra = ...;` has no partner on the original side.
    assert!(
        !verdict.alignment.only_b.is_empty(),
        "the inserted statement must be unmatched on the edited side"
    );
    assert!(verdict.breakdown.type_similarity.is_none());
}

#[test]
fn an_unrelated_function_is_not_a_clone() {
    let alpha = prepare(ALPHA);
    let gamma = prepare(GAMMA);
    let verdict = verify::verify(&view(&alpha), &view(&gamma), &VerifyConfig::default());
    assert_eq!(verdict.class, None);
}
