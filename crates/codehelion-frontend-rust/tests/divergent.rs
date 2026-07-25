//! Per-dimension behaviour over the committed divergence corpus.
//!
//! The graded corpus mutates one function by inserting straight-line
//! statements, which leaves the control-flow and call dimensions pinned at
//! `1.0`; it measures recall but says nothing about where the acceptance
//! threshold sits. This corpus derives its variants by disturbing control flow
//! and the call surface instead, one axis at a time and then all at once, so
//! each dimension is exercised in isolation and the resulting composites
//! bracket the acceptance threshold from both sides.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::features;
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_core::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-divergent";
const SEED: &str = "seed.rs";

/// Variants that disturb the control-flow profile and nothing else.
const CONTROL_FLOW: [&str; 3] = ["guard_added.rs", "loop_nested.rs", "exits_removed.rs"];

/// The variant that renames every callee while leaving the structure alone.
const CALLS_SWAPPED: &str = "calls_swapped.rs";

/// The variant that disturbs control flow and the call surface at once.
const REWRITTEN: &str = "rewritten.rs";

fn parse(name: &str) -> SyntaxIrFile {
    let path = PathBuf::from(CORPUS).join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    RustStructuralFrontend.parse(&text)
}

/// The judge's breakdown for the seed's function against `name`'s.
///
/// Read from [`verify`] rather than from a report, so a pair the funnel
/// rejects still yields its numbers.
fn breakdown(name: &str) -> SimilarityBreakdown {
    let seed = parse(SEED);
    let variant = parse(name);
    let (seed_features, variant_features) = (features::extract(&seed), features::extract(&variant));
    let statements = |file: &SyntaxIrFile| {
        let mut found = None;
        file.walk(&mut |node| {
            if found.is_none() && matches!(node.shape, Shape::Function) {
                found = Some(verify::statement_sequence(node, &file.tokens));
            }
        });
        found.expect("the corpus file holds one function")
    };
    let (seed_statements, variant_statements) = (statements(&seed), statements(&variant));
    let verdict = verify::verify(
        &UnitView {
            statements: &seed_statements,
            features: &seed_features.units[0],
        },
        &UnitView {
            statements: &variant_statements,
            features: &variant_features.units[0],
        },
        &VerifyConfig::default(),
    );
    verdict.breakdown
}

fn analyze(names: &[&str]) -> StructuralReport {
    let files: Vec<SyntaxIrFile> = names.iter().map(|name| parse(name)).collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

#[test]
fn disturbing_control_flow_moves_only_the_control_flow_and_structure_dimensions() {
    for name in CONTROL_FLOW {
        let scores = breakdown(name);
        assert!(
            scores.control_flow < 1.0,
            "{name} disturbs control flow, so the dimension must react: {scores:?}"
        );
        assert_eq!(
            scores.api,
            Some(1.0),
            "{name} leaves every callee in place: {scores:?}"
        );
        let report = analyze(&[SEED, name]);
        assert_eq!(report.groups.groups.len(), 1, "{name} is still a clone");
        assert_eq!(report.groups.groups[0].clone_type, CloneClass::Type3);
    }
}

#[test]
fn renaming_every_callee_costs_the_api_dimension_alone() {
    let scores = breakdown(CALLS_SWAPPED);
    for (dimension, value) in [
        ("lexical", scores.lexical),
        ("structural", scores.structural),
        ("control flow", scores.control_flow),
    ] {
        assert!(
            (value - 1.0).abs() < 1e-9,
            "the rename leaves {dimension} untouched, got {value}"
        );
    }
    assert_eq!(
        scores.api,
        Some(0.0),
        "no callee survives the rename, so the call surfaces are disjoint"
    );
    // The heads a statement summary keeps do not reach the renamed callees, so
    // the call surface is the only evidence that this is not a verbatim copy —
    // and a Type-1 claim would assert that it is.
    let report = analyze(&[SEED, CALLS_SWAPPED]);
    assert_eq!(report.groups.groups.len(), 1);
    assert_eq!(report.groups.groups[0].clone_type, CloneClass::Type2);
}

#[test]
fn the_corpus_brackets_the_acceptance_threshold() {
    let config = VerifyConfig::default();
    let accepted: Vec<f64> = CONTROL_FLOW
        .iter()
        .chain(std::iter::once(&CALLS_SWAPPED))
        .map(|name| breakdown(name).composite)
        .collect();
    for (name, composite) in CONTROL_FLOW.iter().zip(&accepted) {
        assert!(
            *composite > config.type3_min_composite,
            "{name} scored {composite:.4}, below acceptance"
        );
    }

    // Disturbing every axis at once takes the pair below acceptance: the funnel
    // proposes it and verification is what turns it down, so the miss is the
    // threshold's doing rather than a candidate-generation gap.
    let rejected = breakdown(REWRITTEN).composite;
    assert!(
        rejected < config.type3_min_composite,
        "{REWRITTEN} scored {rejected:.4}, at or above acceptance"
    );
    let report = analyze(&[SEED, REWRITTEN]);
    assert_eq!(report.stats.unit_pairs, 1);
    assert_eq!(report.stats.verified_pairs, 0);
    assert!(report.groups.groups.is_empty());

    // Both sides of the threshold, with room to move it either way: that is
    // what makes this corpus usable for calibrating it.
    let strongest = accepted.iter().copied().fold(f64::MIN, f64::max);
    assert!(
        strongest - rejected > 0.25,
        "the corpus spans {rejected:.4}..{strongest:.4}, too narrow to calibrate against"
    );
}

#[test]
fn a_pair_scores_the_same_whichever_file_leads() {
    for name in CONTROL_FLOW {
        let forward = analyze(&[SEED, name]);
        let backward = analyze(&[name, SEED]);
        let composites = |report: &StructuralReport| -> Vec<f64> {
            report
                .details
                .iter()
                .flat_map(|detail| {
                    detail
                        .member_breakdowns
                        .iter()
                        .map(|breakdown| breakdown.composite)
                })
                .collect()
        };
        assert_eq!(
            composites(&forward),
            composites(&backward),
            "{name} scores differently depending on which file the run saw first"
        );
    }
}
