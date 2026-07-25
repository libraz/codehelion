//! Precision over the committed negative corpus.
//!
//! The corpus holds four functions built on the same skeleton — accumulate
//! over a slice under a branch, return the accumulator — that compute
//! genuinely different things, plus a file of verbatim copies of all four. The
//! copies are real clones; every pairing of two *different* functions is
//! labelled a non-clone. What must come out is four groups, one per function,
//! and nothing that mixes two of them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::features;
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_core::verify::{self, UnitView, Verdict, VerifyConfig};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-negative";
const FILES: [&str; 2] = ["seed.rs", "copies.rs"];

/// The seed's functions, in source order.
const FUNCTIONS: [&str; 4] = [
    "sum_positive",
    "longest_run",
    "count_transitions",
    "narrowest_gap",
];

fn parse(name: &str) -> SyntaxIrFile {
    let path = PathBuf::from(CORPUS).join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    RustStructuralFrontend.parse(&text)
}

fn analyze() -> StructuralReport {
    let files: Vec<SyntaxIrFile> = FILES.iter().map(|name| parse(name)).collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// Every pairing of two different seed functions, scored by the judge
/// directly, labelled and in source order.
fn negative_verdicts() -> Vec<(String, Verdict)> {
    let file = parse("seed.rs");
    let extracted = features::extract(&file);
    let mut units = Vec::new();
    file.walk(&mut |node| {
        if matches!(node.shape, Shape::Function) {
            units.push((
                node.name
                    .as_ref()
                    .map_or("?", |name| name.as_str())
                    .to_string(),
                verify::statement_sequence(node, &file.tokens),
            ));
        }
    });
    assert_eq!(units.len(), FUNCTIONS.len());

    let mut scored = Vec::new();
    for (i, first) in units.iter().enumerate() {
        for (j, second) in units.iter().enumerate().skip(i + 1) {
            let verdict = verify::verify(
                &UnitView {
                    statements: &first.1,
                    features: &extracted.units[i],
                },
                &UnitView {
                    statements: &second.1,
                    features: &extracted.units[j],
                },
                &VerifyConfig::default(),
            );
            scored.push((format!("{} x {}", first.0, second.0), verdict));
        }
    }
    scored
}

#[test]
fn only_the_verbatim_copies_are_reported() {
    let report = analyze();
    assert_eq!(report.units.len(), FUNCTIONS.len() * FILES.len());
    assert_eq!(report.groups.groups.len(), FUNCTIONS.len());

    let mut grouped = BTreeSet::new();
    for group in &report.groups.groups {
        assert_eq!(group.clone_type, CloneClass::Type1);
        let names: BTreeSet<&str> = group
            .members
            .iter()
            .map(|&member| {
                report.units[member]
                    .name
                    .as_ref()
                    .map_or("?", |name| name.as_str())
            })
            .collect();
        assert_eq!(
            names.len(),
            1,
            "a group mixes two different functions: {names:?}"
        );
        assert_eq!(group.members.len(), FILES.len());
        grouped.extend(names);
    }
    assert_eq!(grouped, FUNCTIONS.iter().copied().collect::<BTreeSet<_>>());
}

#[test]
fn the_negative_pairs_are_kept_apart_by_candidate_generation() {
    let report = analyze();
    // One pair per function: its copy. No pair of two different functions is
    // proposed, and that is what keeps them out of the report — the judge does
    // not separate this family on its own, as the next test records. Widening
    // candidate generation therefore means re-measuring here before trusting
    // the result.
    assert_eq!(report.stats.unit_pairs, FUNCTIONS.len());
    assert_eq!(report.stats.verified_pairs, FUNCTIONS.len());
}

#[test]
fn the_judge_never_mistakes_a_negative_pair_for_a_copy() {
    // The composite is not what holds these apart, so fix what does: neither
    // strong claim may be made. Type-1 and Type-2 both assert that the two
    // units have identical structure, and these do not.
    for (pair, verdict) in negative_verdicts() {
        assert_ne!(
            verdict.class,
            Some(CloneClass::Type1),
            "{pair} is not a verbatim copy"
        );
        assert_ne!(
            verdict.class,
            Some(CloneClass::Type2),
            "{pair} is not a renamed copy"
        );
        assert!(
            verdict.breakdown.structural < 1.0,
            "{pair} does not have identical structure"
        );
    }
}

#[test]
fn the_corpus_measures_the_same_twice() {
    let composites = |scored: Vec<(String, Verdict)>| -> Vec<(String, f64)> {
        scored
            .into_iter()
            .map(|(pair, verdict)| (pair, verdict.breakdown.composite))
            .collect()
    };
    assert_eq!(
        composites(negative_verdicts()),
        composites(negative_verdicts())
    );
}
