//! Type-3 recall over the committed graded mutation corpus.
//!
//! The corpus derives one function into variants at rising statement-change
//! rates from the same seed, so the labelled clone pairs are exactly
//! seed-to-variant. Two properties are fixed here: every graded variant is
//! still recovered as a clone of the seed, and the measured similarity falls
//! monotonically as the change rate rises. The second is what makes the first
//! meaningful — recall that survives because the score ignores the mutation
//! would be recall by accident.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_core::verify::VerifyConfig;
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-graded";
const SEED: &str = "seed.rs";

/// The graded variants, in rising order of statement-change rate.
const GRADES: [&str; 4] = ["type3_05.rs", "type3_10.rs", "type3_20.rs", "type3_30.rs"];

fn parse(name: &str) -> SyntaxIrFile {
    let path = PathBuf::from(CORPUS).join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    RustStructuralFrontend.parse(&text)
}

fn analyze(names: &[&str]) -> StructuralReport {
    let files: Vec<SyntaxIrFile> = names.iter().map(|name| parse(name)).collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

#[test]
fn every_graded_variant_is_recovered_as_one_clone_group() {
    let mut names = vec![SEED];
    names.extend_from_slice(&GRADES);
    let report = analyze(&names);

    // One function per file, so every file contributes exactly one unit.
    assert_eq!(report.units.len(), names.len());
    assert_eq!(
        report.groups.groups.len(),
        1,
        "the seed and its variants are one clone, not several: {:#?}",
        report.groups.groups
    );
    let group = &report.groups.groups[0];
    assert_eq!(group.clone_type, CloneClass::Type3);
    let mut files: Vec<usize> = group
        .members
        .iter()
        .map(|&member| report.units[member].file)
        .collect();
    files.sort_unstable();
    assert_eq!(
        files,
        (0..names.len()).collect::<Vec<_>>(),
        "every graded variant joins the seed's group"
    );
}

#[test]
fn similarity_falls_monotonically_with_the_change_rate() {
    let composites: Vec<f64> = GRADES
        .iter()
        .map(|grade| {
            let report = analyze(&[SEED, grade]);
            assert_eq!(
                report.groups.groups.len(),
                1,
                "{grade} is still a clone of the seed"
            );
            let group = &report.groups.groups[0];
            assert_eq!(group.clone_type, CloneClass::Type3);
            assert_eq!(group.members.len(), 2);
            // The medoid-to-other-member breakdown is the pair's measurement.
            report.details[0].member_breakdowns[1].composite
        })
        .collect();

    for (grade, pair) in GRADES.windows(2).zip(composites.windows(2)) {
        assert!(
            pair[1] < pair[0],
            "{} scored {:.4}, not below {}'s {:.4}",
            grade[1],
            pair[1],
            grade[0],
            pair[0]
        );
    }

    // The weakest grade still clears acceptance by a wide margin, so the
    // corpus measures recall rather than threshold behaviour: calibrating the
    // acceptance threshold needs mutations that also disturb control flow or
    // calls, which these insertions leave untouched.
    let weakest = *composites.last().unwrap();
    let config = VerifyConfig::default();
    assert!(
        weakest > config.type3_min_composite + 0.15,
        "weakest grade scored {weakest:.4}, unexpectedly close to the \
         acceptance threshold {:.2}",
        config.type3_min_composite
    );
}

#[test]
fn the_same_corpus_measures_the_same_twice() {
    let mut names = vec![SEED];
    names.extend_from_slice(&GRADES);
    let first = analyze(&names);
    let second = analyze(&names);
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
    assert_eq!(composites(&first), composites(&second));
}
