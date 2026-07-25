//! The structural pipeline over the committed C corpus.
//!
//! The corpus derives three variants from one seed and labels the clone pairs
//! among them, so this fixes what structural mode recovers in C: the copies of
//! each seed function group together, the getter the labels call a deliberate
//! non-clone is not reported, and every group that is reported is cohesive.
//!
//! The line ranges below mirror the corpus label file. They are evaluation
//! input only: identity in this tool is fingerprint-based, never positional.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::grouping::GroupingConfig;
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_frontend_c::ir::CStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/c";
const FILES: [&str; 4] = ["seed.c", "type1.c", "type2.c", "type3.c"];

/// One labelled fragment: the file it lives in and the line it starts on.
type Place = (&'static str, u32);

/// The copies of the seed's first function (`sum_even`), by start line.
const SUM_EVEN: [Place; 3] = [("seed.c", 4), ("type1.c", 5), ("type2.c", 4)];

/// The copies of the seed's second function (`max_run`), by start line.
const MAX_RUN: [Place; 4] = [
    ("seed.c", 14),
    ("type1.c", 17),
    ("type2.c", 14),
    ("type3.c", 17),
];

/// The getter the corpus labels a deliberate non-clone.
const GETTER: [Place; 2] = [("seed.c", 34), ("type2.c", 34)];

fn analyze() -> StructuralReport {
    let files: Vec<SyntaxIrFile> = FILES
        .iter()
        .map(|name| {
            let path = PathBuf::from(CORPUS).join(name);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            CStructuralFrontend.parse(&text)
        })
        .collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// The unit index of a labelled place.
fn unit_at(report: &StructuralReport, (file, line): Place) -> usize {
    report
        .units
        .iter()
        .position(|unit| FILES[unit.file] == file && unit.start_line == line)
        .unwrap_or_else(|| panic!("no unit starts at {file}:{line}"))
}

/// The index of the group holding `unit`, if any group does.
fn group_of(report: &StructuralReport, unit: usize) -> Option<usize> {
    report
        .groups
        .groups
        .iter()
        .position(|group| group.members.contains(&unit))
}

#[test]
fn the_copies_of_a_labelled_function_are_recovered_as_one_group() {
    let report = analyze();
    for places in [&SUM_EVEN[..], &MAX_RUN[..]] {
        let units: Vec<usize> = places.iter().map(|&p| unit_at(&report, p)).collect();
        let groups: Vec<Option<usize>> = units.iter().map(|&u| group_of(&report, u)).collect();
        assert!(
            groups[0].is_some(),
            "{:?} is reported as a clone of its copies",
            places[0]
        );
        assert!(
            groups.iter().all(|found| *found == groups[0]),
            "{places:?} landed in {groups:?} instead of one group"
        );
    }
}

#[test]
fn the_getter_the_labels_call_a_non_clone_is_not_reported() {
    let report = analyze();
    for place in GETTER {
        let unit = unit_at(&report, place);
        assert_eq!(
            group_of(&report, unit),
            None,
            "{place:?} is a deliberate non-clone"
        );
    }
}

#[test]
fn every_reported_group_clears_the_cohesion_floor() {
    let report = analyze();
    let floor = GroupingConfig::default().min_pairwise_similarity;
    assert!(!report.groups.groups.is_empty(), "the corpus holds clones");
    for group in &report.groups.groups {
        assert!(
            group.min_pairwise >= floor,
            "group around {} has cohesion {:.3}",
            group.canonical,
            group.min_pairwise
        );
        assert!(group.members.len() >= 2, "a singleton is not a group");
    }
}

#[test]
fn two_runs_over_the_same_corpus_agree() {
    assert_eq!(analyze().groups.groups, analyze().groups.groups);
}
