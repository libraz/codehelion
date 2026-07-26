//! The structural pipeline over the committed C++ corpus.
//!
//! The corpus derives three variants from one seed and labels the clone pairs
//! among them, so this fixes what structural mode recovers in C++: the copies of
//! each seed function group together, the getter the labels call a deliberate
//! non-clone is not reported, and every group that is reported is cohesive.
//!
//! The line ranges below mirror the corpus label file. They are evaluation
//! input only: identity in this tool is fingerprint-based, never positional.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::grouping::GroupingConfig;
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport, StructuralUnit};
use codehelion_frontend_cpp::ir::CppStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/cpp";
const FILES: [&str; 4] = ["seed.cpp", "type1.cpp", "type2.cpp", "type3.cpp"];

/// One labelled fragment: the file it lives in and the line it starts on.
type Place = (&'static str, u32);

/// The copies of the seed's first function (`sum_even`), by start line.
const SUM_EVEN: [Place; 3] = [("seed.cpp", 4), ("type1.cpp", 5), ("type2.cpp", 4)];

/// The copies of the seed's second function (`max_run`), by start line.
const MAX_RUN: [Place; 4] = [
    ("seed.cpp", 14),
    ("type1.cpp", 17),
    ("type2.cpp", 14),
    ("type3.cpp", 17),
];

/// The getter the corpus labels a deliberate non-clone.
const GETTER: [Place; 2] = [("seed.cpp", 32), ("type2.cpp", 32)];

fn analyze() -> StructuralReport {
    let files: Vec<SyntaxIrFile> = FILES
        .iter()
        .map(|name| {
            let path = PathBuf::from(CORPUS).join(name);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            CppStructuralFrontend.parse(&text)
        })
        .collect();
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
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
fn the_gapped_copy_is_recovered_as_a_pair_beside_the_group_it_cannot_join() {
    // The corpus's Type-3 variant of `sum_even` is a copy of the seed and of
    // the verbatim variant, but not of the renamed one — so no group holds it
    // with the family it belongs to, and it is reported on its own instead.
    let report = analyze();
    let gapped = unit_at(&report, ("type3.cpp", 4));
    assert_eq!(
        group_of(&report, gapped),
        None,
        "no group can hold this unit and every member of the family"
    );
    let partners: Vec<Place> = report
        .unrepresented
        .iter()
        .filter(|pair| pair.a == gapped || pair.b == gapped)
        .map(|pair| {
            let other = &report.units[if pair.a == gapped { pair.b } else { pair.a }];
            (FILES[other.file], other.start_line)
        })
        .collect();
    assert!(
        partners.contains(&("seed.cpp", 4)),
        "the gapped copy must be reported against the seed it came from, got {partners:?}"
    );
}

#[test]
fn two_runs_over_the_same_corpus_agree() {
    assert_eq!(analyze().groups.groups, analyze().groups.groups);
}

/// A function whose whole body is one lambda: the function and the closure
/// are made of the same code, one wrapped in the other.
const WRAPPED: &str = "\
double smooth_all(const double *xs, unsigned n) {
    auto step = [&](unsigned count) {
        double acc = 0.5;
        for (unsigned i = 0; i < count; ++i) {
            acc = acc * 0.5 + xs[i] * 0.5;
            acc = acc + (acc / 8.0);
        }
        return acc;
    };
    return step(n);
}
";

#[test]
fn a_namespace_is_not_a_clone_of_the_class_it_holds() {
    // The namespace and the class are made of the same tokens, so every
    // measure agrees on them completely. That is not a copy: it is one stretch
    // of code seen at two levels, and calling it a duplicate points the reader
    // at work that does not exist. The pair is dropped before verification
    // rather than after, so it costs nothing to score either.
    let files = vec![CppStructuralFrontend.parse(WRAPPED)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    assert!(
        report.units.len() >= 2,
        "the namespace and the class are both units, got {}",
        report.units.len()
    );
    assert_eq!(
        report.groups.groups,
        vec![],
        "one nested stretch of code is not two instances of anything"
    );
    assert!(
        report.stats.nested_pairs > 0,
        "the pair is dropped for nesting, and says so"
    );
}

/// Two copies of one case, written the way a C++ test framework makes an
/// author write them, beside the production function they call.
const SUITE: &str = "\
int normalise(int value) {
    int scaled = value * 2;
    int shifted = scaled + 1;
    return shifted;
}

TEST(NormaliseSuite, DoublesAndShifts) {
    int input = 3;
    int result = normalise(input);
    ASSERT_EQ(result, 7);
    ASSERT_NE(result, 0);
}

TEST_F(NormaliseFixture, HandlesZero) {
    int input = 3;
    int result = normalise(input);
    ASSERT_EQ(result, 7);
    ASSERT_NE(result, 0);
}
";

#[test]
fn a_case_written_as_a_framework_macro_is_recognised_as_test_code() {
    // The macro stands where a return type and a name would, so the case
    // parses as a definition named after the macro. That name is the author
    // saying what the body is, and it is the only such statement C++ offers:
    // the language has no attribute for it and no container to inherit from.
    let files = vec![CppStructuralFrontend.parse(SUITE)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    let cases: Vec<&StructuralUnit> = report
        .units
        .iter()
        .filter(|unit| matches!(unit.name.as_deref(), Some("TEST" | "TEST_F")))
        .collect();
    assert_eq!(cases.len(), 2, "both cases are units");
    assert!(
        cases.iter().all(|unit| unit.test_code),
        "a case macro marks the body it opens"
    );
    assert!(
        report
            .units
            .iter()
            .any(|unit| unit.name.as_deref() == Some("normalise") && !unit.test_code),
        "the function under test is not part of the suite"
    );
    // The two cases are copies of each other, so they do reach a group — and
    // the group is the suite's, not the production code's.
    let suite = report
        .groups
        .groups
        .iter()
        .find(|group| group.members.iter().all(|&m| report.units[m].test_code));
    assert!(suite.is_some(), "the duplicated cases group together");
}
