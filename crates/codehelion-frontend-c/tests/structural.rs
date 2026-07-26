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

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
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
fn two_runs_over_the_same_corpus_agree() {
    assert_eq!(analyze().groups.groups, analyze().groups.groups);
}

/// Two copies of one case, written the way a C test framework makes an author
/// write them, beside the production function they call.
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

TEST(NormaliseSuite, HandlesZero) {
    int input = 0;
    int result = normalise(input);
    ASSERT_EQ(result, 1);
    ASSERT_NE(result, 0);
}
";

#[test]
fn a_case_written_as_a_framework_macro_is_no_unit_in_c() {
    // C++ reads `MACRO(suite, name) { ... }` as a definition named after the
    // macro, which is what makes the name usable as a test marker. The C
    // grammar does not: it reads a call and then a block that belongs to
    // nobody. So a C suite contributes no units at all, and the two identical
    // cases below are not reported as duplicates of each other.
    //
    // This is pinned rather than fixed because the marker already handles the
    // case the moment a unit appears — if this assertion ever fails, the
    // grammar started producing one and the classification will be waiting.
    let files = vec![CStructuralFrontend.parse(SUITE)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    let names: Vec<Option<&str>> = report
        .units
        .iter()
        .map(|unit| unit.name.as_deref())
        .collect();
    assert_eq!(
        names,
        vec![Some("normalise")],
        "only the function is a unit"
    );
    assert!(
        report.groups.groups.is_empty(),
        "nothing in the suite reaches a group"
    );
}

/// A store written out one byte at a time, at two widths — the shape C reaches
/// for when a loop would cost more than it saves.
const UNROLLED: &str = "\
static void write_le32(void *dst, unsigned int value32)
{
    unsigned char *const p = (unsigned char *)dst;
    p[0] = (unsigned char)value32;
    p[1] = (unsigned char)(value32 >> 8);
    p[2] = (unsigned char)(value32 >> 16);
    p[3] = (unsigned char)(value32 >> 24);
}

static void write_le64(void *dst, unsigned long long value64)
{
    unsigned char *const p = (unsigned char *)dst;
    p[0] = (unsigned char)value64;
    p[1] = (unsigned char)(value64 >> 8);
    p[2] = (unsigned char)(value64 >> 16);
    p[3] = (unsigned char)(value64 >> 24);
    p[4] = (unsigned char)(value64 >> 32);
    p[5] = (unsigned char)(value64 >> 40);
    p[6] = (unsigned char)(value64 >> 48);
    p[7] = (unsigned char)(value64 >> 56);
}
";

#[test]
fn an_unrolled_run_is_not_a_clone_of_itself() {
    // Every statement of the wider store summarises like every other, so each
    // window of the run matches every shifted window of itself. Those pairs
    // are rejected one by one for covering one stretch of code rather than
    // two — and then arrive together anyway, as occurrences of one run, joined
    // by the narrower store they all match. Reported that way, the run comes
    // back as a clone of itself at four offsets.
    let files = vec![CStructuralFrontend.parse(UNROLLED)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    assert!(
        report.stats.region_overlapping > 0,
        "the shifted windows have to be recognised, not merely absent"
    );
    for region in &report.regions {
        let units: Vec<usize> = region
            .occurrences
            .iter()
            .map(|occurrence| occurrence.unit)
            .collect();
        assert!(
            units.iter().any(|unit| *unit != units[0]),
            "a run reported inside one function only: {:?}",
            region
                .occurrences
                .iter()
                .map(|occurrence| (occurrence.start_line, occurrence.end_line))
                .collect::<Vec<_>>()
        );
    }

    // What the two functions do share is still reported: the narrower store is
    // the wider one's first four bytes.
    assert_eq!(
        report.groups.groups.len(),
        1,
        "the two stores are one group"
    );
}

/// One function written twice, once per platform, the way a portable C source
/// writes it — beside an unguarded pair that really is duplicated.
const PORTABLE: &str = "\
#ifdef _WIN32
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
#else
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
#endif

int scale_a(int v) {
    int ticks = v * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}

int scale_b(int v) {
    int ticks = v * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
";

#[test]
fn the_two_arms_of_one_conditional_are_not_a_clone_pair() {
    // The guarded pair is identical, so every measure agrees on it — and
    // reporting it would tell the reader to delete one of two functions only
    // one of which is ever compiled. The unguarded pair below it is the same
    // code and is reported, so the drop is about the conditional and not
    // about the similarity.
    let files = vec![CStructuralFrontend.parse(PORTABLE)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    let unit_at_line = |line: u32| {
        report
            .units
            .iter()
            .position(|unit| unit.start_line == line)
            .unwrap_or_else(|| panic!("no unit starts at line {line}"))
    };
    let (guarded, otherwise) = (unit_at_line(2), unit_at_line(9));
    let (open_a, open_b) = (unit_at_line(17), unit_at_line(24));

    // Three, not one: the funnel counts proposals, and all three candidate
    // stages propose this pair — it shares fragments, shingles and a
    // control-flow skeleton. The `nested` counter beside it counts the same
    // way.
    assert_eq!(
        report.stats.alternative_pairs, 3,
        "the guarded pair is dropped, and the funnel says so"
    );
    for group in &report.groups.groups {
        assert!(
            !(group.members.contains(&guarded) && group.members.contains(&otherwise)),
            "no group holds both arms of one conditional"
        );
    }
    assert!(
        report
            .groups
            .groups
            .iter()
            .any(|group| group.members.contains(&open_a) && group.members.contains(&open_b)),
        "the same code outside any conditional is still a clone"
    );
}

/// The same portable pair, followed by an item the parser cannot follow: the
/// trailing function is truncated, well after the conditional has closed.
const BROKEN_AFTERWARDS: &str = "\
#ifdef _WIN32
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
#else
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
#endif

int broken(int v) { return v +
";

/// The same portable pair with the unparsable item moved inside the first arm,
/// so error recovery is what decides where that arm ends.
const BROKEN_INSIDE: &str = "\
#ifdef _WIN32
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
int broken(int v) { return v + }
#else
int wait_ticks(int ms) {
    int ticks = ms * 10;
    int capped = ticks > 1000 ? 1000 : ticks;
    int slept = capped;
    return slept;
}
#endif
";

#[test]
fn a_stumble_elsewhere_in_the_file_leaves_the_conditional_readable() {
    // Error recovery is not local to what broke: one truncated item puts an
    // error region in the file, and a header whose include guard encloses
    // everything gets one spanning all of it. Neither says anything about a
    // conditional the parser did read, and refusing that conditional would
    // report two platform variants as a clone.
    let files = vec![CStructuralFrontend.parse(BROKEN_AFTERWARDS)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    assert!(
        !files[0].error_ranges.is_empty(),
        "the fixture is meant to be a file the parser struggled with"
    );
    assert!(
        report.stats.alternative_pairs > 0,
        "the conditional itself parsed, so its arms still rule each other out"
    );
}

#[test]
fn a_stumble_inside_the_conditional_excludes_nothing() {
    // Arms are read off the tree, so an arm whose end the parser guessed at is
    // not worth reading. Dropping a pair hides a finding, so the tool would
    // rather report the platform pair than invent an exclusion.
    let files = vec![CStructuralFrontend.parse(BROKEN_INSIDE)];
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let report = structural::analyze(&files, &variant, &StructuralConfig::default());

    assert!(
        !files[0].error_ranges.is_empty(),
        "the fixture is meant to be a file the parser struggled with"
    );
    assert_eq!(
        report.stats.alternative_pairs, 0,
        "no exclusion is claimed from an arm the parser guessed at"
    );
    // And the pair really is reported: a missed exclusion is meant to cost a
    // noisy finding, not to be lost somewhere else and look like a clean run.
    let unit_at_line = |line: u32| {
        report
            .units
            .iter()
            .position(|unit| unit.start_line == line)
            .unwrap_or_else(|| panic!("no unit starts at line {line}"))
    };
    let (guarded, otherwise) = (unit_at_line(2), unit_at_line(10));
    assert!(
        report
            .groups
            .groups
            .iter()
            .any(|group| group.members.contains(&guarded) && group.members.contains(&otherwise)),
        "the two arms are reported as the clone they measure as"
    );
}
