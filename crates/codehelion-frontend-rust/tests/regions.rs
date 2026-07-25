//! Duplicated statement runs over real parsed Rust.
//!
//! A run is proposed by statement-window hashes, and a statement summary is a
//! shape plus its leading token *kinds* — so `let a = foo(x);` and
//! `let b = bar(y);` propose as the same statement. What separates a finding
//! from a coincidence is confirming the proposal against the tokens, and these
//! sources are built to exercise exactly that: one loop body shared verbatim,
//! one shared under consistent renaming, and one that summarises identically
//! while computing something else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

/// The donor: the loop body is the run every other source is compared against.
const DONOR: &str = "\
fn collect_widths(items: &[String]) -> u32 {
    let mut total = 0;
    let mut seen = 0;
    for item in items {
        let text = item.trim();
        let width = text.chars().count() as u32;
        total += width;
        seen += 1;
    }
    total + seen
}
";

/// The donor's loop body, verbatim, inside a host built on a different
/// skeleton, so the two functions share the run and nothing else.
const VERBATIM_HOST: &str = "\
fn longest_line(lines: &[String]) -> u32 {
    let mut total = 0;
    let mut seen = 0;
    if lines.is_empty() {
        return 0;
    }
    while total < 3 {
        total += 1;
    }
    for item in lines {
        let text = item.trim();
        let width = text.chars().count() as u32;
        total += width;
        seen += 1;
    }
    total
}
";

/// The donor's loop body under consistent renaming, in a third skeleton.
const RENAMED_HOST: &str = "\
fn gather_sizes(entries: &[String]) -> u32 {
    let mut sum = 0;
    let mut count = 0;
    let cap = entries.len();
    match cap {
        0 => return 0,
        _ => {}
    }
    for entry in entries {
        let body = entry.trim();
        let span = body.chars().count() as u32;
        sum += span;
        count += 1;
    }
    sum
}
";

/// A loop body whose statements summarise exactly like the donor's — same
/// shapes, same leading token kinds — while calling different things and
/// accumulating the other way.
const LOOKALIKE_HOST: &str = "\
fn tally_scores(items: &[String]) -> u32 {
    let mut total = 0;
    let mut seen = 0;
    loop {
        total += 1;
        break;
    }
    for item in items {
        let text = item.to_uppercase();
        let width = text.len() as u32;
        total -= width;
        seen += 2;
    }
    total
}
";

fn analyze(sources: &[&str]) -> StructuralReport {
    let files: Vec<SyntaxIrFile> = sources
        .iter()
        .map(|source| RustStructuralFrontend.parse(source))
        .collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// The reported runs as `(clone type, statements, occurrence count)`.
fn shape(report: &StructuralReport) -> Vec<(CloneClass, u32, usize)> {
    report
        .regions
        .iter()
        .map(|region| {
            (
                region.clone_type,
                region.statements,
                region.occurrences.len(),
            )
        })
        .collect()
}

#[test]
fn a_verbatim_shared_loop_body_is_one_type1_run() {
    let report = analyze(&[DONOR, VERBATIM_HOST]);
    assert_eq!(shape(&report), vec![(CloneClass::Type1, 4, 2)]);

    let region = &report.regions[0];
    let files: Vec<usize> = region
        .occurrences
        .iter()
        .map(|occurrence| occurrence.file)
        .collect();
    assert_eq!(files, vec![0, 1]);
    assert_eq!(
        region.occurrences[0].token_end - region.occurrences[0].token_start,
        region.occurrences[1].token_end - region.occurrences[1].token_start,
        "a verbatim copy covers the same tokens"
    );
    // What makes this a sub-unit finding: every occurrence is a fraction of
    // its enclosing unit, which unit-level grouping has no way to say.
    for occurrence in &region.occurrences {
        let unit = &report.units[occurrence.unit];
        assert!(
            occurrence.token_start > unit.token_start && occurrence.token_end < unit.token_end,
            "the run must sit strictly inside its host unit"
        );
    }
}

#[test]
fn a_consistently_renamed_loop_body_is_a_type2_run() {
    let report = analyze(&[DONOR, RENAMED_HOST]);
    assert_eq!(shape(&report), vec![(CloneClass::Type2, 4, 2)]);
    // The occurrences differ in content, which is what makes it Type-2 rather
    // than Type-1.
    let region = &report.regions[0];
    assert_ne!(region.occurrences[0].content, region.occurrences[1].content);
}

#[test]
fn a_run_that_only_summarises_alike_is_confirmed_away() {
    // Same shapes and same leading token kinds statement for statement, so the
    // window hashes collide and the run is proposed. Different callees and a
    // different accumulation, so it is not a duplicate of anything.
    let report = analyze(&[DONOR, LOOKALIKE_HOST]);
    assert!(
        report.regions.is_empty(),
        "a summary-level coincidence is not a duplicated run: {:#?}",
        shape(&report)
    );
    assert!(
        report.stats.maximal.shared > 0,
        "the coincidence must reach confirmation, or this proves nothing"
    );
    assert!(report.stats.region_singletons >= 2);
}

#[test]
fn every_copy_of_one_run_lands_in_the_same_report_entry() {
    // Three copies of one run: one entry with three occurrences, not three
    // entries and not the three pairs they match as.
    let report = analyze(&[DONOR, VERBATIM_HOST, RENAMED_HOST]);
    assert_eq!(shape(&report), vec![(CloneClass::Type2, 4, 3)]);
    let files: Vec<usize> = report.regions[0]
        .occurrences
        .iter()
        .map(|occurrence| occurrence.file)
        .collect();
    assert_eq!(files, vec![0, 1, 2]);
}

#[test]
fn a_run_keeps_its_identity_when_an_unrelated_file_joins_the_scan() {
    // The fingerprint is derived from the members' content, so scanning more
    // code does not rename a run that did not change.
    let alone = analyze(&[DONOR, VERBATIM_HOST]);
    let joined = analyze(&[DONOR, VERBATIM_HOST, LOOKALIKE_HOST]);
    assert_eq!(
        alone.regions[0].fingerprint, joined.regions[0].fingerprint,
        "an unrelated file must not move an existing run's identity"
    );
}

#[test]
fn confirmation_is_deterministic() {
    assert_eq!(
        analyze(&[DONOR, VERBATIM_HOST, RENAMED_HOST]).regions,
        analyze(&[DONOR, VERBATIM_HOST, RENAMED_HOST]).regions
    );
}
