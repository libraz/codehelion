//! Sub-unit clone regions over the committed partial-clone corpus.
//!
//! The corpus transplants a run of statements out of a donor function into an
//! unrelated host, so the two enclosing functions are not clones of each other
//! at all — only a stretch inside them is. Whole-unit grouping cannot express
//! that; the maximal-region stage is what does, and what it must report is the
//! transplanted run, at its labelled extent, once.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::ir::{ByteRange, StructuralFrontend, SyntaxIrFile};
use codehelion_core::maximal::CloneRegion;
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-partial";
const FILES: [&str; 3] = ["seed.rs", "partial1.rs", "partial2.rs"];

fn read(name: &str) -> String {
    let path = PathBuf::from(CORPUS).join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn analyze() -> StructuralReport {
    let files: Vec<SyntaxIrFile> = FILES
        .iter()
        .map(|name| RustStructuralFrontend.parse(&read(name)))
        .collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// The 1-based line range a byte range covers in `text`.
fn lines(text: &str, range: ByteRange) -> (usize, usize) {
    let line_of = |offset: usize| text[..offset].lines().count().max(1);
    (line_of(range.start), line_of(range.end))
}

/// The name of the unit a region side sits in.
fn host(report: &StructuralReport, file: usize, range: ByteRange) -> String {
    report
        .units
        .iter()
        .filter(|unit| {
            unit.file == file && unit.range.start <= range.start && range.end <= unit.range.end
        })
        .find_map(|unit| unit.name.as_ref().map(|name| name.as_str().to_string()))
        .unwrap_or_else(|| panic!("no unit encloses {range:?} in {}", FILES[file]))
}

fn describe(report: &StructuralReport, region: &CloneRegion) -> String {
    let a = read(FILES[region.a.file]);
    let b = read(FILES[region.b.file]);
    format!(
        "{}:{:?} {} <-> {}:{:?} {}",
        FILES[region.a.file],
        lines(&a, region.a.range),
        host(report, region.a.file, region.a.range),
        FILES[region.b.file],
        lines(&b, region.b.range),
        host(report, region.b.file, region.b.range),
    )
}

#[test]
fn the_transplanted_run_is_reported_once_at_its_labelled_extent() {
    let report = analyze();
    let described: Vec<String> = report
        .regions
        .iter()
        .map(|region| describe(&report, region))
        .collect();
    assert_eq!(
        report.regions.len(),
        1,
        "one labelled run is detectable here: {described:#?}"
    );

    let region = report.regions[0];
    // The corpus labels this pair as a verbatim transplant of the measurement
    // loop body out of `measure_lines` into the unrelated host `scan_report`.
    assert_eq!(
        host(&report, region.a.file, region.a.range),
        "measure_lines"
    );
    assert_eq!(host(&report, region.b.file, region.b.range), "scan_report");
    assert_eq!(lines(&read(FILES[region.a.file]), region.a.range), (9, 22));
    assert_eq!(lines(&read(FILES[region.b.file]), region.b.range), (10, 23));

    // A verbatim transplant covers the same source on both sides.
    assert_eq!(
        read(FILES[region.a.file])[region.a.range.start..region.a.range.end].trim(),
        read(FILES[region.b.file])[region.b.range.start..region.b.range.end].trim()
    );
}

#[test]
fn the_sliding_windows_that_found_it_collapse_into_one_region() {
    // Five shared statements are covered by two overlapping length-four
    // windows. Reporting them raw would mean two findings describing one
    // duplicated block, and neither would state the block's real extent.
    let report = analyze();
    let region = report.regions[0];
    assert_eq!(region.seeds, 2);
    assert_eq!(region.a.run.length, 5);
    assert_eq!(region.b.run.length, 5);
    assert!(report.stats.maximal.seeds > report.stats.maximal.regions);
}

#[test]
fn a_run_that_only_matches_on_summaries_is_not_reported() {
    // Both copies of `scan_report` open with the same four statements, but the
    // host's loop carries the whole transplanted body while the seed's is one
    // line. The statement summary cannot see inside a loop, so this matches on
    // summaries alone; the source-length gap is what rejects it.
    let report = analyze();
    assert_eq!(report.stats.maximal.divergent_extent, 1);
    let described: Vec<String> = report
        .regions
        .iter()
        .map(|region| describe(&report, region))
        .collect();
    assert!(
        !report.regions.iter().any(|region| {
            host(&report, region.a.file, region.a.range) == "scan_report"
                && host(&report, region.b.file, region.b.range) == "scan_report"
        }),
        "the summary-level coincidence must not be reported: {described:#?}"
    );
}

#[test]
fn the_renamed_transplant_is_below_the_window_minimum() {
    // The corpus also labels a renamed transplant out of `checksum_records`
    // into `merge_batches`. It is three statements long, and the shortest
    // statement window is four, so no seed can cover it: this is a recall
    // limit of the window lengths, not of the fold. Pinned so that changing
    // the window lengths surfaces here.
    let report = analyze();
    assert!(
        !report
            .regions
            .iter()
            .any(|region| host(&report, region.b.file, region.b.range) == "merge_batches"),
    );
}

#[test]
fn the_corpus_consolidates_the_same_twice() {
    assert_eq!(analyze().regions, analyze().regions);
}
