//! Sub-unit clone regions over the committed partial-clone corpus.
//!
//! The corpus transplants a run of statements out of a donor function into an
//! unrelated host, so the two enclosing functions are not clones of each other
//! at all — only a stretch inside them is. Whole-unit grouping cannot express
//! that; the maximal-region stage is what does, and what it must report is the
//! transplanted run, at its labelled extent, once.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{
    self, RegionOccurrence, StructuralConfig, StructuralRegion, StructuralReport,
};
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
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// The name of the unit an occurrence sits in.
fn host(report: &StructuralReport, occurrence: &RegionOccurrence) -> String {
    report.units[occurrence.unit]
        .name
        .as_ref()
        .map_or_else(|| "?".to_string(), |name| name.as_str().to_string())
}

/// Every occurrence of a region as `file:(first, last) host`.
fn describe(report: &StructuralReport, region: &StructuralRegion) -> Vec<String> {
    region
        .occurrences
        .iter()
        .map(|occurrence| {
            format!(
                "{}:({}, {}) {}",
                FILES[occurrence.file],
                occurrence.start_line,
                occurrence.end_line,
                host(report, occurrence)
            )
        })
        .collect()
}

fn described(report: &StructuralReport) -> Vec<Vec<String>> {
    report
        .regions
        .iter()
        .map(|region| describe(report, region))
        .collect()
}

#[test]
fn the_transplanted_run_is_reported_once_at_its_labelled_extent() {
    let report = analyze();
    assert_eq!(
        report.regions.len(),
        1,
        "one labelled run is detectable here: {:#?}",
        described(&report)
    );

    let region = &report.regions[0];
    assert_eq!(region.occurrences.len(), 2);
    // The corpus labels this pair as a verbatim transplant of the measurement
    // loop body out of `measure_lines` into the unrelated host `scan_report`.
    assert_eq!(region.clone_type, CloneClass::Type1);
    assert_eq!(
        describe(&report, region),
        vec![
            "seed.rs:(9, 22) measure_lines".to_string(),
            "partial1.rs:(10, 23) scan_report".to_string(),
        ]
    );

    // A verbatim transplant covers the same source at every occurrence.
    let text: Vec<String> = region
        .occurrences
        .iter()
        .map(|occurrence| {
            read(FILES[occurrence.file])[occurrence.range.start..occurrence.range.end]
                .trim()
                .to_string()
        })
        .collect();
    assert_eq!(text[0], text[1]);
}

#[test]
fn the_sliding_windows_that_found_it_collapse_into_one_region() {
    // Five shared statements are covered by two overlapping length-four
    // windows. Reporting them raw would mean two findings describing one
    // duplicated block, and neither would state the block's real extent.
    let report = analyze();
    assert_eq!(report.regions[0].statements, 5);
    assert!(report.stats.maximal.seeds > report.stats.maximal.regions);
    assert_eq!(report.stats.regions, report.regions.len());
}

#[test]
fn a_run_that_only_matches_on_summaries_is_not_reported() {
    // Both copies of `scan_report` open with the same four statements, but the
    // host's loop carries the whole transplanted body while the seed's is one
    // line. The statement summary cannot see inside a loop, so this matches on
    // summaries alone; the source-length gap is what rejects it.
    let report = analyze();
    assert_eq!(report.stats.maximal.divergent_extent, 1);
    assert!(
        !report.regions.iter().any(|region| {
            region
                .occurrences
                .iter()
                .all(|occurrence| host(&report, occurrence) == "scan_report")
        }),
        "the summary-level coincidence must not be reported: {:#?}",
        described(&report)
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
    assert!(report.regions.iter().all(|region| {
        region
            .occurrences
            .iter()
            .all(|occurrence| host(&report, occurrence) != "merge_batches")
    }));
}

#[test]
fn the_corpus_consolidates_the_same_twice() {
    assert_eq!(analyze().regions, analyze().regions);
}
