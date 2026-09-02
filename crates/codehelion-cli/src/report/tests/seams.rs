//! How a recorded seam run reaches the text and JSON views.

use super::*;

/// The text of one report's seam section, at the default depth.
fn rendered_seam_section(report: &Report) -> String {
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .expect("render a report with seams");
    let text = String::from_utf8(buffer).expect("UTF-8 report");
    text.lines()
        .filter(|line| line.starts_with("seams:") || line.starts_with("since seam run"))
        .fold(String::new(), |mut section, line| {
            section.push_str(line);
            section.push('\n');
            section
        })
}

#[test]
fn the_seam_section_names_what_each_seam_cost_and_what_moved_since_the_last_one() {
    let mut report = sample_report();
    report.seam = Some(sample_seam_report());
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .expect("render a report with seams");
    let text = String::from_utf8(buffer).expect("UTF-8 report");

    assert!(
        text.contains(
            "seams: frontend-c-cpp 12 asymmetric changes, 7 breaches (last 8f1c2ab0), 4 findings\n"
        ),
        "{text}"
    );
    // The second seam is written under the first, against the same column.
    assert!(
        text.contains("       readme-en-ja 2 asymmetric changes, no breaches\n"),
        "{text}"
    );
    // Only what moved: the findings count stood still and is not named, and
    // the second seam has no earlier generation to be compared with at all.
    assert!(
        text.contains("since seam run 2: frontend-c-cpp +1 asymmetric change, +1 breach\n"),
        "{text}"
    );
    assert!(!text.contains("readme-en-ja +"), "{text}");
}

#[test]
fn a_seam_run_with_no_previous_generation_reports_counts_without_deltas() {
    let mut report = sample_report();
    let mut seam = sample_seam_report();
    seam.since_seam_run_id = None;
    for entry in &mut seam.seams {
        entry.asymmetric_changes_since = None;
        entry.breaches_since = None;
        entry.findings_since = None;
    }
    report.seam = Some(seam);

    let section = rendered_seam_section(&report);
    assert!(
        section.contains("frontend-c-cpp 12 asymmetric changes"),
        "{section}"
    );
    assert!(!section.contains("since seam run"), "{section}");
}

/// A seam crossed repeatedly and never breached is the case the ledger exists
/// to tell apart from one that costs a fix every time, so it is said in words
/// rather than as a zero the reader has to interpret.
#[test]
fn a_seam_that_was_never_breached_says_so_rather_than_printing_a_zero() {
    let mut report = sample_report();
    let mut seam = sample_seam_report();
    seam.seams.truncate(1);
    seam.seams[0].breaches = 0;
    seam.seams[0].last_breach = None;
    seam.seams[0].breaches_since = Some(0);
    report.seam = Some(seam);

    let section = rendered_seam_section(&report);
    assert!(section.contains("no breaches"), "{section}");
    assert!(!section.contains("0 breaches"), "{section}");
    assert!(!section.contains("(last "), "{section}");
    // A delta of zero moved nothing, so it is not a clause either.
    assert!(!section.contains("+0"), "{section}");
}

#[test]
fn a_seam_that_was_never_changed_on_one_side_says_only_that() {
    let mut report = sample_report();
    let mut seam = sample_seam_report();
    seam.seams.truncate(1);
    seam.seams[0].asymmetric_changes = 0;
    seam.seams[0].breaches = 0;
    seam.seams[0].last_breach = None;
    seam.seams[0].findings = 0;
    seam.seams[0].asymmetric_changes_since = Some(0);
    seam.seams[0].breaches_since = Some(0);
    seam.seams[0].findings_since = Some(0);
    report.seam = Some(seam);

    let section = rendered_seam_section(&report);
    assert!(
        section.contains("seams: frontend-c-cpp no asymmetric changes\n"),
        "{section}"
    );
    assert!(!section.contains("breach"), "{section}");
}

#[test]
fn no_recorded_seam_run_leaves_the_section_out_entirely() {
    let report = sample_report();
    assert!(report.seam.is_none());
    assert_eq!(rendered_seam_section(&report), String::new());

    // A run recorded against an empty ledger is not something to print a
    // heading for either.
    let mut empty = sample_report();
    let mut seam = sample_seam_report();
    seam.seams.clear();
    empty.seam = Some(seam);
    assert_eq!(rendered_seam_section(&empty), String::new());
}

#[test]
fn a_recorded_seam_run_round_trips_through_the_shipped_schema() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let uri = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v2.schema.json";
    compiler.add_resource(uri, schema).unwrap();
    let index = compiler.compile(uri, &mut schemas).unwrap();

    let mut report = sample_report();
    report.seam = Some(sample_seam_report());
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    schemas.validate(&value, index).unwrap();
    assert_eq!(value["seam"]["seam_run_id"], 3);
    assert_eq!(value["seam"]["seams"][0]["asymmetric_changes_since"], 1);
    // A seam the previous generation did not carry reports no delta rather
    // than its whole count.
    assert!(value["seam"]["seams"][1]["asymmetric_changes_since"].is_null());

    // The field is optional: a report with no recorded seam run omits it, and
    // that document is still the current schema.
    let without: serde_json::Value =
        serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
    assert!(without.get("seam").is_none());
    schemas.validate(&without, index).unwrap();
}
