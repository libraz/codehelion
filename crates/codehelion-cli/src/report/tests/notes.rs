//! The warnings and notes written around the report body.

use super::*;

#[test]
fn a_rule_that_matched_nothing_is_named_not_left_to_be_noticed() {
    let mut report = sample_report();
    report.summary.unused_suppressions = vec![
        UnusedRule {
            scope: "path_glob".to_string(),
            pattern: "third_party/**".to_string(),
            matched: 0,
        },
        UnusedRule {
            scope: "stable_clone_id".to_string(),
            pattern: "abcd1234".to_string(),
            matched: 0,
        },
    ];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unused_suppressions"][0]["scope"],
        "path_glob"
    );
    assert_eq!(
        value["summary"]["unused_suppressions"][1]["pattern"],
        "abcd1234"
    );

    let mut buffer = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // Named the way a rule that did match is named, so the two read alike.
    assert!(text.contains(
        "note: 2 suppression rule(s) matched nothing: path glob \"third_party/**\", \
         clone id abcd1234"
    ));
}

#[test]
fn a_run_with_every_rule_matching_says_nothing_about_them() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    assert!(
        !String::from_utf8(buffer)
            .unwrap()
            .contains("matched nothing")
    );
}

#[test]
fn fast_summary_names_overlapping_totals_and_unmeasured_evidence() {
    let report = sample_report();
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses"
        ])
    );

    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        notes.contains(
            "Fast duplicated-token totals may overlap because one source location can appear in multiple groups"
        ),
        "{notes}"
    );
    for feature in [
        "identifier agreement",
        "similarity breakdown",
        "siblings",
        "near misses",
    ] {
        assert!(notes.contains(feature), "{feature}: {notes}");
    }
}

#[test]
fn unmeasured_measurements_are_scoped_to_fast_mode() {
    assert_eq!(
        unmeasured_in_this_mode("fast"),
        [
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    );
    assert!(unmeasured_in_this_mode("structural").is_empty());
    assert!(unmeasured_in_this_mode("semantic").is_empty());
}

#[test]
fn structural_summary_serializes_an_empty_fast_only_unmeasured_list() {
    let mut report = sample_report();
    report.run.mode = "structural".to_string();
    report.summary.unmeasured_in_this_mode.clear();

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([])
    );

    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("duplicated-token totals may overlap"),
        "{notes}"
    );
}

#[test]
fn artifact_guidance_appears_only_when_every_group_lacks_savings() {
    let mut report = sample_report();
    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        notes.contains(
            "note: no artifact savings are recorded; run artifact analyze <PATH> --source-run <id> --build-variant <manifest> on a build of this tree, supplying the evidence its format carries:\n"
        ),
        "{notes}"
    );
    // The note names each format's real attribution granularity rather than
    // asking for one condition every format is assumed to meet. A WebAssembly
    // module cannot carry line frames through its name section, so its line
    // has to say so instead of promising line ranges.
    assert!(
        notes.contains("wasm: the name section attributes whole symbols only"),
        "{notes}"
    );
    assert!(notes.contains("elf: supply "), "{notes}");

    report.groups[0].artifact_savings.push(ArtifactSavings {
        artifact_analysis_id: 17,
        source_build_variant_fingerprint: "01".repeat(16),
        artifact_build_variant_fingerprint: "02".repeat(16),
        duplicated_bytes: 24,
        estimated_refactor_savings_bytes: 9,
        mapping_confidence: "high".to_string(),
        clone_confidence: 1.0,
        model_confidence: "low".to_string(),
        savings_confidence: "low".to_string(),
        model_schema_version: "refactor-savings-model-v1".to_string(),
        assumptions: serde_json::json!([]),
    });
    let mut notes = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("no artifact savings are recorded"),
        "{notes}"
    );

    let mut empty = sample_report();
    empty.groups.clear();
    let mut notes = Vec::new();
    empty
        .render_notes(TextOptions::default(), &mut notes)
        .unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert!(
        !notes.contains("no artifact savings are recorded"),
        "{notes}"
    );
}

#[test]
fn partition_artifact_guidance_is_aggregated_over_all_models() {
    const GUIDANCE: &str = "note: no artifact savings are recorded; run artifact analyze <PATH> --source-run <id> --build-variant <manifest> on a build of this tree, supplying the evidence its format carries:";

    let reports = [sample_report(), sample_report()];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 1, "{notes}");

    let mut with_savings = sample_report();
    with_savings.groups[0]
        .artifact_savings
        .push(ArtifactSavings {
            artifact_analysis_id: 17,
            source_build_variant_fingerprint: "01".repeat(16),
            artifact_build_variant_fingerprint: "02".repeat(16),
            duplicated_bytes: 24,
            estimated_refactor_savings_bytes: 9,
            mapping_confidence: "high".to_string(),
            clone_confidence: 1.0,
            model_confidence: "low".to_string(),
            savings_confidence: "low".to_string(),
            model_schema_version: "refactor-savings-model-v1".to_string(),
            assumptions: serde_json::json!([]),
        });
    let reports = [sample_report(), with_savings];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 0, "{notes}");

    let mut empty = sample_report();
    empty.groups.clear();
    let reports = [empty, sample_report()];
    let mut notes = Vec::new();
    for report in &reports {
        report
            .render_notes_without_artifact_guidance(TextOptions::default(), &mut notes)
            .unwrap();
    }
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 1, "{notes}");

    let reports = [empty_report(), empty_report()];
    let mut notes = Vec::new();
    render_partition_artifact_guidance(&reports, &mut notes).unwrap();
    let notes = String::from_utf8(notes).unwrap();
    assert_eq!(notes.matches(GUIDANCE).count(), 0, "{notes}");
}

fn empty_report() -> Report {
    let mut report = sample_report();
    report.groups.clear();
    report
}

#[test]
fn a_candidate_search_cut_is_stated_as_a_note() {
    let mut buffer = Vec::new();
    sample_report()
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("candidate search was truncated by overshared values"));
    assert!(text.contains("may be missing from this report"));
}

#[test]
fn what_unsettles_the_report_is_written_as_a_warning_before_the_notes() {
    let mut report = sample_report();
    report.summary.unused_suppressions = vec![UnusedRule {
        scope: "path".to_string(),
        pattern: "vendor/**".to_string(),
        matched: 0,
    }];
    let mut buffer = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    let warning = text.find("⚠ warning: candidate search was truncated");
    let note = text.find("note: 1 suppression rule(s) matched nothing");
    assert!(warning.is_some() && note.is_some(), "{text}");
    // A reader who stops after one line should have stopped after the line
    // that changes what the rest of the report means.
    assert!(warning < note, "{text}");
}

#[test]
fn a_depth_limited_parse_is_stated_as_a_note() {
    let mut report = sample_report();
    report
        .summary
        .funnel
        .push(FunnelStage::new("structural files", 2).dropping(FunnelCause::DepthLimit, 1));
    let mut buffer = Vec::new();
    report
        .render_notes(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("structural parsing reached its depth limit in 1 file(s)"),
        "{text}"
    );
}

#[test]
fn a_quiet_run_says_nothing_about_what_qualifies_it() {
    let mut buffer = Vec::new();
    sample_report()
        .render_notes(
            TextOptions {
                quiet: true,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    assert!(buffer.is_empty(), "{:?}", String::from_utf8(buffer));
}
