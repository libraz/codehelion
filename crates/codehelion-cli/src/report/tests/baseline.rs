//! What a run says about the baseline it was compared with.

use super::*;

#[test]
fn a_group_standing_where_a_gone_one_stood_says_so_and_the_rest_stay_quiet() {
    let mut report = sample_report();
    report.groups[0].baseline = Some(GroupBaseline {
        state: GROUP_NEW.to_string(),
        added_instances: None,
        derived_from: Some(Derivation {
            group: "aa11".to_string(),
            shared_sites: 2,
        }),
    });
    report.groups[1].baseline = Some(GroupBaseline {
        state: GROUP_CONTINUING.to_string(),
        added_instances: None,
        derived_from: None,
    });

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("new since the baseline, standing where aa11 stood (2 occurrence(s)"),
        "{text}"
    );
    // Continuing is the unremarkable case, and marking every one of them
    // would bury the one that matters.
    assert_eq!(text.matches("since the baseline").count(), 1, "{text}");
}

#[test]
fn an_expanded_group_names_the_uncovered_occurrences() {
    let mut report = sample_report();
    report.groups[0].baseline = Some(GroupBaseline {
        state: GROUP_EXPANDED.to_string(),
        added_instances: Some(1),
        derived_from: None,
    });

    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // The listing marks it; the sentence is one of the details behind it.
    assert!(text.contains("[expanded +1]"), "{text}");

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("expanded since the baseline: 1 new occurrence(s)"),
        "{text}"
    );
}

#[test]
fn a_comparison_says_how_much_went_as_well_as_how_many() {
    let mut report = sample_report();
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_COMPARE.to_string(),
        matched: 8,
        stale: 4,
        appeared: 21,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 3400,
        appeared_tokens: 900,
        expanded_tokens: 0,
        gone: vec![GoneGroup {
            group: "aa11".to_string(),
            clone_type: "type-2".to_string(),
            duplicated_tokens: 3400,
            anchor: Some(GoneAnchor {
                file: "src/gone.rs".to_string(),
                start_line: 10,
                end_line: 40,
                unit: Some("validate".to_string()),
            }),
        }],
    });

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // 21 new against 4 gone reads as a regression until the sizes are on
    // the same line: the four that went were most of the duplication.
    assert!(
        text.contains(
            "since it was recorded: 4 gone (-3400 repeated tokens), 21 new (+900), 0 expanded (+0 occurrence(s), +0 repeated tokens), 8 unchanged"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "gone aa11 type-2 (3400 repeated tokens), last seen at src/gone.rs:10 in validate"
        ),
        "{text}"
    );
}

#[test]
fn a_baseline_with_only_stale_entries_reports_its_actual_counts() {
    let mut report = sample_report();
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_SUPPRESS.to_string(),
        matched: 0,
        stale: 12,
        appeared: 0,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 0,
        appeared_tokens: 0,
        expanded_tokens: 0,
        gone: Vec::new(),
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(
        text.contains("baseline codehelion-baseline.json: 0 of 12 matched, 12 gone"),
        "{text}"
    );
    assert!(!text.contains("warning:"));

    // A baseline that applies says only what it did.
    report.summary.baseline = Some(BaselineStatus {
        file: "codehelion-baseline.json".to_string(),
        entries: 12,
        mode: BASELINE_SUPPRESS.to_string(),
        matched: 11,
        stale: 1,
        appeared: 0,
        expanded: 0,
        expanded_instances: 0,
        stale_tokens: 0,
        appeared_tokens: 0,
        expanded_tokens: 0,
        gone: Vec::new(),
    });
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("11 of 12 matched, 1 gone"), "{text}");
    assert!(!text.contains("warning:"));
}
