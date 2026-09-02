//! The supplemental channels: siblings, near misses and the flags that
//! reveal them.

use super::*;

#[test]
fn a_sibling_is_exported_but_text_hides_it_until_requested() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["siblings"][0]["group_fingerprint"], "0b".repeat(16));
    assert_eq!(
        value["siblings"][0]["siblings"][0]["member"]["file"],
        "src/incomplete.rs"
    );
    assert_eq!(
        value["siblings"][0]["siblings"][0]["similarity"]["composite"],
        0.76
    );
    assert_eq!(value["siblings"][0]["siblings"][0]["basis"], "similarity");
    assert_eq!(
        value["siblings"][0]["siblings"][0]["signature"],
        serde_json::Value::Null
    );

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    assert!(
        !String::from_utf8(default_text)
            .unwrap()
            .contains("sibling type-3")
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("sibling type-3 low (0.76): src/incomplete.rs:30"));
    assert!(shown_text.contains("incomplete_checksum"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let sibling = &sarif["runs"][0]["results"][0]["properties"]["siblings"][0];
    assert_eq!(sibling["basis"], "similarity");
    assert_eq!(sibling["signature"], serde_json::Value::Null);
}

#[test]
fn signature_siblings_keep_their_identity_and_render_as_exact_matches() {
    let mut report = sample_report();
    let mut siblings = sample_siblings();
    let sibling = siblings
        .siblings
        .first_mut()
        .expect("sample has one sibling");
    sibling.basis = "signature".to_string();
    sibling.signature = Some("normalized-signature-sentinel".to_string());
    report.siblings = vec![siblings];
    report.summary.guardrails = Some(Guardrails {
        profile: "untrusted".to_string(),
        max_file_bytes: 1,
        parse_timeout_ms: 2,
        helper_timeout_ms: 3,
        posting_cap: 4,
        pair_budget: 5,
        verification_budget: Some(6),
        max_alignment_cells: Some(7),
        near_miss_delta: Some(0.1),
        near_miss_cap: Some(8),
        sibling_candidate_budget: Some(9),
        sibling_per_group_cap: Some(10),
        sibling_total_cap: Some(11),
        signature_sibling_candidate_budget: Some(12),
        signature_sibling_per_group_cap: Some(13),
        signature_sibling_total_cap: Some(14),
        signature_sibling_max_units_per_signature: Some(16),
        max_component: Some(15),
    });

    let mut disabled_diagnostics = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 2,
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut disabled_diagnostics,
        )
        .unwrap();
    assert!(
        !String::from_utf8(disabled_diagnostics)
            .unwrap()
            .contains("signature sibling sweep"),
        "the opt-in channel's ceilings must not look active when its stage is absent"
    );
    report
        .summary
        .funnel
        .push(FunnelStage::new("signature sibling entries", 1));

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let sibling = &value["siblings"][0]["siblings"][0];
    assert_eq!(sibling["basis"], "signature");
    assert_eq!(sibling["signature"], "normalized-signature-sentinel");
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_candidate_budget"],
        12
    );
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_per_group_cap"],
        13
    );
    assert_eq!(
        value["summary"]["guardrails"]["signature_sibling_total_cap"],
        14
    );

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("sibling type-3 low (0.76) [same signature]: src/incomplete.rs:30"));

    let mut diagnostics = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 2,
                show_siblings: true,
                ..TextOptions::default()
            },
            &mut diagnostics,
        )
        .unwrap();
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(diagnostics.contains("signature sibling sweep 12 candidates, 13 per group, 14 total"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let sibling = &sarif["runs"][0]["results"][0]["properties"]["siblings"][0];
    assert_eq!(sibling["basis"], "signature");
    assert_eq!(sibling["signature"], "normalized-signature-sentinel");
}

#[test]
fn supplemental_totals_count_serialized_hidden_entries_and_name_the_flags() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    report.near_misses = vec![sample_near_miss()];
    report.refresh_supplemental_summary();

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["summary"]["siblings"], 1);
    assert_eq!(value["summary"]["near_misses"], 1);

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    let default_text = String::from_utf8(default_text).unwrap();
    assert!(
        default_text.contains(
            "supplemental: 1 siblings (--show-siblings), 1 near misses (--show-near-misses)"
        ),
        "{default_text}"
    );
    assert!(!default_text.contains("sibling type-3"), "{default_text}");
    assert!(
        !default_text.contains("near-match near misses:"),
        "{default_text}"
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("sibling type-3 low (0.76): src/incomplete.rs:30"));
    assert!(shown_text.contains("near-match near misses:"));
}

#[test]
fn supplemental_totals_omit_the_summary_line_when_empty() {
    let report = sample_report();
    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(!rendered.contains("supplemental:"), "{rendered}");
}

/// The rarity gate is the reason a reader's tree gets no signature siblings,
/// so its two numbers belong in the default body rather than behind a
/// diagnostic switch.
#[test]
fn a_signature_left_out_for_being_common_is_named_with_its_widest_sharing() {
    let mut report = sample_report();
    report.summary.common_signatures_skipped = 3;
    report.summary.largest_skipped_signature_units = 137;

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains(
            "signature siblings: 3 signatures skipped as too common (the most common covers 137 units)"
        ),
        "{rendered}"
    );
}

#[test]
fn no_signature_line_is_written_when_every_signature_stayed_rare() {
    let report = sample_report();
    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(!rendered.contains("signature siblings:"), "{rendered}");
}

/// A run the gate silenced outright keeps no sibling and no near miss, which
/// is the shape the supplemental totals skip. That run is exactly the one
/// whose reader needs the explanation.
#[test]
fn the_silenced_signature_channel_still_explains_itself() {
    let mut report = sample_report();
    report.summary.siblings = 0;
    report.summary.near_misses = 0;
    report.summary.common_signatures_skipped = 1;
    report.summary.largest_skipped_signature_units = 1_204;

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(!rendered.contains("supplemental:"), "{rendered}");
    assert!(
        rendered.contains(
            "signature siblings: 1 signatures skipped as too common (the most common covers 1,204 units)"
        ),
        "{rendered}"
    );
}

#[test]
fn supplemental_cap_note_requires_actual_dropped_entries() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    report.summary.funnel.push(
        FunnelStage::new("sibling entries", 1)
            .dropping(FunnelCause::SiblingTotalCap, 2)
            .dropping(FunnelCause::SiblingCandidateBudget, 0),
    );
    report.refresh_supplemental_summary();

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered
            .contains("supplemental: 1 siblings (--show-siblings; 2 dropped by search ceilings)"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("near miss(es) were dropped"),
        "{rendered}"
    );

    let mut no_drop = sample_report();
    no_drop.siblings = vec![sample_siblings()];
    no_drop
        .summary
        .funnel
        .push(FunnelStage::new("sibling entries", 1));
    no_drop.refresh_supplemental_summary();
    let mut rendered = Vec::new();
    no_drop
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        !rendered.contains("dropped by search ceilings"),
        "{rendered}"
    );
}

#[test]
fn signature_sibling_caps_are_supplemental_but_not_primary_search_truncation() {
    let mut report = sample_report();
    report.summary.funnel = vec![
        FunnelStage::new("signature sibling entries", 0)
            .dropping(FunnelCause::SignatureSiblingCandidateBudget, 2)
            .dropping(FunnelCause::SignatureSiblingPerGroupCap, 3)
            .dropping(FunnelCause::SignatureSiblingTotalCap, 4),
    ];
    assert!(!search_truncated(&report.summary.funnel));

    let mut rendered = Vec::new();
    report
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("supplemental: 9 sibling candidate(s) dropped by search ceilings"),
        "{rendered}"
    );
    assert!(!rendered.contains("search was truncated"), "{rendered}");
}

#[test]
fn a_near_miss_is_exported_but_text_hides_it_until_requested() {
    let mut report = sample_report();
    report.near_misses = vec![sample_near_miss()];

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["near_misses"][0]["estimated_jaccard"], 0.28);
    assert_eq!(value["near_misses"][0]["left"]["file"], "src/left.rs");
    assert!(value["near_misses"][0].get("finding_id").is_none());
    assert!(value["near_misses"][0].get("group_fingerprint").is_none());

    let mut default_text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut default_text)
        .unwrap();
    assert!(
        !String::from_utf8(default_text)
            .unwrap()
            .contains("near-match near misses:")
    );

    let mut shown_text = Vec::new();
    report
        .render_text(
            TextOptions {
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown_text,
        )
        .unwrap();
    let shown_text = String::from_utf8(shown_text).unwrap();
    assert!(shown_text.contains("near-match near misses:"));
    assert!(shown_text.contains("estimated Jaccard 0.28: src/left.rs:10"));
    assert!(shown_text.contains("src/right.rs:31"));
}

#[test]
fn supplemental_diagnostics_respect_show_suppressed_in_text() {
    let suppression = Suppression {
        kind: SuppressionKind::Rule,
        reason: Some("vendored sources".to_string()),
        scope: Some("path_glob".to_string()),
        pattern: Some("vendor/**".to_string()),
        active: Some(true),
    };
    let mut report = sample_report();
    let mut siblings = sample_siblings();
    siblings.siblings[0].suppressed = Some(suppression.clone());
    report.siblings = vec![siblings];
    let mut near_miss = sample_near_miss();
    near_miss.suppressed = Some(suppression);
    report.near_misses = vec![near_miss];

    let mut hidden = Vec::new();
    report
        .render_text(
            TextOptions {
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut hidden,
        )
        .unwrap();
    let hidden = String::from_utf8(hidden).unwrap();
    assert!(!hidden.contains("src/incomplete.rs"));
    assert!(!hidden.contains("near-match near misses:"));

    let mut shown = Vec::new();
    report
        .render_text(
            TextOptions {
                show_suppressed: true,
                show_siblings: true,
                show_near_misses: true,
                ..TextOptions::default()
            },
            &mut shown,
        )
        .unwrap();
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("src/incomplete.rs"));
    assert!(shown.contains("near-match near misses:"));
}

#[test]
fn the_near_miss_text_flag_is_rejected_for_machine_formats() {
    let error = crate::scan::write_report_options(
        crate::scan::ReportOutput {
            format: crate::cli::Format::Json,
            output: None,
            force: false,
            view: crate::cli::ViewArgs::default(),
            show_suppressed: false,
            show_siblings: false,
            show_near_misses: true,
            sort: Sort::Priority,
            min_identifier_jaccard: None,
        },
        &mut Vec::new(),
        &sample_report(),
    )
    .expect_err("machine formats retain near misses without a display flag");
    assert!(format!("{error:#}").contains("--show-near-misses applies only to text reports"));
}
