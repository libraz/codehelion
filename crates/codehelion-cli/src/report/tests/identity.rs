//! Stable-identity normalization and what an adopted group claims.

use super::*;

#[test]
fn identity_normalization_counts_a_duplicate_group_once_without_member_double_counting() {
    let normalized = normalize_identities(vec![visible_group(), visible_group()])
        .expect("exact duplicate groups are safe to collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_counts_duplicate_findings_within_one_group() {
    let mut group = visible_group();
    group.members.push(group.members[0].clone());
    let normalized = normalize_identities(vec![group])
        .expect("equal finding payloads inside one group are safe to collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.groups[0].members.len(), 7);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_rejects_a_finding_id_reused_by_another_group() {
    let mut second = visible_group();
    second.fingerprint = "0c".repeat(16);
    let error = normalize_identities(vec![visible_group(), second])
        .expect_err("one finding id cannot identify two groups");
    assert!(error.to_string().contains("stable finding identity"));
}

#[test]
fn identity_normalization_rejects_an_equal_group_id_with_an_unequal_payload() {
    let mut second = visible_group();
    second.members[0].file = "src/changed.rs".to_string();
    let error = normalize_identities(vec![visible_group(), second])
        .expect_err("an unequal payload cannot be selected by a stable id");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_does_not_collapse_distinct_non_finite_payloads() {
    let mut nan = visible_group();
    nan.confidence = f64::NAN;
    let mut infinity = visible_group();
    infinity.confidence = f64::INFINITY;
    let error = normalize_identities(vec![nan, infinity])
        .expect_err("NaN and infinity must remain unequal identity payloads");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_does_not_collapse_signed_zero_payloads() {
    let mut positive = visible_group();
    positive.entropy_bits = 0.0;
    let mut negative = visible_group();
    negative.entropy_bits = -0.0;
    let error = normalize_identities(vec![positive, negative])
        .expect_err("signed zero must remain unequal identity payloads");
    assert!(error.to_string().contains("stable clone-group identity"));
}

fn artifact_savings_with_assumptions(assumptions: serde_json::Value) -> ArtifactSavings {
    ArtifactSavings {
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
        assumptions,
    }
}

#[test]
fn identity_normalization_collapses_exact_nested_json_assumptions() {
    let assumptions = serde_json::json!({
        "nested": [null, true, "text", 7, { "inner": [1.5, false] }]
    });
    let mut first = visible_group();
    first
        .artifact_savings
        .push(artifact_savings_with_assumptions(assumptions.clone()));
    let mut second = visible_group();
    second
        .artifact_savings
        .push(artifact_savings_with_assumptions(assumptions));
    let normalized = normalize_identities(vec![first, second])
        .expect("exact nested JSON assumptions should collapse");
    assert_eq!(normalized.groups.len(), 1);
    assert_eq!(normalized.identity_collapsed, 1);
}

#[test]
fn identity_normalization_rejects_signed_zero_in_nested_json_assumptions() {
    let positive = serde_json::Value::Number(
        serde_json::Number::from_f64(0.0).expect("finite zero is a JSON number"),
    );
    let negative = serde_json::Value::Number(
        serde_json::Number::from_f64(-0.0).expect("finite zero is a JSON number"),
    );
    let mut first = visible_group();
    first
        .artifact_savings
        .push(artifact_savings_with_assumptions(serde_json::json!({
            "nested": [positive]
        })));
    let mut second = visible_group();
    second
        .artifact_savings
        .push(artifact_savings_with_assumptions(serde_json::json!({
            "nested": [negative]
        })));
    let error = normalize_identities(vec![first, second])
        .expect_err("signed zero in nested JSON must remain unequal");
    assert!(error.to_string().contains("stable clone-group identity"));
}

#[test]
fn identity_normalization_stage_round_trips_through_stored_summary() {
    let mut funnel = Vec::new();
    append_stored_identity_stage(&mut funnel, 3, 2);
    assert_eq!(stored_identity_collapsed(&funnel), 2);

    let stored = SummaryRow {
        funnel,
        ..SummaryRow::default()
    };
    let restored = restored(&stored, &[], "fast");
    assert_eq!(restored.identity_collapsed, 2);
}

/// Render one report at detailed verbosity and hand back its text.
fn detailed_text(report: &Report) -> String {
    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    String::from_utf8(rendered).unwrap()
}

#[test]
fn an_adopted_group_states_its_shared_count_out_of_the_population_it_was_counted_in() {
    // Every member carries one content, which is the population the adoption
    // rule compared: a group of identical copies shares all of it.
    let mut report = sample_report();
    report.groups[0].identity = Some(GroupIdentity {
        origin: IDENTITY_ADOPTED.to_string(),
        compared_with_run: 1,
        adopted_from: Some("ab".repeat(16)),
        shared_members: Some(1),
        compared_members: Some(1),
    });

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let identity = &value["groups"][0]["identity"];
    assert_eq!(identity["shared_members"], 1, "{identity}");
    assert_eq!(identity["compared_members"], 1, "{identity}");

    let text = detailed_text(&report);
    assert!(
        text.contains("1 of 1 member content(s) shared"),
        "the shared count was stated out of a population it was not counted in: {text}"
    );
    // The group's member count is a different population; dividing by it
    // would read as weak evidence for a connection decided on all of it.
    assert!(
        !text.contains(&format!("of {} members", report.groups[0].members.len())),
        "{text}"
    );
}

#[test]
fn an_adopted_group_without_a_measured_population_states_the_shared_count_alone() {
    let mut report = sample_report();
    report.groups[0].identity = Some(GroupIdentity {
        origin: IDENTITY_ADOPTED.to_string(),
        compared_with_run: 1,
        adopted_from: Some("ab".repeat(16)),
        shared_members: Some(2),
        compared_members: None,
    });

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let identity = &value["groups"][0]["identity"];
    assert!(identity.get("compared_members").is_none(), "{identity}");

    let text = detailed_text(&report);
    assert!(text.contains("2 member content(s) shared"), "{text}");
    assert!(!text.contains("2 of "), "{text}");
}
