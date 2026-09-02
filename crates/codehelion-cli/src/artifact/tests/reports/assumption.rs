//! Statements that qualify a reported number, in every rendering of it.

use super::*;

/// An absent retained size states the condition that actually held, because a
/// fixed sentence is a guess about which of six conditions fired.
#[test]
fn a_withdrawn_retained_size_names_the_condition_that_held() {
    let ambiguous = {
        let mut artifact = resolved_call_graph_artifact();
        artifact.symbols[1].fingerprint = artifact.symbols[0].fingerprint;
        artifact
    };
    let unfollowed = {
        let mut artifact = resolved_call_graph_artifact();
        artifact.calls.push(codehelion_artifact::ArtifactCall {
            caller: artifact.symbols[0].fingerprint,
            target: None,
            unresolved: Some(codehelion_artifact::UnresolvedCall::NativeIndirect),
        });
        artifact
    };
    let no_call_edges = {
        let mut artifact = resolved_call_graph_artifact();
        artifact.capabilities.call_graph = false;
        artifact
    };
    for (artifact, expected) in [
        (ambiguous, "one symbol per content fingerprint"),
        (
            unfollowed,
            "every dispatch that may reach a local symbol to be resolved",
        ),
        (no_call_edges, "a backend that establishes call edges"),
    ] {
        let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
        assert!(report.retained_sizes.is_none());
        let reasons = retained_size_unavailability(&report);
        assert!(!reasons.is_empty(), "{:?}", report.sizes.assumptions);

        let text = rendered_text(&report, false);
        assert!(text.contains(expected), "{text}");
        assert!(
            !text.contains("incomplete or ambiguous call graph"),
            "{text}"
        );
        // The reason belongs to the line that reports the absent value, and
        // stating it again among the size assumptions would say it twice.
        assert_eq!(
            text.lines().filter(|line| line.contains(expected)).count(),
            1,
            "{text}"
        );
        // JSON and CSV carry the same reason.
        let json = serde_json::to_value(&report).unwrap();
        let stated: Vec<String> = json["sizes"]["assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        assert!(
            stated.iter().any(|value| value.contains(expected)),
            "{stated:?}"
        );
        let csv = artifact_csv_assumptions(&report);
        assert!(csv.iter().any(|value| value.contains(expected)), "{csv:?}");
    }
}

/// Every statement that qualifies a number reaches every rendering of it, so a
/// dashboard reading one format never sees a number the caveat did not reach.
#[test]
fn text_json_and_csv_state_the_same_assumptions() {
    let mut artifact = resolved_call_graph_artifact();
    artifact.skipped_architectures = vec!["wasm64".to_owned()];
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);

    let stated = report_assumptions(&report);
    assert!(!stated.is_empty());
    let text = rendered_text(&report, false);
    let json = serde_json::to_value(&report).unwrap();
    let csv = artifact_csv_assumptions(&report);
    for assumption in &stated {
        assert!(
            text.contains(assumption.text),
            "{} missing from text",
            assumption.text
        );
        assert!(
            csv.iter().any(|value| value == assumption.text),
            "{} missing from CSV",
            assumption.text
        );
        let block = match assumption.scope {
            AssumptionScope::DeadCode => &json["dead_code"]["assumptions"],
            _ => &json["sizes"]["assumptions"],
        };
        assert!(
            block
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some(assumption.text)),
            "{} missing from JSON",
            assumption.text
        );
    }
    assert_eq!(csv.len(), stated.len());
}

/// The bound over duplicate code says so wherever it appears: the report
/// prints a duplicate-data total two lines above it.
#[test]
fn the_savings_upper_bound_states_that_it_counts_code_only() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);

    assert!(report.sizes.upper_bound_savings_bytes.is_some());
    let text = rendered_text(&report, false);
    assert!(
        text.contains(
            "upper_bound_savings_bytes: 0 (duplicate code only; upper bound, not guaranteed)"
        ),
        "{text}"
    );
    for stated in [
        report.sizes.assumptions.clone(),
        artifact_csv_assumptions(&report),
    ] {
        assert!(
            stated
                .iter()
                .any(|value| value.contains("counts duplicate code only")),
            "{stated:?}"
        );
    }
    // The neighbouring data total stays a separate category.
    assert!(report.sizes.duplicated_data_bytes.is_some());
}

/// A selected architecture slice does not shrink the container the observed
/// bytes were read from, and every rendering says so.
#[test]
fn a_selected_architecture_slice_states_which_numbers_cover_the_container() {
    let mut artifact = resolved_call_graph_artifact();
    artifact.architecture = Some("arm64".to_owned());
    artifact.skipped_architectures = vec!["x86_64".to_owned()];
    let report = ArtifactReport::from_ir(FilePath::new("fixture.dylib"), &artifact, None, None);

    let expected = "observed byte counts cover the whole container";
    assert!(
        report
            .sizes
            .assumptions
            .iter()
            .any(|value| value.contains(expected)),
        "{:?}",
        report.sizes.assumptions
    );
    assert!(rendered_text(&report, false).contains(expected));
    let csv = artifact_csv_assumptions(&report);
    assert!(csv.iter().any(|value| value.contains(expected)), "{csv:?}");

    let comparison = ArtifactComparisonReport::new(
        FilePath::new("before.dylib"),
        &artifact,
        None,
        FilePath::new("after.dylib"),
        &artifact,
        None,
    );
    assert!(
        comparison
            .assumptions
            .iter()
            .any(|value| value.contains(expected)),
        "{:?}",
        comparison.assumptions
    );
    assert!(rendered_compare_text(&comparison).contains(expected));
    let csv = compare_csv_assumptions(&comparison);
    assert!(csv.iter().any(|value| value.contains(expected)), "{csv:?}");
}

/// A verified saving is the measurement invariant 8 keeps furthest from a
/// promise, so the surface that first computes it states what it assumed.
#[test]
fn a_comparison_states_what_a_verified_saving_assumes() {
    let artifact = resolved_call_graph_artifact();
    let mut report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &artifact,
        None,
        FilePath::new("after.wasm"),
        &artifact,
        None,
    );
    report.calibration = Some(CalibrationReport {
        source_run: 7,
        clone_group_fingerprint: fingerprint_hex([7; 16]),
        estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(4),
        verified_savings_bytes: VerifiedSavingsBytes(6),
        absolute_error_bytes: 2,
        relative_error: Some(0.5),
        artifact_analysis_id: 11,
        matching_analyses: 1,
        already_recorded: false,
    });

    let expected = "verified_savings_bytes attributes the whole observed artifact difference";
    assert!(
        report
            .assumptions
            .iter()
            .any(|value| value.starts_with(expected)),
        "{:?}",
        report.assumptions
    );
    let text = rendered_compare_text(&report);
    assert!(text.contains(expected), "{text}");
    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json["assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str().is_some_and(|value| value.contains(expected)))
    );
    let csv = compare_csv_assumptions(&report);
    assert!(csv.iter().any(|value| value.contains(expected)), "{csv:?}");
}

/// One condition is one statement. A caveat with a reported field of its own
/// read as two independent problems when the assumptions repeated it.
#[test]
fn a_build_variant_warning_is_stated_once_per_comparison() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &artifact,
        None,
        FilePath::new("after.wasm"),
        &artifact,
        None,
    );
    let warning = report
        .build_variant_warning
        .clone()
        .expect("a comparison without build variants warns");

    let text = rendered_compare_text(&report);
    assert_eq!(
        text.lines().filter(|line| line.contains(&warning)).count(),
        1,
        "{text}"
    );
    assert!(!report.assumptions.contains(&warning));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["build_variant_warning"], warning);
    assert!(
        !json["assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(warning.as_str()))
    );
    let csv = compare_csv_records(&report);
    assert_eq!(
        csv.iter()
            .filter(|record| record[compare_column::WARNING] == warning
                || record[compare_column::ASSUMPTION] == warning)
            .count(),
        1,
        "{csv:?}"
    );
}
