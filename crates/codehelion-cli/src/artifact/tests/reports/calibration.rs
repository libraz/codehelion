//! Calibration summaries, baseline comparison, and calibration selectors.

use super::*;
use crate::artifact::calibration_report::CalibrationStratumReport;
use crate::artifact::calibration_report::CalibrationSummaryReport;
use crate::cli::{DEFAULT_ARTIFACT_MAX_BYTES, DEFAULT_ARTIFACT_TIMEOUT_SECONDS};
use codehelion_store::artifact::ArtifactSavingsCalibrationStatistics;
use std::fs;

#[test]
fn calibration_summary_keeps_absolute_and_relative_statistics_separate() {
    let report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: 7,
        statistics: ArtifactSavingsCalibrationStatistics {
            samples: 4,
            median_absolute_error_bytes: Some(5.5),
            p90_absolute_error_bytes: Some(10),
            relative_error_samples: 3,
            median_relative_error: Some(0.8),
            p90_relative_error: Some(1.0),
        },
        strata: vec![CalibrationStratumReport {
            dimension: "artifact_format",
            key: "elf".to_owned(),
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 2,
                median_absolute_error_bytes: Some(4.0),
                p90_absolute_error_bytes: Some(7),
                relative_error_samples: 2,
                median_relative_error: Some(0.5),
                p90_relative_error: Some(0.7),
            },
        }],
        comparison: None,
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["statistics"]["samples"], 4);
    assert_eq!(json["statistics"]["relative_error_samples"], 3);
    assert_eq!(json["strata"][0]["dimension"], "artifact_format");
    let mut text = Vec::new();
    render_calibration_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("absolute error: median 5.5000 bytes"));
    assert!(text.contains("artifact_format elf"));
    let mut csv = Vec::new();
    render_calibration_csv(&report, &mut csv).unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("7,overall,,,,4,5.5000,10,3,0.8000,1.0000")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the two reports and every comparison outcome remain visible together"
)]
fn calibration_comparison_reports_deltas_without_a_threshold_gate() {
    let mut report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: 7,
        statistics: ArtifactSavingsCalibrationStatistics {
            samples: 4,
            median_absolute_error_bytes: Some(5.5),
            p90_absolute_error_bytes: Some(10),
            relative_error_samples: 3,
            median_relative_error: Some(0.8),
            p90_relative_error: Some(1.0),
        },
        strata: vec![CalibrationStratumReport {
            dimension: "artifact_format",
            key: "elf".to_owned(),
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 4,
                median_absolute_error_bytes: Some(5.5),
                p90_absolute_error_bytes: Some(10),
                relative_error_samples: 3,
                median_relative_error: Some(0.8),
                p90_relative_error: Some(1.0),
            },
        }],
        comparison: None,
    };
    let baseline = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        baseline.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
            "source_run": 6,
            "statistics": {
                "samples": 2,
                "median_absolute_error_bytes": 3.0,
                "p90_absolute_error_bytes": 7,
                "relative_error_samples": 2,
                "median_relative_error": 0.5,
                "p90_relative_error": 0.7
            },
            "strata": [
                {
                    "dimension": "artifact_format",
                    "key": "elf",
                    "statistics": {
                        "samples": 2,
                        "median_absolute_error_bytes": 3.0,
                        "p90_absolute_error_bytes": 7,
                        "relative_error_samples": 2,
                        "median_relative_error": 0.5,
                        "p90_relative_error": 0.7
                    }
                },
                {
                    "dimension": "clone_type",
                    "key": "type-2",
                    "statistics": {
                        "samples": 1,
                        "median_absolute_error_bytes": 2.0,
                        "p90_absolute_error_bytes": 2,
                        "relative_error_samples": 1,
                        "median_relative_error": 0.4,
                        "p90_relative_error": 0.4
                    }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let comparison = calibration_comparison(&report, baseline.path()).unwrap();
    assert_eq!(
        comparison.baseline_schema_version,
        ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION
    );
    assert_eq!(comparison.baseline_source_run, 6);
    assert_eq!(comparison.overall.samples, 2);
    assert_eq!(comparison.overall.median_absolute_error_bytes, Some(2.5));
    assert_eq!(comparison.strata.len(), 2);
    assert!(comparison.strata.iter().any(|stratum| {
        stratum.dimension == "clone_type"
            && stratum.key == "type-2"
            && stratum.current.is_none()
            && stratum.delta.is_none()
    }));
    report.comparison = Some(comparison);

    let value = serde_json::to_value(&report).unwrap();
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-calibration-report-v1.schema.json",
        ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA,
        &value,
    );
    assert_eq!(value["comparison"]["overall"]["samples"], 2);
    let mut text = Vec::new();
    render_calibration_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("baseline comparison (informational; no threshold)"));
    assert!(text.contains("overall: samples +2"));
    assert!(text.contains("only one report contains this stratum"));
    let mut csv = Vec::new();
    render_calibration_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut rows = csv.lines();
    let width = rows.next().unwrap().split(',').count();
    assert!(rows.all(|row| row.split(',').count() == width));
    assert!(csv.contains("7,comparison-overall,,,6,,,,,,,2,2.5000,3,1,0.3000,0.3000"));
}

/// A comparison request carrying only the calibration selectors under test.
fn calibration_request(
    source_run: Option<i64>,
    clone_group: Option<&str>,
    db: Option<&std::path::Path>,
) -> ArtifactCompareArgs {
    ArtifactCompareArgs {
        before: std::path::PathBuf::from("before.wasm"),
        after: std::path::PathBuf::from("after.wasm"),
        input_format: None,
        arch: None,
        before_build_variant: None,
        after_build_variant: None,
        format: ArtifactFormat::Text,
        output: None,
        force: false,
        max_bytes: DEFAULT_ARTIFACT_MAX_BYTES,
        timeout_seconds: DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        max_memory_bytes: None,
        untrusted: false,
        source_run,
        clone_group: clone_group.map(ToOwned::to_owned),
        db: db.map(ToOwned::to_owned),
    }
}

#[test]
fn a_database_without_a_calibration_request_is_refused_by_naming_the_database() {
    let error = calibration_database(&calibration_request(
        None,
        None,
        Some(std::path::Path::new("audit.db")),
    ))
    .expect_err("a database alone selects no calibration");
    assert_eq!(
        error.to_string(),
        "--db was given without --source-run and --clone-group; artifact compare uses --db only to record a calibration"
    );
}

#[test]
fn a_source_run_without_a_clone_group_is_refused_by_naming_the_missing_group() {
    let error = calibration_database(&calibration_request(Some(7), None, None))
        .expect_err("a source run alone selects no clone group");
    assert_eq!(
        error.to_string(),
        "--source-run was given without --clone-group; artifact compare records a calibration for one clone group of that run"
    );
}

#[test]
fn a_clone_group_without_a_source_run_is_refused_by_naming_the_missing_run() {
    let error = calibration_database(&calibration_request(None, Some("deadbeef"), None))
        .expect_err("a clone group alone selects no source run");
    assert_eq!(
        error.to_string(),
        "--clone-group was given without --source-run; artifact compare records a calibration for that group in one scan run"
    );
}

#[test]
fn a_calibration_request_without_a_database_flag_resolves_the_configured_default() {
    let resolved = calibration_database(&calibration_request(Some(7), Some("deadbeef"), None))
        .expect("the default database resolves")
        .expect("a calibration request selects a database");
    assert_eq!(
        resolved,
        crate::resolve_db(crate::scan::DatabaseUse::Recording, None)
            .expect("the configured default database")
    );
}

#[test]
fn an_explicit_calibration_database_is_used_as_given() {
    let requested = std::path::Path::new("audit.db");
    let resolved = calibration_database(&calibration_request(
        Some(7),
        Some("deadbeef"),
        Some(requested),
    ))
    .expect("an explicit database resolves")
    .expect("a calibration request selects a database");
    assert_eq!(resolved, requested);
}

#[test]
fn a_comparison_without_calibration_selectors_opens_no_database() {
    assert!(
        calibration_database(&calibration_request(None, None, None))
            .expect("a plain comparison resolves no database")
            .is_none()
    );
}
