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
    let width = artifact_csv_fields(rows.next().unwrap()).len();
    assert!(rows.all(|row| artifact_csv_fields(row).len() == width));
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
        compressed: Vec::new(),
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
        crate::resolve_database(
            crate::scan::DatabaseUse::Recording,
            std::path::Path::new("."),
            None,
            None,
            false
        )
        .expect("the configured default database")
        .2
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

/// The build-condition evidence both sides of a calibration share.
fn shared_variant() -> BuildVariantEvidence {
    BuildVariantEvidence {
        manifest_path: "build-variant.json".to_owned(),
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("variant", b"one"),
    }
}

/// A Mach-O IR built for `architecture`, skipping `skipped` from its container.
fn macho_slice(bytes: &[u8], architecture: &str, skipped: &[&str]) -> ArtifactIr {
    let mut artifact = ArtifactIr::empty(BinaryFormat::MachO, bytes);
    artifact.architecture = Some(architecture.to_owned());
    artifact.skipped_architectures = skipped.iter().map(|&label| label.to_owned()).collect();
    artifact
}

/// Attempt a calibration between `before` and `after` against a database that
/// does not exist, so any refusal has to come before the store is opened.
fn refused_calibration(before: &ArtifactIr, after: &ArtifactIr) -> String {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    let variant = shared_variant();
    let error = record_comparison_calibration(
        &calibration_request(Some(1), Some(&"ab".repeat(16)), Some(&database)),
        Some(&"ab".repeat(16)),
        before,
        after,
        Some(&variant),
        Some(&variant),
        Some(&database),
    )
    .expect_err("the calibration must be refused");
    assert!(!database.exists(), "the refusal opened the store");
    error.to_string()
}

#[test]
fn calibration_refuses_artifacts_built_for_different_architectures() {
    let error = refused_calibration(
        &macho_slice(b"before", "arm64", &[]),
        &macho_slice(b"after", "x86_64", &[]),
    );
    assert!(
        error
            .contains("same format and architecture: before is macho arm64, after is macho x86_64"),
        "{error}"
    );
}

#[test]
fn calibration_refuses_a_slice_of_a_universal_container() {
    let error = refused_calibration(
        &macho_slice(b"before", "x86_64", &["arm64"]),
        &macho_slice(b"after", "x86_64", &["arm64"]),
    );
    assert!(
        error.contains("calibration requires whole artifacts"),
        "{error}"
    );
    let error = refused_calibration(
        &macho_slice(b"before", "x86_64", &["arm64"]),
        &macho_slice(b"after", "x86_64", &[]),
    );
    assert!(error.contains("same format and architecture"), "{error}");
}

#[test]
fn a_clone_group_id_that_is_not_a_prefix_is_refused_by_naming_the_accepted_form() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    for typed in ["abc", "not-hex!", &"a".repeat(33)] {
        let error = calibration_clone_group(
            &calibration_request(Some(1), Some(typed), Some(&database)),
            Some(&database),
        )
        .expect_err("a malformed id is refused");
        assert!(error.to_string().contains("at least 8"), "{typed}: {error}");
    }
    assert!(!database.exists(), "a malformed id opened the store");
    let full = "AB".repeat(16);
    assert_eq!(
        calibration_clone_group(
            &calibration_request(Some(1), Some(&full), Some(&database)),
            Some(&database),
        )
        .unwrap(),
        Some("ab".repeat(16))
    );
}

#[test]
fn a_clone_group_prefix_resolves_to_the_one_recorded_group_it_names() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("tree");
    fs::create_dir(&root).unwrap();
    let body = "    let mut total = 0;\n    for value in values {\n        if *value > limit {\n            total += value * 2;\n        } else {\n            total -= value;\n        }\n    }\n    total\n}\n";
    fs::write(
        root.join("lib.rs"),
        format!(
            "pub fn first(values: &[i64], limit: i64) -> i64 {{\n{body}\npub fn second(values: &[i64], limit: i64) -> i64 {{\n{body}"
        ),
    )
    .unwrap();
    let database = directory.path().join("audit.db");
    let parsed = <crate::cli::Cli as clap::Parser>::try_parse_from([
        "codehelion",
        "scan",
        root.to_str().unwrap(),
        "--db",
        database.to_str().unwrap(),
        "--format",
        "json",
    ])
    .unwrap();
    let crate::cli::Command::Scan(scan) = parsed.command else {
        unreachable!("a scan command line parses as a scan");
    };
    crate::scan::run(&scan, &mut Vec::new()).unwrap();
    let store = codehelion_store::Store::open_existing(&database).unwrap();
    let groups: Vec<String> = store
        .ids_starting_with("")
        .unwrap()
        .into_iter()
        .filter(|found| found.kind == codehelion_store::query::IdKind::CloneGroup)
        .map(|found| found.id)
        .collect();
    drop(store);
    assert_eq!(
        groups.len(),
        1,
        "the fixture records one clone group: {groups:?}"
    );
    let group = &groups[0];
    let resolved = calibration_clone_group(
        &calibration_request(Some(1), Some(&group[..8]), Some(&database)),
        Some(&database),
    )
    .unwrap();
    assert_eq!(resolved.as_deref(), Some(group.as_str()));
    let error = calibration_clone_group(
        &calibration_request(Some(1), Some(&"f".repeat(9)), Some(&database)),
        Some(&database),
    )
    .expect_err("an unrecorded prefix names no group");
    assert!(
        error.to_string().contains("no clone group with id"),
        "{error}"
    );
}
