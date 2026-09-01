//! What the artifact commands settle about their output file before they
//! commit anything.
//!
//! Both commands analyse in a private worker process, so every row they write
//! is durable the moment that process exits. A destination that turns out to
//! be unwritable therefore has to be discovered while the run can still be
//! abandoned without a trace, rather than when the report is ready to be
//! written.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_artifact::wasm::WasmBackend;
use codehelion_artifact::{ArtifactBackend, ArtifactFingerprint};
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSnapshot,
};
use codehelion_store::{BuildVariantFingerprint, Store, fingerprint_hex};
use predicates::prelude::*;

/// The smallest byte sequence every backend recognises as a WASM module.
const WASM: &[u8] = b"\0asm\x01\0\0\0";

/// Enough of a tree for a scan to record a run the calibration can refer to.
const SOURCE: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc
}
";

/// A build description the operator writes; its contents are theirs to choose.
const BUILD_VARIANT: &str = "{\"profile\":\"release\",\"target\":\"wasm32\"}\n";

/// The clone group the seeded estimate is about.
const CLONE_GROUP: [u8; 16] = [3; 16];

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Count one table without writing to the database that holds it.
fn table_count(database: &Path, table: &str) -> i64 {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the audit database for reading");
    connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count rows")
}

/// The fingerprint an artifact command derives from a build-variant manifest.
fn build_variant_fingerprint(manifest: &str) -> BuildVariantFingerprint {
    let value: serde_json::Value = serde_json::from_str(manifest).expect("manifest is JSON");
    let normalized = serde_json::to_vec(&value).expect("manifest normalizes");
    BuildVariantFingerprint::from_bytes(
        ArtifactFingerprint::from_content("artifact-build-variant", &normalized).as_bytes(),
    )
}

/// An analysis whose identity is the one a comparison of `WASM` looks for,
/// carrying a saved estimate for one clone group of `source_run`.
fn seed_saved_estimate(database: &Path, source_run: i64) {
    let variant = build_variant_fingerprint(BUILD_VARIANT);
    let artifact = WasmBackend.parse(WASM).expect("parse the WASM fixture");
    let mut store = Store::open(database).expect("open the audit database");
    store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: &artifact.schema_version,
            path: "before.wasm",
            format: "wasm",
            content_fingerprint: artifact.fingerprint.as_bytes(),
            observed_bytes: artifact.observed_bytes,
            ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
            build_variant_manifest_path: Some("build-variant.json"),
            build_variant_fingerprint: Some(variant),
            started_at: "2026-08-01T00:00:00Z",
            finished_at: "2026-08-01T00:00:01Z",
            symbols: &[],
            source_maps: &[],
            containment: None,
            mappings: &[],
            unmapped_symbols: &[],
            unmapped_sources: &[],
            correlation: Some(ArtifactAnalysisCorrelation {
                schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
                source_scan_run_id: source_run,
                mapping_count: 0,
                artifact_symbol_count: 0,
                mapped_symbol_count: 0,
                artifact_symbol_bytes: 0,
                mapped_symbol_bytes: 0,
            }),
            clone_group_savings: &[ArtifactAnalysisCloneGroupSavings {
                schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_owned(),
                source_scan_run_id: source_run,
                clone_group_fingerprint: CLONE_GROUP,
                source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([5; 16]),
                artifact_build_variant_fingerprint: variant,
                duplicated_bytes: 24,
                estimated_refactor_savings_bytes: 9,
                mapping_confidence: ArtifactAnalysisSavingsConfidence::High,
                clone_confidence: 1.0,
                model_confidence: ArtifactAnalysisSavingsConfidence::Low,
                savings_confidence: ArtifactAnalysisSavingsConfidence::Low,
                model_schema_version: "refactor-savings-model-v1".to_owned(),
                assumptions_json: r#"[{"kind":"inlining_outcome_unknown"}]"#.to_owned(),
            }],
        })
        .expect("record a saved estimate for the clone group");
}

/// An analysis that will not be written where it was asked to go records
/// nothing at all.
#[test]
fn analyze_refuses_an_occupied_output_before_recording_an_analysis() {
    let directory = tempfile::tempdir().expect("working directory");
    let artifact = directory.path().join("app.wasm");
    let database = directory.path().join("audit.db");
    let report = directory.path().join("report.json");
    std::fs::write(&artifact, WASM).expect("write the WASM fixture");

    let arguments = [
        "artifact".to_owned(),
        "analyze".to_owned(),
        artifact.to_str().expect("UTF-8 artifact path").to_owned(),
        "--format".to_owned(),
        "json".to_owned(),
        "--db".to_owned(),
        database.to_str().expect("UTF-8 database path").to_owned(),
        "--output".to_owned(),
        report.to_str().expect("UTF-8 report path").to_owned(),
    ];

    // One analysis that does land, so what the refused one leaves behind is
    // measured against a database that already holds a row.
    cmd()
        .current_dir(directory.path())
        .args(&arguments)
        .assert()
        .success();
    assert_eq!(table_count(&database, "artifact_analysis"), 1);
    let recorded_report = std::fs::read(&report).expect("read the written report");
    let recorded_database = std::fs::read(&database).expect("read the audit database");

    cmd()
        .current_dir(directory.path())
        .args(&arguments)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));

    assert_eq!(
        std::fs::read(&database).expect("read the audit database"),
        recorded_database,
        "a refused analysis left the audit database changed"
    );
    assert_eq!(
        table_count(&database, "artifact_analysis"),
        1,
        "a refused analysis recorded an analysis nothing can report on"
    );
    assert_eq!(
        std::fs::read(&report).expect("read the written report"),
        recorded_report,
        "a refused analysis disturbed the file it declined to overwrite"
    );
}

/// A comparison that will not be written where it was asked to go records no
/// calibration, and the same request with `--force` still records one.
///
/// The second half is what makes the first half about the output file: it
/// establishes that this comparison had a measurement to record all along.
#[test]
fn compare_refuses_an_occupied_output_before_recording_a_calibration() {
    let directory = tempfile::tempdir().expect("working directory");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create the source directory");
    std::fs::write(root.join("src/lib.rs"), SOURCE).expect("write the source fixture");
    let before = root.join("before.wasm");
    let after = root.join("after.wasm");
    let variant = root.join("build-variant.json");
    let report = root.join("report.json");
    let database = root.join("audit.db");
    std::fs::write(&before, WASM).expect("write the earlier artifact");
    std::fs::write(&after, WASM).expect("write the later artifact");
    std::fs::write(&variant, BUILD_VARIANT).expect("write the build variant");
    std::fs::write(&report, b"held\n").expect("occupy the output path");

    cmd()
        .current_dir(root)
        .args(["scan", ".", "--db", "audit.db"])
        .assert()
        .success();
    let source_run = {
        let store = Store::open(&database).expect("open the audit database");
        store
            .latest_run()
            .expect("read the recorded run")
            .expect("a recorded run")
            .id
    };
    seed_saved_estimate(&database, source_run);

    let source_run = source_run.to_string();
    let group = fingerprint_hex(CLONE_GROUP);
    let arguments = [
        "artifact",
        "compare",
        "before.wasm",
        "after.wasm",
        "--format",
        "json",
        "--db",
        "audit.db",
        "--source-run",
        &source_run,
        "--clone-group",
        &group,
        "--before-build-variant",
        "build-variant.json",
        "--after-build-variant",
        "build-variant.json",
        "--output",
        "report.json",
    ];

    let recorded_database = std::fs::read(&database).expect("read the audit database");
    cmd()
        .current_dir(root)
        .args(arguments)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));

    assert_eq!(
        std::fs::read(&database).expect("read the audit database"),
        recorded_database,
        "a refused comparison left the audit database changed"
    );
    assert_eq!(
        table_count(&database, "artifact_analysis_savings_calibration"),
        0,
        "a refused comparison recorded a calibration nothing can report on"
    );
    assert_eq!(
        std::fs::read(&report).expect("read the occupied output"),
        b"held\n",
        "a refused comparison disturbed the file it declined to overwrite"
    );

    cmd()
        .current_dir(root)
        .args(arguments)
        .arg("--force")
        .assert()
        .success();
    assert_eq!(
        table_count(&database, "artifact_analysis_savings_calibration"),
        1,
        "the comparison that was refused had a calibration to record"
    );
}

/// A run that fails after its destination was claimed leaves no placeholder
/// for the retry to trip over.
#[test]
fn a_failed_run_leaves_no_placeholder_at_its_output() {
    let directory = tempfile::tempdir().expect("working directory");
    let artifact = directory.path().join("app.wasm");
    let database = directory.path().join("audit.db");
    let report = directory.path().join("report.json");
    std::fs::write(&artifact, b"not an artifact").expect("write an unreadable artifact");

    cmd()
        .current_dir(directory.path())
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("UTF-8 artifact path"),
            "--db",
            database.to_str().expect("UTF-8 database path"),
            "--output",
            report.to_str().expect("UTF-8 report path"),
        ])
        .assert()
        .failure();

    assert!(
        !report.exists(),
        "a failed run left an empty report that a retry would refuse to replace"
    );
}
