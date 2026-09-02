//! Tests for the `artifact` subcommands: analysis, calibration, comparison
//! and saved-report replay.

use super::*;

#[test]
fn artifact_calibration_rejects_a_source_run_that_does_not_exist() {
    let directory = tempfile::tempdir().expect("database directory");
    let database = directory.path().join("audit.db");
    codehelion_store::Store::open(&database).expect("create empty database");
    cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "999",
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "scan run 999 was not found in this database",
        ));
}

#[test]
fn artifact_read_commands_do_not_create_an_absent_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("missing.db");
    let database_arg = database.to_str().expect("database path");

    cmd()
        .args([
            "artifact",
            "report",
            "--analysis",
            "1",
            "--db",
            database_arg,
        ])
        .assert()
        .failure();
    assert!(
        !database.exists(),
        "artifact report created its input database"
    );

    cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "1",
            "--db",
            database_arg,
        ])
        .assert()
        .failure();
    assert!(
        !database.exists(),
        "artifact calibration created its input database"
    );
}

#[test]
fn artifact_worker_failure_has_one_user_facing_error_prefix() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let file = directory.path().join("not-an-artifact");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(&file, b"not an artifact").expect("write invalid artifact");
    // A database of its own: a run that names none takes the lease on the
    // one belonging to whatever directory the test happened to start in,
    // which two tests running at once cannot both hold.
    cmd()
        .args([
            "artifact",
            "analyze",
            file.to_str().expect("artifact path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "artifact worker failed: could not recognise input as a supported artifact format",
        ))
        .stderr(predicate::str::contains("error: error:").not());
}

#[test]
fn debug_companion_is_accepted_without_a_source_run() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let artifact = directory.path().join("module.wasm");
    let debug_file = directory.path().join("module.debug");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");
    std::fs::write(&debug_file, b"").expect("write debug companion");
    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--debug-file",
            debug_file.to_str().expect("debug companion path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--debug-file is only supported for ELF, Mach-O, and PE artifacts",
        ))
        .stderr(predicate::str::contains("--source-run").not());
}

#[test]
fn stale_automatically_discovered_dsym_is_reported_without_failing_analysis() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let artifact = directory.path().join("app");
    let dsym = directory
        .path()
        .join("app.dSYM/Contents/Resources/DWARF/app");
    let database = directory.path().join("artifact.sqlite");
    std::fs::create_dir_all(dsym.parent().expect("dSYM parent")).expect("create dSYM parent");
    let bytes = macho_fixture();
    std::fs::write(&artifact, &bytes).expect("write Mach-O artifact");
    std::fs::write(&dsym, &bytes).expect("write stale dSYM");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("source mappings: 0"))
        .stderr(predicate::str::contains(
            "warning: automatically discovered dSYM",
        ))
        .stderr(predicate::str::contains(
            "does not have the artifact's Mach-O UUID",
        ));
}

/// The manifest the artifact document writes is a manifest the tool accepts.
#[test]
fn the_build_variant_manifest_the_document_writes_is_accepted() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let manifest = directory.path().join("build-variant.json");
    let artifact = directory.path().join("app.wasm");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(
        &manifest,
        r#"{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}"#,
    )
    .expect("write the manifest the artifact document writes");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--build-variant",
            manifest.to_str().expect("manifest path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success()
        // The manifest path and its digest are told apart on the line that
        // prints both.
        .stdout(predicate::str::contains("build variant: "))
        .stdout(predicate::str::contains("(digest "));
}

#[test]
fn artifact_reports_a_minimal_wasm_without_executing_it() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""))
        .stdout(predicate::str::contains("\"analysis_id\": 1"));
    assert!(db.is_file());
}

#[test]
fn the_artifact_schema_declares_each_field_where_the_report_writes_it() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    let output = cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .output()
        .expect("run artifact analyze");
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("artifact report is JSON");
    let schema: serde_json::Value =
        serde_json::from_str(codehelion::artifact::ARTIFACT_REPORT_JSON_SCHEMA)
            .expect("shipped artifact schema is JSON");

    let declared = &schema["properties"];

    // Attributing a symbol to the definition it was instantiated from needs a
    // correlated source run, so the report writes those origins inside the
    // correlation. A top-level declaration would describe a document no run
    // produces.
    assert!(
        !report
            .as_object()
            .expect("report is an object")
            .contains_key("generic_origins"),
        "{report}"
    );
    assert!(declared.get("generic_origins").is_none(), "{declared}");
    assert!(
        schema["$defs"]["correlation"]["properties"]["generic_origins"].is_object(),
        "{schema}"
    );
}

#[test]
fn artifact_analysis_refuses_a_database_held_by_another_writer() {
    let artifact = tempfile::NamedTempFile::new().expect("artifact fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    let database = database_directory.path().join("artifact.db");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(database_directory.path().join("artifact.db.lock"))
        .expect("open database lease");
    FileExt::try_lock_exclusive(&lock).expect("test holds database lease");
    std::fs::write(artifact.path(), b"\0asm\x01\0\0\0").expect("write WASM fixture");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.path().to_str().expect("UTF-8 artifact path"),
            "--db",
            database.to_str().expect("UTF-8 database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another codehelion scan or cache clear",
        ));
}

#[test]
fn artifact_calibration_write_refuses_a_database_held_by_another_writer() {
    let before = tempfile::NamedTempFile::new().expect("before artifact fixture");
    let after = tempfile::NamedTempFile::new().expect("after artifact fixture");
    let variant = tempfile::NamedTempFile::new().expect("build variant fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    let database = database_directory.path().join("artifact.db");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(database_directory.path().join("artifact.db.lock"))
        .expect("open database lease");
    FileExt::try_lock_exclusive(&lock).expect("test holds database lease");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before WASM fixture");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after WASM fixture");
    std::fs::write(variant.path(), "{}\n").expect("write build variant");

    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("UTF-8 before path"),
            after.path().to_str().expect("UTF-8 after path"),
            "--source-run",
            "1",
            "--clone-group",
            "deadbeef",
            "--db",
            database.to_str().expect("UTF-8 database path"),
            "--before-build-variant",
            variant.path().to_str().expect("UTF-8 variant path"),
            "--after-build-variant",
            variant.path().to_str().expect("UTF-8 variant path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another codehelion scan or cache clear",
        ));
}

#[test]
fn artifact_report_rerenders_a_saved_analysis_after_its_input_is_removed() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();
    std::fs::remove_file(file.path()).expect("remove analyzed artifact");
    cmd()
        .args([
            "artifact",
            "report",
            "--analysis",
            "1",
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"))
        .stdout(predicate::str::contains("\"analysis_id\": 1"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""));
}

/// Analysing against a scan records a correlation, and the documented
/// workflow is to analyse once and re-render later. A re-render therefore has
/// to show the correlation the analysis recorded, in every format: a script
/// reading a saved analysis must not receive a structurally poorer document
/// than the analysis it names printed.
#[test]
fn artifact_report_renders_the_correlation_its_analysis_recorded() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    std::fs::write(
        root.join("ledger.rs"),
        "pub fn total(values: &[u32]) -> u32 {\n    values.iter().copied().sum()\n}\n",
    )
    .expect("write source fixture");
    let artifact = root.join("ledger.wasm");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");
    let variant = root.join("artifact-build-variant.json");
    std::fs::write(&variant, "{\"target\":\"fixture\"}\n").expect("write build variant");
    let db = root.join("audit.db");
    let db_path = db.to_str().expect("utf-8 database path");

    let scanned = cmd()
        .args([
            "scan",
            root.to_str().expect("utf-8 fixture root"),
            "--format",
            "json",
            "--db",
            db_path,
        ])
        .output()
        .expect("scan the fixture tree");
    assert!(
        scanned.status.success(),
        "{}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    let source: serde_json::Value =
        serde_json::from_slice(&scanned.stdout).expect("scan report is JSON");
    let source_run = source["run"]["run_id"]
        .as_i64()
        .expect("the scan recorded a run")
        .to_string();

    let analyzed = cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("utf-8 artifact path"),
            "--format",
            "json",
            "--build-variant",
            variant.to_str().expect("utf-8 build variant path"),
            "--source-run",
            &source_run,
            "--db",
            db_path,
        ])
        .output()
        .expect("analyse the artifact against the scan");
    assert!(
        analyzed.status.success(),
        "{}",
        String::from_utf8_lossy(&analyzed.stderr)
    );
    let analysis: serde_json::Value =
        serde_json::from_slice(&analyzed.stdout).expect("analysis report is JSON");
    assert!(
        !analysis["correlation"].is_null(),
        "the analysis recorded no correlation to re-render: {analysis}"
    );

    let rendered = cmd()
        .args(["artifact", "report", "--format", "json", "--db", db_path])
        .output()
        .expect("re-render the saved analysis");
    assert!(
        rendered.status.success(),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&rendered.stdout).expect("saved report is JSON");
    assert_eq!(
        saved["correlation"], analysis["correlation"],
        "the re-rendered correlation differs from the recorded one: {saved}"
    );
    assert_eq!(
        saved["correlation"]["source_run"]
            .as_i64()
            .map(|run| run.to_string()),
        Some(source_run.clone()),
        "the re-render names another scan than the analysis did: {saved}"
    );

    let csv = cmd()
        .args(["artifact", "report", "--format", "csv", "--db", db_path])
        .output()
        .expect("re-render the saved analysis as CSV");
    assert!(
        csv.status.success(),
        "{}",
        String::from_utf8_lossy(&csv.stderr)
    );
    assert!(
        String::from_utf8_lossy(&csv.stdout).contains(source_run.as_str()),
        "the CSV re-render names the correlated scan: {}",
        String::from_utf8_lossy(&csv.stdout)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn artifact_accepts_an_enforced_linux_memory_ceiling() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
            "--max-memory-bytes",
            "268435456",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn artifact_refuses_an_unenforceable_memory_ceiling() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--max-memory-bytes",
            "268435456",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot enforce the requested artifact worker memory limit",
        ));
}

#[test]
fn artifact_compare_reports_the_measured_byte_delta() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");
    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "observed size: +0 bytes (no change)",
        ))
        .stdout(predicate::str::contains(
            "duplicated code: +0 bytes (no change)",
        ));
}

#[test]
fn artifact_compare_refuses_a_database_that_selects_no_calibration() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");
    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
            "--db",
            database_directory
                .path()
                .join("audit.db")
                .to_str()
                .expect("utf-8 database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--db was given without --source-run and --clone-group; artifact compare uses --db only to record a calibration",
        ));
}

#[test]
fn artifact_compare_calibrates_against_the_configured_database_without_a_database_flag() {
    let repository = tempfile::tempdir().expect("repository directory");
    let before = repository.path().join("before.wasm");
    let after = repository.path().join("after.wasm");
    let variant = repository.path().join("build-variant.json");
    std::fs::write(&before, b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(&after, b"\0asm\x01\0\0\0").expect("write after wasm");
    std::fs::write(&variant, b"{}\n").expect("write build variant");
    let configured = repository.path().join(".codehelion").join("audit.db");
    cmd()
        .current_dir(repository.path())
        .args([
            "artifact",
            "analyze",
            before.to_str().expect("utf-8 before path"),
            "--db",
            configured.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();

    cmd()
        .current_dir(repository.path())
        .args([
            "artifact",
            "compare",
            before.to_str().expect("utf-8 before path"),
            after.to_str().expect("utf-8 after path"),
            "--source-run",
            "1",
            "--clone-group",
            &"ab".repeat(16),
            "--before-build-variant",
            variant.to_str().expect("utf-8 variant path"),
            "--after-build-variant",
            variant.to_str().expect("utf-8 variant path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "calibration found no saved estimate",
        ));
}
