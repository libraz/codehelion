//! Tests for the `scan` subcommand's own error paths.

use super::*;

#[test]
fn corrupted_database_error_is_not_repeated_in_the_cli_context_chain() {
    let database = tempfile::NamedTempFile::new().expect("database path");
    std::fs::write(database.path(), b"not an sqlite database").expect("write corrupt database");
    let assertion = cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "1",
            "--db",
            database.path().to_str().expect("database path"),
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert_eq!(
        stderr.matches("file is not a database").count(),
        1,
        "{stderr}"
    );
}

#[test]
fn semantic_scan_rejects_an_invalid_compilation_database() {
    let directory = tempfile::tempdir().expect("project directory");
    std::fs::write(directory.path().join("compile_commands.json"), b"[{")
        .expect("write truncated compilation database");

    cmd()
        .current_dir(directory.path())
        .args(["scan", ".", "--mode", "semantic"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot read compile_commands.json for semantic analysis",
        ));
}

#[test]
fn structural_scan_does_not_report_different_binary_operators_as_type2() {
    let directory = tempfile::tempdir().expect("project directory");
    std::fs::create_dir_all(directory.path().join("src")).expect("create source directory");
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "pub fn add(values: &[u64]) -> u64 {\n    let mut total = 0;\n    for value in values {\n        total = total + *value;\n    }\n    total\n}\n\npub fn divide(values: &[u64]) -> u64 {\n    let mut total = 1;\n    for value in values {\n        total = total / (*value).max(1);\n    }\n    total\n}\n",
    )
    .expect("write source");
    std::fs::write(
        directory.path().join("codehelion.toml"),
        "min-clone-tokens = 1\n",
    )
    .expect("write configuration");

    let output = cmd()
        .current_dir(directory.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run structural scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert!(
        report["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .all(|group| group["clone_type"] != "type-2"),
        "{report}"
    );
}
