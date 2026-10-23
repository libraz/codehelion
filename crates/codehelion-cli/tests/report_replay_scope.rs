//! `report` states what a replay of a recorded scan does not reproduce.
//!
//! The cross-build-variant and cross-language comparisons belong to the scan
//! invocation rather than to any one partition, so a replay cannot restate
//! them and must say so instead of passing for the whole scan document.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;

const NOTE: &str = "cross-build-variant and cross-language comparisons belong to the scan invocation and are not replayed";

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Record one scan of a small tree and return the database path.
fn recorded_scan(directory: &tempfile::TempDir) -> std::path::PathBuf {
    let tree = directory.path().join("tree");
    std::fs::create_dir(&tree).expect("tree directory");
    std::fs::write(tree.join("lib.rs"), "pub fn one() -> i32 { 1 }\n").expect("source");
    let database = directory.path().join("audit.db");
    cmd()
        .args([
            "scan",
            tree.to_str().expect("tree path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success();
    database
}

fn replay_stderr(database: &std::path::Path) -> String {
    let output = cmd()
        .args([
            "report",
            "--run",
            "1",
            "--db",
            database.to_str().expect("database path"),
        ])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stderr).expect("utf-8 stderr")
}

#[test]
fn a_semantic_replay_notes_the_comparisons_it_does_not_reproduce() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = recorded_scan(&directory);
    rusqlite::Connection::open(&database)
        .expect("open database")
        .execute(
            "UPDATE scan_run SET analysis_mode = 'semantic' WHERE id = 1",
            [],
        )
        .expect("mark the run as semantic");
    assert!(replay_stderr(&database).contains(NOTE));
}

#[test]
fn a_replay_of_a_mode_without_comparisons_carries_no_such_note() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = recorded_scan(&directory);
    assert!(!replay_stderr(&database).contains(NOTE));
}
