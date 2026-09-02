//! Tests for the `cache` subcommand.

use super::*;

#[test]
fn cache_status_reports_absent_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["cache", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("absent"));
}

#[test]
fn cache_clear_requires_confirmation_even_when_the_database_is_absent() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --force to confirm"));
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to remove"));
    assert!(
        !dir.path().join(".codehelion").exists(),
        "clearing an unscanned tree must not create cache state"
    );
}

#[test]
fn cache_clear_removes_wal_sidecars_and_status_counts_them() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("audit.db");
    let wal = dir.path().join("audit.db-wal");
    let shm = dir.path().join("audit.db-shm");
    std::fs::write(&database, [0_u8]).expect("write database");
    std::fs::write(&wal, [0_u8; 2]).expect("write WAL sidecar");
    std::fs::write(&shm, [0_u8; 3]).expect("write shared-memory sidecar");
    let database_arg = database.to_str().expect("temporary database path is UTF-8");

    cmd()
        .current_dir(dir.path())
        .args(["cache", "status", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("(6 bytes)"));
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear", "--force", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    assert!(!database.exists(), "main database was removed");
    assert!(!wal.exists(), "WAL sidecar was removed");
    assert!(!shm.exists(), "shared-memory sidecar was removed");
}

#[test]
fn cache_status_breaks_down_valid_storage_and_prune_compacts_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("audit.db");
    let source = directory.path().join("lib.rs");
    std::fs::write(&source, "pub fn tiny() {}\n").expect("write source");
    let database_arg = database.to_str().expect("database path");

    cmd()
        .args([
            "scan",
            directory.path().to_str().expect("scan path"),
            "--db",
            database_arg,
        ])
        .assert()
        .success();
    cmd()
        .args(["cache", "status", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("table storage:"))
        .stdout(predicate::str::contains("scan_run:"));
    cmd()
        .args([
            "cache",
            "prune",
            "--db",
            database_arg,
            "--keep-artifacts",
            "0",
            "--keep-comparisons",
            "0",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pruned"));
}
