//! End-to-end tests that run the compiled binary.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

#[test]
fn doctor_succeeds() {
    cmd().arg("doctor").assert().success();
}

#[test]
fn doctor_reports_own_version() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

/// Whether the Rust helper is found depends on the machine, so what is asserted
/// is the helper nobody can have yet: it has to be reported as absent, as
/// optional, and with something to do about it. A row that said only "not
/// found" would be a report telling somebody a fact they cannot act on.
#[test]
fn doctor_reports_a_helper_that_is_not_installed_as_optional_and_actionable() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("rust-compiler-helper"))
        .stdout(predicate::str::contains("clang-helper"))
        .stdout(predicate::str::contains("not found"))
        .stdout(predicate::str::contains(
            "not needed for fast or structural",
        ))
        .stdout(predicate::str::contains("codehelion-backend-clang"));
}

/// Being on disk is not being usable, so a row that claims a helper is there
/// has to carry what the handshake settled — which compiler will answer and
/// what it will answer about. Whether one is installed depends on the machine,
/// so what is fixed here is the pairing rather than the outcome: available
/// comes with what it said, unusable comes with why it said nothing.
#[test]
fn a_helper_reported_as_present_says_what_it_answered() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.contains("rust-compiler-helper"))
        .expect("the helper is listed whether or not it is installed");
    let row = lines[at];
    let following = lines[at + 1..].join("\n");
    if row.contains("available") {
        assert!(following.starts_with("  "), "{text}");
        assert!(lines[at + 1].contains("version "), "{text}");
        assert!(
            lines[at + 1..at + 4]
                .iter()
                .any(|l| l.contains("supplies:")),
            "{text}"
        );
    } else if row.contains("unusable") {
        assert!(lines[at + 1].contains("could not talk to it"), "{text}");
    } else {
        assert!(row.contains("not found"), "{text}");
    }
}

#[test]
fn missing_subcommand_is_an_error() {
    cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn help_flag_succeeds() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion"));
}

#[test]
fn scan_semantic_reports_unavailable() {
    cmd()
        .args(["scan", "--mode", "semantic"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not available in this release"));
}

#[test]
fn auditing_a_tree_that_was_never_scanned_says_to_scan_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .arg("audit")
        .assert()
        .failure()
        .stderr(predicate::str::contains("run `codehelion scan` first"));
}

#[test]
fn config_show_prints_defaults_when_no_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("built-in defaults"))
        .stdout(predicate::str::contains("min-clone-tokens = 20"));
}

#[test]
fn config_init_writes_a_template_then_refuses_overwrite() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["config", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote"));

    let written = std::fs::read_to_string(dir.path().join("codehelion.toml")).expect("template");
    assert!(written.contains("codehelion configuration"));

    // A second init without --force must not clobber the file.
    cmd()
        .current_dir(dir.path())
        .args(["config", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    cmd()
        .current_dir(dir.path())
        .args(["config", "init", "--force"])
        .assert()
        .success();
}

#[test]
fn config_show_reads_a_discovered_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "min-clone-tokens = 42\n",
    )
    .expect("write config");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("min-clone-tokens = 42"))
        .stdout(predicate::str::contains("codehelion.toml"));
}

#[test]
fn config_show_rejects_unknown_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "min_clone_tokens = 42\n",
    )
    .expect("write config");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown field"));
}

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
fn cache_clear_on_missing_database_is_a_noop() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to remove"));
}
