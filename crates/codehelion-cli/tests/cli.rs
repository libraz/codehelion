//! End-to-end tests that run the compiled binary.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

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

#[test]
fn doctor_reports_the_restricted_semantic_rule_registry() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "restricted semantic rules: 10 enabled",
        ))
        .stdout(predicate::str::contains("semantic-rule-registry-v1"));
}

#[test]
fn doctor_reports_the_portable_sandbox_limitations() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "child-process isolation and request timeouts available",
        ))
        .stdout(predicate::str::contains(
            "OS memory, network, and filesystem containment unavailable",
        ));
}

#[test]
fn doctor_lists_supported_and_recognised_artifact_formats() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("wasm: available"))
        .stdout(predicate::str::contains("elf: available"))
        .stdout(predicate::str::contains(
            "macho: recognised, parser unavailable",
        ));
}

#[test]
fn untrusted_semantic_refuses_an_unenforceable_helper_memory_limit() {
    cmd()
        .args(["scan", ".", "--mode", "semantic", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot enforce the requested helper memory limit",
        ))
        .stderr(predicate::str::contains(
            "OS memory containment is unavailable",
        ));
}

/// Every helper is listed whether or not this machine has it, and every one is
/// optional. A report that left out the ones nobody installed would answer
/// "what can this do here" by saying only what it can already do.
///
/// What a missing one has to carry is fixed here too, and it is the thing a row
/// saying "not found" does not: something to do about it. Whether either helper
/// is installed depends on the machine, so the absent case is asserted where it
/// can be arranged rather than where it might happen to occur.
#[test]
fn doctor_lists_every_helper_as_optional_whether_or_not_it_is_installed() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    for helper in ["rust-compiler-helper", "clang-helper"] {
        let row = text
            .lines()
            .find(|line| line.contains(helper))
            .unwrap_or_else(|| panic!("{helper} is listed: {text}"));
        assert!(row.contains("optional"), "{row}");
        if row.contains("not found") {
            assert!(row.contains("not needed for fast or structural"), "{row}");
            assert!(
                row.contains("codehelion-backend-"),
                "a missing helper names the program to install: {row}"
            );
        }
    }
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
        .stdout(predicate::str::contains("artifact-report-v1"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""))
        .stdout(predicate::str::contains("\"analysis_id\": 1"));
    assert!(db.is_file());
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
        .stdout(predicate::str::contains("size_delta_bytes: +0"));
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
