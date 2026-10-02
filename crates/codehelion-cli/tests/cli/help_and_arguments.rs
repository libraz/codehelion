//! Tests for top-level argument parsing and for the help text of individual
//! subcommands.

use super::*;

#[test]
fn scan_help_marks_the_other_execution_classes_as_unimplemented() {
    cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Only build-script is implemented"))
        .stdout(predicate::str::contains("reserved protocol values"));
}

#[test]
fn scan_help_limits_jobs_to_the_parallel_frontend_stage() {
    cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Frontend read-and-lex worker threads",
        ))
        .stdout(predicate::str::contains(
            "Clone grouping and report rendering remain serial",
        ));
}

#[test]
fn artifact_compare_help_exposes_the_input_format_assertion() {
    cmd()
        .args(["artifact", "compare", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--input-format"))
        .stdout(predicate::str::contains("--untrusted"))
        .stdout(predicate::str::contains(
            "This is an assertion, not an override",
        ));
}

/// The flag's own help says the same thing the artifact document does.
#[test]
fn build_variant_help_says_the_two_conditions_are_not_matched_against_each_other() {
    let output = cmd()
        .args(["artifact", "analyze", "--help"])
        .output()
        .expect("artifact analyze help");
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).expect("help output");
    assert!(help.contains("JSON manifest you write"), "{help}");
    assert!(help.contains("does not have to match"), "{help}");
    assert!(
        help.contains("recorded side by side rather than checked against each other"),
        "{help}"
    );
}

#[test]
fn mode_help_describes_measurement_differences_and_safety() {
    let output = cmd().args(["scan", "--help"]).output().expect("scan help");
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).expect("help output");
    assert!(help.contains("identifier agreement"), "{help}");
    assert!(help.contains("similarity breakdown"), "{help}");
    assert!(help.contains("siblings"), "{help}");
    assert!(help.contains("near misses"), "{help}");
    assert!(help.contains("never runs target code"), "{help}");
    assert!(help.contains("--allow-execution"), "{help}");
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

/// A rejection decided from the command line alone exits 2, the code `clap`
/// uses for its own refusals, and a failure that depends on the environment
/// stays at 1.
#[test]
fn every_command_line_rejection_exits_with_the_usage_status() {
    let directory = tempfile::tempdir().expect("temp dir");
    std::fs::write(directory.path().join("lib.rs"), "pub fn tiny() {}\n").expect("write source");
    for arguments in [
        vec!["scan", ".", "--include-trivial"],
        vec!["scan", ".", "--compare-languages"],
        vec!["scan", ".", "--jobs", "0"],
        vec!["scan", ".", "--format", "json", "--show-siblings"],
        vec!["scan", ".", "--helper", "rust=/bin/true"],
        vec!["scan", ".", "--mode", "semantic", "--helper", "rust"],
        vec!["scan", ".", "--allow-execution", "build-scripts"],
        vec![
            "scan",
            ".",
            "--untrusted",
            "--mode",
            "semantic",
            "--allow-execution",
            "build-scripts",
        ],
        vec!["scan", ".", "--force"],
        vec!["cache", "prune"],
        vec!["cache", "clear"],
        vec![
            "artifact",
            "compare",
            "a.wasm",
            "b.wasm",
            "--source-run",
            "1",
        ],
        vec![
            "artifact",
            "compare",
            "a.wasm",
            "b.wasm",
            "--clone-group",
            "deadbeef",
        ],
    ] {
        let output = cmd()
            .current_dir(directory.path())
            .args(&arguments)
            .output()
            .expect("run a rejected command line");
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
    }

    let output = cmd()
        .current_dir(directory.path())
        .arg("report")
        .output()
        .expect("report with nothing recorded");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}
