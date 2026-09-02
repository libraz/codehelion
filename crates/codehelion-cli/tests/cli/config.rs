//! Tests for the `config` subcommand.

use super::*;

#[test]
fn config_show_prints_defaults_when_no_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("built-in defaults"))
        .stdout(predicate::str::contains("min-clone-tokens = 20"))
        .stdout(predicate::str::contains("jobs: automatic worker count"))
        .stdout(predicate::str::contains(
            "limits.posting-cap: mode-specific default",
        ))
        .stdout(predicate::str::contains(
            "limits.pair-budget: mode-specific default",
        ))
        .stdout(predicate::str::contains(
            "limits.signature-sibling-candidate-budget: default used only with --siblings-by-signature",
        ));
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
    assert!(written.contains("example, not the built-in default"));
    assert!(written.contains("auto-generated"));
    assert!(written.contains("prefix of at least 8 characters"));
    assert!(written.contains("# split-pairs = \"rank-down\""));
    assert!(written.contains("# width-family = \"hide\""));

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
