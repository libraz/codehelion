//! What the scanned tree may and may not decide about its own audit.
//!
//! Two things reach a run at once: what the operator typed, and whatever the
//! directory they pointed at happens to contain. The tree is the subject of
//! the audit, so it does not get to choose which findings are reported or
//! where the audit history is written. These are the two places it used to.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;

/// One member of a verbatim Rust clone pair, holding the suppression marker
/// inside a string literal.
///
/// A project listing the markers it recognises, embedding a template, or
/// asserting on this tool's own output writes exactly this, and none of it is
/// a decision to hide anything.
const QUOTED_MARKER_RS: &str = "pub fn describe_marker() -> &'static str {
    let marker = \"codehelion:ignore\";
    let listed = format!(\"the inline marker is {marker}\");
    let trimmed = listed.trim_end().to_string();
    let folded = trimmed.to_ascii_lowercase();
    folded
}
";

/// The same pair with the marker written where a marker belongs.
const COMMENTED_MARKER_RS: &str = "// codehelion:ignore
pub fn describe_marker() -> &'static str {
    let marker = \"a marker\";
    let listed = format!(\"the inline marker is {marker}\");
    let trimmed = listed.trim_end().to_string();
    let folded = trimmed.to_ascii_lowercase();
    folded
}
";

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A tree holding one verbatim Rust clone pair built from `source`.
fn pair(source: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("one.rs"), source).unwrap();
    std::fs::write(
        src.join("two.rs"),
        source.replace("pub fn describe_marker(", "pub fn describe_marker_copy("),
    )
    .unwrap();
    dir
}

/// Scan `root` in `mode` and parse the JSON report.
fn scan_json(root: &Path, mode: &str) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", mode, "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// How many findings the run hid because a rule matched.
fn suppressed_by_rule(report: &Value) -> u64 {
    report["summary"]["suppressed"]["by_rule"]
        .as_u64()
        .expect("the summary counts findings hidden by a rule")
}

/// The marker suppresses where the language says a comment is, and nowhere
/// else. Both analysis modes derive their marker lines from the same reading
/// of the file, so a string literal cannot hide a duplication in either.
#[test]
fn a_marker_inside_a_string_literal_does_not_hide_the_duplication_around_it() {
    for mode in ["fast", "structural"] {
        let quoted = pair(QUOTED_MARKER_RS);
        let report = scan_json(quoted.path(), mode);
        assert_eq!(
            suppressed_by_rule(&report),
            0,
            "{mode}: quoted marker text hid a finding: {report}"
        );
        assert!(
            !report["groups"]
                .as_array()
                .expect("groups array")
                .is_empty(),
            "{mode}: the duplication is reported: {report}"
        );

        // The control: written as a comment, the same characters are the
        // instruction they look like.
        let commented = pair(COMMENTED_MARKER_RS);
        let report = scan_json(commented.path(), mode);
        assert_eq!(
            suppressed_by_rule(&report),
            1,
            "{mode}: a comment marker still suppresses: {report}"
        );
    }
}

/// A worktree with a vendored subtree that carries its own configuration.
///
/// This is the shape `--untrusted` exists for: auditing code the project
/// ships but did not write, from inside the repository that ships it.
fn vendored_worktree(database: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let vendored = dir.path().join("vendor/hostile");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::write(vendored.join("one.rs"), QUOTED_MARKER_RS).unwrap();
    std::fs::write(
        vendored.join("two.rs"),
        QUOTED_MARKER_RS.replace("pub fn describe_marker(", "pub fn describe_marker_copy("),
    )
    .unwrap();
    std::fs::write(
        vendored.join("codehelion.toml"),
        format!("database = \"{database}\"\n"),
    )
    .unwrap();
    dir
}

/// The tree being audited chooses neither its own trust level nor the place
/// its audit is recorded. `--untrusted` holds a configured database to the
/// directory the operator selected, not to the repository that happens to
/// contain it — otherwise scanning a vendored subtree lets that subtree write
/// among its siblings.
#[test]
fn an_untrusted_scan_keeps_its_database_inside_the_selected_path() {
    let dir = vendored_worktree("escaped/audit.db");
    cmd()
        .current_dir(dir.path())
        .args(["scan", "./vendor/hostile", "--untrusted"])
        .assert()
        .success();

    assert!(
        dir.path().join("vendor/hostile/escaped/audit.db").is_file(),
        "the database is recorded inside the selected tree"
    );
    assert!(
        !dir.path().join("escaped").exists(),
        "nothing was created beside vendor/"
    );
}

/// The same holds for a spelling that climbs: refused rather than resolved
/// against some directory above the selection.
#[test]
fn an_untrusted_scan_refuses_a_database_path_that_climbs_out_of_the_selected_path() {
    let dir = vendored_worktree("../escaped/audit.db");
    cmd()
        .current_dir(dir.path())
        .args(["scan", "./vendor/hostile", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing database path"));

    assert!(!dir.path().join("vendor/escaped").exists());
    assert!(!dir.path().join("escaped").exists());
}

/// A lexically confined path is not enough: a symlink planted below the
/// selection can redirect the write to a sibling of it, still inside the same
/// repository.
#[cfg(unix)]
#[test]
fn an_untrusted_scan_refuses_a_database_path_that_leaves_through_a_symlink() {
    let dir = vendored_worktree("storage/audit.db");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("vendor/hostile/storage")).unwrap();

    cmd()
        .current_dir(dir.path())
        .args(["scan", "./vendor/hostile", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing database path"));

    assert!(!elsewhere.join("audit.db").exists());
}

/// A configuration found inside the tree has no authority over storage
/// whether or not `--untrusted` was asked for: the operator pointed at a
/// directory, and that is the directory the tree's own setting is read
/// against.
#[test]
fn a_discovered_configuration_places_its_database_inside_the_selected_path() {
    let dir = vendored_worktree("state/audit.db");
    cmd()
        .current_dir(dir.path())
        .args(["scan", "./vendor/hostile"])
        .assert()
        .success();

    assert!(dir.path().join("vendor/hostile/state/audit.db").is_file());
    assert!(!dir.path().join("state").exists());
}
