//! End-to-end tests that run the compiled corpus-gen binary.
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(feature = "corpus-gen")]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion-corpus-gen").expect("binary should build")
}

fn corpus_dir() -> PathBuf {
    // Corpus lives at the workspace root, two levels up from this crate.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/synthetic/rust")
}

/// Every generated corpus is a direct child with a mutation spec. Enumerating
/// those specs makes a newly added corpus enter the drift check automatically.
fn synthetic_corpus_dirs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/synthetic");
    let mut directories = fs::read_dir(&root)
        .expect("read synthetic corpus root")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| path.join("spec.json").is_file())
        .collect::<Vec<_>>();
    directories.sort();
    directories
}

fn generate_into(out_dir: &Path) {
    cmd()
        .arg("generate")
        .arg("--spec")
        .arg(corpus_dir().join("spec.json"))
        .arg("--out-dir")
        .arg(out_dir)
        .assert()
        .success();
}

/// Compare two directories written by `generate`: same file names, same bytes.
fn assert_identical_dirs(left: &Path, right: &Path) {
    let mut names: Vec<String> = fs::read_dir(left)
        .expect("read left dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no files generated");
    for name in names {
        let left_bytes = fs::read(left.join(&name)).expect("read left file");
        let right_bytes = fs::read(right.join(&name)).expect("read right file");
        assert_eq!(left_bytes, right_bytes, "{name} differs between runs");
    }
}

#[test]
fn generate_twice_is_byte_identical() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    generate_into(&first);
    generate_into(&second);
    assert_identical_dirs(&first, &second);
    assert_identical_dirs(&second, &first);
}

#[test]
fn generate_reports_achieved_change_rate() {
    let tmp = tempfile::tempdir().expect("temp dir");
    cmd()
        .arg("generate")
        .arg("--spec")
        .arg(corpus_dir().join("spec.json"))
        .arg("--out-dir")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("change rate achieved"));
}

#[test]
fn check_passes_on_freshly_generated_output() {
    let tmp = tempfile::tempdir().expect("temp dir");
    generate_into(tmp.path());
    cmd()
        .arg("check")
        .arg("--spec")
        .arg(corpus_dir().join("spec.json"))
        .arg("--dir")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("match the spec output"));
}

#[test]
fn check_fails_on_drifted_output() {
    let tmp = tempfile::tempdir().expect("temp dir");
    generate_into(tmp.path());
    let target = tmp.path().join("type2.rs");
    let mut text = fs::read_to_string(&target).expect("read variant");
    text.push_str("// stray edit\n");
    fs::write(&target, text).expect("write tampered variant");
    cmd()
        .arg("check")
        .arg("--spec")
        .arg(corpus_dir().join("spec.json"))
        .arg("--dir")
        .arg(tmp.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("type2.rs: differs"));
}

/// Drift guard: every committed corpus must always match its spec. Fails when
/// someone hand-edits a variant or `labels.json` instead of regenerating.
#[test]
fn committed_corpora_match_their_specs() {
    let directories = synthetic_corpus_dirs();
    assert!(
        !directories.is_empty(),
        "synthetic corpus root has no specs"
    );
    for dir in directories {
        cmd()
            .arg("check")
            .arg("--spec")
            .arg(dir.join("spec.json"))
            .arg("--dir")
            .arg(&dir)
            .assert()
            .success();
    }
}
