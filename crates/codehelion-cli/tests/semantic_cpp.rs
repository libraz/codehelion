//! A semantic scan of a C++ tree, from the command line to the compiler and
//! back.
//!
//! The unit tests either side of this fix one half each: that the run puts each
//! file to the helper that reads its language, and that the helper answers
//! about a translation unit it is given. Neither says the two halves agree
//! about how a file is named, which is the thing that goes wrong quietly — a
//! mismatch there produces a scan that succeeds, reports itself as semantic and
//! answered about nothing.
//!
//! Whether either helper is installed is a property of the machine, so these
//! read what `doctor` says and leave rather than fail when the answer is no.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Whether the helper that answers about C and C++ is here and usable.
fn clang_helper_is_usable() -> bool {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.contains("clang-helper") && line.contains("available"))
}

/// A scan of `root` in semantic mode, as the report puts it.
fn scan(root: &std::path::Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// The scan and the helper have to agree about how a file is named, and nothing
/// short of running both says whether they do: a run that named its units one
/// way while the helper looked them up another would come back a full,
/// successful, semantic scan that a compiler answered nothing in.
#[test]
fn a_cpp_tree_is_answered_about_rather_than_reported_as_unreadable() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");

    let report = scan(&root);
    let coverage = &report["summary"]["compiler"];
    assert!(
        coverage["answered"].as_u64().unwrap_or(0) >= 2,
        "the two translation units were not answered about: {coverage}"
    );
    // The header is included by both units and compiled as neither, so nothing
    // names a command for it. That it is reported as such rather than silently
    // absent is the point; that it is not reported as answered is what stops
    // the count above from being met by something other than the units.
    assert!(
        coverage["not_asked"].as_u64().unwrap_or(0) > 0
            || !coverage["unavailable"]
                .as_object()
                .is_none_or(serde_json::Map::is_empty),
        "a header no command compiles was neither asked about nor accounted for: {coverage}"
    );
}

/// A tree with no compilation database is a tree this helper has nothing to say
/// about, and saying so per file is what keeps a mixed project scannable. A run
/// that failed here would make one language's missing build stop the other
/// language's analysis.
#[test]
fn a_cpp_tree_with_no_compilation_database_is_reported_rather_than_refused() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("src");
    std::fs::create_dir_all(&root).expect("create the tree");
    std::fs::write(
        root.join("accumulate.cpp"),
        "int total(int a, int b) { return a + b; }\n",
    )
    .expect("write a source");

    let report = scan(dir.path());
    let coverage = &report["summary"]["compiler"];
    assert_eq!(coverage["answered"].as_u64(), Some(0), "{coverage}");
    assert_eq!(
        coverage["unavailable"]["no_build_information"].as_u64(),
        Some(1),
        "{coverage}"
    );
}
