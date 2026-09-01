//! `cache prune` reports the whole deletion, not the part that was asked for.
//!
//! The retention flags name four kinds of row. Removing one of those rows
//! takes every row referencing it as well, and those live in tables nobody
//! named — so a prune that reports only its named counts understates what it
//! did, and a statistic taken later over one of the silent tables moves with
//! no visible cause.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A WebAssembly module declaring one function under `function_name`.
///
/// The name is what makes the analysis record a symbol row, which is the row
/// that has to disappear with the analysis holding it.
fn named_module(function_name: &str) -> Vec<u8> {
    let name = function_name.as_bytes();
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    // One function type `() -> ()`, one function of that type, one empty body.
    module.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    module.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    module.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);

    // The name section: one function-name entry for function index 0.
    let mut entries = vec![0x01, 0x00, u8::try_from(name.len()).expect("a short name")];
    entries.extend_from_slice(name);
    let mut payload = vec![0x04];
    payload.extend_from_slice(b"name");
    payload.push(0x01);
    payload.push(u8::try_from(entries.len()).expect("a short subsection"));
    payload.extend_from_slice(&entries);
    module.push(0x00);
    module.push(u8::try_from(payload.len()).expect("a short section"));
    module.extend_from_slice(&payload);
    module
}

/// Dropping an analysis drops the symbols recorded under it, and the reader is
/// told so. Without that line the removal is invisible: the named counts say
/// one analysis went, and nothing says the rows that described it went with
/// it.
#[test]
fn pruning_an_analysis_reports_the_rows_removed_with_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("audit.db");

    for (file, function) in [("first.wasm", "alpha"), ("second.wasm", "beta_function")] {
        let artifact = dir.path().join(file);
        std::fs::write(&artifact, named_module(function)).expect("write wasm fixture");
        cmd()
            .current_dir(dir.path())
            .args([
                "artifact",
                "analyze",
                artifact.to_str().expect("utf-8 artifact path"),
                "--db",
                database.to_str().expect("utf-8 database path"),
            ])
            .assert()
            .success();
    }

    let output = cmd()
        .current_dir(dir.path())
        .args([
            "cache",
            "prune",
            "--db",
            database.to_str().expect("utf-8 database path"),
            "--keep-artifacts",
            "1",
            "--force",
        ])
        .output()
        .expect("run cache prune");
    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).expect("prune output is UTF-8");

    assert!(
        printed.contains("1 artifact analysis(es)"),
        "the named retention count is still reported: {printed}"
    );
    assert!(
        printed.contains("also removed 1 row(s) from artifact_analysis_symbol"),
        "the rows that went with the analysis are reported: {printed}"
    );
}

/// A prune that removes nothing says nothing extra: the cascade lines describe
/// a deletion that happened, so an empty list is silence rather than a row of
/// zeroes nobody has to read.
#[test]
fn pruning_within_the_retained_window_reports_no_cascade() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("audit.db");
    let artifact = dir.path().join("only.wasm");
    std::fs::write(&artifact, named_module("alpha")).expect("write wasm fixture");
    cmd()
        .current_dir(dir.path())
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("utf-8 artifact path"),
            "--db",
            database.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();

    cmd()
        .current_dir(dir.path())
        .args([
            "cache",
            "prune",
            "--db",
            database.to_str().expect("utf-8 database path"),
            "--keep-artifacts",
            "20",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("also removed").not());
}
