//! Regression coverage for a duplicated traversal inside one cloned unit.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn scan_corpus(name: &str) -> serde_json::Value {
    let corpus = repo_root().join("corpus/synthetic").join(name);
    let database = tempfile::tempdir().expect("temporary database directory");
    let output = Command::cargo_bin("codehelion")
        .expect("binary should build")
        .args([
            "scan",
            corpus.to_str().expect("corpus path is UTF-8"),
            "--mode",
            "structural",
            "--no-reuse",
            "--format",
            "json",
            "--include-vendored",
            "--db",
            database
                .path()
                .join("audit.db")
                .to_str()
                .expect("database path is UTF-8"),
        ])
        .output()
        .expect("scan runs");
    assert!(
        output.status.success(),
        "scanning {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("report is JSON")
}

fn assert_loop_case(name: &str, function: &str) {
    let report = scan_corpus(name);
    let groups = report["groups"].as_array().expect("groups array");
    let primary: Vec<&serde_json::Value> = groups
        .iter()
        .filter(|group| {
            group["scope"] == "unit"
                && group["members"]
                    .as_array()
                    .is_some_and(|members| members.iter().any(|member| member["unit"] == function))
        })
        .collect();
    assert_eq!(
        primary.len(),
        1,
        "expected one primary group for {function}"
    );
    let members = primary[0]["members"].as_array().expect("group members");
    assert_eq!(members.len(), 2, "the corpus case is a two-file pair");
    assert!(
        members.iter().all(|member| member["unit"] == function),
        "the primary group must contain only {function}"
    );

    let fingerprints: Vec<&str> = groups
        .iter()
        .map(|group| group["fingerprint"].as_str().expect("group fingerprint"))
        .collect();
    let distinct_fingerprints: BTreeSet<&str> = fingerprints.iter().copied().collect();
    assert_eq!(
        fingerprints.len(),
        distinct_fingerprints.len(),
        "group fingerprints must be unique in the loop corpus"
    );

    let finding_ids: Vec<&str> = groups
        .iter()
        .flat_map(|group| group["members"].as_array().expect("group members"))
        .map(|member| member["finding_id"].as_str().expect("finding id"))
        .collect();
    let distinct_finding_ids: BTreeSet<&str> = finding_ids.iter().copied().collect();
    assert_eq!(
        finding_ids.len(),
        distinct_finding_ids.len(),
        "finding ids must be unique in the loop corpus"
    );
}

#[test]
fn rust_values_equal_with_two_identical_loops_is_one_primary_group() {
    assert_loop_case("rust", "values_equal");
}

#[test]
fn cpp_cells_match_with_two_identical_loops_is_one_primary_group() {
    assert_loop_case("cpp", "cells_match");
}
