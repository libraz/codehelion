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
use codehelion_helper::ir::CallTarget;
use codehelion_store::Store;
use codehelion_store::compiler::CompilerOutcome;
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

/// Run the semantic fixture at a floor suitable for checking short, closed
/// compiler-recognized operation windows.
fn scan_short_semantic_windows(root: &std::path::Path) -> Value {
    std::fs::write(root.join("codehelion.toml"), "min-clone-tokens = 1\n")
        .expect("configure the semantic window floor");
    scan(root)
}

fn scan_comparing(root: &std::path::Path, format: &str) -> std::process::Output {
    cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--format",
            format,
            "--compare-build-variants",
        ])
        .output()
        .expect("run scan")
}

fn comparison_json(root: &std::path::Path) -> Value {
    let output = scan_comparing(root, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// One report for an ordinary scan, or one per independent C/C++ variant.
fn reports(value: &Value) -> Vec<&Value> {
    value
        .get("partitions")
        .and_then(Value::as_array)
        .map_or_else(|| vec![value], |partitions| partitions.iter().collect())
}

/// The aspects of a restricted-semantic group which decide whether it exists.
/// Confidence is intentionally excluded: compiler auxiliary evidence may
/// adjust it, but must never create or remove a finding.
fn restricted_finding_set(report: &Value) -> Vec<Value> {
    let mut findings: Vec<_> = reports(report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .filter(|group| group["clone_type"] == "restricted-semantic")
        .map(|group| {
            serde_json::json!({
                "members": group["members"].as_array().into_iter().flatten().map(|member| {
                    serde_json::json!({
                        "file": member["file"],
                        "start_line": member["start_line"],
                        "end_line": member["end_line"],
                        "unit": member["unit"],
                    })
                }).collect::<Vec<_>>(),
                "rules": group["semantic"]["rules"].as_array().into_iter().flatten().map(|rule| {
                    serde_json::json!({"id": rule["id"], "version": rule["version"]})
                }).collect::<Vec<_>>(),
                "graphs": group["semantic"]["graphs"].as_array().into_iter().flatten().map(|graph| {
                    serde_json::json!({
                        "language": graph["language"],
                        "nodes": graph["nodes"],
                        "edges": graph["edges"],
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    findings.sort_by_key(ToString::to_string);
    findings
}

/// The scan and the helper have to agree about how a file is named, and nothing
/// short of running both says whether they do: a run that named its units one
/// way while the helper looked them up another would come back a full,
/// successful, semantic scan that a compiler answered nothing in.
#[path = "semantic_cpp/builds_and_database.rs"]
mod builds_and_database;
#[path = "semantic_cpp/core_semantics.rs"]
mod core_semantics;
#[path = "semantic_cpp/templates_and_artifacts.rs"]
mod templates_and_artifacts;
