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

/// Require the helper that answers about C and C++.
///
/// This used to return a boolean each test branched on, which made a machine
/// without the helper report every C++ semantic test as passing. The helper is
/// a workspace binary and libclang is loaded at run time, so a suite run that
/// cannot find it has an environment to fix, and saying which is more use than
/// a silent success.
fn require_clang_helper() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report
            .lines()
            .any(|line| line.contains("clang-helper") && line.contains("available")),
        "the C/C++ semantic helper is unavailable, so these tests cannot answer about C++.\n\
         It is built by a workspace test run and loads libclang at run time; install a libclang \
         shared library, or run `cargo build -p codehelion-backend-clang` if only the binary is \
         missing.\n{report}"
    );
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

/// Whether `path` ends in `tail`, comparing whole components rather than text.
///
/// A unit is named by where its file is, so the name carries the separator the
/// platform writes paths with, while the tail is written here once for every
/// platform. Compared as text the two agree on one platform and on no other.
fn names_the_file(path: &str, tail: &str) -> bool {
    std::path::Path::new(path).ends_with(tail)
}

/// Whether the artifact's symbols are decorated in an ABI this build does not
/// read a name out of.
///
/// The artifact backend demangles Rust and the Itanium C++ ABI. A C++ compiler
/// targeting the Microsoft ABI decorates differently — `?`-prefixed — and those
/// names reach the report as they stand. Correlating a stripped object to its
/// sources goes through the name, so where this is true there is nothing for it
/// to go through, and the tool is expected to say so rather than to guess.
fn decorated_by_an_unread_abi(report: &Value) -> bool {
    // Any, not all: an object may hold a C symbol nobody decorated, while an
    // Itanium name never begins this way — that ABI spells them `_Z...`, and a
    // `?` cannot open a C identifier either.
    report["symbols"].as_array().is_some_and(|symbols| {
        symbols.iter().any(|symbol| {
            symbol["name"]
                .as_str()
                .is_some_and(|name| name.starts_with('?'))
        })
    })
}
