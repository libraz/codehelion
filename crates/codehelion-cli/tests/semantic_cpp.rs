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
    // Both translation units and the header they share. The header is compiled
    // by no command of its own, so it is answered by the units that read it —
    // with what both of them agree it holds, since in this fixture they compile
    // it into two different programs.
    assert_eq!(
        coverage["answered"].as_u64(),
        Some(3),
        "every file of the tree was answered about: {coverage}"
    );
    assert!(
        coverage["unavailable"]
            .as_object()
            .is_none_or(serde_json::Map::is_empty),
        "nothing was left unanswerable: {coverage}"
    );
}

/// A template use written in a header is reported by both translation units
/// that read it. The CLI keeps the common answer, including a valid type-table
/// index, instead of selecting one unit or dropping template data while it
/// backfills the header.
#[test]
fn template_instantiations_survive_header_agreement_and_storage() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("template-instantiation", dir.path()).expect("plant fixture");

    let report = scan(&root);
    let run_id = report["run"]["run_id"].as_i64().expect("recorded run");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let units = store
        .run_compiler_units(run_id)
        .expect("read compiler results");
    let header = units
        .iter()
        .find_map(|stored| match &stored.outcome {
            CompilerOutcome::Analyzed(ir) if ir.unit.file.ends_with("include/templates.hpp") => {
                Some(ir)
            }
            CompilerOutcome::Analyzed(_) | CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("the units agree on an answer for the header");
    let stamp = header
        .instantiations
        .iter()
        .find(|stamp| stamp.anchor.expansion.file == "include/templates.hpp")
        .expect("the agreed header template use was retained");
    assert!(stamp.instantiation_key.starts_with("clang-usr-v1:"));
    assert_eq!(stamp.arguments.len(), 1);
    let argument = usize::try_from(stamp.arguments[0]).expect("type index fits");
    assert_eq!(
        header.types[argument].category,
        codehelion_helper::ir::TypeCategory::Integer
    );
}

/// The stored header answer is the intersection of its translation-unit
/// readings. A call whose overload changes under `-DWIDE_CALL` is omitted,
/// while an identical direct call survives with its exact static USR.
#[test]
fn call_targets_survive_header_agreement_and_sqlite_round_trip() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("overload-resolution", dir.path()).expect("plant fixture");
    let header_source =
        std::fs::read_to_string(root.join("include/calls.hpp")).expect("read fixture header");
    let stable = u64::try_from(header_source.find("direct(8)").expect("stable call")).unwrap();
    let selected = u64::try_from(
        header_source
            .find("choose(HEADER_ARGUMENT)")
            .expect("variant call"),
    )
    .unwrap();

    let report = scan(&root);
    let run_id = report["run"]["run_id"].as_i64().expect("recorded run");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let units = store
        .run_compiler_units(run_id)
        .expect("read compiler results");
    let header = units
        .iter()
        .find_map(|stored| match &stored.outcome {
            CompilerOutcome::Analyzed(ir) if ir.unit.file.ends_with("include/calls.hpp") => {
                Some(ir)
            }
            CompilerOutcome::Analyzed(_) | CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("the units agree on part of the header");

    let stable_call = header
        .calls
        .iter()
        .find(|call| call.anchor.expansion.start_byte == stable)
        .expect("the agreed direct call survived storage");
    assert!(matches!(stable_call.target, CallTarget::Static { .. }));
    assert!(
        header
            .calls
            .iter()
            .all(|call| call.anchor.expansion.start_byte != selected),
        "one translation unit's selected overload survived disagreement"
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
