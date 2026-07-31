//! Semantic CLI fault tests driven through real helper processes.
//!
//! The mock establishes a normal handshake and build description, then fails
//! while analysing one source. That boundary matters: a scan may only call
//! itself Semantic after those facts establish the variant it records. Once
//! established, a dead, slow, or malformed helper is a per-unit unavailable
//! result rather than a failed whole scan.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
// This conformance suite must drive the compiled CLI through an operating
// system process. The production scan path remains subject to the workspace
// prohibition; only this isolated test harness is exempt.
#[allow(clippy::disallowed_types)]
use std::process::Command;

use codehelion_helper::ir::Unavailability;
use codehelion_store::Store;
use codehelion_store::compiler::CompilerOutcome;
use serde_json::Value;

/// Cargo supplies exact, freshly built paths for both binaries. This avoids
/// target-directory guesses, which can otherwise run an old helper or CLI.
const MOCK: &str = env!("CARGO_BIN_EXE_mock-helper");
const CLI: &str = env!("CARGO_BIN_EXE_mock-semantic-cli");

/// Copy the mock under the Rust helper's production name and make only the
/// child CLI find it. The test process itself never changes `PATH`, so cases
/// remain independent when the harness runs them concurrently.
fn helper_path(bin: &Path) -> PathBuf {
    let destination = bin.join(format!(
        "codehelion-backend-rust{}",
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::copy(MOCK, &destination).expect("copy mock under helper name");
    destination
}

/// Copy the wrapper beside its helper. `locate` intentionally checks beside
/// the running CLI before `PATH`, so this makes the test exercise the same
/// production lookup order without accidentally selecting a backend another
/// test build left in Cargo's target directory.
fn cli_path(bin: &Path) -> PathBuf {
    let destination = bin.join(format!("codehelion{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(CLI, &destination).expect("copy semantic CLI wrapper");
    destination
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-fault-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write manifest");
    std::fs::write(root.join("src/lib.rs"), "pub mod alive;\npub mod poison;\n")
        .expect("write module root");
    std::fs::write(
        root.join("src/alive.rs"),
        "pub fn count(values: &[u64]) -> u64 { values.iter().sum() }\n",
    )
    .expect("write answerable source");
    std::fs::write(
        root.join("src/poison.rs"),
        "pub fn count(values: &[u64]) -> u64 { values.iter().sum() }\n",
    )
    .expect("write faulting source");
    directory
}

#[allow(clippy::disallowed_types)]
fn scan(root: &Path, behaviour: &str, bin: &Path) -> Value {
    let output = Command::new(cli_path(bin))
        .current_dir(root)
        .env("CODEHELION_MOCK_HELPER_BEHAVIOUR", behaviour)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("run the semantic CLI wrapper");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("semantic scan emits JSON")
}

fn unavailable(report: &Value) -> BTreeMap<String, u64> {
    serde_json::from_value(report["summary"]["compiler"]["unavailable"].clone())
        .expect("compiler coverage has unavailable counts")
}

fn records_fault(root: &Path, report: &Value, reason: Unavailability) {
    let run_id = report["run"]["run_id"].as_i64().expect("recorded run id");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let coverage = store
        .run_compiler_coverage(run_id)
        .expect("read compiler coverage")
        .expect("semantic scan records compiler coverage");
    assert!(
        coverage.answered >= 1,
        "the healthy unit was lost: {coverage:?}"
    );
    assert!(
        coverage
            .unavailable
            .get(reason.name())
            .copied()
            .unwrap_or(0)
            >= 1,
        "{coverage:?}"
    );
    assert!(
        store
            .run_compiler_units(run_id)
            .expect("read compiler rows")
            .iter()
            .any(|unit| matches!(
                &unit.outcome,
                CompilerOutcome::Unavailable { reason: found, .. } if *found == reason
            )),
        "the unavailable reason was not persisted"
    );
}

fn assert_fault_is_partial(behaviour: &str, reason: Unavailability, timeout_ms: Option<u64>) {
    let fixture = fixture();
    if let Some(timeout_ms) = timeout_ms {
        std::fs::write(
            fixture.path().join("codehelion.toml"),
            format!("[limits]\nhelper-timeout-ms = {timeout_ms}\n"),
        )
        .expect("write a short helper deadline");
    }
    let bin = fixture.path().join("mock-bin");
    std::fs::create_dir(&bin).expect("create helper directory");
    helper_path(&bin);

    let report = scan(fixture.path(), behaviour, &bin);
    assert!(
        unavailable(&report)
            .get(reason.name())
            .copied()
            .unwrap_or(0)
            >= 1,
        "{report}"
    );
    records_fault(fixture.path(), &report, reason);
}

#[test]
fn a_crashing_helper_leaves_a_persisted_partial_semantic_run() {
    assert_fault_is_partial("allergic", Unavailability::HelperDied, None);
}

#[test]
fn a_timed_out_helper_leaves_a_persisted_partial_semantic_run() {
    assert_fault_is_partial("deaf-on-poison", Unavailability::HelperTimedOut, Some(25));
}

#[test]
fn a_protocol_mismatch_leaves_a_persisted_partial_semantic_run() {
    assert_fault_is_partial(
        "wrong-revision-on-poison",
        Unavailability::ToolchainMismatch,
        None,
    );
}
