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

/// Copying an executable and starting one never overlap.
///
/// A copy holds its destination open for writing. A process started while it
/// is open inherits that descriptor and keeps it for as long as it runs, and
/// a system will not execute a file somebody may still be writing. These
/// cases run at the same time and each copies its own binaries, so the
/// refusal lands on whichever one started at the wrong moment — which is a
/// property of when the machine got round to each case, not of the code
/// under test.
static EXECUTABLE_HANDOFF: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run a prepared command with no executable copy in flight.
#[allow(clippy::disallowed_types)]
fn run(command: &mut Command, description: &str) -> std::process::Output {
    let child = {
        let _handoff = EXECUTABLE_HANDOFF
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect(description)
    };
    child.wait_with_output().expect(description)
}

/// Copy an executable with nothing being started meanwhile.
fn copy_executable(source: &str, destination: &Path, description: &str) {
    let _handoff = EXECUTABLE_HANDOFF
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::fs::copy(source, destination).expect(description);
}

/// Copy the mock under the Rust helper's production name and make only the
/// child CLI find it. The test process itself never changes `PATH`, so cases
/// remain independent when the harness runs them concurrently.
fn helper_path(bin: &Path) -> PathBuf {
    let destination = bin.join(format!(
        "codehelion-backend-rust{}",
        std::env::consts::EXE_SUFFIX
    ));
    copy_executable(MOCK, &destination, "copy mock under helper name");
    destination
}

/// Copy the wrapper beside its helper. `locate` intentionally checks beside
/// the running CLI before `PATH`, so this makes the test exercise the same
/// production lookup order without accidentally selecting a backend another
/// test build left in Cargo's target directory.
fn cli_path(bin: &Path) -> PathBuf {
    let destination = bin.join(format!("codehelion{}", std::env::consts::EXE_SUFFIX));
    copy_executable(CLI, &destination, "copy semantic CLI wrapper");
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
    let mut command = Command::new(cli_path(bin));
    command
        .current_dir(root)
        .env("CODEHELION_MOCK_HELPER_BEHAVIOUR", behaviour)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"]);
    let output = run(&mut command, "run the semantic CLI wrapper");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("semantic scan emits JSON")
}

#[allow(clippy::disallowed_types)]
fn scan_with_explicit_helper(root: &Path, behaviour: &str, helper: &Path) -> Value {
    let mut command = Command::new(CLI);
    command
        .current_dir(root)
        .env("CODEHELION_MOCK_HELPER_BEHAVIOUR", behaviour)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--format",
            "json",
            "--helper",
            &format!("rust={}", helper.display()),
        ]);
    let output = run(
        &mut command,
        "run the semantic CLI wrapper with an explicit helper",
    );
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
fn an_explicit_helper_path_is_used_without_a_sibling_or_path_lookup() {
    let fixture = fixture();
    let helper = fixture.path().join("named-anything");
    copy_executable(MOCK, &helper, "copy the mock to the explicit path");
    let report = scan_with_explicit_helper(fixture.path(), "well-behaved", &helper);
    assert!(
        report["summary"]["compiler"]["answered"]
            .as_u64()
            .is_some_and(|answered| answered > 0),
        "{report}"
    );
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
