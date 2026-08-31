//! What `--untrusted` puts into force around the scanner process itself.
//!
//! The ceilings that bound one file, one posting list or one group act after
//! the bytes have been read and are covered by the scan tests. The one that
//! bounds the run's own memory is installed once for the whole process and
//! cannot be lifted again, so it can only be observed from outside a run.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use codehelion_core::execution::Limits;
use codehelion_helper::sandbox::availability;

/// Enough of a source tree for a scan to have something to read.
const SOURCE: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^= acc >> 17;
    acc
}
";

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A distrusting run either works under the memory ceiling its profile states
/// or says that ceiling is not in force.
///
/// Where the build reports OS memory containment, the ceiling is installed
/// before any of the tree is read and the run completes inside it, which is
/// what the absence of a note asserts. Where the build reports none, the
/// ceiling cannot be installed at all, and the run has to name the number it
/// could not install rather than let a scan of a hostile tree read as a
/// contained one.
#[test]
fn a_distrusting_run_works_under_its_memory_ceiling_or_says_it_is_not_in_force() {
    let bytes = Limits::untrusted()
        .max_subprocess_bytes
        .expect("the untrusted profile states a memory ceiling");
    let tree = tempfile::tempdir().expect("temp tree");
    std::fs::create_dir_all(tree.path().join("src")).unwrap();
    std::fs::write(tree.path().join("src/lib.rs"), SOURCE).unwrap();

    let distrusting = cmd()
        .current_dir(tree.path())
        .args(["scan", ".", "--untrusted"])
        .output()
        .expect("run a distrusting scan");
    let stderr = String::from_utf8_lossy(&distrusting.stderr).into_owned();
    // An exit code at all is part of the claim: a run the operating system
    // ends for its memory leaves a signal and no code of its own.
    assert_eq!(distrusting.status.code(), Some(0), "{stderr}");

    if availability().memory_limit {
        assert!(
            !stderr.contains("memory ceiling"),
            "the ceiling this build can install was reported as not in force: {stderr}"
        );
    } else {
        assert!(
            stderr.contains(&format!(
                "cannot hold the scanner process to the {bytes}-byte memory ceiling"
            )),
            "a build without OS memory containment has to name the ceiling it \
             could not install: {stderr}"
        );
    }

    // The note belongs to the profile, not to every run.
    let trusting = cmd()
        .current_dir(tree.path())
        .args(["scan", "."])
        .output()
        .expect("run a trusting scan");
    let trusting_stderr = String::from_utf8_lossy(&trusting.stderr).into_owned();
    assert_eq!(trusting.status.code(), Some(0), "{trusting_stderr}");
    assert!(
        !trusting_stderr.contains("memory ceiling"),
        "a run that was not told to distrust the tree states no ceiling: {trusting_stderr}"
    );
}
