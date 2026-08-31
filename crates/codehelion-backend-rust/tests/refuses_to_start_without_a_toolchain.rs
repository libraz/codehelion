//! What the helper does on a machine that cannot supply the compiler it
//! analyses with.
//!
//! Every capability it names at the handshake is answered by a toolchain it
//! locates rather than links, so a machine without one has no semantic analysis
//! to offer. Failing to start is how that is said once, to whoever asks whether
//! this helper works, instead of once per unit to a scan that already began.
//!
//! Driven as a process rather than through the client, because the claim is
//! about what happens before a handshake and the environment has to be arranged
//! for the child: a test that changed its own would change it for every other
//! test running beside it.

#![allow(clippy::expect_used)]

/// Starting a process is the thing under test here.
#[allow(
    clippy::disallowed_types,
    reason = "the helper under test is a separate program, which is the isolation being checked"
)]
#[test]
fn a_helper_that_cannot_find_its_toolchain_never_shakes_hands() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let absent = directory.path().join("rustup");

    let finished = std::process::Command::new(env!("CARGO_BIN_EXE_codehelion-backend-rust"))
        // Where the analysis library looks first, so the toolchain this helper
        // would use is one that is not installed.
        .env("RUSTUP", &absent)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the helper should be startable");

    assert!(
        !finished.status.success(),
        "the helper reported success on a machine it cannot analyse anything on"
    );
    assert!(
        finished.stdout.is_empty(),
        "the helper answered over the protocol before it had a toolchain: {}",
        String::from_utf8_lossy(&finished.stdout)
    );
    let said = String::from_utf8_lossy(&finished.stderr);
    assert!(
        said.contains("rustup"),
        "the reason a run would be told is not in what the helper said: {said}"
    );
}
