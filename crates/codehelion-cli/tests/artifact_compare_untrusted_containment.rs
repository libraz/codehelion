//! `artifact compare --untrusted` states the ceilings it installed, the same
//! way `artifact analyze --untrusted` already does.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
#[cfg(target_os = "linux")]
use codehelion::cli::{
    UNTRUSTED_ARTIFACT_MAX_BYTES, UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES,
    UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS,
};

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Where this build can enforce the untrusted preset's memory ceiling, a
/// comparison run under `--untrusted` reports the same containment record an
/// `artifact analyze --untrusted` run already reports.
#[cfg(target_os = "linux")]
#[test]
fn artifact_compare_untrusted_reports_the_installed_containment() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");

    let output = cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
            "--untrusted",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(
        json["containment"]["max_input_bytes"],
        UNTRUSTED_ARTIFACT_MAX_BYTES
    );
    assert_eq!(
        json["containment"]["worker_timeout_seconds"],
        UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS
    );
    assert_eq!(
        json["containment"]["worker_memory_limit_bytes"],
        UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES
    );
}

/// Where this build cannot enforce the untrusted preset's memory ceiling, an
/// `artifact compare --untrusted` run is refused for the same reason
/// `artifact analyze --untrusted` already is, rather than running uncontained.
#[cfg(not(target_os = "linux"))]
#[test]
fn artifact_compare_untrusted_is_refused_without_an_enforceable_memory_limit() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");

    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
            "--untrusted",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "the untrusted artifact profile requires an enforceable worker memory limit on this platform",
        ));
}
