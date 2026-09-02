//! Tests for the `doctor` subcommand.

use super::*;

#[test]
fn doctor_succeeds() {
    cmd().arg("doctor").assert().success();
}

#[test]
fn doctor_reports_own_version() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn doctor_reports_the_restricted_semantic_rule_registry() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "restricted semantic rules: 8 enabled; 4 cross-language rules require --compare-languages",
        ))
        .stdout(predicate::str::contains("semantic-rule-registry-v1"));
}

#[test]
fn doctor_reports_the_platform_sandbox_limitations() {
    let expected = if cfg!(target_os = "linux") {
        "OS memory ceilings available; network and filesystem containment unavailable"
    } else {
        "OS memory, network, and filesystem containment unavailable"
    };
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("child-process isolation"))
        .stdout(predicate::str::contains(expected));
}

#[test]
fn doctor_lists_supported_and_recognised_artifact_formats() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("wasm: available"))
        .stdout(predicate::str::contains("elf: available"))
        .stdout(predicate::str::contains(
            "macho: available (symbols, relocations, data segments, normalized duplicates; source mappings from a matching dSYM DWARF image)",
        ));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn untrusted_semantic_refuses_an_unenforceable_helper_memory_limit() {
    cmd()
        .args(["scan", ".", "--mode", "semantic", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot enforce the requested helper memory limit",
        ))
        .stderr(predicate::str::contains(
            "OS memory containment is unavailable",
        ));
}

/// Every helper is listed whether or not this machine has it, and every one is
/// optional. A report that left out the ones nobody installed would answer
/// "what can this do here" by saying only what it can already do.
///
/// What a missing one has to carry is fixed here too, and it is the thing a row
/// saying "not found" does not: something to do about it. Whether either helper
/// is installed depends on the machine, so the absent case is asserted where it
/// can be arranged rather than where it might happen to occur.
#[test]
fn doctor_lists_every_helper_as_optional_whether_or_not_it_is_installed() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    for helper in ["rust-compiler-helper", "clang-helper"] {
        let row = text
            .lines()
            .find(|line| line.contains(helper))
            .unwrap_or_else(|| panic!("{helper} is listed: {text}"));
        assert!(row.contains("optional"), "{row}");
        if row.contains("not found") {
            assert!(row.contains("not needed for fast or structural"), "{row}");
            assert!(
                row.contains("codehelion-backend-"),
                "a missing helper names the program to install: {row}"
            );
        }
    }
}

/// Being on disk is not being usable, so a row that claims a helper is there
/// has to carry what the handshake settled — which compiler will answer and
/// what it will answer about. Whether one is installed depends on the machine,
/// so what is fixed here is the pairing rather than the outcome: available
/// comes with what it said, unusable comes with why it said nothing.
#[test]
fn a_helper_reported_as_present_says_what_it_answered() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.contains("rust-compiler-helper"))
        .expect("the helper is listed whether or not it is installed");
    let row = lines[at];
    let following = lines[at + 1..].join("\n");
    if row.contains("available") {
        assert!(following.starts_with("  "), "{text}");
        assert!(lines[at + 1].contains("version "), "{text}");
        assert!(
            lines[at + 1..at + 4]
                .iter()
                .any(|l| l.contains("supplies:")),
            "{text}"
        );
    } else if row.contains("unusable") {
        assert!(lines[at + 1].contains("could not talk to it"), "{text}");
    } else {
        assert!(row.contains("not found"), "{text}");
    }
}
