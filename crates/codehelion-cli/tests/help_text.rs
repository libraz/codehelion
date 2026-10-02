//! Help text states what the commands do, and names only flags they accept.
#![allow(clippy::expect_used)]

use assert_cmd::Command;

fn help(args: &[&str]) -> String {
    let output = Command::cargo_bin("codehelion")
        .expect("binary should build")
        .args(args)
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .clone();
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

#[test]
fn scan_help_names_no_flag_scan_does_not_accept() {
    let text = help(&["scan"]);
    assert!(
        !text.contains("--path"),
        "scan takes the path as a positional argument:\n{text}"
    );
    assert!(text.contains("remain inside the scanned path"));
}

#[test]
fn decoration_auto_help_states_the_platform_rule_the_code_applies() {
    let text = help(&["scan"]);
    assert!(
        text.contains("everywhere except Windows"),
        "auto is chosen by platform, not by whether output is a terminal:\n{text}"
    );
    assert!(!text.contains("for a terminal"));
}
