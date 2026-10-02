//! The forbidden-crate list of the dependency boundary script, checked without
//! running `cargo tree` over the workspace.
#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::disallowed_types)]

use std::path::PathBuf;
use std::process::Command;

/// The script's `is_forbidden_crate` function, lifted out of it.
fn classifier() -> String {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify-helper-boundaries.sh");
    let text = std::fs::read_to_string(&script).expect("the boundary script is readable");
    let start = text
        .find("is_forbidden_crate() {")
        .expect("the script defines is_forbidden_crate");
    let end = start + text[start..].find("\n}\n").expect("the function ends") + 3;
    text[start..end].to_owned()
}

fn is_forbidden(crate_name: &str) -> bool {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{}\nis_forbidden_crate \"$1\"", classifier()))
        .arg("sh")
        .arg(crate_name)
        .status()
        .expect("run sh");
    status.success()
}

#[test]
fn analysis_engine_crates_are_forbidden_below_the_engine_and_cli() {
    for name in [
        "rustc_driver",
        "libclang",
        "codehelion-backend-rust",
        "ra_ap_hir",
        "ra_ap_hir_def",
        "ra_ap_hir_ty",
        "ra_ap_ide_db",
        "ra_ap_load-cargo",
        "ra_ap_project_model",
        "ra_ap_vfs",
        "ra_ap_toolchain",
    ] {
        assert!(is_forbidden(name), "{name} is allowed");
    }
}

#[test]
fn lexer_level_crates_stay_allowed() {
    for name in [
        "ra_ap_syntax",
        "ra_ap_parser",
        "ra_ap_stdx",
        "ra_ap_edition",
        "ra-ap-rustc_lexer",
        "rustc-hash",
        "serde",
    ] {
        assert!(!is_forbidden(name), "{name} is forbidden");
    }
}
