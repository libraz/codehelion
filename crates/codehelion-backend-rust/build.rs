//! Records the toolchain this helper is being compiled with.
//!
//! The helper starts `cargo` and `rustc` for whatever project it is asked
//! about, and a project is entitled to pin a toolchain of its own. Naming the
//! one this program was built against keeps that pin from choosing the
//! compiler the helper itself runs on.
//!
//! It is read from the environment rather than from the workspace's
//! `rust-toolchain.toml`, because that file sits outside this package: a copy
//! built from a published tarball has no such file to read, and what matters
//! to a copy built anywhere else is the toolchain it was actually built with.

/// The version the manifest pins `ra_ap_hir` to.
///
/// Every `ra_ap_*` crate is pinned to one version, and a `0.0.x` requirement
/// admits that version alone, so the pin is the version linked into the helper.
/// Read from the manifest the build is given, which a published tarball carries
/// as well, so there is no second copy of the number to keep in step. The
/// workspace spells the pin inline; `cargo package` normalizes it into a
/// `[dependencies.ra_ap_hir]` table with a `version` key, so both are read.
fn rust_analyzer_version() -> Option<String> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let text = std::fs::read_to_string(std::path::Path::new(&manifest).join("Cargo.toml")).ok()?;
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line == "[dependencies.ra_ap_hir]" {
            let version = lines
                .take_while(|line| !line.starts_with('['))
                .find(|line| line.starts_with("version ") || line.starts_with("version="))?;
            return version.split('"').nth(1).map(str::to_owned);
        }
        if line.starts_with("ra_ap_hir ") || line.starts_with("ra_ap_hir=") {
            return line.split('"').nth(1).map(str::to_owned);
        }
    }
    None
}

fn main() {
    println!("cargo::rerun-if-changed=Cargo.toml");
    let Some(version) = rust_analyzer_version() else {
        eprintln!("build.rs: Cargo.toml does not pin ra_ap_hir to a version in quotes");
        std::process::exit(1);
    };
    println!("cargo::rustc-env=CODEHELION_RUST_ANALYZER_VERSION={version}");
    println!("cargo::rerun-if-env-changed=RUSTUP_TOOLCHAIN");
    // Absent when the build is not driven by a rustup proxy. The helper looks
    // for rustup at run time regardless, and reports its own failure to find
    // one, so the default is the channel rustup itself defaults to rather than
    // a build-time refusal.
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "stable".to_owned());
    println!("cargo::rustc-env=CODEHELION_HELPER_TOOLCHAIN={toolchain}");
}
