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

fn main() {
    println!("cargo::rerun-if-env-changed=RUSTUP_TOOLCHAIN");
    // Absent when the build is not driven by a rustup proxy. The helper looks
    // for rustup at run time regardless, and reports its own failure to find
    // one, so the default is the channel rustup itself defaults to rather than
    // a build-time refusal.
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "stable".to_owned());
    println!("cargo::rustc-env=CODEHELION_HELPER_TOOLCHAIN={toolchain}");
}
