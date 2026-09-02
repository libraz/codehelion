//! Locating the compiler this helper analyses with.
//!
//! Its own, bundled as a library — not the one the project builds with. The
//! toolchain is discovered once, from an isolated directory, so that no
//! `rust-toolchain.toml` in a tree under analysis can choose it.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The helper's installed toolchain, fixed before any target workspace is
/// inspected. The absolute sysroot tells rustup proxies to ignore a target
/// repository's `rust-toolchain.toml`.
#[derive(Clone)]
pub(super) struct HelperToolchain {
    pub(super) cargo: PathBuf,
    /// The compiler every Cargo this process starts is told to run, so that
    /// naming one is never left to a file in the tree being read.
    pub(super) rustc: PathBuf,
    pub(super) rustup_toolchain: String,
}

static HELPER_TOOLCHAIN: OnceLock<Result<HelperToolchain, String>> = OnceLock::new();

/// The toolchain this helper itself was built with, recorded by the build
/// script rather than read from a target tree.
const HELPER_TOOLCHAIN_CHANNEL: &str = env!("CODEHELION_HELPER_TOOLCHAIN");

pub(super) fn helper_toolchain() -> Result<HelperToolchain, String> {
    HELPER_TOOLCHAIN
        .get_or_init(discover_helper_toolchain)
        .clone()
}

/// Find the toolchain this helper analyses with, before it offers to.
///
/// Every capability this program names at the handshake is answered by a
/// compiler it locates rather than links, so locating one is part of being able
/// to make the offer. A helper that shook hands and then declined each request
/// for want of a toolchain would have `doctor` report a working semantic
/// analysis on a machine where no scan can get one, and leave the scan to
/// discover it.
///
/// The result is kept, so a request pays nothing for having been checked here.
///
/// # Errors
///
/// Returns why the toolchain could not be located or could not answer.
pub(crate) fn require_toolchain() -> Result<(), String> {
    helper_toolchain().map(|_| ())
}

#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn discover_helper_toolchain() -> Result<HelperToolchain, String> {
    let rustup = resolve_tool(ra_ap_toolchain::Tool::Rustup)?;
    let working_directory = tempfile::tempdir()
        .map_err(|error| format!("creating an isolated toolchain directory: {error}"))?;
    let channel = HELPER_TOOLCHAIN_CHANNEL;
    let cargo = rustup_tool(&rustup, channel, "cargo", working_directory.path())?;
    let rustc = rustup_tool(&rustup, channel, "rustc", working_directory.path())?;
    let output = std::process::Command::new(&rustc)
        .args(["--print", "sysroot"])
        .current_dir(working_directory.path())
        .output()
        .map_err(|error| format!("could not start helper Rustc: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "helper Rustc could not report its installed sysroot: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let sysroot = sysroot.canonicalize().map_err(|error| {
        format!(
            "resolving helper Rustc sysroot {}: {error}",
            sysroot.display()
        )
    })?;
    if !sysroot.is_dir() {
        return Err(format!(
            "helper Rustc sysroot {} is not a directory",
            sysroot.display()
        ));
    }
    Ok(HelperToolchain {
        cargo,
        rustc,
        rustup_toolchain: sysroot.display().to_string(),
    })
}

#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn rustup_tool(
    rustup: &Path,
    channel: &str,
    tool: &str,
    working_directory: &Path,
) -> Result<PathBuf, String> {
    let output = std::process::Command::new(rustup)
        .args(["which", tool])
        .current_dir(working_directory)
        .env("RUSTUP_TOOLCHAIN", channel)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .map_err(|error| format!("could not locate helper {tool}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not locate helper {tool} for toolchain {channel}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.canonicalize().map_err(|error| {
        format!(
            "resolving helper {tool} executable {}: {error}",
            path.display()
        )
    })
}

/// Locate a tool, keeping the name it was found under.
///
/// The link is deliberately left unresolved. `rustup` is a multi-call binary
/// that decides which program to be from the name it was started as, and some
/// distributions install it as a link to `rustup-init`. Resolving that link
/// turns every query into the installer, which answers a request to locate a
/// toolchain by printing its own usage. `is_file` follows the link, so a name
/// pointing at nothing is still reported here rather than at the first
/// spawn.
fn resolve_tool(tool: ra_ap_toolchain::Tool) -> Result<PathBuf, String> {
    executable_named(tool.path().into_std_path_buf(), tool.name())
}

/// Confirm a located tool can be started, returning the path unchanged.
fn executable_named(path: PathBuf, tool: &str) -> Result<PathBuf, String> {
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "helper {tool} executable {} is not a file",
            path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    /// A located tool keeps the name it was found under, links and all.
    ///
    /// `rustup` is one binary that is several programs, told apart by the name
    /// it was started as. Installations that link `rustup` to `rustup-init`
    /// are ordinary, and following that link hands every toolchain query to
    /// the installer instead.
    ///
    /// Stated where a link can be made without asking permission first. The
    /// systems that cannot are the ones where the installations in question
    /// do not exist either.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // Test setup requires a writable temporary directory.
    fn a_linked_tool_keeps_the_name_it_was_found_under() {
        use super::executable_named;

        let directory = tempfile::tempdir().expect("a temporary directory");
        let target = directory.path().join("rustup-init");
        std::fs::write(&target, "").expect("writing the link target");
        let link = directory.path().join("rustup");
        std::os::unix::fs::symlink(&target, &link).expect("linking one name to the other");

        assert_eq!(executable_named(link.clone(), "Rustup"), Ok(link));
    }

    /// Fixed when the helper is built, because nothing at run time can supply
    /// it: an empty value would be handed to every rustup proxy, and rustup
    /// answers an empty `RUSTUP_TOOLCHAIN` by selecting whatever the directory
    /// it runs in declares — the one outcome this constant exists to prevent.
    #[test]
    fn the_helper_knows_which_toolchain_it_was_built_with() {
        assert!(
            !super::HELPER_TOOLCHAIN_CHANNEL.trim().is_empty(),
            "the build recorded no toolchain"
        );
    }
}
