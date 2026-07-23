//! Core library for the `codehelion` command-line tool.
//!
//! The binary in `main.rs` is a thin wrapper: it parses arguments into
//! [`cli::Cli`] and hands them to [`run`]. Keeping the logic here makes it
//! directly unit-testable without spawning a process.
//!
//! Modules mirror the eventual workspace crates. [`cli`] is the command layer;
//! [`core`] is the engine layer. The dependency direction is strictly
//! `cli -> core`.

pub mod cli;
pub mod core;
#[cfg(feature = "eval")]
pub mod eval;

use std::io::{self, Write};

use anyhow::Result;

use crate::cli::{Cli, Command};

/// Execute the parsed command, writing output to stdout.
///
/// # Errors
///
/// Returns an error if writing output fails.
pub fn run(cli: &Cli) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    dispatch(&cli.command, &mut out)
}

/// Dispatch a command to the given writer.
///
/// Separated from [`run`] so tests can capture output into an in-memory buffer.
fn dispatch(command: &Command, out: &mut impl Write) -> Result<()> {
    match command {
        Command::Doctor => {
            core::doctor::render(&core::doctor::diagnose(), out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_doctor_writes_diagnostics() {
        let mut buffer = Vec::new();
        dispatch(&Command::Doctor, &mut buffer).expect("dispatch should succeed");
        let text = String::from_utf8(buffer).expect("output is utf-8");
        assert!(text.contains("codehelion"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }
}
