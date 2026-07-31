//! A thin CLI wrapper used to drive semantic fault tests with a mock helper.
//!
//! Cargo gives integration tests this binary's exact path, so the tests never
//! guess at a target-directory layout or accidentally run a stale CLI.

use std::process::ExitCode;

use clap::Parser;
use codehelion_cli::cli::Cli;

/// Parse the ordinary CLI and forward it to the actual application entrypoint.
fn main() -> ExitCode {
    let cli = Cli::parse();
    match codehelion_cli::run(&cli) {
        Ok(outcome) => outcome.exit_code(),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
