//! Binary entry point for `codehelion`.
//!
//! Parses command-line arguments and delegates to the library's
//! [`codehelion_cli::run`]; all real logic lives in the library crate.

use std::process::ExitCode;

use clap::Parser;

use codehelion_cli::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match codehelion_cli::run(&cli) {
        Ok(outcome) => outcome.exit_code(),
        Err(err) => {
            // `{err:#}` renders the whole anyhow context chain.
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
