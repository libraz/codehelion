//! Command-line interface definition, built with `clap`'s derive API.

use clap::{Parser, Subcommand};

/// Top-level command-line parser.
#[derive(Debug, Parser)]
#[command(name = "codehelion", version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Report which analysis components are available on this machine.
    Doctor,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // `debug_assert` catches structural mistakes in the clap definition.
        Cli::command().debug_assert();
    }
}
