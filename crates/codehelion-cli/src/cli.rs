//! Command-line interface definition, built with `clap`'s derive API.
//!
//! This module only declares the surface: the parsed [`Cli`] is handed to
//! [`crate::run`], which dispatches each [`Command`]. Commands that depend on
//! parts of the engine or store that do not exist yet parse and validate their
//! arguments here, then fail with an explicit message at dispatch.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

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
    /// Scan a codebase for duplicate logic.
    Scan(ScanArgs),
    /// Inspect or initialise configuration.
    Config {
        /// Configuration action.
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Explain a finding by its stable ID.
    Explain(ExplainArgs),
    /// Record or manage scan baselines.
    Baseline {
        /// Baseline action.
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Report which analysis components are available on this machine.
    Doctor,
    /// Inspect or clear cached scan state.
    Cache {
        /// Cache action.
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Report what became of the duplication since the previous audit.
    Audit(AuditArgs),
    /// Analyse compiled artifacts.
    Artifact,
    /// Report source/artifact divergence.
    Divergence,
}

/// Analysis mode selecting how much work the scan performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Token-level Type-1/Type-2 and partial-clone detection; never runs the
    /// target code.
    Fast,
    /// Syntax-structural detection: gapped Type-3 clones and duplicated
    /// statement runs, judged on a similarity breakdown. Parses the sources
    /// and never runs the target code.
    Structural,
    /// Semantic detection via out-of-process compiler helpers. Not available
    /// in this release.
    Semantic,
}

/// Output format for a scan report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable aligned text.
    Text,
    /// Machine-readable JSON (versioned schema).
    Json,
    /// SARIF 2.1.0 log, for static-analysis result consumers.
    Sarif,
}

/// Output format for a single finding's detail view.
///
/// Kept apart from [`Format`]: SARIF describes a run's results, so offering it
/// for a one-occurrence lookup would advertise a format the command could not
/// produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DetailFormat {
    /// Human-readable text.
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Arguments for the `scan` subcommand.
#[derive(Debug, clap::Args)]
#[allow(clippy::struct_excessive_bools)] // independent CLI switches, not a state machine
pub struct ScanArgs {
    /// Path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Analysis mode.
    #[arg(long, value_enum, default_value_t = Mode::Fast)]
    pub mode: Mode,
    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Configuration file to use instead of the discovered `codehelion.toml`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Also scan files that `.gitignore` and related ignore files would hide.
    #[arg(long)]
    pub no_ignore: bool,
    /// Number of worker threads (default: automatic).
    #[arg(long)]
    pub jobs: Option<usize>,
    /// Audit-database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Hide the findings this baseline file froze, reporting what came after.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Also list suppressed groups, with the reason each was hidden.
    #[arg(long)]
    pub show_suppressed: bool,
    /// List every group and every member instead of the summarised excerpt.
    #[arg(long)]
    pub verbose: bool,
    /// Exit with a non-zero status if any findings are reported.
    #[arg(long)]
    pub fail_on_findings: bool,
}

/// Arguments for the `explain` subcommand.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Stable finding ID to explain.
    pub finding_id: String,
    /// Output format for the detail view.
    #[arg(long, value_enum, default_value_t = DetailFormat::Text)]
    pub format: DetailFormat,
    /// Audit-database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for the `audit` subcommand.
#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    /// Scanned path whose recorded runs are compared.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Compare against this exported JSON scan report instead of against the
    /// run recorded before the latest one.
    #[arg(long)]
    pub previous: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = DetailFormat::Text)]
    pub format: DetailFormat,
    /// Also list the groups that did not change.
    #[arg(long)]
    pub show_unchanged: bool,
    /// Exit with a non-zero status if any duplication is new, spreading or
    /// drifting apart.
    #[arg(long)]
    pub fail_on_new: bool,
    /// Audit-database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Actions for the `config` subcommand.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective configuration after resolving files and defaults.
    Show {
        /// Configuration file to use instead of the discovered one.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Write a commented configuration template.
    Init {
        /// Destination file (default: `codehelion.toml` in the current
        /// directory).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Overwrite the destination if it already exists.
        #[arg(long)]
        force: bool,
    },
}

/// Default baseline file, relative to the working directory.
///
/// Unlike the audit database this is meant to be committed: it is a decision
/// the project made, and it has to travel with the code the decision is about.
pub const BASELINE_FILE_NAME: &str = "codehelion-baseline.json";

/// Actions for the `baseline` subcommand.
#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Freeze the last scan's reported findings as a baseline.
    Create(BaselineArgs),
    /// Drop the baseline entries the last scan no longer reports.
    Update(BaselineArgs),
    /// Rewrite a baseline's identifiers onto a run made under changed rules.
    Migrate(MigrateArgs),
}

/// Arguments shared by the `baseline` actions.
#[derive(Debug, clap::Args)]
pub struct BaselineArgs {
    /// Scanned path whose recorded run the baseline is taken from.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Baseline file to write.
    #[arg(long, default_value = BASELINE_FILE_NAME)]
    pub file: PathBuf,
    /// Overwrite an existing baseline file.
    #[arg(long)]
    pub force: bool,
    /// Audit-database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for `baseline migrate`.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    /// Scanned path whose recorded runs the rewrite reads.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Baseline file to rewrite.
    #[arg(long, default_value = BASELINE_FILE_NAME)]
    pub file: PathBuf,
    /// Recorded run to rewrite the baseline onto. Defaults to the newest
    /// completed scan of the path.
    #[arg(long)]
    pub to_run: Option<i64>,
    /// Report what the rewrite would do without writing anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Audit-database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Actions for the `cache` subcommand.
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Show the audit database's location and size.
    Status {
        /// Audit-database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Delete the audit database.
    Clear {
        /// Audit-database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
    },
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
