//! Argument declarations for the commands that inspect or maintain local
//! state: `doctor`, `config`, `baseline` and `cache`.

use std::path::PathBuf;

use clap::Subcommand;

/// Arguments for the `doctor` subcommand.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Repository path whose configuration and local database to inspect.
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from `--path`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override one compiler-helper location as `rust=PATH` or `clang=PATH`.
    #[arg(long = "helper", value_name = "NAME=PATH")]
    pub helpers: Vec<String>,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Treat the selected repository and its configuration as untrusted.
    ///
    /// A configured database path must remain inside `--path`; an explicit
    /// `--db` remains a deliberate operator choice.
    #[arg(long)]
    pub untrusted: bool,
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
/// Unlike the local database this is meant to be committed: it is a decision
/// the project made, and it has to travel with the code the decision is about.
pub const BASELINE_FILE_NAME: &str = "codehelion-baseline.json";

/// Actions for the `baseline` subcommand.
#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Freeze the last scan's reported findings as a baseline.
    Create(BaselineCreateArgs),
    /// Drop the baseline entries the last scan no longer reports.
    Update(BaselineArgs),
}

/// Arguments shared by the `baseline` actions.
#[derive(Debug, clap::Args)]
pub struct BaselineArgs {
    /// Scanned path whose recorded run the baseline is taken from.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from the scanned path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Baseline file to write.
    #[arg(long, default_value = BASELINE_FILE_NAME)]
    pub file: PathBuf,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for `baseline create`.
#[derive(Debug, clap::Args)]
pub struct BaselineCreateArgs {
    /// Arguments shared with `baseline update`.
    #[command(flatten)]
    pub common: BaselineArgs,
    /// Overwrite an existing baseline file.
    #[arg(long)]
    pub force: bool,
}

/// Actions for the `cache` subcommand.
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Show the local database's location and size.
    Status {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
    },
    /// Apply retention limits and compact the local database.
    Prune {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
        /// Newest standalone artifact analyses to retain.
        #[arg(long, default_value_t = 20)]
        keep_artifacts: usize,
        /// Newest comparisons of each kind to retain.
        #[arg(long, default_value_t = 20)]
        keep_comparisons: usize,
        /// Confirm deletion of retained local audit history.
        #[arg(long)]
        force: bool,
    },
    /// Permanently delete the local database.
    Clear {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
        /// Confirm permanent deletion of the local audit database.
        #[arg(long)]
        force: bool,
    },
}
