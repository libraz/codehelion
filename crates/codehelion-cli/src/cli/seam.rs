//! Argument declarations for the commands that read the repository's own
//! history: `history`, `seam` and `guard`.

use std::path::PathBuf;

use clap::ValueEnum;

/// Output format for the history and seam commands.
///
/// Kept apart from [`Format`](super::Format): SARIF describes the results of an analysis run,
/// and these commands count commits rather than analysing code, so offering it
/// would advertise a shape their output does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeamFormat {
    /// Human-readable text.
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Where a history-reading command looks and what it writes.
///
/// Shared by the three commands so that a reader who has learned one has
/// learned the others: the same spelling for the repository, the same spelling
/// for the configuration, the same spelling for the destination.
#[derive(Debug, Clone, clap::Args)]
pub struct SeamCommonArgs {
    /// Repository path whose history and configuration to read.
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from `--path`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = SeamFormat::Text)]
    pub format: SeamFormat,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    pub force: bool,
}

/// Arguments for the `history` subcommand.
#[derive(Debug, clap::Args)]
pub struct HistoryArgs {
    /// Where to look and what to write.
    #[command(flatten)]
    pub common: SeamCommonArgs,
    /// Read the history ending at this revision instead of at `HEAD`.
    ///
    /// What makes two generations comparable: a count taken over "everything
    /// up to now" moves because the repository grew, which is not the movement
    /// anyone is measuring.
    #[arg(long, value_name = "REV")]
    pub until: Option<String>,
}

/// Arguments for the `seam` subcommand.
#[derive(Debug, clap::Args)]
pub struct SeamArgs {
    /// Where to look and what to write.
    #[command(flatten)]
    pub common: SeamCommonArgs,
    /// Read the history ending at this revision instead of at `HEAD`.
    #[arg(long, value_name = "REV")]
    pub until: Option<String>,
    /// Propose seam candidates from co-change instead of reporting the ledger.
    ///
    /// Nothing is written to the ledger. Promoting a candidate is a decision a
    /// person makes, and it is what keeps what `guard` judges from moving on
    /// its own.
    #[arg(long)]
    pub suggest: bool,
    /// Audit database to record this evaluation in.
    ///
    /// Left off, the same database every other command resolves for itself.
    #[arg(long, value_name = "FILE")]
    pub db: Option<PathBuf>,
    /// Report the evaluation without recording it.
    ///
    /// The counts still reach the reader; nothing is written, so the next run
    /// compares itself with whatever generation was recorded before this one.
    #[arg(long)]
    pub no_record: bool,
}

/// Arguments for the `guard` subcommand.
#[derive(Debug, clap::Args)]
pub struct GuardArgs {
    /// Where to look and what to write.
    #[command(flatten)]
    pub common: SeamCommonArgs,
    /// Judge the change from this revision to `HEAD` instead of the working
    /// tree.
    #[arg(long, value_name = "REV", conflicts_with = "paths")]
    pub since: Option<String>,
    /// Name the seam each of these paths belongs to, and the members that
    /// would have to move with it.
    ///
    /// The lookup a person runs before editing. It reads the ledger alone: no
    /// commit, no history, no repository.
    #[arg(long, value_name = "PATH", num_args = 1..)]
    pub paths: Vec<String>,
    /// Exit non-zero when a seam was changed on one side only.
    ///
    /// Off by default, because a fix that belongs to one member alone is a
    /// correct one-sided change and nothing here can tell the two apart. There
    /// is no per-invocation exception: reporting is the default, so an escape
    /// hatch would exist only to defeat a flag somebody deliberately set. A
    /// seam that reports too much is one whose members are cut too coarsely.
    #[arg(long)]
    pub deny_asymmetric: bool,
}
