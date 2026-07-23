//! Core library for the `codehelion` command-line tool.
//!
//! The binary in `main.rs` is a thin wrapper: it parses arguments into
//! [`cli::Cli`] and hands them to [`run`]. Keeping the logic here makes it
//! directly unit-testable without spawning a process.
//!
//! [`cli`] is the command layer; the engine lives in the `codehelion-core`
//! crate. The dependency direction is strictly `cli -> core`.
//!
//! # Exit status
//!
//! `run` returns an [`Outcome`] that maps to a process exit code: `0` on
//! success (whether or not findings were reported), and [`EXIT_FINDINGS`] when
//! a scan reported findings and `--fail-on-findings` was set. Any error maps to
//! `1` in `main`, and `clap` uses `2` for usage errors. Commands whose engine
//! or store support is not built yet fail with an explicit message.

pub mod cli;
pub mod config;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;

use crate::cli::{BaselineAction, CacheAction, Cli, Command, ConfigAction, Mode, ScanArgs};
use crate::config::ConfigSource;

/// Exit code returned when a scan reports findings and gating is requested.
pub const EXIT_FINDINGS: u8 = 3;

/// Successful command outcome, carrying the process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command completed; exit `0`.
    Success,
    /// A scan reported findings and `--fail-on-findings` was set; exit
    /// [`EXIT_FINDINGS`].
    FindingsPresent,
}

impl Outcome {
    /// Process exit code for this outcome.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::FindingsPresent => ExitCode::from(EXIT_FINDINGS),
        }
    }
}

/// Execute the parsed command, writing output to stdout.
///
/// # Errors
///
/// Returns an error if a command fails, including commands whose support is not
/// built in this release.
pub fn run(cli: &Cli) -> Result<Outcome> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    dispatch(&cli.command, &mut out)
}

/// Dispatch a command to the given writer.
///
/// Separated from [`run`] so tests can capture output into an in-memory buffer.
fn dispatch(command: &Command, out: &mut impl Write) -> Result<Outcome> {
    match command {
        Command::Doctor => {
            doctor::render(&doctor::diagnose(), out)?;
            Ok(Outcome::Success)
        }
        Command::Config { action } => config_command(action, out),
        Command::Cache { action } => cache_command(action, out),
        Command::Scan(args) => scan(args),
        Command::Explain(_) => bail!("explain is not yet implemented"),
        Command::Baseline { action } => baseline(action),
        Command::Audit => bail!("audit is not available in this release"),
        Command::Artifact => bail!("artifact analysis is not available in this release"),
        Command::Divergence => bail!("divergence reporting is not available in this release"),
    }
}

fn scan(args: &ScanArgs) -> Result<Outcome> {
    match args.mode {
        Mode::Structural => bail!("structural mode is not available in this release"),
        Mode::Semantic => bail!("semantic mode is not available in this release"),
        // The Fast engine lands in a later step; argument parsing, config
        // resolution and the exit-code contract are wired now.
        Mode::Fast => bail!("fast scanning is not yet implemented"),
    }
}

fn baseline(action: &BaselineAction) -> Result<Outcome> {
    match action {
        BaselineAction::Create { .. } => bail!("baseline recording is not yet implemented"),
    }
}

fn config_command(action: &ConfigAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        ConfigAction::Show { config } => {
            let start = std::env::current_dir().context("resolving the current directory")?;
            let resolved = config::load(config.as_deref(), &start)?;
            match &resolved.source {
                ConfigSource::File(path) => writeln!(out, "# source: {}", path.display())?,
                ConfigSource::Defaults => writeln!(out, "# source: built-in defaults")?,
            }
            write!(out, "{}", resolved.config.to_toml()?)?;
            Ok(Outcome::Success)
        }
        ConfigAction::Init { output, force } => {
            let path = output
                .clone()
                .unwrap_or_else(|| PathBuf::from(config::CONFIG_FILE_NAME));
            if path.exists() && !force {
                bail!(
                    "{} already exists; pass --force to overwrite",
                    path.display()
                );
            }
            std::fs::write(&path, config::TEMPLATE)
                .with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
            Ok(Outcome::Success)
        }
    }
}

fn cache_command(action: &CacheAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        CacheAction::Status { db } => {
            let path = resolve_db(db.as_deref())?;
            match std::fs::metadata(&path) {
                Ok(meta) => writeln!(out, "database: {} ({} bytes)", path.display(), meta.len())?,
                Err(_) => writeln!(out, "database: {} (absent)", path.display())?,
            }
            Ok(Outcome::Success)
        }
        CacheAction::Clear { db } => {
            let path = resolve_db(db.as_deref())?;
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
                writeln!(out, "removed {}", path.display())?;
            } else {
                writeln!(out, "nothing to remove at {}", path.display())?;
            }
            Ok(Outcome::Success)
        }
    }
}

/// Resolve the audit-database path: an explicit flag wins, otherwise the
/// configured location (discovered `codehelion.toml` or defaults).
fn resolve_db(flag: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }
    let start = std::env::current_dir().context("resolving the current directory")?;
    Ok(config::load(None, &start)?.config.database)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cli::{Format, ScanArgs};

    fn scan_args(mode: Mode) -> ScanArgs {
        ScanArgs {
            path: PathBuf::from("."),
            mode,
            format: Format::Text,
            output: None,
            config: None,
            jobs: None,
            db: None,
            fail_on_findings: false,
        }
    }

    #[test]
    fn dispatch_doctor_writes_diagnostics() {
        let mut buffer = Vec::new();
        let outcome = dispatch(&Command::Doctor, &mut buffer).expect("dispatch should succeed");
        assert_eq!(outcome, Outcome::Success);
        let text = String::from_utf8(buffer).expect("output is utf-8");
        assert!(text.contains("codehelion"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn scan_modes_report_distinct_unsupported_reasons() {
        let structural = scan(&scan_args(Mode::Structural)).unwrap_err();
        assert!(format!("{structural:#}").contains("not available in this release"));
        let fast = scan(&scan_args(Mode::Fast)).unwrap_err();
        assert!(format!("{fast:#}").contains("not yet implemented"));
    }

    #[test]
    fn findings_outcome_maps_to_dedicated_exit_code() {
        assert_eq!(Outcome::Success.exit_code(), ExitCode::SUCCESS);
        assert_eq!(
            Outcome::FindingsPresent.exit_code(),
            ExitCode::from(EXIT_FINDINGS)
        );
    }
}
