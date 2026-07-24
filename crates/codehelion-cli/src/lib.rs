//! Core library for the `codehelion` command-line tool.
//!
//! The binary in `main.rs` is a thin wrapper: it parses arguments into
//! [`cli::Cli`] and hands them to [`run`]. Keeping the logic here makes it
//! directly unit-testable without spawning a process.
//!
//! [`cli`] is the command layer; the engine lives in the `codehelion-core`
//! crate. This crate is the composition root: it wires the per-language
//! frontends and the store crate into the core engine, while `core` itself
//! depends on none of them.
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
pub mod report;
pub mod scan;
pub mod suppress;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;
use codehelion_store::Store;

use crate::cli::{
    BaselineAction, CacheAction, Cli, Command, ConfigAction, ExplainArgs, Format, Mode, ScanArgs,
};
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
            doctor_install(out)?;
            doctor_database(out)?;
            Ok(Outcome::Success)
        }
        Command::Config { action } => config_command(action, out),
        Command::Cache { action } => cache_command(action, out),
        Command::Scan(args) => scan_command(args, out),
        Command::Explain(args) => explain(args, out),
        Command::Baseline { action } => baseline(action),
        Command::Audit => bail!("audit is not available in this release"),
        Command::Artifact => bail!("artifact analysis is not available in this release"),
        Command::Divergence => bail!("divergence reporting is not available in this release"),
    }
}

fn scan_command(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    match args.mode {
        Mode::Structural => bail!("structural mode is not available in this release"),
        Mode::Semantic => bail!("semantic mode is not available in this release"),
        Mode::Fast => scan::run(args, out),
    }
}

/// Look one occurrence up by its stable finding id and print its detail.
///
/// Both output formats render the same [`report::FindingDetail`] value, in
/// the shape a scan report's member entries use.
fn explain(args: &ExplainArgs, out: &mut impl Write) -> Result<Outcome> {
    let path = resolve_db(args.db.as_deref())?;
    if !path.is_file() {
        bail!(
            "no audit database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = Store::open(&path)?;
    let Some(occurrence) = store.occurrence(&args.finding_id)? else {
        bail!(
            "no occurrence with finding id {} in {}",
            args.finding_id,
            path.display()
        );
    };
    let line = |value: Option<i64>| u32::try_from(value.unwrap_or(0)).unwrap_or(0);
    let detail = report::FindingDetail {
        member: report::Member {
            finding_id: occurrence.member.finding_hex,
            file: occurrence.member.file_path,
            start_line: line(occurrence.member.start_line),
            end_line: line(occurrence.member.end_line),
            unit: occurrence.member.unit_name,
            tokens: u64::try_from(occurrence.member.token_count).unwrap_or(0),
            canonical: occurrence.member.is_canonical,
        },
        group: report::GroupRef {
            fingerprint: occurrence.group_fingerprint_hex,
            clone_type: occurrence.clone_type,
            confidence: occurrence.score,
        },
        scan_run: occurrence.scan_run_id,
    };
    match args.format {
        Format::Json => write!(out, "{}", detail.to_json()?)?,
        Format::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

/// Append the binary's install channel and location to the doctor report.
fn doctor_install(out: &mut impl Write) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the executable path")?;
    writeln!(out)?;
    writeln!(
        out,
        "  install: {} ({})",
        install_channel(&exe),
        exe.display()
    )?;
    Ok(())
}

/// The distribution channel this binary appears to come from, inferred from
/// its on-disk location. A heuristic for diagnostics only: an unrecognised
/// location reports as a standalone install rather than failing.
fn install_channel(exe: &Path) -> &'static str {
    let components: Vec<String> = exe
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let has = |name: &str| components.iter().any(|c| c == name);
    if has("Cellar") || has("homebrew") || has(".linuxbrew") {
        return "homebrew";
    }
    if has(".cargo") {
        return "cargo (crates.io)";
    }
    if has("site-packages") {
        return "pypi";
    }
    let is_cargo_target = components
        .iter()
        .zip(components.iter().skip(1))
        .any(|(a, b)| a == "target" && (b == "debug" || b == "release"));
    if is_cargo_target {
        return "local build";
    }
    "standalone (archive or manual install)"
}

/// Append the audit database's location to the doctor report, with a hint
/// when the database would be committed to version control.
fn doctor_database(out: &mut impl Write) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving the current directory")?;
    let db = resolve_db(None)?;
    let db_abs = if db.is_absolute() {
        db.clone()
    } else {
        cwd.join(&db)
    };
    writeln!(out)?;
    match std::fs::metadata(&db_abs) {
        Ok(meta) => writeln!(
            out,
            "  audit database: {} ({} bytes)",
            db.display(),
            meta.len()
        )?,
        Err(_) => writeln!(out, "  audit database: {} (absent)", db.display())?,
    }
    if let Some(repo_root) = find_git_root(&cwd) {
        if !is_git_ignored(&repo_root, &db_abs) {
            writeln!(
                out,
                "  hint: the audit database is not matched by .gitignore; \
                 consider ignoring it (for example, add `.codehelion/`)"
            )?;
        }
    }
    Ok(())
}

/// The enclosing git repository root, found by walking up for a `.git` entry.
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        dir = current.parent();
    }
    None
}

/// Whether the repository root's `.gitignore` ignores `target`.
///
/// Only the root ignore file is consulted — this backs a hint, not an access
/// decision. Paths outside the repository are reported as ignored so the
/// hint stays quiet about them.
fn is_git_ignored(repo_root: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(repo_root) else {
        return true;
    };
    let (gitignore, _error) = ignore::gitignore::Gitignore::new(repo_root.join(".gitignore"));
    gitignore
        .matched_path_or_any_parents(relative, false)
        .is_ignore()
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

    fn scan_args(mode: Mode) -> ScanArgs {
        ScanArgs {
            path: PathBuf::from("."),
            mode,
            format: Format::Text,
            output: None,
            config: None,
            no_ignore: false,
            jobs: None,
            db: None,
            show_suppressed: false,
            verbose: false,
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
        // The test binary runs from the cargo target directory.
        assert!(text.contains("install: local build"));
    }

    #[test]
    fn install_channel_is_inferred_from_the_executable_location() {
        let channel = |path: &str| install_channel(Path::new(path));
        assert_eq!(
            channel("/opt/homebrew/Cellar/codehelion/0.1.0/bin/codehelion"),
            "homebrew"
        );
        assert_eq!(channel("/home/user/.linuxbrew/bin/codehelion"), "homebrew");
        assert_eq!(
            channel("/home/user/.cargo/bin/codehelion"),
            "cargo (crates.io)"
        );
        assert_eq!(
            channel("/venv/lib/python3.12/site-packages/codehelion/bin/codehelion"),
            "pypi"
        );
        assert_eq!(
            channel("/work/codehelion/target/release/codehelion"),
            "local build"
        );
        assert_eq!(
            channel("/usr/local/bin/codehelion"),
            "standalone (archive or manual install)"
        );
    }

    #[test]
    fn unsupported_scan_modes_report_their_reason() {
        let mut buffer = Vec::new();
        let structural = scan_command(&scan_args(Mode::Structural), &mut buffer).unwrap_err();
        assert!(format!("{structural:#}").contains("not available in this release"));
        let semantic = scan_command(&scan_args(Mode::Semantic), &mut buffer).unwrap_err();
        assert!(format!("{semantic:#}").contains("not available in this release"));
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
