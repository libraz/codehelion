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
//! `1` in `main`, and `clap` uses `2` for usage errors.
//!
//! A reader that stops reading — `codehelion scan | head` — ends the output,
//! not the run: the remaining text is dropped and the exit code stays the one
//! the completed work earned.

pub mod artifact;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod report;
pub mod scan;
#[doc(hidden)]
pub mod scan_lock;
pub mod seam;
pub mod semantic;
pub mod suppress;

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;

use crate::cli::{ArtifactAction, Cli, Command, Mode, ScanArgs};

pub(crate) mod provenance;

/// Digits in a full stable id.
const FULL_ID_CHARS: usize = 32;

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

/// A failure in the selected analysis stage, kept distinct from discovery,
/// persistence and output errors so the command can offer an honest mode
/// alternative only when another analysis is actually relevant.
#[derive(Debug)]
struct AnalysisFailure {
    mode: Mode,
    source: anyhow::Error,
}

impl fmt::Display for AnalysisFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} analysis failed: {}",
            self.mode.name(),
            self.source
        )
    }
}

impl std::error::Error for AnalysisFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn analysis_failure(mode: Mode, source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(AnalysisFailure { mode, source })
}

const fn analysis_hint(mode: Mode) -> &'static str {
    match mode {
        Mode::Fast => {
            "hint: fast analysis failed; structural mode measures parsed source independently"
        }
        Mode::Structural => {
            "hint: structural analysis failed; fast mode measures token-level duplication independently"
        }
        Mode::Semantic => {
            "hint: semantic analysis failed; structural and fast modes make separate parsed-source and token-level measurements"
        }
    }
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
/// Returns an error if the dispatched command fails, or if the completed
/// output cannot be delivered to standard output.
pub fn run(cli: &Cli) -> Result<Outcome> {
    let stdout = io::stdout();
    let mut out = UntilClosed::new(stdout.lock());
    let outcome = dispatch(&cli.command, &mut out)?;
    out.flush().context("writing to standard output")?;
    Ok(outcome)
}

/// A writer that takes a closed consumer as the end of the output.
///
/// `codehelion scan | head` closes the pipe once the reader has what it came
/// for. The analysis and the recording are complete by the time a report is
/// rendered, so the closed pipe is the reader's decision about how much to
/// read, not a failure of the run: the rest of the text is dropped and the
/// command still exits on what it did. Every other write failure is passed on.
struct UntilClosed<W: Write> {
    /// The stream the output is meant for.
    inner: W,
    /// Whether the consumer has already gone away.
    closed: bool,
}

impl<W: Write> UntilClosed<W> {
    /// Wrap a stream whose consumer may stop reading.
    const fn new(inner: W) -> Self {
        Self {
            inner,
            closed: false,
        }
    }
}

impl<W: Write> Write for UntilClosed<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(buf.len())
            }
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            other => other,
        }
    }
}

/// Dispatch a command to the given writer.
///
/// Separated from [`run`] so tests can capture output into an in-memory buffer.
fn dispatch(command: &Command, out: &mut impl Write) -> Result<Outcome> {
    match command {
        Command::Doctor(args) => {
            let root = codehelion_core::paths::canonical(&args.path)
                .with_context(|| format!("resolving path {}", args.path.display()))?;
            let resolved = config::load(args.config.as_deref(), &root)?;
            if let Some(note) = config::disregarded_helpers_note(&resolved) {
                eprintln!("{note}");
            }
            let helpers = config::helper_paths(&resolved, &args.helpers)?;
            // The lookup is supplied here rather than by the engine: starting
            // a program is this layer's business, and keeping it out of the
            // engine is what stops a compiler helper from becoming something
            // the analysis crates link.
            doctor::render(
                &doctor::diagnose_with(&|name| {
                    interrogate(
                        name,
                        configured_helper_path(name, &helpers),
                        codehelion_helper::SandboxRequest::unrestricted(),
                    )
                }),
                out,
            )?;
            writeln!(out, "  {}", codehelion_helper::doctor_summary())?;
            let semantic_rules = codehelion_core::semantic::registered_rules();
            let same_variant_rules = semantic_rules
                .iter()
                .filter(|rule| {
                    rule.scope == codehelion_core::semantic::SemanticRuleScope::SameBuildVariant
                })
                .count();
            writeln!(
                out,
                "  restricted semantic rules: {same_variant_rules} enabled; {} cross-language rules require --compare-languages (registry {})",
                semantic_rules.len().saturating_sub(same_variant_rules),
                codehelion_core::semantic::SEMANTIC_RULE_REGISTRY_VERSION,
            )?;
            doctor_install(out)?;
            doctor_database(args, out)?;
            doctor_artifacts(out)?;
            Ok(Outcome::Success)
        }
        Command::Config { action } => config_command(action, out),
        Command::Cache { action } => cache_command(action, out),
        Command::Scan(args) => scan_command(args, out),
        Command::Report(args) => report_command(args, out),
        Command::Explain(args) => explain(args, out),
        Command::Baseline { action } => baseline(action, out),
        Command::Artifact { action } => match action {
            ArtifactAction::Analyze(args) => artifact::run(args, out),
            ArtifactAction::Report(args) => artifact::report(args, out),
            ArtifactAction::Isolated(args) => artifact::run_isolated_worker(args),
            ArtifactAction::Compare(args) => artifact::compare(args, out),
            ArtifactAction::Calibration(args) => artifact::calibration(args, out),
        },
        Command::History(args) => seam::history(args, out),
        Command::Seam(args) => seam::seam(args, out),
        Command::Guard(args) => seam::guard(args, out),
    }
}

fn configured_helper_path<'a>(name: &str, helpers: &'a config::Helpers) -> Option<&'a Path> {
    match name {
        "codehelion-backend-rust" => helpers.rust.as_deref(),
        "codehelion-backend-clang" => helpers.clang.as_deref(),
        _ => None,
    }
}

fn scan_command(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    if args.compare_build_variants && args.mode != Mode::Semantic {
        bail!("--compare-build-variants requires --mode semantic");
    }
    if args.compare_languages && args.mode != Mode::Semantic {
        bail!("--compare-languages requires --mode semantic");
    }
    if args.include_trivial && args.mode == Mode::Fast {
        bail!("--include-trivial requires --mode structural or --mode semantic");
    }
    if args.siblings_by_signature && args.mode == Mode::Fast {
        bail!("--siblings-by-signature requires --mode structural or --mode semantic");
    }
    // Only semantic analysis starts a compiler helper. Pinning one for a mode
    // that starts none reads as pinning the run, so it is refused with the mode
    // named rather than accepted and ignored.
    if !args.helpers.is_empty() && args.mode != Mode::Semantic {
        bail!(
            "--helper has nothing to act on in {} mode, which reads source \
             without a compiler helper; it applies to --mode semantic",
            args.mode.name()
        );
    }
    // Resolved before the mode is dispatched on, because a permission that
    // nothing in the chosen mode could act on is refused rather than accepted:
    // Fast and Structural run nothing whatever they are told, and somebody who
    // granted an execution to one of them is owed the sentence saying so.
    let permitted = scan::permitted(args)?;
    // The scan lock creates the database's parent directory. Capture whether
    // that would be a first creation before dispatching into any mode, then
    // announce it only after the complete scan (including report output) has
    // succeeded.
    let database_hint = scan::new_database_directory_hint(args)?;
    let result = match args.mode {
        Mode::Semantic => scan::structural::semantic(args, &permitted, out),
        Mode::Structural => scan::structural::run(args, out),
        Mode::Fast => scan::run(args, out),
    };
    if let Err(error) = &result
        && let Some(failure) = error.downcast_ref::<AnalysisFailure>()
    {
        eprintln!("{}", analysis_hint(failure.mode));
    }
    if result.is_ok()
        && let Some(hint) = database_hint
    {
        hint.emit();
    }
    result
}

/// Re-render a completed snapshot without reading the scanned source tree.
pub(crate) mod report_command;

use report_command::{explain, report_command};

/// Resolve the local-database path: an explicit flag wins, otherwise the
/// configured location (discovered `codehelion.toml` or defaults).
fn resolve_db(intent: scan::DatabaseUse, flag: Option<&Path>) -> Result<PathBuf> {
    let current = std::env::current_dir().context("resolving the current directory")?;
    let root =
        codehelion_core::paths::canonical(&current).context("resolving the current directory")?;
    resolve_db_at(intent, &root, flag, None, false)
}

/// Resolve a local-database path for the repository selected by one command.
///
/// All source-audit commands use this path so an explicit database, a named
/// configuration, and a discovered configuration receive identical handling.
/// What the command then does with the file decides whether a default this
/// build cannot open is stepped around; see [`scan::DatabaseUse`].
fn resolve_db_at(
    intent: scan::DatabaseUse,
    root: &Path,
    flag: Option<&Path>,
    config_path: Option<&Path>,
    untrusted: bool,
) -> Result<PathBuf> {
    let root = codehelion_core::paths::canonical(root)
        .with_context(|| format!("resolving path {}", root.display()))?;
    let resolved_config = config::load(config_path, &root)?;
    scan::database_path_for(intent, &root, flag, &resolved_config, untrusted)
}

mod baseline_command;
mod cache;
mod doctor_command;
mod git;

use baseline_command::{baseline, config_command};
use cache::cache_command;
use doctor_command::{doctor_artifacts, doctor_database, doctor_install, interrogate};
pub(crate) use git::{find_git_root, is_git_ignored};

// Names the crate-local test module reads through `use super::*`, and that the
// crate root does not otherwise mention.
#[cfg(test)]
use crate::cache::{database_files, database_storage_bytes};
#[cfg(test)]
use crate::cli::DoctorArgs;
#[cfg(test)]
use crate::doctor_command::install_channel;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
