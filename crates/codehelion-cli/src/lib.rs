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

pub mod artifact;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod report;
pub mod scan;
#[doc(hidden)]
pub mod scan_lock;
pub mod semantic;
pub mod suppress;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;
use codehelion_store::query::{IdKind, IdMatch, RunOrigin};
use codehelion_store::{Store, fingerprint_hex};

use crate::cli::{
    ArtifactAction, BaselineAction, CacheAction, Cli, Command, ConfigAction, DetailFormat,
    ExplainArgs, Mode, ReportArgs, ScanArgs,
};
use crate::config::ConfigSource;

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
            // The lookup is supplied here rather than by the engine: starting
            // a program is this layer's business, and keeping it out of the
            // engine is what stops a compiler helper from becoming something
            // the analysis crates link.
            doctor::render(
                &doctor::diagnose_with(&|name| {
                    interrogate(
                        name,
                        None,
                        codehelion_helper::SandboxRequest::unrestricted(),
                    )
                }),
                out,
            )?;
            writeln!(out, "  {}", codehelion_helper::doctor_summary())?;
            writeln!(
                out,
                "  restricted semantic rules: {} enabled (registry {})",
                codehelion_core::semantic::registered_rules().len(),
                codehelion_core::semantic::SEMANTIC_RULE_REGISTRY_VERSION,
            )?;
            doctor_install(out)?;
            doctor_database(out)?;
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
    }
}

/// How long a diagnostic waits for a helper to introduce itself.
///
/// Shorter than a scan's, because a handshake reads nothing: a helper that
/// takes longer than this to say its own name is one a person is waiting on,
/// and reporting it as unusable with the reason beats hanging the command that
/// exists to explain what is wrong.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Find a helper and ask it what it is.
///
/// Going as far as the handshake rather than stopping at the path, because a
/// program being on disk says nothing about whether this build can talk to it,
/// which compiler will answer, or what it will answer about. All three decide
/// whether a semantic run is worth starting.
///
/// The helper is shut down again. `doctor` inspects; it does not leave a
/// process running behind a command that printed a table and returned. The
/// caller supplies containment so semantic discovery and later analysis start
/// under the same policy.
fn interrogate(
    name: &str,
    configured: Option<&Path>,
    sandbox: codehelion_helper::SandboxRequest,
) -> Option<doctor::HelperFacts> {
    let path = codehelion_helper::locate(name, configured)?;
    let state =
        match codehelion_helper::Helper::start_with_sandbox(&path, &[], HANDSHAKE_TIMEOUT, sandbox)
        {
            Ok(helper) => {
                let identity = helper.identity();
                let greeting = doctor::Greeting {
                    version: identity.version.clone(),
                    protocol: helper.protocol_version(),
                    toolchains: identity.toolchains.clone(),
                    capabilities: identity
                        .capabilities
                        .iter()
                        .map(|capability| capability.name().to_string())
                        .collect(),
                    executes: identity
                        .executes
                        .iter()
                        .map(|execution| execution.name().to_string())
                        .collect(),
                };
                // Failing to stop cleanly is not a reason to withhold what it
                // already said: the answer was given before the goodbye.
                drop(helper.shutdown());
                doctor::HelperState::Answered(greeting)
            }
            Err(error) => doctor::HelperState::Silent(format!("{error}")),
        };
    Some(doctor::HelperFacts { path, state })
}

/// Describe artifact formats this build can inspect without running them.
///
/// Kept in the composition root alongside helper discovery: format backends
/// are optional CLI capabilities and are not dependencies of the source
/// clone engine.
fn doctor_artifacts(out: &mut impl Write) -> Result<()> {
    writeln!(out, "  artifacts:")?;
    writeln!(out, "    wasm: available (core modules; wasmparser)")?;
    writeln!(out, "    elf: available (sized text symbols; object)")?;
    writeln!(
        out,
        "    macho: available (symbols, relocations, data; matching dSYM source mappings)"
    )?;
    writeln!(
        out,
        "    pe-coff: available (symbols, relocations, data; matching PDB source mappings)"
    )?;
    writeln!(
        out,
        "    archive: available (local member enumeration and delegated parsing)"
    )?;
    Ok(())
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
    // Resolved before the mode is dispatched on, because a permission that
    // nothing in the chosen mode could act on is refused rather than accepted:
    // Fast and Structural run nothing whatever they are told, and somebody who
    // granted an execution to one of them is owed the sentence saying so.
    let permitted = scan::permitted(args)?;
    match args.mode {
        Mode::Semantic => scan::structural::semantic(args, &permitted, out),
        Mode::Structural => scan::structural::run(args, out),
        Mode::Fast => scan::run(args, out),
    }
}

/// Re-render a completed snapshot without reading the scanned source tree.
pub(crate) mod report_command;

use report_command::{explain, report_command};

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
    // A build directory is recognised by its shape rather than by the literal
    // name `target`: `CARGO_TARGET_DIR` renames it, and the tools that wrap a
    // build pick their own name for it, so a binary under `llvm-cov-target` is
    // as local a build as one under `target`.
    let is_cargo_target = components
        .iter()
        .zip(components.iter().skip(1))
        .any(|(a, b)| a.ends_with("target") && (b == "debug" || b == "release"));
    if is_cargo_target {
        return "local build";
    }
    "standalone (archive or manual install)"
}

/// Append the local database's location to the doctor report, with a hint
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
            "  local database: {} ({} bytes)",
            db.display(),
            meta.len()
        )?,
        Err(_) => writeln!(out, "  local database: {} (absent)", db.display())?,
    }
    if let Some(repo_root) = find_git_root(&cwd) {
        if !is_git_ignored(&repo_root, &db_abs) {
            writeln!(
                out,
                "  hint: the local database is not matched by .gitignore; \
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

/// Freeze or prune a baseline against the last recorded scan of a tree.
///
/// Both actions read a scan that already happened rather than performing one:
/// a baseline is a judgement about a result, and taking it from the recorded
/// result keeps the judgement and the report it refers to the same thing.
#[allow(
    clippy::too_many_lines,
    reason = "create and update share the same invocation and compatibility contract"
)]
fn baseline(action: &BaselineAction, out: &mut impl Write) -> Result<Outcome> {
    let (args, create) = match action {
        BaselineAction::Create(args) => (args, true),
        BaselineAction::Update(args) => (args, false),
    };
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = scan::database_path(&root, args.db.as_deref(), &resolved_config, false)?;
    if !db_path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = Store::open(&db_path)?;
    let root_path = root.to_string_lossy();
    let invocation = store.latest_completed_invocation(&root_path)?;
    if invocation.is_empty() {
        bail!(
            "{} holds no completed scan of {}; run `codehelion scan` first",
            db_path.display(),
            root.display()
        );
    }
    let runs: Vec<_> = invocation
        .into_iter()
        .map(|origin| {
            let groups = store.run_groups(origin.id)?;
            Ok((origin, groups))
        })
        .collect::<Result<_>>()?;

    if create {
        if args.file.exists() && !args.force {
            bail!(
                "{} already exists; pass --force to overwrite",
                args.file.display()
            );
        }
        let recorded = baseline::Baseline::from_runs(&runs, &scan::rfc3339_now())?;
        recorded.write(&args.file)?;
        writeln!(
            out,
            "wrote {} ({} findings frozen across {} build variants from {} run parts)",
            args.file.display(),
            recorded
                .partitions
                .iter()
                .map(|partition| partition.entries.len())
                .sum::<usize>(),
            recorded.partitions.len(),
            runs.len(),
        )?;
        return Ok(Outcome::Success);
    }

    let existing = baseline::Baseline::load(&args.file)?;
    let mut pruned = existing.clone();
    let mut dropped = Vec::new();
    for (origin, groups) in &runs {
        let Some(partition) = existing.partition(&origin.variant_fingerprint) else {
            bail!(
                "{} does not describe run {}: it has no partition for build variant {}",
                args.file.display(),
                origin.id,
                origin.variant_fingerprint
            );
        };
        let fit = partition.compatibility(&origin.detector_versions);
        if let Some(reason) = fit.mismatch {
            bail!(
                "{} does not describe run {}: {}",
                args.file.display(),
                origin.id,
                reason
            );
        }
        let present: std::collections::BTreeSet<String> = groups
            .iter()
            .map(|group| group.fingerprint_hex.clone())
            .collect();
        let (next, part_dropped) = pruned.pruned_partition(&origin.variant_fingerprint, &present);
        pruned = next;
        dropped.extend(
            part_dropped
                .into_iter()
                .map(|id| (origin.variant_fingerprint.clone(), id)),
        );
    }
    pruned.write(&args.file)?;
    writeln!(
        out,
        "updated {} ({} entries kept across {} build variants, {} resolved and dropped)",
        args.file.display(),
        pruned
            .partitions
            .iter()
            .map(|partition| partition.entries.len())
            .sum::<usize>(),
        pruned.partitions.len(),
        dropped.len(),
    )?;
    for (variant, id) in &dropped {
        writeln!(
            out,
            "  resolved [{}]: {id}",
            variant.get(..12).unwrap_or(variant)
        )?;
    }
    Ok(Outcome::Success)
}

fn config_command(action: &ConfigAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        ConfigAction::Show { config } => {
            let start = std::env::current_dir().context("resolving the current directory")?;
            let resolved = config::load(config.as_deref(), &start)?;
            match &resolved.source {
                ConfigSource::Explicit(path) | ConfigSource::Discovered(path) => {
                    writeln!(out, "# source: {}", path.display())?;
                }
                ConfigSource::Defaults => writeln!(out, "# source: built-in defaults")?,
            }
            write!(out, "{}", resolved.config.to_display_toml()?)?;
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
        CacheAction::Status { path, config, db } => {
            let path = resolve_db_at(path, db.as_deref(), config.as_deref())?;
            match std::fs::metadata(&path) {
                Ok(meta) => writeln!(out, "database: {} ({} bytes)", path.display(), meta.len())?,
                Err(_) => writeln!(out, "database: {} (absent)", path.display())?,
            }
            Ok(Outcome::Success)
        }
        CacheAction::Clear {
            path,
            config,
            db,
            force,
        } => {
            if !force {
                bail!(
                    "`cache clear` permanently deletes the local audit database; pass --force to confirm"
                );
            }
            let path = resolve_db_at(path, db.as_deref(), config.as_deref())?;
            let _lock = scan_lock::acquire(&path)?;
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

/// Resolve the local-database path: an explicit flag wins, otherwise the
/// configured location (discovered `codehelion.toml` or defaults).
fn resolve_db(flag: Option<&Path>) -> Result<PathBuf> {
    let root = std::env::current_dir()
        .context("resolving the current directory")?
        .canonicalize()
        .context("resolving the current directory")?;
    resolve_db_at(&root, flag, None)
}

/// Resolve a local-database path for the repository selected by one command.
///
/// All source-audit commands use this path so an explicit database, a named
/// configuration, and a discovered configuration receive identical handling.
fn resolve_db_at(root: &Path, flag: Option<&Path>, config_path: Option<&Path>) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolving path {}", root.display()))?;
    let resolved_config = config::load(config_path, &root)?;
    scan::database_path(&root, flag, &resolved_config, false)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
