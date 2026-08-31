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
pub mod semantic;
pub mod suppress;

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;
use codehelion_helper::client::ConfiguredHelper;
use codehelion_store::query::{IdKind, IdMatch, RunOrigin};
use codehelion_store::{Store, fingerprint_hex};

use crate::cli::{
    ArtifactAction, BaselineAction, CacheAction, Cli, Command, ConfigAction, DetailFormat,
    DoctorArgs, ExplainArgs, Mode, ReportArgs, ScanArgs,
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
    }
}

fn configured_helper_path<'a>(name: &str, helpers: &'a config::Helpers) -> Option<&'a Path> {
    match name {
        "codehelion-backend-rust" => helpers.rust.as_deref(),
        "codehelion-backend-clang" => helpers.clang.as_deref(),
        _ => None,
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
///
/// `configured` carries operator authority: [`config::helper_paths`] is the
/// only way a location reaches this, and it is what keeps a path written by the
/// tree under analysis from naming the program that gets started here.
fn interrogate(
    name: &str,
    configured: Option<&Path>,
    sandbox: codehelion_helper::SandboxRequest,
) -> Option<doctor::HelperFacts> {
    let path = codehelion_helper::locate(name, configured.map(ConfiguredHelper::operator))?;
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
fn doctor_database(args: &DoctorArgs, out: &mut impl Write) -> Result<()> {
    let cwd = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving {}", args.path.display()))?;
    // Literal on purpose: doctor reports the state of the directory, so it has
    // to name the database that was configured rather than the one another
    // command would fall back to. Which file each of them would use is the
    // next few lines' subject.
    let db = resolve_db_at(
        scan::DatabaseUse::Literal,
        &cwd,
        args.db.as_deref(),
        args.config.as_deref(),
        args.untrusted,
    )?;
    let db_abs = if db.is_absolute() {
        db.clone()
    } else {
        cwd.join(&db)
    };
    writeln!(out)?;
    match std::fs::metadata(&db_abs) {
        Ok(meta) => {
            writeln!(
                out,
                "  local database: {} ({} bytes)",
                db.display(),
                meta.len()
            )?;
            match Store::open_existing(&db_abs) {
                Ok(store) => writeln!(
                    out,
                    "  database health: schema {}, {} scan run(s), {} abandoned",
                    store.schema_version()?,
                    store.table_count("scan_run")?,
                    store.abandoned_runs()?.len()
                )?,
                Err(error) => writeln!(out, "  database health: unreadable ({error})")?,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            writeln!(out, "  local database: {} (absent)", db.display())?;
        }
        Err(error) => {
            writeln!(
                out,
                "  local database: {} (metadata unreadable: {error})",
                db.display()
            )?;
        }
    }
    write_lease_status(&db_abs, out)?;
    doctor_database_directory(&db, &db_abs, args.db.is_some(), out)?;
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

/// Append every audit database beside the selected one, what this build can do
/// with each, and which one a scan would write.
///
/// A database written by another schema version is left exactly where it is and
/// a scan records beside it, so one directory can end up holding more than one
/// audit history. Which of them to keep is the reader's decision, and this is
/// the evidence for it.
fn doctor_database_directory(
    db: &Path,
    db_abs: &Path,
    explicit: bool,
    out: &mut impl Write,
) -> Result<()> {
    let Some(directory) = db_abs.parent() else {
        return Ok(());
    };
    let databases = audit_databases(directory, db_abs);
    if databases.is_empty() {
        return Ok(());
    }
    // The selection is made the same way a scan makes it, including the rule
    // that a named database is used as named however this build reads it.
    let replacement = if explicit {
        None
    } else {
        scan::incompatible_database_replacement(db_abs)
    };
    let recorded_into = replacement.clone().unwrap_or_else(|| db_abs.to_path_buf());
    // A reader takes a neighbour that is already there and makes none, so the
    // two answers differ exactly when the scan has not been run yet.
    let read_from = replacement
        .filter(|path| scan::readable_here(path))
        .unwrap_or_else(|| db_abs.to_path_buf());
    writeln!(
        out,
        "  databases in {}:",
        db.parent().unwrap_or(directory).display()
    )?;
    for path in &databases {
        let bytes = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
        writeln!(
            out,
            "    {}: {} ({bytes} bytes)",
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy(),
            database_readability(path),
        )?;
    }
    writeln!(
        out,
        "  a scan would use {}",
        spelled_beside(db, &recorded_into).display()
    )?;
    writeln!(
        out,
        "  a read would use {}",
        spelled_beside(db, &read_from).display()
    )?;
    // `cache clear` and `cache prune` act on the file they were pointed at, so
    // a second history in the same directory outlives them. Saying so here is
    // cheaper than discovering it after a --force.
    if databases.len() > 1 {
        writeln!(
            out,
            "  `cache clear` and `cache prune` act on the configured database alone; the other database(s) here are left as they are"
        )?;
    }
    Ok(())
}

/// `selected`, spelled the way the configured database was spelled.
///
/// The configured path is what the reader typed or read out of a
/// configuration; an absolute neighbour of it in the same line would read as
/// somewhere else.
fn spelled_beside(configured: &Path, selected: &Path) -> PathBuf {
    match (configured.parent(), selected.file_name()) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => selected.to_path_buf(),
    }
}

/// The files in `directory` that are named the way audit databases are.
///
/// Matching the selected database's extension keeps `SQLite`'s own sidecars and
/// the lease file out of a list that is about audit histories.
fn audit_databases(directory: &Path, like: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension() == like.extension())
        .collect();
    found.sort();
    found
}

/// What this build can do with one candidate audit database.
fn database_readability(path: &Path) -> String {
    match Store::open_existing(path) {
        Ok(store) => match store.schema_version() {
            Ok(version) => format!("schema {version}, readable by this build"),
            Err(error) => format!("unreadable ({error})"),
        },
        Err(codehelion_store::StoreError::UnsupportedSchema { found: 0 }) => {
            "no schema marker, not readable by this build".to_owned()
        }
        Err(codehelion_store::StoreError::UnsupportedSchema { found }) => {
            format!("schema {found}, not readable by this build")
        }
        Err(error) => format!("unreadable ({error})"),
    }
}

/// Append the point-in-time state of the database writer lease.
fn write_lease_status(database: &Path, out: &mut impl Write) -> Result<()> {
    match scan_lock::lease_status(database) {
        scan_lock::LeaseStatus::Available => writeln!(out, "  database lease: available")?,
        scan_lock::LeaseStatus::Held => writeln!(
            out,
            "  database lease: held by another codehelion scan or cache command"
        )?,
        scan_lock::LeaseStatus::Unreadable(error) => {
            writeln!(out, "  database lease: unreadable ({error})")?;
        }
    }
    Ok(())
}

/// The enclosing git repository root, found by walking up for a `.git` entry.
pub(crate) fn find_git_root(start: &Path) -> Option<PathBuf> {
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
pub(crate) fn is_git_ignored(repo_root: &Path, target: &Path) -> bool {
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
    let (args, create, force) = match action {
        BaselineAction::Create(args) => (&args.common, true, args.force),
        BaselineAction::Update(args) => (args, false, false),
    };
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    // Reading: a baseline is taken from runs that are already recorded, so a
    // neighbour this build just created would hold nothing to take one from.
    let db_path = scan::database_path_for(
        scan::DatabaseUse::Reading,
        &root,
        args.db.as_deref(),
        &resolved_config,
        false,
    )?;
    if !db_path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = scan::open_recorded_store(&db_path)?;
    let root_path = scan::path_key(&root);
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
        if args.file.exists() && !force {
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
        let fit = partition.compatibility(&origin.detector_versions, origin.min_clone_tokens);
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

/// The database one `cache` action works on.
///
/// The three actions resolve it the same way and differ only in what they are
/// allowed to do about a default this build cannot open; see
/// [`scan::DatabaseUse`].
fn cache_database(
    intent: scan::DatabaseUse,
    path: &Path,
    db: Option<&Path>,
    config: Option<&Path>,
    untrusted: bool,
) -> Result<PathBuf> {
    resolve_db_at(intent, path, db, config, untrusted)
}

fn cache_command(action: &CacheAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        CacheAction::Status {
            path,
            config,
            db,
            untrusted,
        } => cache_status(
            &cache_database(
                scan::DatabaseUse::Reading,
                path,
                db.as_deref(),
                config.as_deref(),
                *untrusted,
            )?,
            out,
        ),
        CacheAction::Prune {
            path,
            config,
            db,
            untrusted,
            keep_artifacts,
            keep_comparisons,
            force,
        } => {
            if !force {
                bail!("`cache prune` deletes retained local history; pass --force to confirm");
            }
            // Literal: a command that deletes acts on the file it was pointed
            // at, whatever this build can make of it.
            cache_prune(
                &cache_database(
                    scan::DatabaseUse::Literal,
                    path,
                    db.as_deref(),
                    config.as_deref(),
                    *untrusted,
                )?,
                *keep_artifacts,
                *keep_comparisons,
                out,
            )
        }
        CacheAction::Clear {
            path,
            config,
            db,
            untrusted,
            force,
        } => {
            if !force {
                bail!(
                    "`cache clear` permanently deletes the local audit database; pass --force to confirm"
                );
            }
            cache_clear(
                &cache_database(
                    scan::DatabaseUse::Literal,
                    path,
                    db.as_deref(),
                    config.as_deref(),
                    *untrusted,
                )?,
                out,
            )
        }
    }
}

/// Report where the local database is, what this build makes of it, and
/// whether anything holds its lease.
fn cache_status(path: &Path, out: &mut impl Write) -> Result<Outcome> {
    let files = database_files(path);
    if let Some(size) = database_storage_bytes(&files)? {
        writeln!(out, "database: {} ({} bytes)", path.display(), size)?;
        match Store::open_existing(path) {
            Ok(store) => {
                writeln!(out, "schema: {}", store.schema_version()?)?;
                writeln!(out, "scan runs: {}", store.table_count("scan_run")?)?;
                writeln!(out, "abandoned runs: {}", store.abandoned_runs()?.len())?;
                writeln!(out, "table storage:")?;
                for table in store.table_storage()? {
                    writeln!(out, "  {}: {} bytes", table.table, table.bytes)?;
                }
            }
            Err(error) => writeln!(out, "database health: unreadable ({error})")?,
        }
    } else {
        writeln!(out, "database: {} (absent)", path.display())?;
    }
    write_lease_status(path, out)?;
    Ok(Outcome::Success)
}

/// Drop the retained history the flags do not ask to keep.
fn cache_prune(
    path: &Path,
    keep_artifacts: usize,
    keep_comparisons: usize,
    out: &mut impl Write,
) -> Result<Outcome> {
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let _lock = scan_lock::acquire(path)?;
    let mut store = Store::open_existing(path)
        .with_context(|| format!("opening audit database {}", path.display()))?;
    let pruned = store.prune(keep_artifacts, keep_comparisons)?;
    writeln!(
        out,
        "pruned {} abandoned run(s), {} artifact analysis(es), {} cross-variant comparison(s), {} cross-language comparison(s), and {} orphaned fingerprint(s)",
        pruned.abandoned_runs,
        pruned.artifact_analyses,
        pruned.cross_variant_comparisons,
        pruned.cross_language_comparisons,
        pruned.orphaned_fingerprints
    )?;
    Ok(Outcome::Success)
}

/// Remove the named database and the sidecars WAL mode created beside it.
fn cache_clear(path: &Path, out: &mut impl Write) -> Result<Outcome> {
    if !database_files(path).iter().any(|file| file.exists()) {
        writeln!(out, "nothing to remove at {}", path.display())?;
        return Ok(Outcome::Success);
    }
    let _lock = scan_lock::acquire(path)?;
    let removed = database_files(path)
        .iter()
        .map(|file| remove_database_file(file))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|removed| *removed)
        .count();
    if removed > 0 {
        writeln!(out, "removed {}", path.display())?;
    } else {
        writeln!(out, "nothing to remove at {}", path.display())?;
    }
    Ok(Outcome::Success)
}

/// The main `SQLite` database and the two sidecars created by WAL mode.
fn database_files(database: &Path) -> [PathBuf; 3] {
    [
        database.to_path_buf(),
        database_sidecar_path(database, "-wal"),
        database_sidecar_path(database, "-shm"),
    ]
}

/// Sum the main database and WAL sidecars, distinguishing absent files from
/// metadata failures that deserve to reach the caller.
fn database_storage_bytes(files: &[PathBuf; 3]) -> Result<Option<u64>> {
    let mut size = 0_u64;
    let mut present = false;
    for file in files {
        match std::fs::metadata(file) {
            Ok(metadata) => {
                present = true;
                size = size.saturating_add(metadata.len());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading database metadata {}", file.display()));
            }
        }
    }
    Ok(present.then_some(size))
}

fn database_sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut sidecar: OsString = database.as_os_str().to_owned();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

/// Remove one database file, allowing an absent WAL sidecar.
fn remove_database_file(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
