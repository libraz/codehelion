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

pub mod audit;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod migrate;
pub mod report;
pub mod reuse;
pub mod scan;
pub mod semantic;
pub mod suppress;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;
use codehelion_store::Store;

use crate::cli::{
    BaselineAction, CacheAction, Cli, Command, ConfigAction, DetailFormat, ExplainArgs,
    MigrateArgs, Mode, ScanArgs,
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
            // The lookup is supplied here rather than by the engine: starting
            // a program is this layer's business, and keeping it out of the
            // engine is what stops a compiler helper from becoming something
            // the analysis crates link.
            doctor::render(&doctor::diagnose_with(&|name| interrogate(name, None)), out)?;
            doctor_install(out)?;
            doctor_database(out)?;
            Ok(Outcome::Success)
        }
        Command::Config { action } => config_command(action, out),
        Command::Cache { action } => cache_command(action, out),
        Command::Scan(args) => scan_command(args, out),
        Command::Explain(args) => explain(args, out),
        Command::Baseline { action } => baseline(action, out),
        Command::Audit(args) => audit::run(args, out),
        Command::Artifact => bail!("artifact analysis is not available in this release"),
        Command::Divergence => bail!("divergence reporting is not available in this release"),
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
/// process running behind a command that printed a table and returned.
fn interrogate(name: &str, configured: Option<&Path>) -> Option<doctor::HelperFacts> {
    let path = codehelion_helper::locate(name, configured)?;
    let state = match codehelion_helper::Helper::start(&path, HANDSHAKE_TIMEOUT) {
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

fn scan_command(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    match args.mode {
        Mode::Semantic => scan::structural::semantic(args, out),
        Mode::Structural => scan::structural::run(args, out),
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
            content: occurrence.member.content_hex,
            file: occurrence.member.file_path,
            language: occurrence.member.language,
            start_line: line(occurrence.member.start_line),
            end_line: line(occurrence.member.end_line),
            unit: occurrence.member.unit_name,
            tokens: u64::try_from(occurrence.member.token_count).unwrap_or(0),
            canonical: occurrence.member.is_canonical,
        },
        group: report::GroupRef {
            fingerprint: occurrence.group_fingerprint_hex,
            clone_type: occurrence.clone_type,
            scope: occurrence.member_scope,
            confidence: occurrence.score,
            priority: occurrence.priority.as_ref().map(recorded_priority),
            members: u64::try_from(occurrence.member_count).unwrap_or(0),
            boilerplate: occurrence.boilerplate,
            test_code: occurrence.test_code,
            split_pair: occurrence.split_pair,
            similarity: occurrence.similarity.map(|stored| report::Similarity {
                weight_version: stored.weight_version,
                lexical: stored.lexical,
                structural: stored.structural,
                control_flow: stored.control_flow,
                type_similarity: stored.type_similarity,
                api: stored.api,
                composite: stored.composite,
                min_pairwise: stored.min_pairwise,
                confidence_band: stored.confidence_band,
            }),
            suppressed: occurrence.suppression.map(|rule| report::Suppression {
                kind: report::SuppressionKind::Rule,
                reason: None,
                scope: Some(rule.scope),
                pattern: Some(rule.pattern),
            }),
        },
        scan_run: occurrence.scan_run_id,
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        DetailFormat::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

/// A stored ranking as the detail view shows it.
///
/// A count that will not fit is reported at the ceiling rather than wrapping:
/// a group with more occurrences than a `u64` can hold is past anything the
/// derivation would say about it anyway.
fn recorded_priority(stored: &codehelion_store::query::StoredPriority) -> report::RecordedPriority {
    let count = |value: i64| u64::try_from(value).unwrap_or(u64::MAX);
    report::RecordedPriority {
        value: stored.final_priority,
        clone_confidence: stored.clone_confidence,
        maintenance_risk: stored.maintenance_risk,
        refactoring_difficulty: stored.refactoring_difficulty,
        semantic_confidence: stored.semantic_confidence,
        source_artifact_confidence: stored.source_artifact_confidence,
        savings_confidence: stored.savings_confidence,
        inputs: report::RecordedInputs {
            smallest_member_tokens: count(stored.facts.smallest_member_tokens),
            largest_member_tokens: count(stored.facts.largest_member_tokens),
            instances: count(stored.facts.instances),
            files: count(stored.facts.files),
            directories: count(stored.facts.directories),
            languages: count(stored.facts.languages),
            min_clone_tokens: stored.facts.min_clone_tokens.map(count),
        },
    }
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

/// Freeze or prune a baseline against the last recorded scan of a tree.
///
/// Both actions read a scan that already happened rather than performing one:
/// a baseline is a judgement about a result, and taking it from the recorded
/// result keeps the judgement and the report it refers to the same thing.
fn baseline(action: &BaselineAction, out: &mut impl Write) -> Result<Outcome> {
    let (args, create) = match action {
        BaselineAction::Create(args) => (args, true),
        BaselineAction::Update(args) => (args, false),
        BaselineAction::Migrate(args) => return baseline_migrate(args, out),
    };
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let cfg = config::load(None, &root)?.config;
    let db_path = scan::database_path(&root, args.db.as_deref(), &cfg);
    if !db_path.is_file() {
        bail!(
            "no audit database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = Store::open(&db_path)?;
    let root_path = root.to_string_lossy();
    let Some(origin) = store.latest_completed_run(&root_path)? else {
        bail!(
            "{} holds no completed scan of {}; run `codehelion scan` first",
            db_path.display(),
            root.display()
        );
    };
    let groups = store.run_groups(origin.id)?;

    if create {
        if args.file.exists() && !args.force {
            bail!(
                "{} already exists; pass --force to overwrite",
                args.file.display()
            );
        }
        let recorded = baseline::Baseline::from_run(&origin, &groups, &scan::rfc3339_now());
        recorded.write(&args.file)?;
        writeln!(
            out,
            "wrote {} ({} findings frozen from run {}, {} mode)",
            args.file.display(),
            recorded.entries.len(),
            origin.id,
            origin.analysis_mode,
        )?;
        return Ok(Outcome::Success);
    }

    let existing = baseline::Baseline::load(&args.file)?;
    let fit = existing.compatibility(&origin.variant_fingerprint, &origin.detector_versions);
    if let Some(reason) = fit.mismatch {
        bail!(
            "{} does not describe run {}: {}",
            args.file.display(),
            origin.id,
            reason
        );
    }
    if let Some(caveat) = fit.caveat {
        writeln!(out, "note: {caveat}")?;
    }
    let present: std::collections::BTreeSet<String> = groups
        .iter()
        .map(|group| group.fingerprint_hex.clone())
        .collect();
    let (pruned, dropped) = existing.pruned(&present);
    pruned.write(&args.file)?;
    writeln!(
        out,
        "updated {} ({} entries kept, {} resolved and dropped)",
        args.file.display(),
        pruned.entries.len(),
        dropped.len(),
    )?;
    for id in &dropped {
        writeln!(out, "  resolved: {id}")?;
    }
    Ok(Outcome::Success)
}

/// Rewrite a baseline's identifiers onto a run made under changed rules, and
/// carry the recorded history of each group across with them.
///
/// Both runs are read out of the audit database rather than rescanned. A
/// migration is a statement about two results that already exist, and scanning
/// again here would produce a third one whose relationship to the frozen
/// judgements is exactly the question being asked.
///
/// A project with no baseline still has a history worth carrying, so a missing
/// file is not an error: the recorded lineage is migrated on its own, and the
/// two runs to migrate between are then the newest pair, the same ones an
/// audit would compare.
fn baseline_migrate(args: &MigrateArgs, out: &mut impl Write) -> Result<Outcome> {
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let cfg = config::load(None, &root)?.config;
    let db_path = scan::database_path(&root, args.db.as_deref(), &cfg);
    if !db_path.is_file() {
        bail!(
            "no audit database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let mut store = scan::open_store(&db_path)?;
    let existing = args
        .file
        .is_file()
        .then(|| baseline::Baseline::load(&args.file))
        .transpose()?;
    let (source, target) = migration_runs(&store, &root, &db_path, args, existing.as_ref())?;

    let drift: Vec<String> =
        codehelion_core::compat::drift(&source.detector_versions, &target.detector_versions)
            .iter()
            .map(codehelion_core::compat::Drift::describe)
            .collect();
    let mapping = migrate::by_place(&store.run_groups(source.id)?, &store.run_groups(target.id)?);
    let rewritten = existing
        .as_ref()
        .map(|baseline| baseline.migrated(&mapping, &target, &scan::rfc3339_now(), &drift));

    let verb = if args.dry_run {
        "would rewrite"
    } else {
        "rewriting"
    };
    writeln!(out, "{verb} run {} -> run {}", source.id, target.id)?;
    for line in &drift {
        writeln!(out, "  version drift: {line}")?;
    }
    match (existing.as_ref(), rewritten.as_ref()) {
        (Some(existing), Some(rewritten)) => {
            writeln!(
                out,
                "  {} of {} entries carried, {} stale",
                rewritten.entries.len(),
                existing.entries.len(),
                rewritten.stale.len() - existing.stale.len(),
            )?;
            for entry in rewritten.stale.iter().skip(existing.stale.len()) {
                writeln!(
                    out,
                    "  stale: {} — run {} found no duplication where it stood",
                    entry.group, target.id
                )?;
            }
        }
        _ => writeln!(
            out,
            "  no baseline at {}; carrying the recorded history only",
            args.file.display()
        )?,
    }
    if args.dry_run {
        return Ok(Outcome::Success);
    }

    if let Some(rewritten) = &rewritten {
        rewritten.write(&args.file)?;
    }
    let adoptions = adoptions(&store, source.id, &mapping)?;
    let adopted = store.adopt_lineage(target.id, source.id, &adoptions)?;
    writeln!(
        out,
        "  {} of {} groups in run {} now continue a history from before the change",
        adopted.taken.len(),
        mapping.continuations.len(),
        target.id,
    )?;
    for id in &adopted.already_connected {
        writeln!(out, "  already connected: {id}")?;
    }
    if rewritten.is_some() {
        writeln!(out, "wrote {}", args.file.display())?;
    }
    Ok(Outcome::Success)
}

/// Settle which two recorded runs a rewrite is between, and refuse the pairs
/// it cannot honestly map.
///
/// A migration maps one result of a tree onto another result of the *same*
/// text. Across two different trees it would be answering "what changed in the
/// code" with a mechanism built for "what changed in the rules", and afterwards
/// the two answers are indistinguishable.
fn migration_runs(
    store: &Store,
    root: &Path,
    db_path: &Path,
    args: &MigrateArgs,
    existing: Option<&baseline::Baseline>,
) -> Result<(
    codehelion_store::query::RunOrigin,
    codehelion_store::query::RunOrigin,
)> {
    let root_path = root.to_string_lossy();
    let recent = store.completed_runs(&root_path, 2)?;
    let target = match args.to_run {
        Some(id) => store
            .run_origin(id)
            .with_context(|| format!("reading run {id} from {}", db_path.display()))?,
        None => recent.first().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "{} holds no completed scan of {}; run `codehelion scan` first",
                db_path.display(),
                root.display()
            )
        })?,
    };
    let source = match existing {
        Some(baseline) => store.run_origin(baseline.from_run).with_context(|| {
            format!(
                "{} was recorded from run {}, which {} no longer holds",
                args.file.display(),
                baseline.from_run,
                db_path.display()
            )
        })?,
        None => recent
            .into_iter()
            .find(|run| run.id != target.id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "only one scan of {} is recorded (run {}); \
                     there is no earlier result to carry forward",
                    root.display(),
                    target.id
                )
            })?,
    };
    if source.id == target.id {
        bail!(
            "{} already describes run {}: there is nothing to rewrite it onto",
            args.file.display(),
            target.id
        );
    }
    let before = store.run_tree(source.id)?;
    let after = store.run_tree(target.id)?;
    if before.is_empty() || after.is_empty() {
        bail!(
            "run {} or run {} did not record what it read, so this build cannot \
             establish that both saw the same text; re-record the baseline with \
             `baseline create --force`",
            source.id,
            target.id
        );
    }
    if before != after {
        bail!(
            "run {} and run {} read different source; a migration rewrites one \
             reading of a tree onto another reading of the same text, and the \
             ordinary `codehelion audit` is what compares two trees",
            source.id,
            target.id
        );
    }
    Ok((source, target))
}

/// Pair each continuing group with the history its predecessor belonged to.
///
/// A predecessor whose history the store does not hold is left out rather than
/// given a fresh one: inventing a history here would record the group as having
/// existed since the migration, which is the claim the migration exists to
/// avoid making.
fn adoptions(
    store: &Store,
    previous_run: i64,
    mapping: &migrate::Mapping,
) -> Result<Vec<codehelion_store::migrate::LineageAdoption>> {
    let history = lineage_by_group(store, previous_run)?;
    Ok(mapping
        .continuations
        .iter()
        .filter_map(|carried| {
            Some(codehelion_store::migrate::LineageAdoption {
                group: carried.group.clone(),
                previous_group: carried.previous_group.clone(),
                lineage: history.get(&carried.previous_group)?.clone(),
                shared: carried.shared,
                overlap: carried.overlap,
            })
        })
        .collect())
}

/// The history each group of a run belongs to, by hex group fingerprint.
fn lineage_by_group(
    store: &Store,
    run_id: i64,
) -> Result<std::collections::BTreeMap<String, String>> {
    Ok(store
        .run_group_snapshots(run_id)?
        .into_iter()
        .filter_map(|group| Some((group.fingerprint.to_hex(), group.lineage?.to_hex())))
        .collect())
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
    fn findings_outcome_maps_to_dedicated_exit_code() {
        assert_eq!(Outcome::Success.exit_code(), ExitCode::SUCCESS);
        assert_eq!(
            Outcome::FindingsPresent.exit_code(),
            ExitCode::from(EXIT_FINDINGS)
        );
    }
}
