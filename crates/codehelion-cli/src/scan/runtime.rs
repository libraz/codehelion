//! Scan resource limits, discovery, parallel mapping, and database confinement.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares runtime helpers across scan modes"
)]

use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    Config, ConfigSource, Context, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    EngineConfig, Frontend, GeneratedMarkers, Glob, GlobSet, GlobSetBuilder, Language,
    LanguageSelection, LexedSource, LiteralNorm, LiteralNormalization, Path, PathBuf,
    ResolvedConfig, Result, ScanArgs, SourceUnit, bail, discovery, path_key, report, suppress,
};
#[cfg(test)]
use std::io::Read;

/// Maximum parser workers accepted from either the command line or config.
///
/// A deliberate user value can use more workers than the automatic setting,
/// but never enough to turn an accidental large value into a resource-exhaustion
/// request.
pub(super) fn maximum_jobs() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .saturating_mul(4)
}

/// Resolve the worker-thread count: flag over configuration over the number
/// of available CPUs, with an explicit resource ceiling.
pub(crate) fn effective_jobs(flag: Option<usize>, configured: Option<usize>) -> Result<usize> {
    match flag.or(configured) {
        Some(0) => bail!("jobs must be at least 1"),
        Some(jobs) => Ok(jobs.min(maximum_jobs())),
        None => Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)),
    }
}

/// The configuration a scan actually works under, once the command line has
/// had its say, and what to report about it.
///
/// The profile only ever *lowers* a ceiling. A configuration already stricter
/// than the profile stays where it is: taking the profile's number outright
/// would let asking for less trust loosen a deliberately tight setting, which
/// is the opposite of what asking for it means.
///
/// The candidate ceiling is set rather than clamped because leaving it unset
/// means "each pass keeps its own default", and every one of those defaults is
/// above the profile's number.
pub(crate) fn guarded(mut cfg: Config, args: &ScanArgs) -> (Config, Option<report::Guardrails>) {
    // Undoing a default the tool applied unasked, for this run only: the
    // configuration file is not edited and the next run hides them again.
    if args.include_vendored {
        cfg.suppression.vendored_paths.clear();
    }
    if !args.untrusted {
        return (cfg, None);
    }
    let profile = codehelion_core::execution::Limits::untrusted();
    cfg.limits.clamp_to_untrusted(&profile);
    let guardrails = report::Guardrails::untrusted(&cfg.limits, &profile);
    (cfg, Some(guardrails))
}

/// Build the engine configuration from the effective scan configuration:
/// detection knobs plus any candidate ceiling the configuration overrides.
pub(super) fn engine_config(cfg: &Config) -> Result<EngineConfig> {
    let defaults = EngineConfig::default();
    Ok(EngineConfig {
        min_clone_tokens: usize::try_from(cfg.min_clone_tokens)
            .context("min-clone-tokens out of range")?,
        entropy_ratio_floor: cfg.entropy_ratio_floor,
        literals: literal_norm(cfg.literal_normalization),
        posting_cap: cfg.limits.posting_cap.unwrap_or(defaults.posting_cap),
        pair_budget: cfg.limits.pair_budget.unwrap_or(defaults.pair_budget),
        ..defaults
    })
}

/// Map the configured literal strategy onto the engine's.
pub(crate) const fn literal_norm(setting: LiteralNormalization) -> LiteralNorm {
    match setting {
        LiteralNormalization::Preserve => LiteralNorm::Preserve,
        LiteralNormalization::Category => LiteralNorm::Category,
        LiteralNormalization::Full => LiteralNorm::Full,
    }
}

/// Run project discovery under the effective configuration.
pub(crate) fn discover_sources(
    root: &Path,
    cfg: &Config,
    no_ignore: bool,
    follow_links: bool,
    compile_commands: Option<&Path>,
) -> Result<DiscoveryReport> {
    let discovery_config = DiscoveryConfig {
        respect_gitignore: !no_ignore,
        max_file_bytes: cfg.limits.max_file_bytes,
        languages: LanguageSelection {
            rust: cfg.languages.rust,
            c: cfg.languages.c,
            cpp: cfg.languages.cpp,
        },
        header_policy: cfg.languages.headers.into(),
        generated_markers: GeneratedMarkers::new(
            &cfg.suppression.generated_markers,
            DEFAULT_SCAN_LINES,
        ),
        compile_commands: compile_commands.map(Path::to_path_buf),
        follow_links,
    };
    Ok(discovery::discover(root, &discovery_config)?)
}

/// Apply the configured include/exclude globs to the discovered sources.
/// Returns the retained sources and how many were filtered out.
pub(crate) fn filter_globs(
    cfg: &Config,
    sources: Vec<SourceUnit>,
) -> Result<(Vec<SourceUnit>, usize)> {
    let include = build_globset(&cfg.include).context("in include globs")?;
    let exclude = build_globset(&cfg.exclude).context("in exclude globs")?;
    let before = sources.len();
    let kept: Vec<SourceUnit> = sources
        .into_iter()
        .filter(|source| {
            let path = &source.relative_path;
            include.as_ref().is_none_or(|globs| globs.is_match(path))
                && exclude.as_ref().is_none_or(|globs| !globs.is_match(path))
        })
        .collect();
    let excluded = before - kept.len();
    Ok((kept, excluded))
}

pub(crate) fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("glob pattern {pattern:?}"))?);
    }
    Ok(Some(builder.build()?))
}

/// What became of one source file handed to a frontend.
pub(crate) enum FileOutcome<T> {
    /// Read and analysed within the deterministic parse-work budget.
    Done(Box<T>),
    /// The file could not be read.
    #[cfg(test)]
    Unreadable,
    /// The file exceeded the configured parse-work budget; the file is
    /// excluded.
    TimedOut,
}

/// Parse-work capacity represented by one configured millisecond. The public
/// setting keeps its established unit for configuration compatibility, but the
/// decision is a pure function of input bytes rather than wall-clock load.
pub(crate) const PARSE_BYTES_PER_MILLISECOND: u64 = 256;

/// The effective byte ceiling for one frontend's deterministic parse work.
///
/// `parse-timeout-ms` is a compatibility spelling for a work budget, not a
/// wall-clock deadline. It can tighten the discovery ceiling but never loosen
/// it, so the report's two limits describe the exact enforced bound.
#[must_use]
pub(crate) fn parse_work_byte_limit(max_file_bytes: u64, budget: std::time::Duration) -> u64 {
    let milliseconds = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    max_file_bytes.min(milliseconds.saturating_mul(PARSE_BYTES_PER_MILLISECOND))
}

/// Read no more than one byte beyond `maximum_bytes`, so a file that grew
/// after discovery cannot make a frontend retain unbounded input.
///
/// `Ok(None)` means the file exceeded the limit; I/O failures remain distinct
/// so callers can account for unreadable files separately.
#[cfg(test)]
pub(crate) fn read_bounded_source(
    path: &Path,
    maximum_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok((u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= maximum_bytes).then_some(bytes))
}

/// Run `frontend` over every source, letting `jobs` worker threads claim the
/// next available source as soon as they finish their prior one.
///
/// Chunks are joined in order, so the result order equals the (deterministic)
/// discovery order regardless of thread scheduling. Files that vanished since
/// discovery or exceeded the parse-work budget are counted, not fatal. Returns the
/// analysed files plus the unreadable and timed-out counts.
pub(crate) fn map_sources<T: Send>(
    sources: &[SourceUnit],
    jobs: usize,
    frontend: impl Fn(&SourceUnit) -> FileOutcome<T> + Sync,
) -> Result<(Vec<T>, u64, u64)> {
    if jobs == 0 {
        bail!("jobs must be at least 1");
    }
    if sources.is_empty() {
        return Ok((Vec::new(), 0, 0));
    }
    let next_source = AtomicUsize::new(0);
    let mut indexed_results: Vec<(usize, FileOutcome<T>)> = Vec::with_capacity(sources.len());
    let mut worker_panicked = false;
    let frontend = &frontend;
    let next_source = &next_source;
    std::thread::scope(|scope| -> Result<()> {
        let handles: Result<Vec<_>> = (0..jobs.min(sources.len()))
            .map(|_| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        let mut results = Vec::new();
                        loop {
                            let index = next_source.fetch_add(1, Ordering::Relaxed);
                            let Some(source) = sources.get(index) else {
                                break;
                            };
                            results.push((index, frontend(source)));
                        }
                        results
                    })
                    .context("starting frontend worker thread")
            })
            .collect();
        for handle in handles? {
            match handle.join() {
                Ok(results) => indexed_results.extend(results),
                Err(_) => worker_panicked = true,
            }
        }
        Ok(())
    })?;
    if worker_panicked {
        bail!("a frontend worker thread panicked");
    }
    indexed_results.sort_unstable_by_key(|(index, _)| *index);
    let mut analysed = Vec::with_capacity(sources.len());
    #[cfg(test)]
    let mut unreadable = 0u64;
    #[cfg(not(test))]
    let unreadable = 0u64;
    let mut timed_out = 0u64;
    for (_, result) in indexed_results {
        match result {
            FileOutcome::Done(file) => analysed.push(*file),
            #[cfg(test)]
            FileOutcome::Unreadable => unreadable += 1,
            FileOutcome::TimedOut => timed_out += 1,
        }
    }
    Ok((analysed, unreadable, timed_out))
}

/// Lex every source with the Fast frontends.
pub(super) fn lex_sources(
    sources: &[SourceUnit],
    jobs: usize,
    max_file_bytes: u64,
    timeout: std::time::Duration,
) -> Result<(Vec<LexedSource>, u64, u64)> {
    map_sources(sources, jobs, |source| {
        lex_one(source, max_file_bytes, timeout)
    })
}

/// Read and lex one source file, enforcing the deterministic parse-work
/// budget before frontend work begins.
fn lex_one(
    source: &SourceUnit,
    max_file_bytes: u64,
    budget: std::time::Duration,
) -> FileOutcome<LexedSource> {
    let limit = parse_work_byte_limit(max_file_bytes, budget);
    if u64::try_from(source.source_bytes.len()).unwrap_or(u64::MAX) > limit {
        return FileOutcome::TimedOut;
    }
    let bytes = &source.source_bytes;
    let text = String::from_utf8_lossy(bytes);
    let file = match source.language {
        Language::Rust => codehelion_frontend_rust::RustFrontend.lex(&text),
        Language::C => codehelion_frontend_c::CFrontend.lex(&text),
        Language::Cpp => codehelion_frontend_cpp::CppFrontend.lex(&text),
    };
    let arm_paths = match source.language {
        Language::Rust => None,
        Language::C => Some(codehelion_frontend_c::lexer::conditional_paths(
            &text,
            &file.tokens,
            &codehelion_frontend_c::dialect::C,
        )),
        Language::Cpp => Some(codehelion_frontend_c::lexer::conditional_paths(
            &text,
            &file.tokens,
            &codehelion_frontend_cpp::CPP,
        )),
    };
    let unit_lines = file
        .units
        .iter()
        .map(|unit| {
            let start = unit.token_start.min(file.tokens.len());
            let end = unit.token_end.min(file.tokens.len()).max(start);
            let end_line = file.tokens[start..end]
                .last()
                .map_or(unit.span.start_line, |token| token.span.start_line);
            (unit.span.start_line, end_line)
        })
        .collect();
    FileOutcome::Done(Box::new(LexedSource {
        relative_path: path_key(&source.relative_path),
        language: file.language,
        frontend_version: file.frontend_version,
        tokens: file.tokens,
        arm_paths,
        units: file.units,
        unit_lines,
        marker_lines: suppress::marker_lines(&text),
        lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
        diagnostics: file.diagnostics.len(),
    }))
}

/// Resolve the audit-database path with the authority that selected it.
///
/// `--db` is an explicit user instruction and may name storage outside the
/// scan. A database setting from a configuration found at the scan root is
/// not: it is confined to the repository boundary, including its existing symlink
/// components. `--untrusted` applies that confinement to any configured path,
/// even one from an explicitly named configuration file.
///
/// # Errors
///
/// Returns an actionable error when a repository-controlled configuration
/// names an absolute, traversing, or symlink-escaping database path.
pub(crate) fn database_path(
    root: &Path,
    flag: Option<&Path>,
    config: &ResolvedConfig,
    untrusted: bool,
) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(spelled_natively(path));
    }
    let boundary = repository_root(root);
    let discovered = matches!(&config.source, ConfigSource::Discovered(_));
    if untrusted || discovered {
        return confined_database_path(
            &boundary,
            &config.config.database,
            if untrusted {
                "--untrusted"
            } else {
                "a configuration discovered in the scanned repository"
            },
        )
        .map(|path| spelled_natively(&path));
    }
    Ok(spelled_natively(&configured_database_path(
        &boundary,
        &config.config.database,
    )))
}

/// What a command does with the audit database it names, which decides
/// whether it may step around a default one this build cannot open.
///
/// One rule, three answers, because the same step aside is right for a
/// command that records, half right for one that reads, and wrong for one
/// that deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatabaseUse {
    /// The command records: it may write beside an unreadable default, making
    /// the neighbour if it is not there yet.
    Recording,
    /// The command reads: it opens a neighbour that already exists, and never
    /// makes one. A missing neighbour leaves the default's own error, so
    /// "nothing has been scanned yet" stays distinguishable from "the scan
    /// went somewhere else".
    Reading,
    /// The command acts on the file it names — deleting or pruning it. It uses
    /// exactly the path that was resolved, because reading a destructive
    /// instruction as naming some other file is how the wrong history gets
    /// erased.
    Literal,
}

/// Resolve the audit database one command uses, stepping around a default
/// database this build cannot open when that command's job allows it.
///
/// A schema this build does not support is the one recording failure the tool
/// can settle on its own: nothing about the existing file has to change for a
/// scan to keep a durable record, so the run writes beside it instead of
/// finishing with nothing recorded. Every other recording failure — a full
/// disk, a read-only file, a lease another scan holds — still fails, because
/// choosing a different file would not fix any of them.
///
/// The choice lives here rather than in each command so that the reader who
/// followed a note printed by one of them arrives at the same file. A scan
/// that records beside an unreadable default and a report that then opens the
/// default is one tool disagreeing with itself.
///
/// `--db` names one file deliberately. Using a different one would be ignoring
/// that instruction, so an explicit path is never traded, whatever the job.
///
/// # Errors
///
/// Returns what [`database_path`] refuses: a repository-controlled
/// configuration naming storage outside the scanned repository.
pub(crate) fn database_path_for(
    intent: DatabaseUse,
    root: &Path,
    flag: Option<&Path>,
    config: &ResolvedConfig,
    untrusted: bool,
) -> Result<PathBuf> {
    let path = database_path(root, flag, config, untrusted)?;
    if flag.is_some() || intent == DatabaseUse::Literal {
        return Ok(path);
    }
    let Some(replacement) = incompatible_database_replacement(&path) else {
        return Ok(path);
    };
    if intent == DatabaseUse::Reading && !readable_here(&replacement) {
        return Ok(path);
    }
    announce_stepping_aside(&path, &replacement);
    Ok(replacement)
}

/// Resolve the database a scan writes.
///
/// # Errors
///
/// Returns what [`database_path_for`] returns.
pub(crate) fn scan_database_path(
    root: &Path,
    flag: Option<&Path>,
    config: &ResolvedConfig,
    untrusted: bool,
) -> Result<PathBuf> {
    database_path_for(DatabaseUse::Recording, root, flag, config, untrusted)
}

/// Say which database was used and which was left alone.
///
/// Announced rather than done quietly: a second audit database is as large as
/// the first one, and the reader is the only one who can decide what becomes
/// of the file this command did not touch. One wording for every command, so
/// that meeting the same situation twice does not read as two situations.
pub(crate) fn announce_stepping_aside(left: &Path, used: &Path) {
    eprintln!(
        "note: {} was written by another schema version and was left unchanged; codehelion used {}",
        left.display(),
        used.display()
    );
}

/// Whether `path` holds a database this build can open.
pub(crate) fn readable_here(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
        && codehelion_store::Store::open_existing(path).is_ok()
}

/// Where a run goes instead of `path`, when `path` holds a database written by
/// a schema version this build does not support.
///
/// `None` for every other state, including a database this build can open and
/// one that cannot be read at all: those belong to the run's own open, which
/// reports them where they happen.
pub(crate) fn incompatible_database_replacement(path: &Path) -> Option<PathBuf> {
    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
        return None;
    }
    match codehelion_store::Store::open_existing(path) {
        Err(codehelion_store::StoreError::UnsupportedSchema { .. }) => {
            schema_versioned_sibling(path)
        }
        _ => None,
    }
}

/// The next command to type, when `path` holds a database written by a schema
/// version this build does not support.
///
/// A refusal that names no way forward leaves the reader to work out that the
/// tool has a naming rule for this, which they cannot know. Naming the file is
/// enough: the two ways out are to record beside the old history or to stop
/// naming it, and both are one flag away.
///
/// `None` when `path` is fine, unreadable for some other reason, or has no
/// name a neighbour could be derived from — nothing to advise in any of those.
pub(crate) fn incompatible_database_advice(path: &Path) -> Option<String> {
    let sibling = incompatible_database_replacement(path)?;
    let already_there = readable_here(&sibling);
    let sibling = sibling.display();
    Some(if already_there {
        format!(
            "an audit history this build can open is already at {sibling}: read it with --db {sibling}, or drop --db to let codehelion choose it"
        )
    } else {
        format!(
            "record beside it with --db {sibling}, or drop --db to let codehelion choose a database it can open"
        )
    })
}

/// `path` renamed to carry the schema version this build writes.
///
/// Derived from the name actually in use rather than a fixed string, so a
/// configured database keeps its own name and the two files in one directory
/// read as what they are: the same audit history under two schema versions.
pub(crate) fn schema_versioned_sibling(path: &Path) -> Option<PathBuf> {
    let mut name = path.file_stem()?.to_os_string();
    name.push(format!("-v{}", codehelion_store::schema::SCHEMA_VERSION));
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    Some(path.with_file_name(name))
}

/// `path` with every component separated the way the platform separates them.
///
/// Where the database is gets recorded in a report and printed by every reader
/// of it, and the part of it a configuration supplies is written by hand — on
/// Windows commonly with the separator the rest of the world uses. Joining that
/// onto a resolved root leaves one path spelled two ways in the middle, which
/// reads as a typo and compares as a different file.
fn spelled_natively(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Apply the established, trusted configuration-path behaviour.
fn configured_database_path(boundary: &Path, configured: &Path) -> PathBuf {
    if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        boundary.join(configured)
    }
}

/// Keep a configuration-controlled database path inside `boundary`.
fn confined_database_path(boundary: &Path, configured: &Path, authority: &str) -> Result<PathBuf> {
    if configured.is_absolute() {
        bail!(
            "refusing database path {} from {authority}: repository configuration cannot choose storage outside {}; use --db <path> to explicitly choose an external database",
            configured.display(),
            boundary.display()
        );
    }
    if configured
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!(
            "refusing database path {} from {authority}: `..` can escape {}; use a relative path below that directory or --db <path> for an explicitly external database",
            configured.display(),
            boundary.display()
        );
    }
    let candidate = boundary.join(configured);
    ensure_existing_path_is_confined(boundary, configured, authority)?;
    Ok(candidate)
}

/// Reject an existing symlink component that would make a lexical relative
/// path leave the repository boundary.
fn ensure_existing_path_is_confined(
    boundary: &Path,
    configured: &Path,
    authority: &str,
) -> Result<()> {
    let mut prefix = boundary.to_path_buf();
    for component in configured.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(part) => prefix.push(part),
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                bail!(
                    "refusing database path {} from {authority}: it must be relative to {}",
                    configured.display(),
                    boundary.display()
                );
            }
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(_) => {
                let resolved = codehelion_core::paths::canonical(&prefix).with_context(|| {
                    format!("resolving database path component {}", prefix.display())
                })?;
                if !resolved.starts_with(boundary) {
                    bail!(
                        "refusing database path {} from {authority}: {} resolves outside {}; use --db <path> to explicitly choose an external database",
                        configured.display(),
                        prefix.display(),
                        boundary.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("checking database path component {}", prefix.display())
                });
            }
        }
    }
    Ok(())
}

/// Find the repository containing a scan root, falling back to the scan root
/// when it is not inside a Git worktree.
fn repository_root(root: &Path) -> PathBuf {
    let mut current = Some(root);
    while let Some(directory) = current {
        if directory.join(".git").exists() {
            return directory.to_path_buf();
        }
        current = directory.parent();
    }
    root.to_path_buf()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{incompatible_database_replacement, schema_versioned_sibling, spelled_natively};

    /// Where the database is has to read as one path, whatever mixture of
    /// separators and redundant components the configuration reached it by.
    #[test]
    fn a_configured_location_is_spelled_one_way() {
        let boundary = Path::new("project");
        for configured in ["state/audit.db", "state/./audit.db", "./state/audit.db"] {
            assert_eq!(
                spelled_natively(&boundary.join(configured)),
                ["project", "state", "audit.db"].iter().collect::<PathBuf>(),
                "{configured}"
            );
        }
    }

    /// The database written beside an unreadable one keeps the name in use,
    /// so a configured location and its neighbour read as one pair rather than
    /// as two unrelated files.
    #[test]
    fn the_database_written_beside_another_keeps_the_configured_name() {
        let version = codehelion_store::schema::SCHEMA_VERSION;
        for (configured, expected) in [
            (
                ".codehelion/audit.db",
                format!(".codehelion/audit-v{version}.db"),
            ),
            (
                "state/history.sqlite",
                format!("state/history-v{version}.sqlite"),
            ),
            ("state/history", format!("state/history-v{version}")),
        ] {
            assert_eq!(
                schema_versioned_sibling(Path::new(configured)),
                Some(PathBuf::from(&expected)),
                "{configured}"
            );
        }
    }

    /// A path with no database at it needs no neighbour: a run creates it and
    /// records there, which is what an absent database is for.
    #[test]
    fn an_absent_database_is_left_for_the_run_to_create() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert_eq!(
            incompatible_database_replacement(&directory.path().join("audit.db")),
            None
        );
    }

    /// Folding the spelling is not folding the path: what climbs out of a
    /// directory still climbs out of it, so the checks that refuse such a path
    /// are looking at what it says.
    #[test]
    fn respelling_a_path_does_not_resolve_it() {
        assert_eq!(
            spelled_natively(Path::new("project/../elsewhere/audit.db")),
            ["project", "..", "elsewhere", "audit.db"]
                .iter()
                .collect::<PathBuf>()
        );
    }
}
