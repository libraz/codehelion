//! Scan resource limits, discovery, parallel mapping, and database confinement.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares runtime helpers across scan modes"
)]

use super::{
    ArmPath, Config, ConfigSource, Context, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    EngineConfig, Frontend, GeneratedMarkers, Glob, GlobSet, GlobSetBuilder, Language,
    LanguageSelection, LexedSource, LiteralNorm, LiteralNormalization, Path, PathBuf,
    ResolvedConfig, Result, ScanArgs, SourceUnit, bail, discovery, path_key, report, suppress,
};

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
    Unreadable,
    /// The file exceeded the configured parse-work budget; the file is
    /// excluded.
    TimedOut,
}

/// Parse-work capacity represented by one configured millisecond. The public
/// setting keeps its established unit for configuration compatibility, but the
/// decision is a pure function of input bytes rather than wall-clock load.
pub(super) const PARSE_BYTES_PER_MILLISECOND: u64 = 256;

/// Whether an input must be excluded before lexing or parsing.
///
/// A deterministic byte budget makes `--jobs` and host load unable to change
/// which files enter a scan. The discovery file-size ceiling remains the
/// primary bound; this is the tighter configurable per-frontend work budget.
pub(crate) fn exceeds_parse_budget(bytes: &[u8], budget: std::time::Duration) -> bool {
    let milliseconds = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    let allowed = milliseconds.saturating_mul(PARSE_BYTES_PER_MILLISECOND);
    u64::try_from(bytes.len()).unwrap_or(u64::MAX) > allowed
}

/// Run `frontend` over every source, spreading contiguous chunks across
/// `jobs` worker threads.
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
    let chunk_size = sources.len().div_ceil(jobs);
    let mut chunk_results: Vec<Vec<FileOutcome<T>>> = Vec::new();
    let mut worker_panicked = false;
    let frontend = &frontend;
    std::thread::scope(|scope| -> Result<()> {
        let handles: Result<Vec<_>> = sources
            .chunks(chunk_size)
            .map(|chunk| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        chunk.iter().map(frontend).collect::<Vec<_>>()
                    })
                    .context("starting frontend worker thread")
            })
            .collect();
        for handle in handles? {
            match handle.join() {
                Ok(results) => chunk_results.push(results),
                Err(_) => worker_panicked = true,
            }
        }
        Ok(())
    })?;
    if worker_panicked {
        bail!("a frontend worker thread panicked");
    }
    let mut analysed = Vec::with_capacity(sources.len());
    let mut unreadable = 0u64;
    let mut timed_out = 0u64;
    for result in chunk_results.into_iter().flatten() {
        match result {
            FileOutcome::Done(file) => analysed.push(*file),
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
    timeout: std::time::Duration,
) -> Result<(Vec<LexedSource>, u64, u64)> {
    map_sources(sources, jobs, |source| lex_one(source, timeout))
}

/// Read and lex one source file, enforcing the deterministic parse-work
/// budget before frontend work begins.
fn lex_one(source: &SourceUnit, budget: std::time::Duration) -> FileOutcome<LexedSource> {
    let Ok(bytes) = std::fs::read(&source.absolute_path) else {
        return FileOutcome::Unreadable;
    };
    if exceeds_parse_budget(&bytes, budget) {
        return FileOutcome::TimedOut;
    }
    let text = String::from_utf8_lossy(&bytes);
    let file = match source.language {
        Language::Rust => codehelion_frontend_rust::RustFrontend.lex(&text),
        Language::C => codehelion_frontend_c::CFrontend.lex(&text),
        Language::Cpp => codehelion_frontend_cpp::CppFrontend.lex(&text),
    };
    let arm_paths = match source.language {
        Language::Rust => vec![ArmPath::default(); file.tokens.len()],
        Language::C | Language::Cpp => {
            codehelion_frontend_c::lexer::conditional_paths(&text, &file.tokens)
        }
    };
    let unit_lines = file
        .units
        .iter()
        .map(|unit| {
            let end = unit.token_end.min(file.tokens.len());
            let end_line = file.tokens[unit.token_start..end]
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
        return Ok(path.to_path_buf());
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
        );
    }
    Ok(configured_database_path(&boundary, &config.config.database))
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
                let resolved = prefix.canonicalize().with_context(|| {
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
