//! The `scan` command: the Fast pipeline from project discovery to the
//! recorded snapshot.
//!
//! The stages are: resolve configuration, discover source files, lex them
//! with the per-language frontends (files spread across worker threads),
//! detect clones, derive stable identifiers, record one atomic snapshot in
//! the audit database, and render a report. Nothing in this path executes
//! target code: files are only read.
//!
//! Everything the pipeline drops is accounted for in the report — generated
//! files, glob-excluded files, unreadable files and engine budget exhaustion
//! all surface as counts or notes, never as silent omissions.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::discovery::{
    self, BuildVariant, ContentHash, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    GeneratedMarkers, Language, LanguageSelection, NORMALIZATION_VERSION, SourceUnit,
};
use codehelion_core::engine::{
    self, CloneGroup, CloneType, EngineConfig, EngineReport, InputFile, LiteralNorm,
};
use codehelion_core::frontend::{Frontend, Token, Unit};
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, FileContext, GroupIds};
use codehelion_store::Store;
use codehelion_store::snapshot::{GroupRow, MemberRow, Snapshot, UnitRow};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::Outcome;
use crate::cli::{Format, ScanArgs};
use crate::config::{self, Config, LiteralNormalization};

/// Number of groups the text report lists in detail.
const REPORT_GROUP_LIMIT: usize = 10;

/// One lexed source file, ready for the engine.
struct LexedSource {
    relative_path: String,
    language: Language,
    frontend_version: &'static str,
    tokens: Vec<Token>,
    units: Vec<Unit>,
    diagnostics: usize,
}

/// Execute `codehelion scan` in Fast mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report
/// output fails. Per-file problems (unreadable or malformed sources) are
/// counted and reported instead of failing the scan.
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    if args.format == Format::Json {
        bail!("JSON reports are not yet implemented; use --format text");
    }
    let started_at = rfc3339_now();
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let cfg = config::load(args.config.as_deref(), &root)?.config;
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(&root, &cfg, args.no_ignore)?;
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;
    let (lexed, unreadable) = lex_sources(&sources, jobs)?;

    let engine_config = EngineConfig {
        min_clone_tokens: usize::try_from(cfg.min_clone_tokens)
            .context("min-clone-tokens out of range")?,
        literals: literal_norm(cfg.literal_normalization),
        ..EngineConfig::default()
    };
    let input: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|file| InputFile {
            tokens: &file.tokens,
            units: &file.units,
        })
        .collect();
    let contexts: Vec<FileContext<'_>> = lexed
        .iter()
        .map(|file| FileContext {
            frontend_version: file.frontend_version,
            language: file.language,
        })
        .collect();
    let report = engine::detect(&input, &engine_config);
    let ids = stable_id::report_ids(
        &input,
        &contexts,
        &discovered.build_variant,
        &report,
        engine_config.literals,
    );

    let db_path = database_path(&root, args.db.as_deref(), &cfg);
    let run_id = record(
        &root,
        &cfg,
        &db_path,
        &started_at,
        &discovered.build_variant,
        &lexed,
        &contexts,
        &report,
        &ids,
    )?;

    let render = RenderContext {
        root: &root,
        lexed: &lexed,
        discovered: &discovered,
        glob_excluded,
        unreadable,
        report: &report,
        ids: &ids,
        db_path: &db_path,
        run_id,
    };
    write_report(args.output.as_deref(), out, &render)?;

    let visible = report
        .groups
        .iter()
        .filter(|group| group.suppressed.is_none())
        .count();
    if args.fail_on_findings && visible > 0 {
        Ok(Outcome::FindingsPresent)
    } else {
        Ok(Outcome::Success)
    }
}

/// Resolve the worker-thread count: flag over configuration over the number
/// of available CPUs.
fn effective_jobs(flag: Option<usize>, configured: Option<usize>) -> Result<usize> {
    match flag.or(configured) {
        Some(0) => bail!("jobs must be at least 1"),
        Some(jobs) => Ok(jobs),
        None => Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)),
    }
}

/// Map the configured literal strategy onto the engine's.
const fn literal_norm(setting: LiteralNormalization) -> LiteralNorm {
    match setting {
        LiteralNormalization::Preserve => LiteralNorm::Preserve,
        LiteralNormalization::Category => LiteralNorm::Category,
        LiteralNormalization::Full => LiteralNorm::Full,
    }
}

/// Run project discovery under the effective configuration.
fn discover_sources(root: &Path, cfg: &Config, no_ignore: bool) -> Result<DiscoveryReport> {
    let discovery_config = DiscoveryConfig {
        respect_gitignore: !no_ignore,
        languages: LanguageSelection {
            rust: cfg.languages.rust,
            c: cfg.languages.c,
            cpp: cfg.languages.cpp,
        },
        generated_markers: GeneratedMarkers::new(
            cfg.suppression.generated_markers.clone(),
            DEFAULT_SCAN_LINES,
        ),
        ..DiscoveryConfig::default()
    };
    Ok(discovery::discover(root, &discovery_config)?)
}

/// Apply the configured include/exclude globs to the discovered sources.
/// Returns the retained sources and how many were filtered out.
fn filter_globs(cfg: &Config, sources: Vec<SourceUnit>) -> Result<(Vec<SourceUnit>, usize)> {
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

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("glob pattern {pattern:?}"))?);
    }
    Ok(Some(builder.build()?))
}

/// Lex every source, spreading contiguous chunks across `jobs` worker
/// threads. Chunks are joined in order, so the result order equals the
/// (deterministic) discovery order regardless of thread scheduling. Files
/// that vanished since discovery are counted, not fatal.
fn lex_sources(sources: &[SourceUnit], jobs: usize) -> Result<(Vec<LexedSource>, u64)> {
    if sources.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let chunk_size = sources.len().div_ceil(jobs);
    let mut chunk_results: Vec<Vec<Option<LexedSource>>> = Vec::new();
    let mut worker_panicked = false;
    std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(lex_one).collect::<Vec<_>>()))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(results) => chunk_results.push(results),
                Err(_) => worker_panicked = true,
            }
        }
    });
    if worker_panicked {
        bail!("a lexer worker thread panicked");
    }
    let mut lexed = Vec::with_capacity(sources.len());
    let mut unreadable = 0u64;
    for result in chunk_results.into_iter().flatten() {
        match result {
            Some(file) => lexed.push(file),
            None => unreadable += 1,
        }
    }
    Ok((lexed, unreadable))
}

/// Read and lex one source file; `None` when the file cannot be read.
fn lex_one(source: &SourceUnit) -> Option<LexedSource> {
    let bytes = std::fs::read(&source.absolute_path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let file = match source.language {
        Language::Rust => codehelion_frontend_rust::RustFrontend.lex(&text),
        Language::C => codehelion_frontend_c::CFrontend.lex(&text),
        Language::Cpp => codehelion_frontend_cpp::CppFrontend.lex(&text),
    };
    Some(LexedSource {
        relative_path: source.relative_path.to_string_lossy().into_owned(),
        language: file.language,
        frontend_version: file.frontend_version,
        tokens: file.tokens,
        units: file.units,
        diagnostics: file.diagnostics.len(),
    })
}

/// The audit-database location: an explicit flag is taken as given (relative
/// to the working directory); the configured path resolves against the scan
/// root unless absolute.
fn database_path(root: &Path, flag: Option<&Path>, cfg: &Config) -> PathBuf {
    flag.map_or_else(
        || {
            if cfg.database.is_absolute() {
                cfg.database.clone()
            } else {
                root.join(&cfg.database)
            }
        },
        Path::to_path_buf,
    )
}

/// Assemble and persist the snapshot; returns the recorded run id.
#[allow(clippy::too_many_arguments)] // pipeline hand-off, one call site
fn record(
    root: &Path,
    cfg: &Config,
    db_path: &Path,
    started_at: &str,
    variant: &BuildVariant,
    lexed: &[LexedSource],
    contexts: &[FileContext<'_>],
    report: &EngineReport,
    ids: &[GroupIds],
) -> Result<i64> {
    let (units, groups) = snapshot_rows(lexed, contexts, variant, report, ids);
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let detector_versions = detector_versions();
    let root_path = root.to_string_lossy();
    let finished_at = rfc3339_now();
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
        started_at,
        finished_at: &finished_at,
        variant,
        detector_versions: &detector_versions,
        units,
        groups,
    };
    let mut store = open_store(db_path)?;
    Ok(store.record_snapshot(&snapshot)?)
}

/// Open (creating directories and running migrations as needed) the store.
fn open_store(path: &Path) -> Result<Store> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    Store::open(path).with_context(|| format!("opening audit database {}", path.display()))
}

/// The `(component, version)` pairs recorded with every snapshot.
fn detector_versions() -> Vec<(String, String)> {
    vec![
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        (
            "normalization".to_string(),
            NORMALIZATION_VERSION.to_string(),
        ),
        (
            "frontend.rust".to_string(),
            codehelion_frontend_rust::FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.c".to_string(),
            codehelion_frontend_c::FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.cpp".to_string(),
            codehelion_frontend_cpp::FRONTEND_VERSION.to_string(),
        ),
    ]
}

/// Turn the engine report and its stable identifiers into store rows.
///
/// Only units that host at least one occurrence are written; each is written
/// once even when several members share it. The unit fingerprint is computed
/// exactly as the finding ids' host fingerprint was, so the stored unit row
/// and the finding identity always agree.
fn snapshot_rows(
    lexed: &[LexedSource],
    contexts: &[FileContext<'_>],
    variant: &BuildVariant,
    report: &EngineReport,
    ids: &[GroupIds],
) -> (Vec<UnitRow>, Vec<GroupRow>) {
    let mut host_index: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for group in &report.groups {
        for member in &group.members {
            if let Some(unit) = member.unit {
                host_index.entry((member.file, unit)).or_insert(0);
            }
        }
    }
    let mut units = Vec::with_capacity(host_index.len());
    for (index, ((file, unit_idx), slot)) in host_index.iter_mut().enumerate() {
        *slot = index;
        let source = &lexed[*file];
        let unit = &source.units[*unit_idx];
        let end = unit.token_end.min(source.tokens.len());
        let tokens = &source.tokens[unit.token_start..end];
        let end_line = tokens
            .last()
            .map_or(unit.span.start_line, |token| token.span.start_line);
        units.push(UnitRow {
            fingerprint: stable_id::unit_fingerprint(
                variant,
                &contexts[*file],
                tokens,
                ContentNorm::Raw,
            ),
            language: source.language,
            kind: unit.kind,
            name: unit.name.clone(),
            file_path: source.relative_path.clone(),
            start_line: unit.span.start_line,
            end_line,
            token_count: tokens.len(),
        });
    }

    let groups = report
        .groups
        .iter()
        .zip(ids)
        .map(|(group, group_ids)| GroupRow {
            fingerprint: group_ids.fingerprint,
            clone_type: group.clone_type,
            score: group.score,
            entropy_bits: group.entropy_bits,
            suppress_reason: group.suppressed.map(|reason| reason.name().to_string()),
            members: group
                .members
                .iter()
                .zip(&group_ids.members)
                .map(|(instance, member_ids)| MemberRow {
                    content: member_ids.content,
                    finding: member_ids.finding,
                    language: lexed[instance.file].language,
                    host_unit: instance.unit.map(|unit| host_index[&(instance.file, unit)]),
                    file_path: lexed[instance.file].relative_path.clone(),
                    start_line: instance.start_line,
                    end_line: instance.end_line,
                    token_count: instance.token_end - instance.token_start,
                })
                .collect(),
        })
        .collect();
    (units, groups)
}

/// Everything the text report needs.
struct RenderContext<'a> {
    root: &'a Path,
    lexed: &'a [LexedSource],
    discovered: &'a DiscoveryReport,
    glob_excluded: usize,
    unreadable: u64,
    report: &'a EngineReport,
    ids: &'a [GroupIds],
    db_path: &'a Path,
    run_id: i64,
}

/// Render the report to `--output` when given, otherwise to `out`.
fn write_report(
    output: Option<&Path>,
    out: &mut impl Write,
    render: &RenderContext<'_>,
) -> Result<()> {
    let mut text = Vec::new();
    render_summary(&mut text, render)?;
    render_groups(&mut text, render)?;
    match output {
        Some(path) => {
            std::fs::write(path, &text).with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
        }
        None => out.write_all(&text)?,
    }
    Ok(())
}

fn render_summary(out: &mut impl Write, ctx: &RenderContext<'_>) -> Result<()> {
    let count = |language: Language| {
        ctx.lexed
            .iter()
            .filter(|file| file.language == language)
            .count()
    };
    writeln!(out, "codehelion scan (fast mode)")?;
    writeln!(out, "  root: {}", ctx.root.display())?;
    writeln!(
        out,
        "  files: {} analysed (rust {}, c {}, cpp {})",
        ctx.lexed.len(),
        count(Language::Rust),
        count(Language::C),
        count(Language::Cpp),
    )?;
    writeln!(
        out,
        "  excluded: {} generated, {} by glob, {} skipped",
        ctx.discovered.suppressed_generated.len(),
        ctx.glob_excluded,
        ctx.discovered.skipped.total() + ctx.unreadable,
    )?;
    let diagnostics: usize = ctx.lexed.iter().map(|file| file.diagnostics).sum();
    writeln!(
        out,
        "  tokens: {}; lexer diagnostics: {diagnostics}",
        ctx.report.stats.tokens
    )?;
    let type1 = clone_type_count(ctx.report, CloneType::Type1);
    let type2 = clone_type_count(ctx.report, CloneType::Type2);
    let suppressed = ctx
        .report
        .groups
        .iter()
        .filter(|group| group.suppressed.is_some())
        .count();
    writeln!(
        out,
        "  clone groups: {} (type-1 {type1}, type-2 {type2}; {suppressed} suppressed as noise)",
        ctx.report.groups.len(),
    )?;
    writeln!(
        out,
        "  snapshot: run {} in {}",
        ctx.run_id,
        ctx.db_path.display()
    )?;
    if ctx.report.stats.pair_budget_exhausted {
        writeln!(
            out,
            "  note: the candidate-pair budget was exhausted; results may be incomplete"
        )?;
    }
    Ok(())
}

fn clone_type_count(report: &EngineReport, clone_type: CloneType) -> usize {
    report
        .groups
        .iter()
        .filter(|group| group.clone_type == clone_type)
        .count()
}

/// List the largest unsuppressed groups: size descending, fingerprint bytes
/// ascending on ties, so the listing is stable across reruns.
fn render_groups(out: &mut impl Write, ctx: &RenderContext<'_>) -> Result<()> {
    let mut visible: Vec<(usize, &CloneGroup)> = ctx
        .report
        .groups
        .iter()
        .enumerate()
        .filter(|(_, group)| group.suppressed.is_none())
        .collect();
    visible.sort_by(|(a_idx, a), (b_idx, b)| {
        group_size(b).cmp(&group_size(a)).then_with(|| {
            ctx.ids[*a_idx]
                .fingerprint
                .cmp(&ctx.ids[*b_idx].fingerprint)
        })
    });
    if visible.is_empty() {
        return Ok(());
    }
    writeln!(out)?;
    writeln!(out, "largest groups:")?;
    for (index, group) in visible.iter().take(REPORT_GROUP_LIMIT) {
        writeln!(
            out,
            "  {} {} {} instances, {} tokens",
            ctx.ids[*index].fingerprint.to_hex(),
            group.clone_type.name(),
            group.members.len(),
            group_size(group),
        )?;
        for (position, member) in group.members.iter().enumerate() {
            let source = &ctx.lexed[member.file];
            let unit_name = member
                .unit
                .and_then(|unit| source.units[unit].name.as_deref())
                .map_or_else(String::new, |name| format!(" ({name})"));
            let canonical = if position == 0 { " [canonical]" } else { "" };
            writeln!(
                out,
                "    {}:{}-{}{unit_name}{canonical}",
                source.relative_path, member.start_line, member.end_line,
            )?;
        }
    }
    if visible.len() > REPORT_GROUP_LIMIT {
        writeln!(
            out,
            "  ... and {} more groups",
            visible.len() - REPORT_GROUP_LIMIT
        )?;
    }
    Ok(())
}

/// The largest member's token count, used as the group's reported size.
fn group_size(group: &CloneGroup) -> usize {
    group
        .members
        .iter()
        .map(|member| member.token_end - member.token_start)
        .max()
        .unwrap_or(0)
}

/// The current time as fixed-width RFC 3339 UTC with microsecond precision.
///
/// Hand-formatted so the width never varies: lexicographic order then equals
/// chronological order, which the store's latest-run ordering relies on.
fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let micros = now.subsec_micros();
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rem = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
    )
}

/// Convert days since 1970-01-01 to a proleptic-Gregorian civil date.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_point = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_point + 2) / 5 + 1;
    let month = if month_point < 10 {
        month_point + 3
    } else {
        month_point - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // leap year start
        assert_eq!(civil_from_days(19_783), (2024, 3, 1)); // day after Feb 29
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn timestamps_are_fixed_width_rfc3339() {
        let stamp = rfc3339_now();
        assert_eq!(stamp.len(), "1970-01-01T00:00:00.000000Z".len());
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp.as_bytes()[10], b'T');
    }

    #[test]
    fn jobs_resolution_prefers_flag_then_config() {
        assert_eq!(effective_jobs(Some(3), Some(8)).unwrap(), 3);
        assert_eq!(effective_jobs(None, Some(8)).unwrap(), 8);
        assert!(effective_jobs(None, None).unwrap() >= 1);
        assert!(effective_jobs(Some(0), None).is_err());
    }

    #[test]
    fn glob_filter_applies_include_then_exclude() {
        let cfg = Config {
            include: vec!["src/**".to_string()],
            exclude: vec!["src/gen/**".to_string()],
            ..Config::default()
        };
        let sources = ["src/a.rs", "src/gen/b.rs", "vendor/c.rs"]
            .iter()
            .map(|path| SourceUnit {
                relative_path: PathBuf::from(path),
                absolute_path: PathBuf::from(path),
                language: Language::Rust,
                is_header: false,
                content_hash: ContentHash::of(b""),
                byte_len: 0,
                package: None,
                target_kind: discovery::TargetKind::Library,
            })
            .collect();
        let (kept, excluded) = filter_globs(&cfg, sources).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].relative_path, PathBuf::from("src/a.rs"));
        assert_eq!(excluded, 2);
    }

    #[test]
    fn malformed_globs_are_an_error() {
        let cfg = Config {
            include: vec!["src/[".to_string()],
            ..Config::default()
        };
        assert!(filter_globs(&cfg, Vec::new()).is_err());
    }
}
