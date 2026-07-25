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

pub mod structural;

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{
    self, BuildVariant, ContentHash, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    GeneratedMarkers, Language, LanguageSelection, NORMALIZATION_VERSION, SourceUnit,
};
use codehelion_core::engine::{
    self, CloneGroup, EngineConfig, EngineReport, InputFile, LiteralNorm,
};
use codehelion_core::frontend::{Frontend, Token, Unit};
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, FileContext, GroupIds};
use codehelion_store::Store;
use codehelion_store::snapshot::{GroupRow, MemberRow, Snapshot, UnitRow};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::Outcome;
use crate::cli::{Format, ScanArgs};
use crate::config::{self, Config, LiteralNormalization};
use crate::report::{self, Report};
use crate::suppress;

/// One lexed source file, ready for the engine.
struct LexedSource {
    relative_path: String,
    language: Language,
    frontend_version: &'static str,
    tokens: Vec<Token>,
    units: Vec<Unit>,
    /// `(start, end)` line range of each unit, parallel to `units`.
    unit_lines: Vec<(u32, u32)>,
    /// 1-based lines carrying an inline suppression marker.
    marker_lines: Vec<u32>,
    /// Source lines in the file.
    lines: u64,
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
    let lex_timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (lexed, unreadable, timed_out) = lex_sources(&sources, jobs, lex_timeout)?;

    let engine_config = engine_config(&cfg)?;
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

    let any_markers = lexed.iter().any(|file| !file.marker_lines.is_empty());
    let rules = suppress::Rules::compile(&cfg.suppression, any_markers)?;
    let file_suppressions: Vec<suppress::FileSuppression> = lexed
        .iter()
        .map(|file| rules.evaluate_file(&file.relative_path, &file.marker_lines, &unit_spans(file)))
        .collect();
    let group_suppressed: Vec<Option<usize>> = report
        .groups
        .iter()
        .zip(&ids)
        .map(|(group, group_ids)| {
            // A clone id names this exact group, so it decides before any
            // rule that happens to cover where the members sit.
            rules
                .clone_id_rule(&group_ids.fingerprint.to_hex())
                .or_else(|| group_rule(&rules, &file_suppressions, group))
        })
        .collect();

    let db_path = database_path(&root, args.db.as_deref(), &cfg);
    let finished_at = rfc3339_now();
    let run_id = record(
        &root,
        &cfg,
        &db_path,
        &started_at,
        &finished_at,
        &discovered.build_variant,
        &lexed,
        &contexts,
        &report,
        &ids,
        &rules,
        &group_suppressed,
    )?;

    let model = build_report(&BuildInputs {
        root: &root,
        db_path: &db_path,
        run_id,
        started_at: &started_at,
        finished_at: &finished_at,
        discovered: &discovered,
        glob_excluded,
        unreadable,
        timed_out,
        lexed: &lexed,
        report: &report,
        ids: &ids,
        rules: &rules,
        group_suppressed: &group_suppressed,
    });
    write_report(args, out, &model)?;

    let visible = model
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

/// Everything [`build_report`] needs from the pipeline.
struct BuildInputs<'a> {
    root: &'a Path,
    db_path: &'a Path,
    run_id: i64,
    started_at: &'a str,
    finished_at: &'a str,
    discovered: &'a DiscoveryReport,
    glob_excluded: usize,
    unreadable: u64,
    timed_out: u64,
    lexed: &'a [LexedSource],
    report: &'a EngineReport,
    ids: &'a [GroupIds],
    rules: &'a suppress::Rules,
    group_suppressed: &'a [Option<usize>],
}

/// The configured suppression rules that hid nothing this run, read off the
/// rules the groups actually cited.
fn unused_suppressions(inputs: &BuildInputs<'_>) -> Vec<report::UnusedRule> {
    let used: std::collections::BTreeSet<usize> = inputs
        .group_suppressed
        .iter()
        .filter_map(|rule| *rule)
        .collect();
    inputs
        .rules
        .unused(&used)
        .into_iter()
        .map(|row| report::UnusedRule {
            scope: row.scope.clone(),
            pattern: row.pattern.clone(),
        })
        .collect()
}

/// A count as the report model carries it. Saturating rather than fallible:
/// a count this large is already past any meaning a report could carry.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The Fast pipeline's pass counts, stage by stage: a winnowed fingerprint
/// index, the seed pairs its posting lists propose, the fragments the
/// identifier-normalized pass cuts from those seeds, and the pairs that
/// survive verification.
fn funnel(stats: &engine::EngineStats) -> Vec<report::FunnelStage> {
    vec![
        report::FunnelStage::new("tokens", as_u64(stats.tokens)),
        report::FunnelStage::new("fingerprints", as_u64(stats.raw_fingerprints)),
        report::FunnelStage::new(
            "indexed values",
            as_u64(stats.raw_distinct.saturating_sub(stats.stop_fingerprints)),
        )
        .dropping("high_frequency", as_u64(stats.stop_fingerprints))
        .dropping("high_frequency_postings", as_u64(stats.stop_postings)),
        report::FunnelStage::new("seed pairs", as_u64(stats.seed_candidates)),
        report::FunnelStage::new("fragments", as_u64(stats.fragments)),
        report::FunnelStage::new("fragment classes", as_u64(stats.fragment_classes))
            .dropping("class_cap", as_u64(stats.class_cap_dropped))
            .dropping("hash_collision", as_u64(stats.hash_collisions)),
        report::FunnelStage::new("verified pairs", as_u64(stats.pairs)),
    ]
}

/// Assemble the report model both output formats render from. Groups are
/// ordered by priority descending, fingerprint bytes ascending on ties, so
/// every view is stable across reruns.
fn build_report(inputs: &BuildInputs<'_>) -> Report {
    let count = |language: Language| {
        u64::try_from(
            inputs
                .lexed
                .iter()
                .filter(|file| file.language == language)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    let count_groups = |predicate: &dyn Fn(usize) -> bool| {
        u64::try_from(
            (0..inputs.report.groups.len())
                .filter(|i| predicate(*i))
                .count(),
        )
        .unwrap_or(u64::MAX)
    };

    let variant = &inputs.discovered.build_variant;
    let mut order: Vec<usize> = (0..inputs.report.groups.len()).collect();
    order.sort_by(|a, b| {
        let (pa, pb) = (
            final_priority(&inputs.report.groups[*a]),
            final_priority(&inputs.report.groups[*b]),
        );
        pb.total_cmp(&pa)
            .then_with(|| inputs.ids[*a].fingerprint.cmp(&inputs.ids[*b].fingerprint))
    });

    Report {
        schema_version: report::SCHEMA_VERSION,
        run: report::RunInfo {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            mode: variant.mode.name().to_string(),
            root: inputs.root.display().to_string(),
            started_at: inputs.started_at.to_string(),
            finished_at: inputs.finished_at.to_string(),
            build_variant: report::BuildVariantInfo {
                mode: variant.mode.name().to_string(),
                languages: variant
                    .languages
                    .enabled()
                    .into_iter()
                    .map(|language| language.name().to_string())
                    .collect(),
                normalization_version: variant.normalization_version,
                fingerprint: variant.fingerprint(),
            },
            detector_versions: detector_versions()
                .into_iter()
                .map(|(component, version)| report::DetectorVersion { component, version })
                .collect(),
            database: inputs.db_path.display().to_string(),
            run_id: inputs.run_id,
        },
        summary: report::Summary {
            files: report::FileCounts {
                total: as_u64(inputs.lexed.len()),
                rust: count(Language::Rust),
                c: count(Language::C),
                cpp: count(Language::Cpp),
            },
            lines: inputs.lexed.iter().map(|file| file.lines).sum(),
            tokens: as_u64(inputs.report.stats.tokens),
            lexer_diagnostics: as_u64(inputs.lexed.iter().map(|file| file.diagnostics).sum()),
            excluded: report::ExcludedCounts {
                generated: as_u64(inputs.discovered.suppressed_generated.len()),
                by_glob: as_u64(inputs.glob_excluded),
                skipped: inputs.discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
            },
            groups: report::GroupCounts {
                total: as_u64(inputs.report.groups.len()),
                type_1: count_groups(&|i| inputs.report.groups[i].clone_type == CloneClass::Type1),
                type_2: count_groups(&|i| inputs.report.groups[i].clone_type == CloneClass::Type2),
                // The Fast engine matches identical content only.
                type_3: 0,
                // The Fast engine compares whole units only.
                fragment_scope: 0,
                folded_runs: 0,
                subsumed_runs: 0,
                test_code: 0,
            },
            suppressed: report::SuppressedCounts {
                noise: count_groups(&|i| inputs.report.groups[i].suppressed.is_some()),
                by_rule: count_groups(&|i| {
                    inputs.report.groups[i].suppressed.is_none()
                        && inputs.group_suppressed[i].is_some()
                }),
            },
            unused_suppressions: unused_suppressions(inputs),
            funnel: funnel(&inputs.report.stats),
            pair_budget_exhausted: inputs.report.stats.pair_budget_exhausted,
        },
        groups: order
            .iter()
            .map(|&index| build_group(inputs, index))
            .collect(),
    }
}

/// One group of the report model, with its suppression cause resolved.
fn build_group(inputs: &BuildInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.report.groups[index];
    let suppressed = group.suppressed.map_or_else(
        || {
            inputs.group_suppressed[index].map(|rule| {
                let row = &inputs.rules.rows[rule];
                report::Suppression {
                    kind: report::SuppressionKind::Rule,
                    reason: None,
                    scope: Some(row.scope.clone()),
                    pattern: Some(row.pattern.clone()),
                }
            })
        },
        |reason| {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some(reason.name().to_string()),
                scope: None,
                pattern: None,
            })
        },
    );
    report::Group {
        fingerprint: inputs.ids[index].fingerprint.to_hex(),
        clone_type: group.clone_type.name().to_string(),
        scope: CloneScope::Unit.name().to_string(),
        statements: None,
        confidence: group.score,
        priority: report::Priority {
            value: final_priority(group),
            largest_member_tokens: u64::try_from(group_size(group)).unwrap_or(u64::MAX),
            extra_instances: u64::try_from(group.members.len().saturating_sub(1))
                .unwrap_or(u64::MAX),
            similarity: group.score,
        },
        // The Fast engine groups on identical content; it scores no
        // similarity dimensions to report, classifies no shapes and reads no
        // test marker: all three need Syntax IR, which this mode never builds.
        similarity: None,
        boilerplate: None,
        test_code: false,
        suppressed,
        members: group
            .members
            .iter()
            .zip(&inputs.ids[index].members)
            .enumerate()
            .map(|(position, (instance, member_ids))| {
                let source = &inputs.lexed[instance.file];
                report::Member {
                    finding_id: member_ids.finding.to_hex(),
                    file: source.relative_path.clone(),
                    start_line: instance.start_line,
                    end_line: instance.end_line,
                    unit: instance
                        .unit
                        .and_then(|unit| source.units[unit].name.clone()),
                    tokens: u64::try_from(instance.token_end - instance.token_start)
                        .unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    }
}

/// Render the model in the requested format, to `--output` when given,
/// otherwise to `out`. Colour is used only for text going to a terminal.
pub(crate) fn write_report(args: &ScanArgs, out: &mut impl Write, model: &Report) -> Result<()> {
    let text = match args.format {
        Format::Json => model.to_json().context("serializing the JSON report")?,
        Format::Sarif => model.to_sarif().context("serializing the SARIF report")?,
        Format::Text => {
            let options = report::TextOptions {
                verbose: args.verbose,
                color: args.output.is_none() && std::io::stdout().is_terminal(),
                show_suppressed: args.show_suppressed,
            };
            let mut buffer = Vec::new();
            model.render_text(options, &mut buffer)?;
            String::from_utf8(buffer).context("rendering the text report")?
        }
    };
    match args.output.as_deref() {
        Some(path) => {
            std::fs::write(path, &text).with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
        }
        None => out.write_all(text.as_bytes())?,
    }
    Ok(())
}

/// One lexed file's units as the suppression rules see them: their line
/// ranges paired with the names the lexer recovered.
fn unit_spans(file: &LexedSource) -> Vec<suppress::UnitSpan<'_>> {
    file.units
        .iter()
        .zip(&file.unit_lines)
        .map(|(unit, &(start_line, end_line))| suppress::UnitSpan {
            start_line,
            end_line,
            name: unit.name.as_deref(),
        })
        .collect()
}

/// The rule suppressing a whole group: present only when *every* member is
/// suppressed. The canonical (first) member's rule is the one recorded.
fn group_rule(
    rules: &suppress::Rules,
    files: &[suppress::FileSuppression],
    group: &CloneGroup,
) -> Option<usize> {
    let mut first = None;
    for member in &group.members {
        let rule = rules.member_rule(
            &files[member.file],
            member.start_line,
            member.end_line,
            member.unit,
        )?;
        if first.is_none() {
            first = Some(rule);
        }
    }
    first
}

/// Final priority: `largest member size × extra instances × similarity` — a
/// proxy for the tokens duplicated beyond the first instance. The inputs are
/// always reported alongside; the collapsed number never replaces them.
fn final_priority(group: &CloneGroup) -> f64 {
    let size = u32::try_from(group_size(group)).unwrap_or(u32::MAX);
    let extra = u32::try_from(group.members.len().saturating_sub(1)).unwrap_or(u32::MAX);
    f64::from(size) * f64::from(extra) * group.score
}

/// Resolve the worker-thread count: flag over configuration over the number
/// of available CPUs.
pub(crate) fn effective_jobs(flag: Option<usize>, configured: Option<usize>) -> Result<usize> {
    match flag.or(configured) {
        Some(0) => bail!("jobs must be at least 1"),
        Some(jobs) => Ok(jobs),
        None => Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)),
    }
}

/// Build the engine configuration from the effective scan configuration:
/// detection knobs plus the configured candidate ceilings.
fn engine_config(cfg: &Config) -> Result<EngineConfig> {
    Ok(EngineConfig {
        min_clone_tokens: usize::try_from(cfg.min_clone_tokens)
            .context("min-clone-tokens out of range")?,
        literals: literal_norm(cfg.literal_normalization),
        posting_cap: cfg.limits.posting_cap,
        pair_budget: cfg.limits.pair_budget,
        ..EngineConfig::default()
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

/// What became of one source file handed to a frontend.
pub(crate) enum FileOutcome<T> {
    /// Read and analysed within the time ceiling.
    Done(Box<T>),
    /// The file could not be read.
    Unreadable,
    /// The frontend exceeded the configured time ceiling; the file is
    /// excluded.
    TimedOut,
}

/// Run `frontend` over every source, spreading contiguous chunks across
/// `jobs` worker threads.
///
/// Chunks are joined in order, so the result order equals the (deterministic)
/// discovery order regardless of thread scheduling. Files that vanished since
/// discovery or blew the time ceiling are counted, not fatal. Returns the
/// analysed files plus the unreadable and timed-out counts.
pub(crate) fn map_sources<T: Send>(
    sources: &[SourceUnit],
    jobs: usize,
    frontend: impl Fn(&SourceUnit) -> FileOutcome<T> + Sync,
) -> Result<(Vec<T>, u64, u64)> {
    if sources.is_empty() {
        return Ok((Vec::new(), 0, 0));
    }
    let chunk_size = sources.len().div_ceil(jobs);
    let mut chunk_results: Vec<Vec<FileOutcome<T>>> = Vec::new();
    let mut worker_panicked = false;
    let frontend = &frontend;
    std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(frontend).collect::<Vec<_>>()))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(results) => chunk_results.push(results),
                Err(_) => worker_panicked = true,
            }
        }
    });
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
fn lex_sources(
    sources: &[SourceUnit],
    jobs: usize,
    timeout: std::time::Duration,
) -> Result<(Vec<LexedSource>, u64, u64)> {
    map_sources(sources, jobs, |source| lex_one(source, timeout))
}

/// Read and lex one source file, enforcing the per-file time ceiling.
///
/// The ceiling is checked after the (single-pass, linear-time) lexer
/// returns: with the discovery size ceiling bounding the input, lexing
/// cannot run away, so a post-hoc check suffices to keep an unexpectedly
/// slow file out of the results while the skipped count keeps it visible.
fn lex_one(source: &SourceUnit, timeout: std::time::Duration) -> FileOutcome<LexedSource> {
    let started = std::time::Instant::now();
    let Ok(bytes) = std::fs::read(&source.absolute_path) else {
        return FileOutcome::Unreadable;
    };
    let text = String::from_utf8_lossy(&bytes);
    let file = match source.language {
        Language::Rust => codehelion_frontend_rust::RustFrontend.lex(&text),
        Language::C => codehelion_frontend_c::CFrontend.lex(&text),
        Language::Cpp => codehelion_frontend_cpp::CppFrontend.lex(&text),
    };
    if started.elapsed() > timeout {
        return FileOutcome::TimedOut;
    }
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
        relative_path: source.relative_path.to_string_lossy().into_owned(),
        language: file.language,
        frontend_version: file.frontend_version,
        tokens: file.tokens,
        units: file.units,
        unit_lines,
        marker_lines: suppress::marker_lines(&text),
        lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
        diagnostics: file.diagnostics.len(),
    }))
}

/// The audit-database location: an explicit flag is taken as given (relative
/// to the working directory); the configured path resolves against the scan
/// root unless absolute.
pub(crate) fn database_path(root: &Path, flag: Option<&Path>, cfg: &Config) -> PathBuf {
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
    finished_at: &str,
    variant: &BuildVariant,
    lexed: &[LexedSource],
    contexts: &[FileContext<'_>],
    report: &EngineReport,
    ids: &[GroupIds],
    rules: &suppress::Rules,
    group_suppressed: &[Option<usize>],
) -> Result<i64> {
    let (units, groups) = snapshot_rows(lexed, contexts, variant, report, ids, group_suppressed);
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let detector_versions = detector_versions();
    let root_path = root.to_string_lossy();
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
        started_at,
        finished_at,
        variant,
        detector_versions: &detector_versions,
        suppressions: rules.rows.clone(),
        units,
        groups,
        features: Vec::new(),
    };
    let mut store = open_store(db_path)?;
    Ok(store.record_snapshot(&snapshot)?)
}

/// Open (creating directories and running migrations as needed) the store.
pub(crate) fn open_store(path: &Path) -> Result<Store> {
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
    group_suppressed: &[Option<usize>],
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
        let (_, end_line) = source.unit_lines[*unit_idx];
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
        .zip(group_suppressed)
        .map(|((group, group_ids), suppressed_by)| GroupRow {
            fingerprint: group_ids.fingerprint,
            clone_type: group.clone_type,
            member_scope: CloneScope::Unit,
            // Fast mode compares tokens without a syntax tree, so it never
            // sees the attribute that marks a test.
            test_code: false,
            score: group.score,
            entropy_bits: group.entropy_bits,
            suppress_reason: group.suppressed.map(|reason| reason.name().to_string()),
            boilerplate: None,
            suppressed_by: *suppressed_by,
            final_priority: final_priority(group),
            // Fast mode measures no similarity breakdown and classifies no
            // boilerplate shapes.
            similarity: None,
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
pub(crate) fn rfc3339_now() -> String {
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
    fn engine_config_applies_configured_ceilings() {
        let cfg = Config {
            limits: config::Limits {
                posting_cap: 5,
                pair_budget: 7,
                ..config::Limits::default()
            },
            ..Config::default()
        };
        let engine = engine_config(&cfg).unwrap();
        assert_eq!(engine.posting_cap, 5);
        assert_eq!(engine.pair_budget, 7);
        // Detection knobs stay at their defaults.
        assert_eq!(engine.min_clone_tokens, 20);
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
