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

mod shared;
pub mod structural;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::clone_class::CloneScope;
use codehelion_core::conditional::ArmPath;
use codehelion_core::discovery::{
    self, BuildVariant, ContentHash, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    GeneratedMarkers, Language, LanguageSelection, NORMALIZATION_VERSION, SourceUnit,
};
use codehelion_core::engine::{
    self, CloneGroup, EngineConfig, EngineReport, InputFile, LiteralNorm,
};
use codehelion_core::execution::ExecutionPolicy;
use codehelion_core::frontend::{Frontend, Token, Unit};
use codehelion_core::priority::Weights;
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, FileContext, GroupIds};
use codehelion_store::snapshot::{
    FileCountsRow, FileRow, GroupRow, GuardrailsRow, MemberRow, PriorityRow, Snapshot, SummaryRow,
    UnitRow,
};
use codehelion_store::{Store, fingerprint_hex};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::Value;

use crate::Outcome;
use crate::cli::{BaselineMode, Format, Mode, ScanArgs, SortAxis, ViewArgs};
use crate::config::{self, Config, ConfigSource, LiteralNormalization, ResolvedConfig};
use crate::report::{self, Report};
use crate::suppress;

/// Version of the JSON envelope used when a scan contains multiple build
/// variants or an explicit comparison report.
pub(crate) const PARTITIONED_REPORT_SCHEMA_VERSION: &str = "partitioned-scan-report-v2";

/// URI of the schema that describes [`PARTITIONED_REPORT_SCHEMA_VERSION`].
pub(crate) const PARTITIONED_REPORT_SCHEMA_URI: &str = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/partitioned-scan-report-v2.schema.json";

/// Turn configuration selection into durable report provenance.
#[must_use]
pub(crate) fn configuration_info(
    source: &ConfigSource,
    min_clone_tokens: u32,
) -> report::ConfigurationInfo {
    let (source, path) = match source {
        ConfigSource::Explicit(path) => ("explicit", Some(path.display().to_string())),
        ConfigSource::Discovered(path) => ("root", Some(path.display().to_string())),
        ConfigSource::Defaults => ("defaults", None),
    };
    report::ConfigurationInfo {
        source: source.to_string(),
        path,
        min_clone_tokens,
    }
}

/// One lexed source file, ready for the engine.
struct LexedSource {
    relative_path: String,
    language: Language,
    frontend_version: &'static str,
    tokens: Vec<Token>,
    /// Preprocessor arms for C-family tokens; Rust has none.
    arm_paths: Option<Vec<ArmPath>>,
    units: Vec<Unit>,
    /// `(start, end)` line range of each unit, parallel to `units`.
    unit_lines: Vec<(u32, u32)>,
    /// 1-based lines carrying an inline suppression marker.
    marker_lines: Vec<u32>,
    /// Source lines in the file.
    lines: u64,
    diagnostics: usize,
}

/// A first-run hint for the local audit database directory.
///
/// The scan lock creates the directory before the source pipeline starts, so
/// this value is captured by the command dispatcher before a mode acquires
/// that lock. It is emitted only after the mode and its report have completed.
pub(crate) struct DatabaseDirectoryHint {
    directory: PathBuf,
    ignore_entry: String,
}

impl DatabaseDirectoryHint {
    pub(crate) fn emit(self) {
        eprintln!(
            "note: created local database directory {}; consider adding `{}` to .gitignore",
            self.directory.display(),
            self.ignore_entry,
        );
    }
}

/// Capture whether this scan will create a new, unignored database directory.
///
/// An explicit `--db` is an intentional storage choice and never receives this
/// default-database hint. For all other paths, including a database selected by
/// configuration, the actual parent-directory state is the authority: this is
/// what the lock acquisition will create. Git classification is delegated to
/// the same helpers used by `doctor`.
pub(crate) fn new_database_directory_hint(
    args: &ScanArgs,
) -> Result<Option<DatabaseDirectoryHint>> {
    if args.db.is_some() {
        return Ok(None);
    }
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        // Let the selected mode return its usual actionable scan-path error.
        return Ok(None);
    }
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = database_path(&root, None, &resolved_config, args.untrusted)?;
    let Some(directory) = db_path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(None);
    };
    if directory.exists() {
        return Ok(None);
    }
    let Some(repo_root) = crate::find_git_root(&root) else {
        return Ok(None);
    };
    if crate::is_git_ignored(&repo_root, &db_path) {
        return Ok(None);
    }
    let ignore_entry = db_path
        .strip_prefix(&repo_root)
        .ok()
        .and_then(Path::parent)
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(
            || directory.display().to_string(),
            |path| format!("{}/", path.to_string_lossy().replace('\\', "/")),
        );
    Ok(Some(DatabaseDirectoryHint {
        directory: directory.to_path_buf(),
        ignore_entry,
    }))
}

/// Execute `codehelion scan` in Fast mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report
/// output fails. Per-file problems (unreadable or malformed sources) are
/// counted and reported instead of failing the scan.
#[allow(
    clippy::too_many_lines,
    reason = "the Fast scan orchestration intentionally keeps its stage order visible"
)]
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    validate_fast_args(args)?;
    let started_at = rfc3339_now();
    // Measured with a monotonic clock rather than by subtracting the recorded
    // timestamps: those are RFC 3339 strings whose resolution is the report's,
    // and a run that takes two seconds has to be reported as taking two
    // seconds rather than as taking some number of whole ones.
    let analysis_began = std::time::Instant::now();
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = scan_database_path(&root, args.db.as_deref(), &resolved_config, args.untrusted)?;
    let replay_database = args.db.is_some().then(|| spelled_for_a_command(&db_path));
    let _database_lock = crate::scan_lock::acquire(&db_path)?;
    let configuration = configuration_info(
        &resolved_config.source,
        resolved_config.config.min_clone_tokens,
    );
    let (cfg, guardrails) = guarded(resolved_config.config, args);
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(
        &root,
        &cfg,
        args.no_ignore,
        args.follow_links,
        args.compile_commands.as_deref(),
    )?;
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;

    let lex_timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (lexed, unreadable, timed_out) =
        lex_sources(&sources, jobs, cfg.limits.max_file_bytes, lex_timeout)
            .map_err(|error| crate::analysis_failure(Mode::Fast, error))?;

    let engine_config = engine_config(&cfg)?;
    let input: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|file| InputFile {
            tokens: &file.tokens,
            units: &file.units,
        })
        .collect();
    let arm_paths: Vec<Option<&[ArmPath]>> =
        lexed.iter().map(|file| file.arm_paths.as_deref()).collect();
    let contexts: Vec<FileContext<'_>> = lexed
        .iter()
        .map(|file| FileContext {
            frontend_version: file.frontend_version,
            language: file.language,
        })
        .collect();
    let report = engine::detect_with_arm_paths(&input, &arm_paths, &engine_config);
    let ids = stable_id::report_ids(
        &input,
        &contexts,
        &discovered.build_variant,
        &report,
        engine_config.literals,
    );

    let suppression =
        evaluate_suppression(args, &cfg, &discovered.build_variant, &lexed, &report, &ids)?;
    let Suppression {
        rules,
        baseline,
        groups: group_suppressed,
        matched_rules,
    } = suppression;

    let finished_at = rfc3339_now();
    let analysis_took = analysis_began.elapsed();
    let mut inputs = BuildInputs {
        root: &root,
        db_path: &db_path,
        replay_database: replay_database.as_deref(),
        configuration: &configuration,
        // Filled in only after the snapshot has been recorded. A provisional
        // report therefore cannot accidentally publish a fake database id.
        run_id: None,
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
        matched_rules: &matched_rules,
        suppression: &cfg.suppression,
        weights: cfg.priority.weights(),
        min_clone_tokens: u64::from(cfg.min_clone_tokens),
        literals: engine_config.literals,
        entropy_ratio_floor: engine_config.entropy_ratio_floor,
        sort: args.sort.axis(),
        reuse_allowed: !args.no_reuse,
        untrusted: args.untrusted,
        reused: false,
        changes: None,
    };
    let mut stored = summary_row(
        &inputs,
        baseline.as_ref().map(ScanBaseline::digest),
        guardrails.as_ref(),
    );
    let ranked = rank_groups(&inputs, &mut stored)?;
    let mut model = build_report(&inputs, &stored, ranked);
    model.run.run_id = inputs.run_id;
    model.run.reused = inputs.reused;
    model.summary.changes.clone_from(&inputs.changes);
    model.summary.guardrails = guardrails;
    // Counted against the assembled report rather than the raw analysis: a
    // stale entry is one whose duplication this run does not list.
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| apply_baseline(baseline, &mut model.groups));
    model.refresh_supplemental_summary();
    let recording_began = std::time::Instant::now();
    let record_result = record_ranked(
        &mut inputs,
        &cfg,
        &contexts,
        file_rows(&sources),
        &stored,
        &model.groups,
    );
    let recording_took = recording_began.elapsed();
    match record_result {
        Ok(()) => {
            model.run.run_id = inputs.run_id;
            model.run.reused = inputs.reused;
            model.run.timings = Some(report::RunTimings {
                analysis: analysis_took,
                recording: (!inputs.reused).then_some(recording_took),
            });
            model.summary.changes.clone_from(&inputs.changes);
            let hydration_error = if let Some(run_id) = model.run.run_id {
                match open_store(&db_path) {
                    Ok(store) => hydrate_artifact_savings(&store, run_id, &mut model.groups)
                        .and_then(|()| {
                            store
                                .preceding_compatible_run(run_id)
                                .map_err(Into::into)
                                .and_then(|predecessor| {
                                    predecessor.map_or(Ok(()), |predecessor| {
                                        hydrate_group_identity(
                                            &store,
                                            run_id,
                                            predecessor,
                                            &mut model.groups,
                                        )?;
                                        model.summary.top_churn = Some(top_group_churn(
                                            &store,
                                            run_id,
                                            predecessor,
                                            cfg.report.churn_top,
                                        )?);
                                        Ok(())
                                    })
                                })
                        })
                        .err()
                        .map(|error| (run_id, error)),
                    Err(error) => Some((run_id, error)),
                }
            } else {
                None
            };
            if let Some((run_id, error)) = hydration_error {
                for group in &mut model.groups {
                    group.artifact_savings.clear();
                }
                model.refresh_supplemental_summary();
                write_report_without_artifact_guidance(args, out, &model)?;
                eprintln!(
                    "warning: artifact savings were not loaded ({error}); run {run_id} remains recorded, but artifact evidence and guidance are unavailable for this report"
                );
                return Err(error);
            }
            model.refresh_supplemental_summary();
            write_report(args, out, &model)?;
            Ok(outcome(args, &model))
        }
        Err(error) => {
            // The analysis result is still useful even though it has no
            // durable identity. Do not hydrate artifact rows or emit replay
            // guidance for this provisional report.
            model.run.run_id = None;
            model.run.reused = false;
            model.run.timings = Some(report::RunTimings {
                analysis: analysis_took,
                recording: None,
            });
            model.summary.changes = None;
            for group in &mut model.groups {
                group.artifact_savings.clear();
            }
            model.refresh_supplemental_summary();
            write_report(args, out, &model)?;
            eprintln!(
                "warning: this run was not recorded ({error}); replay and baseline comparison are unavailable for it"
            );
            Err(error)
        }
    }
}

fn validate_fast_args(args: &ScanArgs) -> Result<()> {
    if args.compare_build_variants {
        bail!("--compare-build-variants requires --mode semantic");
    }
    if args.compare_languages {
        bail!("--compare-languages requires --mode semantic");
    }
    if args.include_trivial {
        bail!("--include-trivial requires --mode structural or --mode semantic");
    }
    if args.show_siblings {
        bail!("--show-siblings requires --mode structural or --mode semantic");
    }
    if args.siblings_by_signature {
        bail!("--siblings-by-signature requires --mode structural or --mode semantic");
    }
    if args.show_near_misses {
        bail!("--show-near-misses requires --mode structural or --mode semantic");
    }
    if args.sort == SortAxis::IdentifierJaccard {
        bail!("--sort identifier-jaccard requires --mode structural or --mode semantic");
    }
    if args.min_identifier_jaccard.is_some() {
        bail!("--min-identifier-jaccard requires --mode structural or --mode semantic");
    }
    Ok(())
}

/// What this invocation lets a compiler helper run out of the project.
///
/// Every way the permission could not take effect is refused here rather than
/// accepted and quietly dropped. A granted permission changes what a person
/// believes the run did: they think the thin part of the answer is the
/// project's, when it is the tool's.
///
/// # Errors
///
/// Fails on a class name that does not exist, on a permission given to a mode
/// that runs nothing, and on one given alongside `--untrusted`.
pub(crate) fn permitted(args: &ScanArgs) -> Result<ExecutionPolicy> {
    let Some(names) = args.allow_execution.as_deref() else {
        return Ok(ExecutionPolicy::deny_all());
    };
    if args.untrusted {
        bail!(
            "--untrusted permits nothing to run, and --allow-execution={names} \
             asks for something to. Drop whichever of the two was not meant"
        );
    }
    if args.mode != Mode::Semantic {
        bail!(
            "--allow-execution={names} has nothing to act on in {} mode, which \
             reads source and runs nothing; it applies to --mode semantic",
            args.mode.name()
        );
    }
    ExecutionPolicy::parse(names).map_err(Into::into)
}

/// What a finished scan exits with: findings present only when the caller
/// asked to be told by the status, and only counting what the report shows —
/// a suppressed group is one the reader said not to be told about.
pub(crate) fn outcome(args: &ScanArgs, model: &Report) -> Outcome {
    let visible = model
        .groups
        .iter()
        .filter(|group| group.suppressed.is_none())
        .count();
    if args.fail_on_findings && visible > 0 {
        Outcome::FindingsPresent
    } else {
        Outcome::Success
    }
}

/// What suppression decided for one run.
struct Suppression {
    /// The compiled rules, which the snapshot records.
    rules: suppress::Rules,
    /// The baseline the scan was given, if any.
    baseline: Option<ScanBaseline>,
    /// The rule hiding each group, parallel to the engine's groups.
    groups: Vec<Option<usize>>,
    /// Selectors that matched scanned source, even when another rule had
    /// precedence for a particular finding.
    matched_rules: BTreeSet<usize>,
}

/// Compile the suppression rules, apply the baseline, and decide which rule
/// hides each detected group.
fn evaluate_suppression(
    args: &ScanArgs,
    cfg: &Config,
    variant: &BuildVariant,
    lexed: &[LexedSource],
    report: &EngineReport,
    ids: &[GroupIds],
) -> Result<Suppression> {
    let any_markers = lexed.iter().any(|file| !file.marker_lines.is_empty());
    let mut rules = suppress::Rules::compile(&cfg.suppression, any_markers)?;
    let baseline = load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules,
        variant,
        &detector_versions(
            literal_norm(cfg.literal_normalization),
            cfg.entropy_ratio_floor,
        ),
        cfg.min_clone_tokens,
    )?;
    let file_suppressions: Vec<suppress::FileSuppression> = lexed
        .iter()
        .map(|file| rules.evaluate_file(&file.relative_path, &file.marker_lines, &unit_spans(file)))
        .collect();
    let matched_rules = file_suppressions
        .iter()
        .flat_map(suppress::FileSuppression::matched_rules)
        .collect();
    let groups = report
        .groups
        .iter()
        .zip(ids)
        .map(|(group, group_ids)| {
            // A clone id names this exact group, so it decides before any
            // rule that happens to cover where the members sit. The baseline
            // decides last: that a finding is not new says less about it than
            // anything the rules say about the code.
            shared::SuppressionPriority::first(|| {
                rules.clone_id_rule(&group_ids.fingerprint.to_hex())
            })
            .or_else(|| group_rule(&rules, &file_suppressions, group))
            .or_else(|| {
                rules.baseline_rule(&group_ids.fingerprint.to_hex(), as_u64(group.members.len()))
            })
            .finish()
        })
        .collect();
    Ok(Suppression {
        rules,
        baseline,
        groups,
        matched_rules,
    })
}

/// Everything [`build_report`] needs from the pipeline.
struct BuildInputs<'a> {
    root: &'a Path,
    db_path: &'a Path,
    /// The `--db` the commands this report prints have to repeat.
    replay_database: Option<&'a str>,
    configuration: &'a report::ConfigurationInfo,
    run_id: Option<i64>,
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
    matched_rules: &'a BTreeSet<usize>,
    /// What the report does with each classification a group can carry, which
    /// is what decides where a classified group is listed.
    suppression: &'a config::Suppression,
    /// How the run weighs the priority measures against one another.
    weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    min_clone_tokens: u64,
    /// The literal strategy the content ids were folded under.
    literals: LiteralNorm,
    /// The configured low-entropy suppression floor, normalized by clone
    /// length. It changes which groups are visible, so it is baseline input.
    entropy_ratio_floor: f64,
    /// The axis the run puts its entries in order on.
    sort: report::Sort,
    reuse_allowed: bool,
    untrusted: bool,
    reused: bool,
    changes: Option<report::TreeChanges>,
}

/// The configured suppression rules whose selectors matched no scanned source
/// or finding in this run.
fn unused_suppressions(inputs: &BuildInputs<'_>) -> Vec<report::UnusedRule> {
    shared::unused_suppressions(
        inputs.rules,
        inputs
            .matched_rules
            .iter()
            .copied()
            .chain(inputs.group_suppressed.iter().filter_map(|rule| *rule)),
    )
}

/// A count as the report model carries it. Saturating rather than fallible:
/// a count this large is already past any meaning a report could carry.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Count analyzed files by language in the persisted summary shape.
pub(crate) fn file_counts(languages: impl IntoIterator<Item = Language>) -> FileCountsRow {
    let mut counts = FileCountsRow::default();
    for language in languages {
        counts.total = counts.total.saturating_add(1);
        match language {
            Language::Rust => counts.rust = counts.rust.saturating_add(1),
            Language::C => counts.c = counts.c.saturating_add(1),
            Language::Cpp => counts.cpp = counts.cpp.saturating_add(1),
        }
    }
    counts
}

/// Convert one effective execution ceiling into its persisted summary shape.
pub(crate) fn guardrails_row(guardrails: &report::Guardrails) -> GuardrailsRow {
    GuardrailsRow {
        profile: guardrails.profile.clone(),
        max_file_bytes: guardrails.max_file_bytes,
        parse_timeout_ms: guardrails.parse_timeout_ms,
        helper_timeout_ms: guardrails.helper_timeout_ms,
        posting_cap: u64::try_from(guardrails.posting_cap).unwrap_or(u64::MAX),
        pair_budget: u64::try_from(guardrails.pair_budget).unwrap_or(u64::MAX),
        near_miss_delta_bits: guardrails.near_miss_delta.to_bits(),
        near_miss_cap: u64::try_from(guardrails.near_miss_cap).unwrap_or(u64::MAX),
        verification_budget: u64::try_from(guardrails.verification_budget).unwrap_or(u64::MAX),
        max_alignment_cells: u64::try_from(guardrails.max_alignment_cells).unwrap_or(u64::MAX),
        sibling_candidate_budget: u64::try_from(guardrails.sibling_candidate_budget)
            .unwrap_or(u64::MAX),
        sibling_per_group_cap: u64::try_from(guardrails.sibling_per_group_cap).unwrap_or(u64::MAX),
        sibling_total_cap: u64::try_from(guardrails.sibling_total_cap).unwrap_or(u64::MAX),
        signature_sibling_candidate_budget: u64::try_from(
            guardrails.signature_sibling_candidate_budget,
        )
        .unwrap_or(u64::MAX),
        signature_sibling_per_group_cap: u64::try_from(guardrails.signature_sibling_per_group_cap)
            .unwrap_or(u64::MAX),
        signature_sibling_total_cap: u64::try_from(guardrails.signature_sibling_total_cap)
            .unwrap_or(u64::MAX),
        signature_sibling_max_units_per_signature: u64::try_from(
            guardrails.signature_sibling_max_units_per_signature,
        )
        .unwrap_or(u64::MAX),
        max_component: u64::try_from(guardrails.max_component).unwrap_or(u64::MAX),
    }
}

/// Common inputs for the durable metadata every source scan reports.
pub(crate) struct RunInfoInputs<'a> {
    /// Scan root.
    pub root: &'a Path,
    /// Local audit database path.
    pub db_path: &'a Path,
    /// The `--db` the commands this report prints have to repeat.
    ///
    /// A database nobody named is the one every other command resolves for
    /// itself, so those commands leave `--db` off. A named one has to be
    /// repeated, or the next command reads somewhere else.
    pub replay_database: Option<&'a str>,
    /// Effective configuration recorded with the scan.
    pub configuration: &'a report::ConfigurationInfo,
    /// Persisted scan run identifier.
    pub run_id: Option<i64>,
    /// Invocation start timestamp.
    pub started_at: &'a str,
    /// Invocation finish timestamp.
    pub finished_at: &'a str,
    /// First-class build variant that produced this partition.
    pub variant: &'a BuildVariant,
    /// Detector versions that affect this mode's findings.
    pub detector_versions: Vec<report::DetectorVersion>,
    /// Priority recipe used to rank the report entries.
    pub weights: &'a Weights,
}

/// Build the report metadata shared by Fast, Structural, and Semantic scans.
pub(crate) fn common_run_info(mut inputs: RunInfoInputs<'_>) -> report::RunInfo {
    let variant = inputs.variant;
    // The store restores these rows by their natural identity. Emit that same
    // canonical order from a fresh scan so a later `report --run` is a true
    // rendering change rather than a metadata change.
    inputs.detector_versions.sort_unstable_by(|left, right| {
        left.component
            .cmp(&right.component)
            .then_with(|| left.version.cmp(&right.version))
    });
    report::RunInfo {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        mode: variant.mode.name().to_string(),
        root: inputs.root.display().to_string(),
        configuration: inputs.configuration.clone(),
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
            headers: variant.headers.map(|language| language.name().to_string()),
            normalization_version: variant.normalization_version,
            fingerprint: variant.fingerprint(),
            settings: build_variant_settings(variant),
        },
        detector_versions: inputs.detector_versions,
        ranking: report::RankingInfo {
            recipe: inputs.weights.recipe(),
            maintenance_risk: inputs.weights.maintenance_risk,
            refactoring_ease: inputs.weights.refactoring_ease,
        },
        database: inputs.db_path.display().to_string(),
        replay_database: inputs.replay_database.map(ToOwned::to_owned),
        // Filled in after recording, which is the half this cannot know about
        // yet, by the same code that fills in the run id.
        timings: None,
        run_id: inputs.run_id,
        reused: false,
    }
}

/// `path`, spelled the way it is shortest to type from here.
///
/// A printed command is read on one line beside everything else the report
/// says, and an absolute path in the middle of it costs more width than it
/// carries meaning. Anything outside the current directory keeps its full
/// spelling, because a relative path to it would be the longer of the two.
pub(crate) fn spelled_for_a_command(path: &Path) -> String {
    let relative = std::env::current_dir()
        .ok()
        .and_then(|current| path.strip_prefix(current).ok().map(Path::to_path_buf));
    relative.as_deref().unwrap_or(path).display().to_string()
}

/// Renderable settings that explain the identity of a resolved build variant.
///
/// The map's ordering matches the persisted query order, so a fresh report and
/// a `report --run` replay serialize the same evidence.
pub(crate) fn build_variant_settings(
    variant: &BuildVariant,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut settings = BTreeMap::new();
    for build in &variant.builds {
        let language = build.language().to_string();
        for setting in build.settings() {
            let values = setting
                .shape
                .values()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if !values.is_empty() {
                settings
                    .entry(language.clone())
                    .or_insert_with(BTreeMap::new)
                    .insert(setting.name.to_string(), values);
            }
        }
    }
    settings
}

/// The Fast pipeline's pass counts, stage by stage: a winnowed fingerprint
/// index, the seed pairs its posting lists propose, the fragments the
/// identifier-normalized pass cuts from those seeds, the pairs that pass
/// proposes in turn, and the pairs that survive verification.
///
/// Both pairing stages carry their own budget accounting, because both hold
/// their own allowance.
fn funnel(stats: &engine::EngineStats, groups: usize) -> Vec<report::FunnelStage> {
    vec![
        report::FunnelStage::new("tokens", as_u64(stats.tokens)),
        report::FunnelStage::new("fingerprints", as_u64(stats.raw_fingerprints)),
        report::FunnelStage::new(
            "indexed values",
            as_u64(stats.raw_distinct.saturating_sub(stats.stop_fingerprints)),
        )
        .dropping("high_frequency", as_u64(stats.stop_fingerprints))
        .dropping("high_frequency_postings", as_u64(stats.stop_postings)),
        report::FunnelStage::new("seed pairs", as_u64(stats.seed_candidates)).dropping(
            "pair_budget",
            as_u64(
                stats
                    .raw_pairs_available
                    .saturating_sub(stats.seed_candidates),
            ),
        ),
        report::FunnelStage::new("fragments", as_u64(stats.fragments)).dropping(
            "control_header_limit",
            as_u64(stats.control_headers_over_limit),
        ),
        report::FunnelStage::new("fragment classes", as_u64(stats.fragment_classes))
            .dropping("class_cap", as_u64(stats.class_cap_dropped))
            .dropping("hash_collision", as_u64(stats.hash_collisions)),
        // The two passes hold separate allowances, so each says separately how
        // much of its own search it got through. One combined figure would let
        // a pass that stopped early hide behind one that finished.
        report::FunnelStage::new("fragment pairs", as_u64(stats.fragment_candidates)).dropping(
            "pair_budget",
            as_u64(
                stats
                    .fragment_pairs_available
                    .saturating_sub(stats.fragment_candidates),
            ),
        ),
        report::FunnelStage::new("verified pairs", as_u64(stats.pairs))
            .dropping("conditional_arms", as_u64(stats.conditional_pairs)),
        report::FunnelStage::new("clone groups", as_u64(groups))
            .dropping("subsumed", as_u64(stats.subsumed_groups)),
    ]
}

/// What the run reported about itself beyond the groups it found, in the shape
/// the audit database stores.
///
/// Built before the snapshot is written and read back out of it by
/// [`build_summary`], so the recorded run and the printed report carry one set
/// of numbers rather than two derivations that happen to agree.
fn summary_row(
    inputs: &BuildInputs<'_>,
    baseline_digest: Option<String>,
    guardrails: Option<&report::Guardrails>,
) -> SummaryRow {
    shared::summary(shared::SummaryInputs {
        analyzed_files: file_counts(inputs.lexed.iter().map(|file| file.language)),
        lines: inputs.lexed.iter().map(|file| file.lines).sum(),
        tokens: as_u64(inputs.report.stats.tokens),
        lexer_diagnostics: as_u64(inputs.lexed.iter().map(|file| file.diagnostics).sum()),
        // Fast mode lexes and does not parse, so it has nothing to report
        // here; a zero would read as "the parser followed everything".
        unparsed: None,
        excluded_generated: as_u64(inputs.discovered.suppressed_generated.len()),
        excluded_by_glob: as_u64(inputs.glob_excluded),
        excluded_too_large: inputs.discovered.skipped.too_large,
        excluded_binary: inputs.discovered.skipped.binary,
        excluded_unreadable: inputs.discovered.skipped.unreadable + inputs.unreadable,
        excluded_symlinks: inputs.discovered.skipped.symlinks,
        excluded_walk_errors: inputs.discovered.skipped.walk_errors,
        excluded_timed_out: inputs.timed_out,
        excluded_language: inputs.discovered.skipped.language_excluded,
        excluded_symlink_files: inputs.discovered.skipped.symlink_files,
        excluded_symlink_directories: inputs.discovered.skipped.symlink_directories,
        guardrails: guardrails.map(guardrails_row),
        excluded_skipped: inputs.discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
        // The Fast engine compares whole units, so it folds and subsumes no
        // runs, and its equivalence classes need no refinement to bound.
        folded_runs: 0,
        subsumed_runs: 0,
        split_components: 0,
        // The signature-sibling channel is structural-only, so a Fast run has
        // no signature to have judged too common.
        common_signatures_skipped: 0,
        largest_skipped_signature_units: 0,
        pair_budget_exhausted: inputs.report.stats.pair_budget_exhausted,
        baseline_digest,
        funnel: funnel(&inputs.report.stats, inputs.report.groups.len()),
        unused_suppressions: unused_suppressions(inputs),
    })
}

/// Assemble the report model both output formats render from, from the groups
/// the run already ranked, in the order every view shows them in.
fn build_report(
    inputs: &BuildInputs<'_>,
    stored: &SummaryRow,
    mut groups: Vec<report::Group>,
) -> Report {
    report::order(&mut groups, inputs.suppression, inputs.sort);
    shared::report(
        common_run_info(RunInfoInputs {
            root: inputs.root,
            db_path: inputs.db_path,
            replay_database: inputs.replay_database,
            configuration: inputs.configuration,
            run_id: inputs.run_id,
            started_at: inputs.started_at,
            finished_at: inputs.finished_at,
            variant: &inputs.discovered.build_variant,
            detector_versions: detector_versions(inputs.literals, inputs.entropy_ratio_floor)
                .into_iter()
                .map(|(component, version)| report::DetectorVersion { component, version })
                .collect(),
            weights: &inputs.weights,
        }),
        stored,
        groups,
        inputs.discovered.build_variant.mode.name(),
    )
}

/// One group of the report model, ranked, with its suppression cause resolved.
fn build_group(inputs: &BuildInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.report.groups[index];
    let suppressed = group.suppressed.map_or_else(
        || inputs.group_suppressed[index].map(|rule| shared::rule_suppression(inputs.rules, rule)),
        |reason| {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some(reason.name().to_string()),
                scope: None,
                pattern: None,
                active: None,
            })
        },
    );
    report::ranked(
        {
            let mut report_group = shared::report_group(shared::ReportGroupCore {
                fingerprint: inputs.ids[index].fingerprint.to_hex(),
                clone_type: group.clone_type,
                scope: fast_group_scope(group, inputs.lexed),
                statements: None,
                confidence: group.score,
                entropy_bits: group.entropy_bits,
                members: group
                    .members
                    .iter()
                    .zip(&inputs.ids[index].members)
                    .enumerate()
                    .map(|(position, (instance, member_ids))| {
                        let source = &inputs.lexed[instance.file];
                        report::Member {
                            finding_id: member_ids.finding.to_hex(),
                            content: member_ids.content.to_hex(),
                            file: display_path(&source.relative_path),
                            language: source.language.name().to_string(),
                            start_line: instance.start_line,
                            end_line: instance.end_line,
                            unit: instance
                                .unit
                                .and_then(|unit| source.units[unit].name.clone()),
                            boilerplate: None,
                            tokens: u64::try_from(instance.token_end - instance.token_start)
                                .unwrap_or(u64::MAX),
                            canonical: position == 0,
                        }
                    })
                    .collect(),
            });
            report_group.suppressed = suppressed;
            report_group
        },
        &inputs.weights,
        inputs.min_clone_tokens,
    )
}

/// Classify a Fast finding by what its matched spans actually cover.
///
/// The lexer can anchor a token-window clone inside a unit, but that anchor
/// does not make the window a whole-unit finding. Every occurrence must cover
/// its host exactly before the group can use unit scope.
fn fast_group_scope(group: &CloneGroup, lexed: &[LexedSource]) -> CloneScope {
    if group.members.iter().all(|member| {
        member.unit.is_some_and(|unit| {
            let host = &lexed[member.file].units[unit];
            member.token_start == host.token_start && member.token_end == host.token_end
        })
    }) {
        CloneScope::Unit
    } else {
        CloneScope::Fragment
    }
}

pub(crate) mod output;

pub(crate) use output::{
    ReportOutput, hydrate_artifact_savings, hydrate_group_identity, top_group_churn,
    write_partitioned_reports, write_partitioned_reports_without_artifact_guidance, write_report,
    write_report_options, write_report_options_without_artifact_guidance,
    write_report_without_artifact_guidance,
};

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

/// A report entry's ranking as the audit database records it.
///
/// Both analysis modes go through here, so what the store holds is what the
/// report showed rather than a second derivation of it.
pub(crate) const fn priority_row(priority: &report::Priority) -> PriorityRow {
    PriorityRow {
        clone_confidence: priority.clone_confidence,
        maintenance_risk: priority.maintenance_risk,
        refactoring_difficulty: priority.refactoring_difficulty,
        final_priority: priority.value,
        semantic_confidence: priority.semantic_confidence,
        source_artifact_confidence: priority.source_artifact_confidence,
        savings_confidence: priority.savings_confidence,
    }
}

pub(crate) mod runtime;

pub(crate) use runtime::{
    DatabaseUse, FileOutcome, build_globset, database_path, database_path_for, discover_sources,
    effective_jobs, filter_globs, guarded, incompatible_database_replacement, literal_norm,
    map_sources, parse_work_byte_limit, readable_here, scan_database_path,
};
use runtime::{engine_config, lex_sources};

pub(crate) mod baseline;

pub(crate) use baseline::{ScanBaseline, apply_baseline, load_baseline};

pub(crate) mod store;

pub(crate) use codehelion_store::{display_path, path_key};
use store::{detector_versions, rank_groups, record_ranked};
pub(crate) use store::{file_rows, open_recorded_store, open_store, reuse_config_hash};

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
mod tests;
