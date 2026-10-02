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

mod funnel;
mod shared;
pub mod structural;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_core::conditional::ArmPath;
use codehelion_core::discovery::{AnalysisMode, BuildVariant, ContentHash};
use codehelion_core::engine::{self, InputFile};
use codehelion_core::execution::ExecutionPolicy;
use codehelion_core::stable_id::{self, FileContext};

use crate::Outcome;
use crate::cli::{BaselineMode, Mode, ScanArgs, SortAxis};
use crate::config::{self};
use crate::report::{self, Report};
use crate::suppress;

/// Version of the JSON envelope used when a scan contains multiple build
/// variants or an explicit comparison report.
pub(crate) const PARTITIONED_REPORT_SCHEMA_VERSION: &str = "partitioned-scan-report-v2";

/// URI of the schema that describes [`PARTITIONED_REPORT_SCHEMA_VERSION`].
pub(crate) const PARTITIONED_REPORT_SCHEMA_URI: &str = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/partitioned-scan-report-v2.schema.json";

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
    let db_path = database_path_for(
        DatabaseUse::Recording,
        &root,
        args.db.as_deref(),
        &resolved_config,
        args.untrusted,
    )?;
    let replay_flags = replay_flags(
        &root,
        args.config.as_deref(),
        args.db.is_some().then_some(db_path.as_path()),
        args.untrusted,
    );
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
        replay_flags: &replay_flags,
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
            // What the seam ledger has cost is read back from the database
            // rather than measured here: a scan reads source text and no
            // commits, and the recorded seam run already settled these counts.
            let failures = hydrate_recorded_reports(
                &db_path,
                cfg.report.churn_top,
                std::slice::from_mut(&mut model),
            );
            if artifact_guidance_holds(&failures) {
                write_report(args, out, &model)?;
            } else {
                write_report_without_artifact_guidance(args, out, &model)?;
            }
            report_hydration_failures(failures)?;
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

/// The flags whose answer only some analysis modes measure.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independent command-line flag"
)]
#[derive(Clone, Copy, Default)]
pub(crate) struct ModeBoundFlags {
    pub(crate) compare_build_variants: bool,
    pub(crate) compare_languages: bool,
    pub(crate) include_trivial: bool,
    pub(crate) show_siblings: bool,
    pub(crate) siblings_by_signature: bool,
    pub(crate) show_near_misses: bool,
    pub(crate) identifier_jaccard_sort: bool,
    pub(crate) min_identifier_jaccard: bool,
}

impl ModeBoundFlags {
    /// The mode-bound flags a scan's command line sets.
    pub(crate) fn of_scan(args: &ScanArgs) -> Self {
        Self {
            compare_build_variants: args.compare_build_variants,
            compare_languages: args.compare_languages,
            include_trivial: args.include_trivial,
            show_siblings: args.show_siblings,
            siblings_by_signature: args.siblings_by_signature,
            show_near_misses: args.show_near_misses,
            identifier_jaccard_sort: args.sort == SortAxis::IdentifierJaccard,
            min_identifier_jaccard: args.min_identifier_jaccard.is_some(),
        }
    }
}

/// Refuse a flag that `mode` measures nothing for.
///
/// One rule for a scan, checked against the mode it runs, and for a report,
/// checked against the mode the replayed run was recorded in: a flag a scan
/// refuses for Fast is not one a replay of a Fast run may accept.
///
/// # Errors
///
/// Returns an error naming the first such flag and the modes that measure it.
pub(crate) fn check_mode_flags(mode: AnalysisMode, flags: ModeBoundFlags) -> Result<()> {
    let semantic_only = [
        (flags.compare_build_variants, "--compare-build-variants"),
        (flags.compare_languages, "--compare-languages"),
    ];
    let structural_or_semantic = [
        (flags.include_trivial, "--include-trivial"),
        (flags.show_siblings, "--show-siblings"),
        (flags.siblings_by_signature, "--siblings-by-signature"),
        (flags.show_near_misses, "--show-near-misses"),
        (flags.identifier_jaccard_sort, "--sort identifier-jaccard"),
        (flags.min_identifier_jaccard, "--min-identifier-jaccard"),
    ];
    let refused =
        |flags: &[(bool, &'static str)]| flags.iter().find(|(set, _)| *set).map(|(_, flag)| *flag);
    if mode != AnalysisMode::Semantic
        && let Some(flag) = refused(&semantic_only)
    {
        usage_bail!("{flag} requires --mode semantic");
    }
    if mode == AnalysisMode::Fast
        && let Some(flag) = refused(&structural_or_semantic)
    {
        usage_bail!("{flag} requires --mode structural or --mode semantic");
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
        usage_bail!(
            "--untrusted permits nothing to run, and --allow-execution={names} \
             asks for something to. Drop whichever of the two was not meant"
        );
    }
    if args.mode != Mode::Semantic {
        usage_bail!(
            "--allow-execution={names} has nothing to act on in {} mode, which \
             reads source and runs nothing; it applies to --mode semantic",
            args.mode.name()
        );
    }
    ExecutionPolicy::parse(names).map_err(|error| crate::UsageError::new(error.to_string()).into())
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

mod build;

use build::{BuildInputs, Suppression, as_u64, build_report, evaluate_suppression, summary_row};

pub(crate) mod run_info;

pub(crate) use run_info::{
    RunInfoInputs, common_run_info, configuration_info, file_counts, guardrails_row,
    new_database_directory_hint, priority_row, replay_flags, rfc3339_now,
};

pub(crate) mod output;

pub(crate) use output::{
    ReportOutput, artifact_guidance_holds, hydrate_artifact_savings, hydrate_group_identity,
    hydrate_recorded_reports, hydrate_recorded_run, report_hydration_failures,
    write_partitioned_reports, write_partitioned_reports_without_artifact_guidance, write_report,
    write_report_without_artifact_guidance,
};
pub(crate) use output::{overwrite_refusal, write_output};

pub(crate) mod runtime;

pub(crate) use runtime::{
    DatabaseUse, build_globset, database_path_for, discover_sources, effective_jobs, filter_globs,
    guarded, incompatible_database_replacement, literal_norm, readable_here,
};
use runtime::{engine_config, lex_sources};

pub(crate) mod baseline;

pub(crate) use baseline::{ScanBaseline, apply_baseline, load_baseline};

pub(crate) mod store;

pub(crate) use codehelion_store::{display_path, path_key, path_label};
use store::{detector_versions, rank_groups, record_ranked};
pub(crate) use store::{file_rows, open_recorded_store, open_store, reuse_config_hash};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
