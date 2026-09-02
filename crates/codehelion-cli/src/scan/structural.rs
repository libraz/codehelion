//! The `scan --mode structural` pipeline: from project discovery to the
//! recorded snapshot, over parsed Syntax IR instead of a raw token stream.
//!
//! The stages mirror the Fast pipeline — resolve configuration, discover
//! sources, run the per-language frontends across worker threads, detect,
//! record one atomic snapshot, render a report — but the frontends here are
//! parsers and detection is the structural funnel (candidate extraction,
//! near-match, weighted verification, medoid grouping). Like Fast, nothing in
//! this path executes target code: files are only read and parsed.
//!
//! What a group carries differs: members are similar rather than identical,
//! so every group reports its per-dimension similarity breakdown, and the
//! dimension the mode cannot measure (types) is reported as absent rather
//! than guessed.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_core::discovery::{
    BuildVariant, ContentHash, Language, LanguageSelection, SourceUnit,
};
use codehelion_core::ir::StructuralFrontend;
use codehelion_core::structural::DirectoryPartition;
use codehelion_store::snapshot::{SnapshotComparisons, StagedSnapshotPart, SummaryRow};

use super::build::as_u64;
use super::output::write_partitioned_reports;
use super::run_info::rfc3339_now;
use super::runtime::{
    FileOutcome, discover_sources, effective_jobs, filter_globs, read_within_budget,
    scan_database_path,
};
use super::store::open_store;
use codehelion_store::path_key;

use crate::Outcome;
use crate::cli::ScanArgs;
use crate::config::{self, Config};
use crate::report::{self, Report};
use crate::semantic;
use codehelion_core::execution::{Execution as PermittedExecution, ExecutionPolicy};

mod model;

use model::{
    ParsedSource, SemanticDetection, SemanticGroup, SemanticPair, SemanticUnitGraph, SourceMeta,
};

/// Intern repository-relative parent directory keys deterministically before
/// crossing into core. Raw paths remain a CLI/reporting concern; core sees
/// only opaque integer partitions.
fn directory_partitions(files: &[SourceMeta]) -> Vec<DirectoryPartition> {
    let mut keys: Vec<&str> = files
        .iter()
        .map(|file| file.directory_key.as_str())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let indexes: BTreeMap<&str, u32> = keys
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key, u32::try_from(index).unwrap_or(u32::MAX)))
        .collect();
    files
        .iter()
        .map(|file| DirectoryPartition::new(indexes[file.directory_key.as_str()]))
        .collect()
}

const SIGNATURE_SIBLING_FUNNEL_STAGE: &str = "signature sibling entries";

/// Remove the signature-specific funnel stage from a default-off report.
pub(super) fn remove_signature_sibling_funnel_stage(summary: &mut SummaryRow) {
    summary
        .funnel
        .retain(|stage| stage.name != SIGNATURE_SIBLING_FUNNEL_STAGE);
}

fn reuse_semantic_partition(
    report: &mut Report,
    db_path: &Path,
    root: &Path,
    config_hash: &ContentHash,
    staged: &StagedSnapshotPart,
) -> Result<bool> {
    let Some(new_run_id) = report.run.run_id else {
        return Ok(false);
    };
    let mut store = open_store(db_path)?;
    let Some(previous) = store.latest_compatible_run(
        &path_key(root),
        config_hash.as_str(),
        &report.run.build_variant.fingerprint,
    )?
    else {
        return Ok(false);
    };
    let same_baseline = store
        .run_summary_row(previous.id)?
        .zip(store.run_summary_row(new_run_id)?)
        .is_some_and(|(old, new)| old.baseline_digest == new.baseline_digest);
    if !same_baseline || store.run_tree(previous.id)? != store.run_tree(new_run_id)? {
        return Ok(false);
    }
    // Keep the opaque token alive for invocation-level suppression cleanup.
    // The run itself is discarded now because this partition reuses the
    // completed predecessor; aborting the token here could delete a newly
    // created rule that a later live partition shares.
    store.discard_run(staged.run_id())?;
    report.run.run_id = Some(previous.id);
    report.run.reused = true;
    Ok(true)
}

/// Execute `codehelion scan` in Structural mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report output
/// fails. Per-file problems (unreadable or malformed sources) are counted and
/// reported instead of failing the scan.
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    run_with(args, out, None)
}

/// Execute `codehelion scan` in Semantic mode: the same pipeline, over what a
/// compiler resolved about the same files.
///
/// # Errors
///
/// Additionally fails when no compiler helper is installed or the installed
/// one cannot be talked to. Semantic mode does not fall back to Structural: a
/// run that answered without a compiler and called itself semantic would be
/// syntactic results under another name, and nothing downstream could tell.
pub fn semantic(
    args: &ScanArgs,
    permitted: &ExecutionPolicy,
    out: &mut impl Write,
) -> Result<Outcome> {
    let sandbox = semantic_sandbox(args)?;
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    let resolved = config::load(args.config.as_deref(), &root)?;
    if let Some(note) = config::disregarded_helpers_note(&resolved) {
        eprintln!("{note}");
    }
    let helper_paths = config::helper_paths(&resolved, &args.helpers)?;
    let compilers = Compilers::found(permitted, sandbox, &helper_paths)?;
    run_with(args, out, Some(&compilers))
}

/// Containment requested for compiler helpers in this semantic run.
///
/// The untrusted profile requires the core profile's subprocess ceiling. A
/// platform that cannot apply it fails before any helper is launched rather
/// than analysing an untrusted tree with an unenforced policy.
mod helpers;

use helpers::{Compilers, Installed, asking_about, helper_timeout, semantic_sandbox};

#[allow(clippy::too_many_lines)]
fn run_with(
    args: &ScanArgs,
    out: &mut impl Write,
    compilers: Option<&Compilers>,
) -> Result<Outcome> {
    if args.compare_build_variants && compilers.is_none() {
        bail!("--compare-build-variants requires --mode semantic");
    }
    if args.compare_languages && compilers.is_none() {
        bail!("--compare-languages requires --mode semantic");
    }
    let started_at = rfc3339_now();
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = scan_database_path(&root, args.db.as_deref(), &resolved_config, args.untrusted)?;
    let _database_lock = crate::scan_lock::acquire(&db_path)?;
    let configuration = crate::scan::configuration_info(
        &resolved_config.source,
        resolved_config.config.min_clone_tokens,
    );
    let (cfg, guardrails) = crate::scan::guarded(resolved_config.config, args);
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(
        &root,
        &cfg,
        args.no_ignore,
        args.follow_links,
        args.compile_commands.as_deref(),
    )?;
    if compilers.is_some()
        && let Some(diagnostic) = &discovered.compile_commands_error
    {
        bail!(
            "cannot read compile_commands.json for semantic analysis ({}): {}",
            diagnostic.path.display(),
            diagnostic.message
        );
    }
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;

    let asking = asking_about(compilers, &sources)?;
    let partitions = if compilers.is_some() {
        semantic_partitions(
            &discovered,
            &sources,
            &cfg,
            asking.as_deref(),
            &root,
            helper_timeout(&cfg),
        )?
    } else {
        Vec::new()
    };
    // A tree no compilation database splits is one program: it takes the same
    // path as a partitioned run, recording a complete snapshot of its own
    // rather than a part the invocation commits with others.
    let whole_tree = partitions
        .is_empty()
        .then(|| variant_of(asking.as_deref(), &cfg, discovered.header_language, &root))
        .transpose()?;
    let no_commands = BTreeMap::new();
    let programs: Vec<_> = whole_tree.as_ref().map_or_else(
        || partitions.iter().map(SemanticPartition::program).collect(),
        |variant| {
            vec![SemanticProgram {
                variant,
                sources: &sources,
                commands: &no_commands,
            }]
        },
    );
    let context = ProgramContext {
        args,
        cfg: &cfg,
        guardrails: guardrails.as_ref(),
        jobs,
        root: &root,
        db_path: &db_path,
        configuration: &configuration,
        started_at: &started_at,
        asking: asking.as_deref(),
        glob_excluded,
        mode: if compilers.is_some() {
            crate::cli::Mode::Semantic
        } else {
            crate::cli::Mode::Structural
        },
        whole_run: whole_tree.is_some(),
    };

    let mut reports = Vec::with_capacity(programs.len());
    let mut comparison_units = Vec::new();
    let mut cross_language_units = Vec::new();
    let mut staged_parts: Vec<StagedSnapshotPart> = Vec::with_capacity(programs.len());
    let mut retired_parts: Vec<StagedSnapshotPart> = Vec::new();
    let mut outcome = Outcome::Success;
    let mut recording_error: Option<anyhow::Error> = None;
    for (index, program) in programs.into_iter().enumerate() {
        // Discovery happens before a source can belong to a build variant.
        // Record its exclusions exactly once rather than copying them into
        // every independent semantic report. The partition list is
        // fingerprint-sorted, so this owner is deterministic.
        let shared_discovery = (index == 0).then_some(&discovered);
        let mut finished = match run_program(&context, shared_discovery, program) {
            Ok(finished) => finished,
            Err(error) => {
                if let Ok(mut store) = open_store(&db_path) {
                    let mut cleanup_parts = staged_parts.clone();
                    cleanup_parts.extend(retired_parts.clone());
                    let _ = store.abort_snapshot_parts(&cleanup_parts);
                }
                return Err(error);
            }
        };
        if recording_error.is_none() {
            recording_error = finished.recording_error.take();
        }
        let mut staged = finished.staged.take();
        if recording_error.is_none()
            && !args.no_reuse
            && !args.compare_build_variants
            && !args.compare_languages
            && let Some(staged_part) = staged.as_ref()
            && let Some(reuse_key) = finished.reuse_key.as_ref()
            && let Err(error) = reuse_semantic_partition(
                &mut finished.report,
                &db_path,
                &root,
                reuse_key,
                staged_part,
            )
        {
            recording_error = Some(error);
        }
        if finished.report.run.reused
            && let Some(staged) = staged.take()
        {
            retired_parts.push(staged);
        }
        if let Some(staged) = staged {
            staged_parts.push(staged);
        }
        if finished.outcome == Outcome::FindingsPresent {
            outcome = Outcome::FindingsPresent;
        }
        comparison_units.extend(finished.comparison_units);
        cross_language_units.extend(finished.cross_language_units);
        reports.push(finished.report);
    }
    let mut prepared_variant = None;
    if recording_error.is_none() && args.compare_build_variants {
        match prepare_cross_variant_comparison(&root, &started_at, &comparison_units) {
            Ok(value) => prepared_variant = value,
            Err(error) => recording_error = Some(error),
        }
    }
    // A comparison the caller asked for says what became of it on every exit,
    // however many programs the tree held: a report with no word about it
    // cannot be told apart from one that compared and found nothing.
    let comparison_not_run = (recording_error.is_none() && args.compare_build_variants)
        .then(|| prepared_variant.is_none())
        .filter(|not_run| *not_run)
        .map(|_| cross_variant_comparison_not_run(&reports));
    let mut prepared_cross_language = None;
    if recording_error.is_none() && args.compare_languages {
        match prepare_cross_language_comparison(&root, &started_at, &cross_language_units, &cfg) {
            Ok(value) => prepared_cross_language = value,
            Err(error) => recording_error = Some(error),
        }
    }
    let cross_language_not_run = (recording_error.is_none() && args.compare_languages)
        .then(|| prepared_cross_language.is_none())
        .filter(|not_run| *not_run)
        .map(|_| cross_language_comparison_not_run(&reports, &cross_language_units));
    if recording_error.is_none() && (!staged_parts.is_empty() || !retired_parts.is_empty()) {
        let variant_snapshot = prepared_variant
            .as_ref()
            .map(PreparedCrossVariant::snapshot);
        let language_snapshot = prepared_cross_language
            .as_ref()
            .map(PreparedCrossLanguage::snapshot);
        let comparisons = SnapshotComparisons {
            cross_variant: variant_snapshot.as_ref(),
            cross_language: language_snapshot.as_ref(),
        };
        if let Err(error) = open_store(&db_path).and_then(|mut store| {
            store.finalize_snapshot_parts_with_retired(
                &staged_parts,
                &retired_parts,
                comparisons,
            )?;
            Ok(())
        }) {
            recording_error = Some(error);
        }
    }
    if let Some(error) = recording_error {
        if let Ok(mut store) = open_store(&db_path) {
            let mut cleanup_parts = staged_parts.clone();
            cleanup_parts.extend(retired_parts.clone());
            let _ = store.abort_snapshot_parts(&cleanup_parts);
        }
        for report in &mut reports {
            report.run.run_id = None;
            report.run.reused = false;
            report.summary.changes = None;
            for group in &mut report.groups {
                group.artifact_savings.clear();
            }
            report.refresh_supplemental_summary();
        }
        crate::scan::write_partitioned_reports_without_artifact_guidance(
            args, out, &reports, None, None, None, None,
        )?;
        eprintln!(
            "warning: this run was not recorded ({error}); replay and baseline comparison are unavailable for it"
        );
        return Err(error);
    }
    if !retired_parts.is_empty()
        && let Ok(mut store) = open_store(&db_path)
    {
        // Reused partitions have no running row left, but their tokens still
        // own any suppression row created while staging. Missing runs are
        // intentionally idempotent here.
        let _ = store.abort_snapshot_parts(&retired_parts);
    }
    let comparison = prepared_variant.map(|prepared| prepared.report);
    let cross_language_comparison = prepared_cross_language.map(|prepared| prepared.report);
    if let Err(error) = hydrate_recorded_runs(&db_path, &cfg, &mut reports) {
        for report in &mut reports {
            for group in &mut report.groups {
                group.artifact_savings.clear();
            }
            report.refresh_supplemental_summary();
        }
        crate::scan::write_partitioned_reports_without_artifact_guidance(
            args,
            out,
            &reports,
            comparison.as_ref(),
            comparison_not_run.as_ref(),
            cross_language_comparison.as_ref(),
            cross_language_not_run.as_ref(),
        )?;
        eprintln!(
            "warning: artifact savings were not loaded ({error}); recorded run data remains available, but artifact evidence and guidance are unavailable for this report"
        );
        return Err(error);
    }
    for report in &mut reports {
        report.refresh_supplemental_summary();
    }
    write_partitioned_reports(
        args,
        out,
        &reports,
        comparison.as_ref(),
        comparison_not_run.as_ref(),
        cross_language_comparison.as_ref(),
        cross_language_not_run.as_ref(),
    )?;
    Ok(outcome)
}

/// Fill in what the audit database knows about every recorded run of this
/// invocation: supplemental artifact savings, the recorded seam run, what
/// became of each group since the compatible predecessor, and the churn
/// summary.
///
/// One derivation for every exit, so a scan's own report and a later
/// `report --run` of the same run carry the same continuity evidence however
/// many programs the tree held.
fn hydrate_recorded_runs(db_path: &Path, cfg: &Config, reports: &mut [Report]) -> Result<()> {
    if reports.iter().all(|report| report.run.run_id.is_none()) {
        return Ok(());
    }
    let store = open_store(db_path)?;
    for report in reports {
        let Some(run_id) = report.run.run_id else {
            continue;
        };
        crate::scan::hydrate_artifact_savings(&store, run_id, &mut report.groups)?;
        // What the ledger's seams cost belongs to the repository rather than
        // to one program in it, and it is attached to every report for the
        // reason the churn summary is: each is read on its own, and one that
        // left the section out would read as a repository with nothing
        // written down. It is filled in before the predecessor is looked for,
        // because a seam run has generations of its own and a first scan is
        // not a reason to withhold them.
        if let Some(summary) = store.run_summary(run_id)? {
            report.seam = crate::report_command::recorded_seam(&store, &summary.root_path)?;
        }
        let Some(predecessor) = store.preceding_compatible_run(run_id)? else {
            continue;
        };
        crate::scan::hydrate_group_identity(&store, run_id, predecessor, &mut report.groups)?;
        report.summary.top_churn = Some(crate::scan::top_group_churn(
            &store,
            run_id,
            predecessor,
            cfg.report.churn_top,
        )?);
    }
    Ok(())
}

mod comparison;

use comparison::{
    PreparedCrossLanguage, PreparedCrossVariant, cross_language_comparison_not_run,
    cross_variant_comparison_not_run, prepare_cross_language_comparison,
    prepare_cross_variant_comparison,
};

/// What the results belong to.
///
/// Discovery reports the Fast variant; these results belong to the Structural
/// or Semantic one, and no two of the three ever share a fingerprint. The
/// header grammar carries over unchanged: it decided which frontend read every
/// `.h` below, so it describes these results just as it does Fast's.
fn variant_of(
    asking: Option<&[&Installed]>,
    cfg: &Config,
    headers: Language,
    root: &Path,
) -> Result<BuildVariant> {
    let languages = LanguageSelection {
        rust: cfg.languages.rust,
        c: cfg.languages.c,
        cpp: cfg.languages.cpp,
    };
    let Some(asking) = asking else {
        return Ok(BuildVariant::structural(languages, headers));
    };
    let builds = asking
        .iter()
        .map(|helper| helper.build(root, helper_timeout(cfg)))
        .collect::<Result<Vec<_>>>()?;
    Ok(BuildVariant::semantic(languages, headers, builds))
}

/// One independently recorded semantic program. Headers are present in every
/// C/C++ partition because the selected translation units are what give them
/// meaning; their compiler answers never cross this boundary.
mod semantic_analysis;

use comparison::{ProgramContext, run_program};
use semantic_analysis::{
    SemanticPartition, SemanticProgram, semantic_group_member_fingerprints, semantic_member_ranks,
    semantic_partitions, semantic_scope,
};

/// What the compilers managed to say about the tree, as the report puts it.
///
/// The restarts are summed across the helpers, because a restart is trouble the
/// run had rather than trouble one program had: what a reader does with the
/// number is decide whether a thin result was the tree's fault.
///
/// Which of the two gaps a file falls in is decided by its reason rather than
/// by whether a process was started for it, so that a run and the record it
/// leaves behind split the same three ways. The record has only the reason to
/// go on: a helper that dies before its handshake is in no run's helper list
/// and leaves nothing else to tell the two apart by.
fn coverage(asked: &semantic::Answers) -> report::CompilerCoverage {
    let mut unavailable: BTreeMap<String, u64> = BTreeMap::new();
    let mut not_asked_reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut diagnostics: BTreeMap<String, u64> = BTreeMap::new();
    let mut answered = 0;
    let mut not_asked = 0;
    let mut build_script_refused = 0_u64;
    for answer in &asked.per_source {
        let (reason, unit_diagnostics) = match answer {
            semantic::Answer::Analyzed { .. } => {
                answered += 1;
                continue;
            }
            semantic::Answer::NotAsked { reason, .. } => (*reason, [].as_slice()),
            semantic::Answer::Unavailable {
                reason,
                diagnostics: unit_diagnostics,
                ..
            } => (*reason, unit_diagnostics.as_slice()),
        };
        if reason.is_helper_failure() {
            *unavailable.entry(reason.name().to_string()).or_default() += 1;
        } else {
            not_asked += 1;
            *not_asked_reasons
                .entry(reason.name().to_string())
                .or_default() += 1;
        }
        for diagnostic in unit_diagnostics {
            *diagnostics.entry(diagnostic.clone()).or_default() += 1;
        }
        // The only whole-unit `RequiresExecution` outcome the shipped helper
        // emits is a Cargo build script. Procedural macros are recorded as
        // individual unexpanded invocations instead, so this mapping neither
        // guesses a broader permission nor hides the precise one the user can
        // grant.
        if reason == codehelion_helper::ir::Unavailability::RequiresExecution {
            build_script_refused = build_script_refused.saturating_add(1);
        }
    }
    let execution_refusals = ExecutionPolicy::deny_all()
        .refusal(PermittedExecution::BuildScript)
        .filter(|_| build_script_refused > 0)
        .map(|refusal| {
            let message = refusal.describe();
            report::ExecutionRefusal {
                execution: refusal.execution.name().to_string(),
                files: build_script_refused,
                cost: refusal.cost.to_string(),
                permission_argument: refusal.permission_argument,
                message,
            }
        })
        .into_iter()
        .collect();
    report::CompilerCoverage {
        answered,
        not_asked,
        not_asked_reasons,
        unavailable,
        diagnostics,
        execution_refusals,
        restarts: asked
            .helpers
            .iter()
            .map(|helper| helper.restarts)
            .fold(0, u32::saturating_add),
    }
}

/// Read and parse one source file, enforcing the deterministic parse-work
/// budget before frontend work begins.
fn parse_one(
    source: &SourceUnit,
    max_file_bytes: u64,
    budget: std::time::Duration,
) -> FileOutcome<ParsedSource> {
    let Some(read) = read_within_budget(source, max_file_bytes, budget) else {
        return FileOutcome::TimedOut;
    };
    let text = read.text;
    let ir = match source.language {
        Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(&text),
        Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(&text),
        Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(&text),
    };
    let unaccounted_tokens = as_u64(ir.unaccounted_tokens());
    let directory_key = source
        .relative_path
        .parent()
        .map(path_key)
        .unwrap_or_default();
    FileOutcome::Done(Box::new(ParsedSource {
        meta: SourceMeta {
            relative_path: path_key(&source.relative_path),
            directory_key,
            language: source.language,
            marker_lines: read.marker_lines,
            lines: read.lines,
            diagnostics: ir.diagnostics.len(),
            unaccounted_tokens,
            depth_truncated: ir.depth_truncated,
        },
        ir,
    }))
}

/// Record which parsed files are the body of a module the tree declares
/// test-only.
///
/// A parse sees one file, and the `#[cfg(test)]` that puts a file in the suite
/// is written on the declaration in another one. This is where the whole set
/// is in hand, so it is where the two are put together.
mod suppression;

use suppression::{
    aggregate_test_code_evidence, region_identifier_jaccard, region_test_code_evidence,
};

mod inputs;

use inputs::ReportInputs;

/// Similarity reported for a confirmed duplicated run.
///
/// A run is confirmed by hashing the tokens its occurrences cover, so every
/// occurrence carries identical content under the run's literal strategy.
/// That is an exact match rather than a scored one: the similarity is 1 and
/// there is no per-dimension breakdown to report, for the same reason the
/// Fast engine reports none.
const REGION_SIMILARITY: f64 = 1.0;

/// Every reported entry, in the order the views render them: ranked-down
/// entries last, then the run's chosen axis descending, then fingerprint
/// ascending, so every view is stable across reruns.
///
/// Duplicated units and duplicated runs share one ranking. They describe the
/// code differently, and each entry says which it is, but they compete for
/// the same attention and a reader wants the biggest duplication first
/// whichever shape it has.
mod reporting;

mod store;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
