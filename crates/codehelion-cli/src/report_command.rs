//! Replaying recorded scans and explaining stored findings.

#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    reason = "the implementation module exposes command helpers to crate-local tests and reconstructs one persisted report schema in one place"
)]

use super::cli::ReportArgs;
use super::{Outcome, config, report, scan};
use anyhow::{Context, Result, bail};
use codehelion_core::discovery::AnalysisMode;
use codehelion_store::Store;
use codehelion_store::query::RunOrigin;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) fn report_command(args: &ReportArgs, out: &mut impl Write) -> Result<Outcome> {
    let (root, resolved_config, path) = report_database(args)?;
    let churn_top = resolved_config.config.report.churn_top;
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = scan::open_recorded_store(&path)?;
    let mut models = selected_runs(&store, args.run, &root)?
        .into_iter()
        .map(|run_id| replayed_model(&store, run_id, args, &root, &path))
        .collect::<Result<Vec<_>>>()?;
    let failures = models
        .iter_mut()
        .filter_map(|model| model.run.run_id.map(|run_id| (run_id, model)))
        .flat_map(|(run_id, model)| scan::hydrate_recorded_run(&store, run_id, churn_top, model))
        .collect::<Vec<_>>();
    let output = scan::ReportOutput {
        format: args.format,
        output: args.output.as_deref(),
        force: args.force,
        view: args.view,
        show_suppressed: args.show_suppressed,
        show_siblings: args.show_siblings,
        show_near_misses: args.show_near_misses,
        sort: args.sort.axis(),
        min_identifier_jaccard: args.min_identifier_jaccard,
    };
    let write = if scan::artifact_guidance_holds(&failures) {
        scan::write_partitioned_reports
    } else {
        scan::write_partitioned_reports_without_artifact_guidance
    };
    write(output, out, &models, None, None, None, None)?;
    scan::report_hydration_failures(failures)?;
    Ok(Outcome::Success)
}

/// Rebuild the report one recorded run printed, from its own rows.
///
/// What is read back from beyond the run — seam summary, artifact savings,
/// group history — is left to [`scan::hydrate_recorded_run`].
fn replayed_model(
    store: &Store,
    run_id: i64,
    args: &ReportArgs,
    root: &Path,
    path: &Path,
) -> Result<report::Report> {
    let run = store
        .run_summary(run_id)?
        .with_context(|| format!("no recorded run {run_id} in {}", path.display()))?;
    store.ensure_completed_run(run.id)?;
    let recorded_mode = [
        AnalysisMode::Fast,
        AnalysisMode::Structural,
        AnalysisMode::Semantic,
    ]
    .into_iter()
    .find(|mode| mode.name() == run.analysis_mode)
    .with_context(|| {
        format!(
            "run {run_id} names an unknown analysis mode {:?}",
            run.analysis_mode
        )
    })?;
    scan::check_mode_flags(
        recorded_mode,
        scan::ModeBoundFlags {
            show_siblings: args.show_siblings,
            show_near_misses: args.show_near_misses,
            identifier_jaccard_sort: args.sort == crate::cli::SortAxis::IdentifierJaccard,
            min_identifier_jaccard: args.min_identifier_jaccard.is_some(),
            ..scan::ModeBoundFlags::default()
        },
    )
    .with_context(|| format!("run {run_id} was recorded in {} mode", run.analysis_mode))?;
    if run.root_path != scan::path_key(root) {
        eprintln!(
            "note: run {run_id} was recorded for {}, not for {}; it is replayed as recorded",
            scan::display_path(&run.root_path),
            root.display()
        );
    }
    let finished_at = run
        .finished_at
        .as_deref()
        .context("the selected run did not complete and cannot be reported")?;
    let origin = store.run_origin(run.id)?;
    let variant = store
        .build_variant(&origin.variant_fingerprint)?
        .context("the selected run has no stored build variant")?;
    let summary_row = store
        .run_summary_row(run.id)?
        .context("the selected run has no stored summary")?;
    let groups = ordered_recorded_groups(store, run.id, args.sort.axis())?;
    let siblings = recorded_siblings(&store.run_groups(run.id)?);
    let near_misses = recorded_near_misses(&store.run_near_misses(run.id)?);
    let compiler = store
        .run_compiler_coverage(run.id)?
        .map(restored_compiler_coverage);
    let ranking = recorded_ranking(&origin.detector_versions)?;
    let analysis_mode = run.analysis_mode.clone();
    let mut model = report::Report {
        schema_version: report::SCHEMA_VERSION,
        run: report::RunInfo {
            tool_version: run.tool_version,
            mode: run.analysis_mode,
            root: scan::display_path(&run.root_path),
            configuration: recorded_configuration(&origin)?,
            started_at: run.started_at,
            finished_at: finished_at.to_string(),
            build_variant: report::BuildVariantInfo {
                mode: variant.analysis_mode,
                languages: variant
                    .languages
                    .as_deref()
                    .map_or_else(Vec::new, |languages| {
                        languages
                            .split(',')
                            .filter(|language| !language.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    }),
                headers: variant.header_language.filter(|header| !header.is_empty()),
                normalization_version: u32::try_from(origin.normalization_version)
                    .context("stored normalization version does not fit the report")?,
                fingerprint: variant.fingerprint,
                settings: recorded_build_variant_settings(&variant.settings),
            },
            detector_versions: origin
                .detector_versions
                .iter()
                .filter(|(component, _)| component != "ranking")
                .map(|(component, version)| report::DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            ranking,
            database: path.display().to_string(),
            // A replay measured nothing: it reconstructs a document from what
            // was recorded, and the clock is not part of that.
            timings: None,
            replay_flags: scan::replay_flags(
                root,
                args.config.as_deref(),
                args.db.is_some().then_some(path),
                args.untrusted,
            ),
            run_id: Some(run.id),
            reused: false,
        },
        summary: report::Summary {
            compiler,
            baseline_not_replayed: summary_row.baseline_digest.is_some(),
            ..report::restored(&summary_row, &groups, &analysis_mode)
        },
        groups,
        siblings,
        near_misses,
        seam: None,
    };
    model.order_supplemental();
    model.refresh_supplemental_summary();
    Ok(model)
}

/// The runs a report replays: the one `--run` names, or every completed
/// partition of the newest scan invocation of `root`, which is what that scan
/// printed.
fn selected_runs(store: &Store, explicit: Option<i64>, root: &Path) -> Result<Vec<i64>> {
    if let Some(run_id) = explicit {
        return Ok(vec![run_id]);
    }
    let invocation = store.latest_completed_invocation(&scan::path_key(root))?;
    if invocation.is_empty() {
        bail!("no completed scan for this path; run `codehelion scan` first");
    }
    Ok(invocation.into_iter().map(|origin| origin.id).collect())
}

mod explain;
mod recorded;

pub(crate) use explain::explain;
#[cfg(test)]
pub(crate) use explain::the_one;
pub(crate) use recorded::{
    ordered_recorded_groups, recorded_configuration, recorded_ranking, recorded_seam,
    restored_compiler_coverage,
};
use recorded::{recorded_build_variant_settings, recorded_near_misses, recorded_siblings};

/// Resolve the configuration that also supplies a recorded report's view
/// policy, together with its local database path.
pub(crate) fn report_database(
    args: &ReportArgs,
) -> Result<(PathBuf, config::ResolvedConfig, PathBuf)> {
    crate::resolve_database(
        scan::DatabaseUse::Reading,
        &args.path,
        args.db.as_deref(),
        args.config.as_deref(),
        args.untrusted,
    )
}
