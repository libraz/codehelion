//! Replaying recorded scans and explaining stored findings.

#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    reason = "the implementation module exposes command helpers to crate-local tests and reconstructs one persisted report schema in one place"
)]

use super::cli::ReportArgs;
use super::{Outcome, config, report, scan};
use anyhow::{Context, Result, bail};
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
    let run_id = selected_run_id(&store, args.run, &root)?;
    let run = store
        .run_summary(run_id)?
        .with_context(|| format!("no recorded run {run_id} in {}", path.display()))?;
    store.ensure_completed_run(run.id)?;
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
    let mut groups = recorded_groups(&store, run.id)?;
    let siblings = recorded_siblings(&store.run_groups(run.id)?);
    let near_misses = recorded_near_misses(&store.run_near_misses(run.id)?);
    let sort = args.sort.axis();
    let ranked_down = store.run_group_ranked_down(run.id)?;
    report::order_recorded(&mut groups, &ranked_down, sort);
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
            replay_database: args
                .db
                .is_some()
                .then(|| scan::spelled_for_a_command(&path)),
            run_id: Some(run.id),
            reused: false,
        },
        summary: report::Summary {
            compiler,
            ..report::restored(&summary_row, &groups, &analysis_mode)
        },
        groups,
        siblings,
        near_misses,
        seam: recorded_seam(&store, &run.root_path)?,
    };
    let hydration_error = scan::hydrate_artifact_savings(&store, run.id, &mut model.groups)
        .and_then(|()| {
            store
                .preceding_compatible_run(run.id)
                .map_err(Into::into)
                .and_then(|predecessor| {
                    predecessor.map_or(Ok(()), |predecessor| {
                        scan::hydrate_group_identity(
                            &store,
                            run.id,
                            predecessor,
                            &mut model.groups,
                        )?;
                        model.summary.top_churn = Some(scan::top_group_churn(
                            &store,
                            run.id,
                            predecessor,
                            churn_top,
                        )?);
                        Ok(())
                    })
                })
        })
        .err();
    model.order_supplemental();
    model.refresh_supplemental_summary();
    if let Some(error) = hydration_error {
        for group in &mut model.groups {
            group.artifact_savings.clear();
        }
        model.refresh_supplemental_summary();
        scan::write_report_options_without_artifact_guidance(
            scan::ReportOutput {
                format: args.format,
                output: args.output.as_deref(),
                force: args.force,
                view: args.view,
                show_suppressed: args.show_suppressed,
                show_siblings: args.show_siblings,
                show_near_misses: args.show_near_misses,
                sort,
                min_identifier_jaccard: args.min_identifier_jaccard,
            },
            out,
            &model,
        )?;
        eprintln!(
            "warning: artifact savings were not loaded ({error}); run {} remains recorded, but artifact evidence and guidance are unavailable for this report",
            run.id
        );
        return Err(error);
    }
    scan::write_report_options(
        scan::ReportOutput {
            format: args.format,
            output: args.output.as_deref(),
            force: args.force,
            view: args.view,
            show_suppressed: args.show_suppressed,
            show_siblings: args.show_siblings,
            show_near_misses: args.show_near_misses,
            sort,
            min_identifier_jaccard: args.min_identifier_jaccard,
        },
        out,
        &model,
    )?;
    Ok(Outcome::Success)
}

fn selected_run_id(store: &Store, explicit: Option<i64>, root: &Path) -> Result<i64> {
    explicit.map_or_else(
        || {
            store
                .latest_completed_run(&scan::path_key(root))?
                .map(|origin| origin.id)
                .context("no completed scan for this path; run `codehelion scan` first")
        },
        Ok,
    )
}

mod explain;
mod recorded;

pub(crate) use explain::explain;
#[cfg(test)]
pub(crate) use explain::the_one;
use recorded::{recorded_build_variant_settings, recorded_near_misses, recorded_siblings};
pub(crate) use recorded::{
    recorded_configuration, recorded_groups, recorded_ranking, recorded_seam,
    restored_compiler_coverage,
};

/// Resolve the configuration that also supplies a recorded report's view
/// policy, together with its local database path.
pub(crate) fn report_database(
    args: &ReportArgs,
) -> Result<(PathBuf, config::ResolvedConfig, PathBuf)> {
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let path = scan::database_path_for(
        scan::DatabaseUse::Reading,
        &root,
        args.db.as_deref(),
        &resolved_config,
        args.untrusted,
    )?;
    Ok((root, resolved_config, path))
}
