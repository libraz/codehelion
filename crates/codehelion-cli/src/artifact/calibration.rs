//! Calibration summaries and baseline comparisons for measured artifact savings.

use super::ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION;
use super::calibration_report::{
    CalibrationBaselineReport, CalibrationComparisonReport, CalibrationStatisticsDelta,
    CalibrationStratumComparison, CalibrationStratumReport, CalibrationSummaryReport,
};
use crate::Outcome;
use crate::cli::{ArtifactCalibrationArgs, ArtifactFormat};
use anyhow::{Context, Result, bail};
use codehelion_store::artifact::{
    ArtifactAnalysisSavingsCalibration, ArtifactSavingsCalibrationStatistics,
    artifact_savings_calibration_statistics,
};
use codehelion_store::{Store, fingerprint_hex};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path as FilePath;

/// Summarize controlled before/after calibration measurements for one run.
///
/// # Errors
///
/// Returns database and output errors. This command only reads recorded local
/// measurements; it never opens or executes an artifact. `SQLite`'s WAL mode
/// supplies the concurrent read snapshot, so it deliberately does not take
/// the writer lease.
pub fn calibration(args: &ArtifactCalibrationArgs, out: &mut impl Write) -> Result<Outcome> {
    let db = crate::resolve_db(crate::scan::DatabaseUse::Reading, args.db.as_deref())?;
    let store = crate::scan::open_recorded_store(&db)?;
    let source_run = args.source_run.map_or_else(
        || {
            store
                .latest_completed_run_any_root()?
                .map(|run| run.id)
                .context("no completed scan in this database; run `codehelion scan` first")
        },
        Ok,
    )?;
    store.ensure_completed_run(source_run)?;
    let measurements = store.artifact_savings_calibrations_for_run(source_run)?;
    let mut report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run,
        statistics: artifact_savings_calibration_statistics(&measurements),
        strata: calibration_strata(&store, &measurements)?,
        comparison: None,
    };
    if let Some(path) = args.baseline.as_deref() {
        report.comparison = Some(calibration_comparison(&report, path)?);
    }
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_calibration_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_calibration_text(&report, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        super::write_output(path, &rendered, args.force)?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

/// Compare a calibration summary with a previously recorded baseline report.
///
/// # Errors
///
/// Returns an error when the baseline cannot be read, cannot be parsed, or
/// carries a schema version this build does not accept.
pub(super) fn calibration_comparison(
    current: &CalibrationSummaryReport,
    baseline_path: &FilePath,
) -> Result<CalibrationComparisonReport> {
    let bytes = super::read_artifact_input(
        baseline_path,
        super::MAX_JSON_DOCUMENT_BYTES,
        "calibration baseline",
    )?;
    let baseline: CalibrationBaselineReport = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing calibration baseline {}", baseline_path.display()))?;
    if baseline.schema_version != ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION {
        bail!(
            "calibration baseline {} has unsupported schema version {}",
            baseline_path.display(),
            baseline.schema_version
        );
    }
    let mut baseline_strata: BTreeMap<_, _> = baseline
        .strata
        .into_iter()
        .map(|stratum| ((stratum.dimension, stratum.key), stratum.statistics))
        .collect();
    let mut current_strata: BTreeMap<_, _> = current
        .strata
        .iter()
        .map(|stratum| {
            (
                (stratum.dimension.to_owned(), stratum.key.clone()),
                stratum.statistics.clone(),
            )
        })
        .collect();
    let keys: BTreeSet<_> = baseline_strata
        .keys()
        .cloned()
        .chain(current_strata.keys().cloned())
        .collect();
    let strata = keys
        .into_iter()
        .map(|(dimension, key)| {
            let baseline = baseline_strata.remove(&(dimension.clone(), key.clone()));
            let current = current_strata.remove(&(dimension.clone(), key.clone()));
            let delta = baseline
                .as_ref()
                .zip(current.as_ref())
                .map(|(baseline, current)| calibration_statistics_delta(current, baseline));
            CalibrationStratumComparison {
                dimension,
                key,
                baseline,
                current,
                delta,
            }
        })
        .collect();
    Ok(CalibrationComparisonReport {
        baseline_path: baseline_path.display().to_string(),
        baseline_schema_version: baseline.schema_version,
        baseline_source_run: baseline.source_run,
        overall: calibration_statistics_delta(&current.statistics, &baseline.statistics),
        strata,
    })
}

fn calibration_statistics_delta(
    current: &ArtifactSavingsCalibrationStatistics,
    baseline: &ArtifactSavingsCalibrationStatistics,
) -> CalibrationStatisticsDelta {
    CalibrationStatisticsDelta {
        samples: signed_delta(current.samples, baseline.samples),
        median_absolute_error_bytes: optional_f64_delta(
            current.median_absolute_error_bytes,
            baseline.median_absolute_error_bytes,
        ),
        p90_absolute_error_bytes: optional_u64_delta(
            current.p90_absolute_error_bytes,
            baseline.p90_absolute_error_bytes,
        ),
        relative_error_samples: signed_delta(
            current.relative_error_samples,
            baseline.relative_error_samples,
        ),
        median_relative_error: optional_f64_delta(
            current.median_relative_error,
            baseline.median_relative_error,
        ),
        p90_relative_error: optional_f64_delta(
            current.p90_relative_error,
            baseline.p90_relative_error,
        ),
    }
}

fn signed_delta(current: u64, baseline: u64) -> i64 {
    if current >= baseline {
        i64::try_from(current - baseline).unwrap_or(i64::MAX)
    } else {
        i64::try_from(baseline - current)
            .unwrap_or(i64::MAX)
            .saturating_neg()
    }
}

fn optional_f64_delta(current: Option<f64>, baseline: Option<f64>) -> Option<f64> {
    current
        .zip(baseline)
        .map(|(current, baseline)| current - baseline)
}

fn optional_u64_delta(current: Option<u64>, baseline: Option<u64>) -> Option<i64> {
    current
        .zip(baseline)
        .map(|(current, baseline)| signed_delta(current, baseline))
}

fn calibration_strata(
    store: &Store,
    measurements: &[ArtifactAnalysisSavingsCalibration],
) -> Result<Vec<CalibrationStratumReport>> {
    let mut formats = BTreeMap::<String, Vec<ArtifactAnalysisSavingsCalibration>>::new();
    let mut variants = BTreeMap::<String, Vec<ArtifactAnalysisSavingsCalibration>>::new();
    let mut clone_types = BTreeMap::<String, Vec<ArtifactAnalysisSavingsCalibration>>::new();
    for measurement in measurements {
        let identity = store
            .artifact_analysis_identity(measurement.artifact_analysis_id)?
            .ok_or_else(|| anyhow::anyhow!("calibration refers to a missing artifact analysis"))?;
        let clone_group = fingerprint_hex(measurement.clone_group_fingerprint);
        let clone_type = store
            .clone_group_type(measurement.source_scan_run_id, &clone_group)?
            .ok_or_else(|| anyhow::anyhow!("calibration refers to a missing source clone group"))?;
        formats
            .entry(identity.format)
            .or_default()
            .push(measurement.clone());
        variants
            .entry(fingerprint_hex(
                measurement
                    .before_artifact_build_variant_fingerprint
                    .as_bytes(),
            ))
            .or_default()
            .push(measurement.clone());
        clone_types
            .entry(clone_type)
            .or_default()
            .push(measurement.clone());
    }
    let mut strata = Vec::new();
    for (dimension, cohorts) in [
        ("artifact_format", formats),
        ("artifact_build_variant", variants),
        ("clone_type", clone_types),
    ] {
        strata.extend(
            cohorts
                .into_iter()
                .map(|(key, measurements)| CalibrationStratumReport {
                    dimension,
                    key,
                    statistics: artifact_savings_calibration_statistics(&measurements),
                }),
        );
    }
    Ok(strata)
}

pub(super) fn render_calibration_csv(
    report: &CalibrationSummaryReport,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(
        out,
        "source_run,record_type,dimension,key,baseline_source_run,samples,median_absolute_error_bytes,p90_absolute_error_bytes,relative_error_samples,median_relative_error,p90_relative_error,delta_samples,delta_median_absolute_error_bytes,delta_p90_absolute_error_bytes,delta_relative_error_samples,delta_median_relative_error,delta_p90_relative_error"
    )?;
    render_calibration_csv_statistics_row(
        out,
        report.source_run,
        "overall",
        "",
        "",
        &report.statistics,
    )?;
    for stratum in &report.strata {
        render_calibration_csv_statistics_row(
            out,
            report.source_run,
            "stratum",
            stratum.dimension,
            &stratum.key,
            &stratum.statistics,
        )?;
    }
    if let Some(comparison) = &report.comparison {
        render_calibration_csv_delta_row(
            out,
            report.source_run,
            "comparison-overall",
            "",
            "",
            comparison.baseline_source_run,
            &comparison.overall,
        )?;
        for stratum in &comparison.strata {
            if let Some(delta) = &stratum.delta {
                render_calibration_csv_delta_row(
                    out,
                    report.source_run,
                    "comparison-stratum",
                    &stratum.dimension,
                    &stratum.key,
                    comparison.baseline_source_run,
                    delta,
                )?;
            }
        }
    }
    Ok(())
}

fn render_calibration_csv_statistics_row(
    out: &mut impl Write,
    source_run: i64,
    record_type: &str,
    dimension: &str,
    key: &str,
    statistics: &ArtifactSavingsCalibrationStatistics,
) -> Result<()> {
    let mut fields = vec![
        source_run.to_string(),
        record_type.to_owned(),
        dimension.to_owned(),
        csv(key),
        String::new(),
        statistics.samples.to_string(),
        optional_f64(statistics.median_absolute_error_bytes),
        optional_u64(statistics.p90_absolute_error_bytes),
        statistics.relative_error_samples.to_string(),
        optional_f64(statistics.median_relative_error),
        optional_f64(statistics.p90_relative_error),
    ];
    fields.extend(vec![String::new(); 6]);
    writeln!(out, "{}", fields.join(",")).map_err(Into::into)
}

fn render_calibration_csv_delta_row(
    out: &mut impl Write,
    source_run: i64,
    record_type: &str,
    dimension: &str,
    key: &str,
    baseline_source_run: i64,
    delta: &CalibrationStatisticsDelta,
) -> Result<()> {
    let mut fields = vec![
        source_run.to_string(),
        record_type.to_owned(),
        dimension.to_owned(),
        csv(key),
        baseline_source_run.to_string(),
    ];
    fields.extend(vec![String::new(); 6]);
    fields.extend([
        delta.samples.to_string(),
        optional_f64(delta.median_absolute_error_bytes),
        optional_i64(delta.p90_absolute_error_bytes),
        delta.relative_error_samples.to_string(),
        optional_f64(delta.median_relative_error),
        optional_f64(delta.p90_relative_error),
    ]);
    writeln!(out, "{}", fields.join(",")).map_err(Into::into)
}

pub(super) fn render_calibration_text(
    report: &CalibrationSummaryReport,
    out: &mut impl Write,
) -> Result<()> {
    let statistics = &report.statistics;
    writeln!(
        out,
        "artifact calibration: source run {}",
        report.source_run
    )?;
    writeln!(out, "  samples: {}", statistics.samples)?;
    writeln!(
        out,
        "  absolute error: median {} bytes, p90 {} bytes",
        optional_f64(statistics.median_absolute_error_bytes),
        optional_u64(statistics.p90_absolute_error_bytes),
    )?;
    writeln!(
        out,
        "  relative error: {} samples, median {}, p90 {}",
        statistics.relative_error_samples,
        optional_f64(statistics.median_relative_error),
        optional_f64(statistics.p90_relative_error),
    )?;
    if !report.strata.is_empty() {
        writeln!(out, "  strata:")?;
        for stratum in &report.strata {
            let statistics = &stratum.statistics;
            writeln!(
                out,
                "    {} {}: {} samples, absolute median {} bytes, relative median {}",
                stratum.dimension,
                stratum.key,
                statistics.samples,
                optional_f64(statistics.median_absolute_error_bytes),
                optional_f64(statistics.median_relative_error),
            )?;
        }
    }
    if let Some(comparison) = &report.comparison {
        writeln!(
            out,
            "  baseline comparison (informational; no threshold): {} (schema {}, source run {})",
            comparison.baseline_path,
            comparison.baseline_schema_version,
            comparison.baseline_source_run,
        )?;
        render_calibration_delta_text(out, "overall", &comparison.overall)?;
        for stratum in &comparison.strata {
            if let Some(delta) = &stratum.delta {
                render_calibration_delta_text(
                    out,
                    &format!("{} {}", stratum.dimension, stratum.key),
                    delta,
                )?;
            } else {
                writeln!(
                    out,
                    "    {} {}: unavailable (only one report contains this stratum)",
                    stratum.dimension, stratum.key,
                )?;
            }
        }
    }
    Ok(())
}

fn render_calibration_delta_text(
    out: &mut impl Write,
    label: &str,
    delta: &CalibrationStatisticsDelta,
) -> Result<()> {
    writeln!(
        out,
        "    {label}: samples {:+}, absolute median {} bytes, relative median {}",
        delta.samples,
        signed_optional_f64(delta.median_absolute_error_bytes),
        signed_optional_f64(delta.median_relative_error),
    )
    .map_err(Into::into)
}

pub(super) fn csv(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

pub(super) fn optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.4}"))
}

fn signed_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| format!("{value:+.4}"))
}
