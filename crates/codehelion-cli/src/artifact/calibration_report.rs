//! Calibration report models and the measurement `artifact compare` records.

use std::path::Path as FilePath;

use anyhow::{Context, Result, bail};
use codehelion_artifact::ArtifactIr;
use codehelion_artifact::metrics::{EstimatedRefactorSavingsBytes, VerifiedSavingsBytes};
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisSavingsCalibration,
    ArtifactSavingsCalibrationStatistics,
};
use codehelion_store::{BuildVariantFingerprint, CalibrationRecord, Store};
use serde::{Deserialize, Serialize};

use super::input::read_artifact_input;
use super::{BuildVariantEvidence, CalibrationReport, MAX_JSON_DOCUMENT_BYTES};
use crate::cli::ArtifactCompareArgs;

/// Corpus-wide calibration-error summary for one source run.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationSummaryReport {
    pub(super) schema_version: &'static str,
    pub(super) source_run: i64,
    pub(super) statistics: ArtifactSavingsCalibrationStatistics,
    pub(super) strata: Vec<CalibrationStratumReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) comparison: Option<CalibrationComparisonReport>,
}

/// One non-overlapping calibration cohort whose key remains explicit.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationStratumReport {
    pub(super) dimension: &'static str,
    pub(super) key: String,
    pub(super) statistics: ArtifactSavingsCalibrationStatistics,
}

/// An informational comparison with one explicitly supplied prior report.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationComparisonReport {
    pub(super) baseline_path: String,
    pub(super) baseline_schema_version: String,
    pub(super) baseline_source_run: i64,
    pub(super) overall: CalibrationStatisticsDelta,
    pub(super) strata: Vec<CalibrationStratumComparison>,
}

/// One same-key calibration stratum compared across two local reports.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationStratumComparison {
    pub(super) dimension: String,
    pub(super) key: String,
    pub(super) baseline: Option<ArtifactSavingsCalibrationStatistics>,
    pub(super) current: Option<ArtifactSavingsCalibrationStatistics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) delta: Option<CalibrationStatisticsDelta>,
}

/// Signed change in reported calibration statistics.
#[derive(Debug, Serialize)]
pub(super) struct CalibrationStatisticsDelta {
    pub(super) samples: i64,
    pub(super) median_absolute_error_bytes: Option<f64>,
    pub(super) p90_absolute_error_bytes: Option<i64>,
    pub(super) relative_error_samples: i64,
    pub(super) median_relative_error: Option<f64>,
    pub(super) p90_relative_error: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CalibrationBaselineReport {
    pub(super) schema_version: String,
    pub(super) source_run: i64,
    pub(super) statistics: ArtifactSavingsCalibrationStatistics,
    pub(super) strata: Vec<CalibrationBaselineStratum>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CalibrationBaselineStratum {
    pub(super) dimension: String,
    pub(super) key: String,
    pub(super) statistics: ArtifactSavingsCalibrationStatistics,
}

/// Resolve the database only for the comparison shape that persists a
/// calibration measurement: `--source-run` together with `--clone-group`,
/// whose database defaults exactly like every other command's. An incomplete
/// request is refused by naming the flag that arrived rather than the ones
/// that did not, and a persisted measurement holds its lease for the whole
/// run.
pub(super) fn calibration_database(
    args: &ArtifactCompareArgs,
) -> Result<Option<std::path::PathBuf>> {
    match (args.source_run.is_some(), args.clone_group.is_some()) {
        (true, true) => Ok(Some(crate::resolve_db(
            crate::scan::DatabaseUse::Recording,
            args.db.as_deref(),
        )?)),
        (true, false) => bail!(
            "--source-run was given without --clone-group; artifact compare records a calibration for one clone group of that run"
        ),
        (false, true) => bail!(
            "--clone-group was given without --source-run; artifact compare records a calibration for that group in one scan run"
        ),
        (false, false) if args.db.is_some() => bail!(
            "--db was given without --source-run and --clone-group; artifact compare uses --db only to record a calibration"
        ),
        (false, false) => Ok(None),
    }
}

pub(super) fn record_comparison_calibration(
    args: &ArtifactCompareArgs,
    before: &ArtifactIr,
    after: &ArtifactIr,
    before_variant: Option<&BuildVariantEvidence>,
    after_variant: Option<&BuildVariantEvidence>,
    database: Option<&FilePath>,
) -> Result<Option<CalibrationReport>> {
    let Some(source_run) = args.source_run else {
        return Ok(None);
    };
    let clone_group = args
        .clone_group
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("calibration clone group is absent"))?;
    let before_variant = before_variant
        .ok_or_else(|| anyhow::anyhow!("calibration requires --before-build-variant"))?;
    let after_variant = after_variant
        .ok_or_else(|| anyhow::anyhow!("calibration requires --after-build-variant"))?;
    if before.format != after.format {
        bail!("calibration requires before and after artifacts of the same format");
    }
    if before_variant.fingerprint != after_variant.fingerprint {
        bail!("calibration requires equal before and after build variants");
    }
    let db = database.ok_or_else(|| anyhow::anyhow!("calibration database is absent"))?;
    let mut store = Store::open_existing(db)
        .with_context(|| format!("opening calibration database {}", db.display()))?;
    // Analysing the same artifact twice leaves two rows describing one
    // measurement. The store resolves them under its own recency order and
    // names the analysis it took, so re-analysing never makes this path
    // unusable.
    let selected = store
        .select_clone_group_estimate(
            source_run,
            clone_group,
            before.fingerprint.as_bytes(),
            before_variant.fingerprint.as_bytes(),
        )?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "calibration found no saved estimate for this source run, group, artifact, and build variant"
            )
        })?;
    let analysis_id = selected.artifact_analysis_id;
    let estimate = &selected.estimate;
    let verified =
        i64::try_from(i128::from(before.observed_bytes) - i128::from(after.observed_bytes))
            .map_err(|_| anyhow::anyhow!("artifact size difference exceeds calibration range"))?;
    let absolute_error = u64::try_from(
        (i128::from(estimate.estimated_refactor_savings_bytes) - i128::from(verified))
            .unsigned_abs(),
    )
    .unwrap_or(u64::MAX);
    #[allow(
        clippy::cast_precision_loss,
        reason = "calibration reports a dimensionless ratio as a floating-point value"
    )]
    let relative_error =
        (verified != 0).then(|| absolute_error as f64 / verified.unsigned_abs() as f64);
    let calibration = ArtifactAnalysisSavingsCalibration {
        schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
        artifact_analysis_id: analysis_id,
        source_scan_run_id: source_run,
        clone_group_fingerprint: estimate.clone_group_fingerprint,
        source_build_variant_fingerprint: estimate.source_build_variant_fingerprint,
        before_artifact_build_variant_fingerprint: BuildVariantFingerprint::from_bytes(
            before_variant.fingerprint.as_bytes(),
        ),
        after_artifact_fingerprint: after.fingerprint.as_bytes(),
        after_artifact_build_variant_fingerprint: BuildVariantFingerprint::from_bytes(
            after_variant.fingerprint.as_bytes(),
        ),
        estimated_refactor_savings_bytes: estimate.estimated_refactor_savings_bytes,
        verified_savings_bytes: verified,
        absolute_error_bytes: absolute_error,
        relative_error,
        recorded_at: crate::scan::rfc3339_now(),
    };
    // Recording is idempotent, so taking the measurement again reports the
    // same comparison instead of failing the whole command.
    let record = store.record_artifact_savings_calibration(&calibration)?;
    Ok(Some(CalibrationReport {
        source_run,
        clone_group_fingerprint: clone_group.to_owned(),
        estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(
            calibration.estimated_refactor_savings_bytes,
        ),
        verified_savings_bytes: VerifiedSavingsBytes(verified),
        absolute_error_bytes: absolute_error,
        relative_error,
        artifact_analysis_id: analysis_id,
        matching_analyses: selected.matching_analyses,
        already_recorded: matches!(record, CalibrationRecord::ReRecorded),
    }))
}

/// Load a user-supplied build description without running anything from it.
pub(super) fn read_build_variant(
    path: Option<&std::path::Path>,
) -> Result<Option<BuildVariantEvidence>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = read_artifact_input(path, MAX_JSON_DOCUMENT_BYTES, "build variant")?;
    let value = serde_json::from_slice::<serde_json::Value>(&bytes)
        .with_context(|| format!("parsing build variant {} as JSON", path.display()))?;
    let normalized = serde_json::to_vec(&value)
        .with_context(|| format!("normalizing build variant {} as JSON", path.display()))?;
    Ok(Some(BuildVariantEvidence {
        manifest_path: path.display().to_string(),
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "artifact-build-variant",
            &normalized,
        ),
    }))
}
