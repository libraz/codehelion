//! Group-level savings estimates and the measured outcomes that calibrate them.
//!
//! Estimates and verified measurements stay in separate records: a controlled
//! before/after comparison never rewrites the estimate it evaluates, so the
//! distribution of the error remains reportable.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::StoreError;
use crate::fingerprint::BuildVariantFingerprint;

/// One versioned source/artifact-correlated clone-group estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactAnalysisCloneGroupSavings {
    /// Version of this savings record and structured assumptions vocabulary.
    pub schema_version: String,
    /// Source scan whose group identity and members were considered.
    pub source_scan_run_id: i64,
    /// Stable clone-group fingerprint.
    pub clone_group_fingerprint: [u8; 16],
    /// Build variant that minted the source group.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Build variant of the artifact receiving the attribution.
    pub artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Fully attributed observed duplicate bytes for the group.
    pub duplicated_bytes: u64,
    /// Model-derived refactoring estimate; it may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Mapping-confidence category retained separately from the estimate.
    pub mapping_confidence: ArtifactAnalysisSavingsConfidence,
    /// Score emitted by the source clone engine.
    pub clone_confidence: f64,
    /// Confidence in the model assumptions.
    pub model_confidence: ArtifactAnalysisSavingsConfidence,
    /// Confidence in this estimate, without collapsing the components.
    pub savings_confidence: ArtifactAnalysisSavingsConfidence,
    /// Model vocabulary version.
    pub model_schema_version: String,
    /// Canonical JSON array of structured assumptions.
    pub assumptions_json: String,
}

/// Fixed confidence vocabulary for persisted savings components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAnalysisSavingsConfidence {
    /// Direct evidence establishes the component.
    High,
    /// Conservative inference supports the component.
    Medium,
    /// Significant model uncertainty remains.
    Low,
    /// Required evidence is absent.
    Unavailable,
}

impl ArtifactAnalysisSavingsConfidence {
    pub(super) const fn as_sql(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unavailable => "unavailable",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, StoreError> {
        match value {
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(StoreError::UnknownVocabulary {
                field: "artifact_analysis_clone_group_savings.savings_confidence",
                value: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for ArtifactAnalysisSavingsConfidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_sql())
    }
}

/// Current savings-record schema.
pub const ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION: &str =
    "artifact-clone-group-savings-v1";

/// One measured before/after outcome evaluating a persisted group estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactAnalysisSavingsCalibration {
    /// Versioned calibration-record shape.
    pub schema_version: String,
    /// Analysis that produced the estimate being evaluated.
    pub artifact_analysis_id: i64,
    /// Source run and stable group identity of that estimate.
    pub source_scan_run_id: i64,
    /// Stable clone-group identity.
    pub clone_group_fingerprint: [u8; 16],
    /// Build variants remain separate rather than being inferred from paths.
    pub source_build_variant_fingerprint: BuildVariantFingerprint,
    /// Build variant of the analyzed before artifact.
    pub before_artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Content-derived identity of the measured after artifact.
    pub after_artifact_fingerprint: [u8; 16],
    /// Build variant of the measured after artifact.
    pub after_artifact_build_variant_fingerprint: BuildVariantFingerprint,
    /// Estimate retained verbatim; it may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Observed before-minus-after size difference; it may be negative.
    pub verified_savings_bytes: i64,
    /// Absolute difference between estimate and observation.
    pub absolute_error_bytes: u64,
    /// Error relative to a nonzero observation, absent for zero baseline.
    pub relative_error: Option<f64>,
    /// RFC 3339 time the controlled comparison was recorded.
    pub recorded_at: String,
}

/// Current calibration-record schema.
pub const ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION: &str =
    "artifact-savings-calibration-v1";

/// Distribution summary for independently retained calibration errors.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ArtifactSavingsCalibrationStatistics {
    /// Number of controlled measurements, including zero-verified cases.
    pub samples: u64,
    /// Median absolute byte error, or absent when no measurement exists.
    pub median_absolute_error_bytes: Option<f64>,
    /// Nearest-rank 90th percentile absolute byte error.
    pub p90_absolute_error_bytes: Option<u64>,
    /// Number of measurements for which relative error is meaningful.
    pub relative_error_samples: u64,
    /// Median relative error, excluding zero-verified measurements.
    pub median_relative_error: Option<f64>,
    /// Nearest-rank 90th percentile relative error.
    pub p90_relative_error: Option<f64>,
}

/// Summarize controlled calibration errors without merging their source facts.
///
/// The median averages the two central values for an even population. The p90
/// uses the nearest-rank definition, so small corpora never invent an
/// interpolated measurement. Relative error is absent for a zero verified
/// value because no denominator was observed.
#[must_use]
pub fn artifact_savings_calibration_statistics(
    calibrations: &[ArtifactAnalysisSavingsCalibration],
) -> ArtifactSavingsCalibrationStatistics {
    let mut absolute: Vec<_> = calibrations
        .iter()
        .map(|value| value.absolute_error_bytes)
        .collect();
    absolute.sort_unstable();
    let mut relative: Vec<_> = calibrations
        .iter()
        .filter_map(|value| value.relative_error)
        .collect();
    relative.sort_by(f64::total_cmp);
    ArtifactSavingsCalibrationStatistics {
        samples: u64::try_from(absolute.len()).unwrap_or(u64::MAX),
        median_absolute_error_bytes: median_u64(&absolute),
        p90_absolute_error_bytes: percentile_u64(&absolute, 90),
        relative_error_samples: u64::try_from(relative.len()).unwrap_or(u64::MAX),
        median_relative_error: median_f64(&relative),
        p90_relative_error: percentile_f64(&relative, 90),
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "the report intentionally exposes byte-error medians as floating-point values"
)]
fn median_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let middle = values.len().checked_div(2)?;
    if values.len().is_multiple_of(2) {
        Some(f64::midpoint(
            values[middle - 1] as f64,
            values[middle] as f64,
        ))
    } else {
        Some(values[middle] as f64)
    }
}

fn median_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let middle = values.len().checked_div(2)?;
    if values.len().is_multiple_of(2) {
        Some(f64::midpoint(values[middle - 1], values[middle]))
    } else {
        Some(values[middle])
    }
}

fn percentile_u64(values: &[u64], percentile: usize) -> Option<u64> {
    nearest_rank(values.len(), percentile).map(|index| values[index])
}

fn percentile_f64(values: &[f64], percentile: usize) -> Option<f64> {
    nearest_rank(values.len(), percentile).map(|index| values[index])
}

fn nearest_rank(length: usize, percentile: usize) -> Option<usize> {
    let rank = length.checked_mul(percentile)?.saturating_add(99) / 100;
    rank.checked_sub(1)
}
