//! Compiled-artifact command wiring and report rendering.
//!
//! This module is intentionally above the source clone engine. It dispatches
//! a format-specific backend over bytes read from a named file and never
//! loads, instantiates, or otherwise executes the inspected artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::path::Path as FilePath;
#[cfg(test)]
use std::time::Duration;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use codehelion_artifact::ArtifactBackend;
#[cfg(test)]
use codehelion_artifact::wasm::WasmBackend;
use codehelion_artifact::{
    ARTIFACT_IR_SCHEMA_VERSION, ArtifactFormat as BinaryFormat, ArtifactIr, metrics,
    metrics::{EstimatedRefactorSavingsBytes, EvidenceConfidence, VerifiedSavingsBytes},
};
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisMapping, ArtifactAnalysisSavingsCalibration,
    ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSource, ArtifactAnalysisUnmappedSourceReason,
    ArtifactAnalysisUnmappedSymbol, ArtifactSavingsCalibrationStatistics, MappingEvidence,
    MappingEvidenceFact, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
    artifact_savings_calibration_statistics,
};
#[cfg(test)]
use codehelion_store::artifact::{ArtifactAnalysisSnapshot, ArtifactAnalysisSymbol};
use codehelion_store::query::{
    SourceFragmentIdentity, SourceInstantiation, SourceResolvedCall, SourceResolvedSymbol,
    SourceUnitIdentity,
};
use codehelion_store::{Store, fingerprint_hex};
use serde::Serialize;

use crate::Outcome;
use crate::cli::{
    ArtifactArgs, ArtifactCalibrationArgs, ArtifactCompareArgs, ArtifactFormat, ArtifactReportArgs,
};
#[cfg(test)]
use crate::cli::{
    ArtifactInputFormat, UNTRUSTED_ARTIFACT_MAX_BYTES, UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES,
    UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS,
};

/// JSON schema emitted by the artifact command.
pub const ARTIFACT_REPORT_SCHEMA_VERSION: &str = "artifact-report-v2";

/// JSON schema emitted by the artifact comparison command.
pub const ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION: &str = "artifact-comparison-report-v2";

/// JSON Schema for the versioned artifact-analysis report.
pub const ARTIFACT_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-report-v2.schema.json");

/// JSON Schema for the versioned artifact comparison report.
pub const ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-comparison-report-v2.schema.json");

/// JSON Schema for the versioned calibration summary report.
pub const ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-calibration-report-v1.schema.json");

/// JSON report schema emitted by artifact calibration.
const ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION: &str = "artifact-calibration-report-v1";

/// Number of fields in every artifact CSV record.
///
/// Columns are only ever appended, so a consumer that reads by position keeps
/// reading the same values after a release adds one.
const ARTIFACT_CSV_COLUMNS: usize = 36;

/// A direct before-minus-after artifact-size observation.
///
/// This is deliberately distinct from [`EstimatedRefactorSavingsBytes`] and
/// [`VerifiedSavingsBytes`]: comparing arbitrary files observes a difference,
/// but verifies no particular source refactoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct ObservedSizeReductionBytes(i128);

/// Largest accepted local linker-map input.
const MAX_LINKER_MAP_BYTES: u64 = 64 * 1024 * 1024;

/// Largest JSON document accepted from a path named on the command line.
///
/// A build-variant manifest and a calibration report are both small structured
/// documents, so a real one is orders of magnitude below this. The ceiling is
/// here because the file behind a named path is read whole: one that turns out
/// to be enormous is refused with a sentence rather than allocated until the
/// machine gives out.
const MAX_JSON_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

mod calibration_report;
mod input;
mod output;
mod recorded;

use calibration_report::{
    CalibrationBaselineReport, CalibrationComparisonReport, CalibrationStatisticsDelta,
    CalibrationStratumComparison, CalibrationStratumReport, CalibrationSummaryReport,
    calibration_database, read_build_variant, record_comparison_calibration,
};
use input::{
    compare_untrusted_containment, inspect, read_artifact_input, resolve_wasm_source_maps,
    untrusted_containment,
};
#[cfg(test)]
use input::{input_format, parse_input_format, resolve_wasm_source_map, source_map_locations};
#[cfg(test)]
use output::CappedArtifactIrBuffer;
use output::{OutputReservation, write_output};
use recorded::{record, recorded_containment, recorded_correlation, recorded_source_maps};

mod worker;

pub use worker::run_isolated_worker;
use worker::{IsolatedArtifactRequest, clamp_untrusted_artifact_limits, run_isolated_request};
#[cfg(test)]
use worker::{deadline_after, read_worker_stderr};
// The test that reaches this one kills a process the way only a Unix host
// does, so Windows builds would carry an import nothing uses.
#[cfg(all(test, unix))]
use worker::wait_for_worker;

/// Inspect one artifact and render its observed facts and equality groups.
///
/// # Errors
///
/// Returns an error if the file cannot be read, its format is unknown or not
/// implemented, its parser rejects the bytes, or an output file cannot be
/// written. No error path executes the inspected input.
pub fn run(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    worker::run_isolated(args, out)
}

/// Run the artifact pipeline in the already isolated worker process.
fn run_direct(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    worker::set_stage("persistence setup");
    let database = crate::resolve_db(crate::scan::DatabaseUse::Recording, args.db.as_deref())?;
    let _database_lock = crate::scan_lock::acquire(&database)?;
    let started_at = crate::scan::rfc3339_now();
    worker::set_stage("parsing");
    let artifact = inspect(
        &args.path,
        args.max_bytes,
        args.input_format,
        args.debug_file.as_deref(),
        args.arch.as_deref(),
        args.untrusted,
    )?;
    worker::set_stage("source-map correlation");
    let source_maps = resolve_wasm_source_maps(&args.path, &artifact, args.max_bytes);
    let finished_at = crate::scan::rfc3339_now();
    let build_variant = read_build_variant(args.build_variant.as_deref())?;
    let containment = untrusted_containment(args);
    worker::set_stage("persistence and source correlation");
    // The facts the report states are the facts recorded with the analysis, so
    // re-rendering it later reads them back rather than deriving them again.
    let facts = AnalysisFacts {
        source_maps: &source_maps,
        containment: containment.as_ref(),
    };
    let (analysis_id, correlation) = record(
        &artifact,
        &facts,
        args,
        &database,
        build_variant.as_ref(),
        &started_at,
        &finished_at,
    )?;
    let report = ArtifactReport::from_ir(
        &args.path,
        &artifact,
        Some(analysis_id),
        build_variant.as_ref().map(BuildVariantEvidence::for_report),
    )
    .with_containment(containment)
    .with_source_maps(source_maps)
    .with_correlation(correlation);
    worker::set_stage("rendering");
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_text(&report, args.verbose, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        write_output(path, &rendered, args.force)?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

mod calibration;

pub use calibration::calibration;
#[cfg(test)]
use calibration::{calibration_comparison, render_calibration_csv, render_calibration_text};
use calibration::{csv, optional_f64};
/// Render one stored artifact analysis in the requested output format.
///
/// Everything the analysis stated is read back from its own rows — the
/// correlation, the outcome of each declared source-map reference, and the
/// ceilings an untrusted run installed — so this re-render says what that
/// analysis said rather than what re-deriving it today would say.
///
/// # Errors
///
/// Returns an error when the analysis cannot be loaded, decoded, rendered, or
/// written to the selected destination.
pub fn report(args: &ArtifactReportArgs, out: &mut impl Write) -> Result<Outcome> {
    // A report only reads a committed SQLite snapshot. WAL lets this proceed
    // alongside one writer, so it deliberately does not take the writer lease.
    let db = crate::resolve_db(crate::scan::DatabaseUse::Reading, args.db.as_deref())?;
    let store = crate::scan::open_recorded_store(&db)?;
    let analysis_id = args.analysis.map_or_else(
        || {
            store
                .latest_artifact_analysis_id()?
                .context("no saved artifact analysis; run `codehelion artifact analyze` first")
        },
        Ok,
    )?;
    let analysis = store
        .artifact_analysis(analysis_id)?
        .ok_or_else(|| anyhow::anyhow!("artifact analysis {analysis_id} was not found"))?;
    let artifact: ArtifactIr = serde_json::from_str(&analysis.ir_json)
        .with_context(|| format!("decoding saved artifact analysis {analysis_id}"))?;
    if analysis.schema_version != ARTIFACT_IR_SCHEMA_VERSION
        || artifact.schema_version != analysis.schema_version
    {
        bail!(
            "saved artifact analysis {} has incompatible IR schema (row {}, document {}; this build supports {ARTIFACT_IR_SCHEMA_VERSION})",
            analysis_id,
            analysis.schema_version,
            artifact.schema_version
        );
    }
    let build_variant = analysis
        .build_variant_manifest_path
        .zip(analysis.build_variant_fingerprint)
        .map(|(manifest_path, fingerprint)| ComparisonBuildVariant {
            manifest_path,
            fingerprint: fingerprint_hex(fingerprint.as_bytes()),
        });
    let report = ArtifactReport::from_ir(
        FilePath::new(&analysis.path),
        &artifact,
        Some(analysis.analysis_id),
        build_variant,
    )
    .with_containment(recorded_containment(&store, analysis_id)?)
    .with_source_maps(recorded_source_maps(&store, analysis_id)?)
    .with_correlation(recorded_correlation(&store, analysis_id, &artifact)?);
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_text(&report, args.verbose, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        write_output(path, &rendered, args.force)?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

/// What one analysis established beside its IR.
///
/// Both values reach the report and the database from here, so a saved
/// analysis carries everything its own rendering stated.
struct AnalysisFacts<'a> {
    source_maps: &'a [SourceMapResolution],
    containment: Option<&'a ArtifactContainment>,
}

mod correlation;

use correlation::ArtifactCorrelationReport;
/// Compare two artifacts by their content-derived symbol identities.
///
/// # Errors
///
/// Returns an error under the same conditions as [`run`]. The artifacts are
/// read as bytes only; neither one is executed.
pub fn compare(args: &ArtifactCompareArgs, out: &mut impl Write) -> Result<Outcome> {
    let mut args = args.clone();
    if args.untrusted {
        clamp_untrusted_artifact_limits(
            &mut args.max_bytes,
            &mut args.timeout_seconds,
            &mut args.max_memory_bytes,
        )?;
    }
    let output = args.output.clone();
    let force = args.force;
    run_isolated_request(
        IsolatedArtifactRequest::Compare(args.clone()),
        args.timeout_seconds,
        output.as_deref(),
        force,
        out,
    )
}

/// Run an artifact comparison in the already isolated worker process.
fn compare_direct(args: &ArtifactCompareArgs, out: &mut impl Write) -> Result<Outcome> {
    worker::set_stage("persistence setup");
    let database = calibration_database(args)?;
    let _database_lock = database
        .as_deref()
        .map(crate::scan_lock::acquire)
        .transpose()?;
    worker::set_stage("parsing before artifact");
    let before = inspect(
        &args.before,
        args.max_bytes,
        args.input_format,
        None,
        args.arch.as_deref(),
        args.untrusted,
    )?;
    worker::set_stage("parsing after artifact");
    let after = inspect(
        &args.after,
        args.max_bytes,
        args.input_format,
        None,
        args.arch.as_deref(),
        args.untrusted,
    )?;
    let before_variant = read_build_variant(args.before_build_variant.as_deref())?;
    let after_variant = read_build_variant(args.after_build_variant.as_deref())?;
    let mut report = ArtifactComparisonReport::new(
        &args.before,
        &before,
        before_variant
            .as_ref()
            .map(BuildVariantEvidence::for_report),
        &args.after,
        &after,
        after_variant.as_ref().map(BuildVariantEvidence::for_report),
    );
    report.containment = compare_untrusted_containment(args);
    worker::set_stage("calibration persistence");
    report.calibration = record_comparison_calibration(
        args,
        &before,
        &after,
        before_variant.as_ref(),
        after_variant.as_ref(),
        database.as_deref(),
    )?;
    worker::set_stage("rendering");
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_compare_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_compare_text(&report, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        write_output(path, &rendered, args.force)?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

mod model;

use model::{
    ArtifactComparisonReport, ArtifactContainment, ArtifactReport, BuildVariantEvidence,
    CalibrationReport, ComparisonBuildVariant, SourceMapLocation, SourceMapResolution,
    SourceMapResolutionStatus,
};

mod render;

use render::{render_compare_csv, render_compare_text, render_csv, render_text};
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
