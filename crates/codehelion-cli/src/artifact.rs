//! Compiled-artifact command wiring and report rendering.
//!
//! This module is intentionally above the source clone engine. It dispatches
//! a format-specific backend over bytes read from a named file and never
//! loads, instantiates, or otherwise executes the inspected artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::Path as FilePath;
#[cfg(test)]
use std::time::Duration;

use anyhow::{Context, Result, bail};
use codehelion_artifact::{
    ARTIFACT_IR_SCHEMA_VERSION, ArtifactBackend, ArtifactFormat as BinaryFormat, ArtifactIr,
    detect_format, metrics,
    metrics::{EstimatedRefactorSavingsBytes, EvidenceConfidence, VerifiedSavingsBytes},
};
use codehelion_artifact_archive::ArchiveBackend;
use codehelion_artifact_elf::ElfBackend;
use codehelion_artifact_macho::MachOBackend;
use codehelion_artifact_pe::PeCoffBackend;
use codehelion_artifact_wasm::WasmBackend;
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisMapping, ArtifactAnalysisSavingsCalibration,
    ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSnapshot, ArtifactAnalysisSourceKind,
    ArtifactAnalysisSymbol, ArtifactAnalysisUnmappedReason, ArtifactAnalysisUnmappedSource,
    ArtifactAnalysisUnmappedSourceReason, ArtifactAnalysisUnmappedSymbol,
    ArtifactSavingsCalibrationStatistics, MAX_ARTIFACT_IR_JSON_BYTES, MappingEvidence,
    MappingEvidenceFact, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
    artifact_savings_calibration_statistics,
};
use codehelion_store::query::{
    SourceFragmentIdentity, SourceInstantiation, SourceResolvedCall, SourceResolvedSymbol,
    SourceUnitIdentity,
};
use codehelion_store::{Store, fingerprint_hex};
use serde::{Deserialize, Serialize};

use crate::Outcome;
use crate::cli::{
    ArtifactArgs, ArtifactCalibrationArgs, ArtifactCompareArgs, ArtifactFormat,
    ArtifactInputFormat, ArtifactReportArgs,
};
#[cfg(test)]
use crate::cli::{
    UNTRUSTED_ARTIFACT_MAX_BYTES, UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES,
    UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS,
};

/// JSON schema emitted by the artifact command.
pub const ARTIFACT_REPORT_SCHEMA_VERSION: &str = "artifact-report-v1";

/// JSON schema emitted by the artifact comparison command.
pub const ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION: &str = "artifact-comparison-report-v1";

/// JSON Schema for the versioned artifact-analysis report.
pub const ARTIFACT_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-report-v1.schema.json");

/// JSON Schema for the versioned artifact comparison report.
pub const ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-comparison-report-v1.schema.json");

/// JSON Schema for the versioned calibration summary report.
pub const ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-calibration-report-v1.schema.json");

/// JSON report schema emitted by artifact calibration.
const ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION: &str = "artifact-calibration-report-v1";

/// Number of fields in every artifact CSV record.
const ARTIFACT_CSV_COLUMNS: usize = 33;

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

mod worker;

pub use worker::run_isolated_worker;
use worker::{IsolatedArtifactRequest, clamp_untrusted_artifact_limits, run_isolated_request};
#[cfg(test)]
use worker::{deadline_after, read_worker_stderr, wait_for_worker};

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
    let database = crate::resolve_db(args.db.as_deref())?;
    let _database_lock = crate::scan_lock::acquire(&database)?;
    let started_at = crate::scan::rfc3339_now();
    worker::set_stage("parsing");
    let artifact = inspect(
        &args.path,
        args.max_bytes,
        args.input_format,
        args.debug_file.as_deref(),
        args.arch.as_deref(),
    )?;
    worker::set_stage("source-map correlation");
    let source_maps = resolve_wasm_source_maps(&args.path, &artifact, args.max_bytes);
    let finished_at = crate::scan::rfc3339_now();
    let build_variant = read_build_variant(args.build_variant.as_deref())?;
    worker::set_stage("persistence and source correlation");
    let (analysis_id, correlation) = record(
        &artifact,
        &source_maps,
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
    .with_containment(untrusted_containment(args))
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

fn untrusted_containment(args: &ArtifactArgs) -> Option<ArtifactContainment> {
    if !args.untrusted {
        return None;
    }
    let memory = args.max_memory_bytes?;
    Some(ArtifactContainment {
        max_input_bytes: args.max_bytes,
        worker_timeout_seconds: args.timeout_seconds,
        worker_memory_limit_bytes: memory,
    })
}

mod calibration;

pub use calibration::calibration;
#[cfg(test)]
use calibration::{calibration_comparison, render_calibration_csv, render_calibration_text};
use calibration::{csv, optional_f64};
/// Render one stored artifact analysis in the requested output format.
///
/// # Errors
///
/// Returns an error when the analysis cannot be loaded, decoded, rendered, or
/// written to the selected destination.
pub fn report(args: &ArtifactReportArgs, out: &mut impl Write) -> Result<Outcome> {
    // A report only reads a committed SQLite snapshot. WAL lets this proceed
    // alongside one writer, so it deliberately does not take the writer lease.
    let db = crate::resolve_db(args.db.as_deref())?;
    let store = Store::open_existing(&db)
        .with_context(|| format!("opening artifact database {}", db.display()))?;
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
            fingerprint: fingerprint_hex(fingerprint),
        });
    let report = ArtifactReport::from_ir(
        FilePath::new(&analysis.path),
        &artifact,
        Some(analysis.analysis_id),
        build_variant,
    );
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

fn write_output(path: &FilePath, bytes: &[u8], force: bool) -> Result<()> {
    if force {
        fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "writing {} (refusing to overwrite an existing file; pass --force to replace it)",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

/// Corpus-wide calibration-error summary for one source run.
#[derive(Debug, Serialize)]
struct CalibrationSummaryReport {
    schema_version: &'static str,
    source_run: i64,
    statistics: ArtifactSavingsCalibrationStatistics,
    strata: Vec<CalibrationStratumReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<CalibrationComparisonReport>,
}

/// One non-overlapping calibration cohort whose key remains explicit.
#[derive(Debug, Serialize)]
struct CalibrationStratumReport {
    dimension: &'static str,
    key: String,
    statistics: ArtifactSavingsCalibrationStatistics,
}

/// An informational comparison with one explicitly supplied prior report.
#[derive(Debug, Serialize)]
struct CalibrationComparisonReport {
    baseline_path: String,
    baseline_schema_version: String,
    baseline_source_run: i64,
    overall: CalibrationStatisticsDelta,
    strata: Vec<CalibrationStratumComparison>,
}

/// One same-key calibration stratum compared across two local reports.
#[derive(Debug, Serialize)]
struct CalibrationStratumComparison {
    dimension: String,
    key: String,
    baseline: Option<ArtifactSavingsCalibrationStatistics>,
    current: Option<ArtifactSavingsCalibrationStatistics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta: Option<CalibrationStatisticsDelta>,
}

/// Signed change in reported calibration statistics.
#[derive(Debug, Serialize)]
struct CalibrationStatisticsDelta {
    samples: i64,
    median_absolute_error_bytes: Option<f64>,
    p90_absolute_error_bytes: Option<i64>,
    relative_error_samples: i64,
    median_relative_error: Option<f64>,
    p90_relative_error: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CalibrationBaselineReport {
    schema_version: String,
    source_run: i64,
    statistics: ArtifactSavingsCalibrationStatistics,
    strata: Vec<CalibrationBaselineStratum>,
}

#[derive(Debug, Deserialize)]
struct CalibrationBaselineStratum {
    dimension: String,
    key: String,
    statistics: ArtifactSavingsCalibrationStatistics,
}

fn record(
    artifact: &ArtifactIr,
    source_maps: &[SourceMapResolution],
    args: &ArtifactArgs,
    database: &FilePath,
    build_variant: Option<&BuildVariantEvidence>,
    started_at: &str,
    finished_at: &str,
) -> Result<(i64, Option<ArtifactCorrelationReport>)> {
    let symbols: Vec<ArtifactAnalysisSymbol> = artifact
        .symbols
        .iter()
        .map(|symbol| ArtifactAnalysisSymbol {
            fingerprint: symbol.fingerprint.as_bytes(),
            name: symbol.name.clone(),
            exported: symbol.exported,
            section_index: symbol.section,
            offset: symbol.offset,
            size_bytes: symbol.size,
            size_inferred: symbol.size_inferred,
            code_fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "artifact-code",
                &symbol.code,
            )
            .as_bytes(),
            normalization_version: symbol
                .normalized
                .as_ref()
                .map(|value| value.version.clone()),
            normalization_fingerprint: symbol.normalized.as_ref().map(|value| {
                codehelion_artifact::ArtifactFingerprint::from_content(
                    "artifact-normalized",
                    &value.bytes,
                )
                .as_bytes()
            }),
        })
        .collect();
    let mut store = if args.source_run.is_some() {
        Store::open_existing(database)?
    } else {
        Store::open(database)?
    };
    let linker_map = read_linker_map(args.linker_map.as_deref())?;
    let correlation = correlate_source_run(
        artifact,
        &source_map_locations(source_maps),
        args.source_run,
        build_variant,
        &linker_map,
        &store,
    )?;
    if artifact.schema_version != ARTIFACT_IR_SCHEMA_VERSION {
        bail!(
            "refusing to persist artifact IR schema {} (this build supports {ARTIFACT_IR_SCHEMA_VERSION})",
            artifact.schema_version
        );
    }
    let ir_json = serialize_artifact_ir(artifact)?;
    let correlation_report = args
        .source_run
        .map(|source_run| ArtifactCorrelationReport::from_rows(source_run, artifact, &correlation));
    let clone_group_savings = correlation_report.as_ref().map_or_else(
        || Ok(Vec::new()),
        |report| stored_clone_group_savings(report.source_run, &report.estimated_refactor_savings),
    )?;
    let analysis_id = store.record_artifact_analysis(&ArtifactAnalysisSnapshot {
        schema_version: &artifact.schema_version,
        path: &args.path.display().to_string(),
        format: artifact.format.name(),
        content_fingerprint: artifact.fingerprint.as_bytes(),
        observed_bytes: artifact.observed_bytes,
        ir_json: &ir_json,
        build_variant_manifest_path: build_variant.map(|value| value.manifest_path.as_str()),
        build_variant_fingerprint: build_variant.map(|value| value.fingerprint.as_bytes()),
        started_at,
        finished_at,
        symbols: &symbols,
        mappings: &correlation.mappings,
        unmapped_symbols: &correlation.unmapped_symbols,
        unmapped_sources: &correlation.unmapped_sources,
        correlation: correlation_report
            .as_ref()
            .map(|report| report.snapshot(artifact)),
        clone_group_savings: &clone_group_savings,
    })?;
    Ok((analysis_id, correlation_report))
}

/// Serialize a persisted artifact IR without allowing its temporary buffer to
/// exceed the same storage budget the database enforces.
fn serialize_artifact_ir(artifact: &ArtifactIr) -> Result<String> {
    let mut output = CappedArtifactIrBuffer::new(MAX_ARTIFACT_IR_JSON_BYTES);
    if let Err(error) = serde_json::to_writer(&mut output, artifact) {
        if output.exceeded {
            bail!(
                "artifact analysis IR exceeds the storage limit of {MAX_ARTIFACT_IR_JSON_BYTES} bytes"
            );
        }
        return Err(error).context("serializing artifact IR for SQLite");
    }
    String::from_utf8(output.bytes).context("encoding artifact IR for SQLite")
}

/// A growable JSON buffer that stops immediately at its explicit storage cap.
struct CappedArtifactIrBuffer {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    exceeded: bool,
}

impl CappedArtifactIrBuffer {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
            exceeded: false,
        }
    }
}

impl Write for CappedArtifactIrBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self.maximum_bytes.saturating_sub(self.bytes.len());
        if bytes.len() > remaining {
            self.bytes.extend_from_slice(&bytes[..remaining]);
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "artifact IR storage limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

mod correlation;

use correlation::{
    ArtifactCorrelationReport, correlate_source_run, read_linker_map, stored_clone_group_savings,
};
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
    )?;
    worker::set_stage("parsing after artifact");
    let after = inspect(
        &args.after,
        args.max_bytes,
        args.input_format,
        None,
        args.arch.as_deref(),
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

/// Resolve the database only for the comparison shape that persists a
/// calibration measurement. A partial calibration request cannot reach the
/// artifact readers, and a persisted one holds its lease for the whole run.
fn calibration_database(args: &ArtifactCompareArgs) -> Result<Option<std::path::PathBuf>> {
    let supplied = [
        args.source_run.is_some(),
        args.clone_group.is_some(),
        args.db.is_some(),
    ];
    if supplied.iter().any(|value| *value) && supplied.iter().any(|value| !*value) {
        bail!("calibration requires --source-run, --clone-group, and --db together");
    }
    if args.source_run.is_some() {
        Ok(Some(crate::resolve_db(args.db.as_deref())?))
    } else {
        Ok(None)
    }
}

fn record_comparison_calibration(
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
    let candidates = store.clone_group_savings(source_run, clone_group)?;
    let mut matching = Vec::new();
    for (analysis_id, estimate) in candidates {
        let identity = store
            .artifact_analysis_identity(analysis_id)?
            .ok_or_else(|| anyhow::anyhow!("saved estimate refers to missing artifact analysis"))?;
        if estimate.artifact_build_variant_fingerprint == before_variant.fingerprint.as_bytes()
            && identity.content_fingerprint == before.fingerprint.as_bytes()
            && identity.build_variant_fingerprint == Some(before_variant.fingerprint.as_bytes())
        {
            matching.push((analysis_id, estimate));
        }
    }
    let [(analysis_id, estimate)] = matching.as_slice() else {
        bail!(
            "calibration needs exactly one matching saved estimate for this source run, group, artifact, and build variant"
        );
    };
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
        artifact_analysis_id: *analysis_id,
        source_scan_run_id: source_run,
        clone_group_fingerprint: estimate.clone_group_fingerprint,
        source_build_variant_fingerprint: estimate.source_build_variant_fingerprint,
        before_artifact_build_variant_fingerprint: before_variant.fingerprint.as_bytes(),
        after_artifact_fingerprint: after.fingerprint.as_bytes(),
        after_artifact_build_variant_fingerprint: after_variant.fingerprint.as_bytes(),
        estimated_refactor_savings_bytes: estimate.estimated_refactor_savings_bytes,
        verified_savings_bytes: verified,
        absolute_error_bytes: absolute_error,
        relative_error,
        recorded_at: crate::scan::rfc3339_now(),
    };
    store.record_artifact_savings_calibration(&calibration)?;
    Ok(Some(CalibrationReport {
        source_run,
        clone_group_fingerprint: clone_group.to_owned(),
        estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(
            calibration.estimated_refactor_savings_bytes,
        ),
        verified_savings_bytes: VerifiedSavingsBytes(verified),
        absolute_error_bytes: absolute_error,
        relative_error,
    }))
}

/// Load a user-supplied build description without running anything from it.
fn read_build_variant(path: Option<&std::path::Path>) -> Result<Option<BuildVariantEvidence>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes =
        fs::read(path).with_context(|| format!("reading build variant {}", path.display()))?;
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

fn inspect(
    path: &std::path::Path,
    max_bytes: u64,
    required_format: Option<ArtifactInputFormat>,
    debug_file: Option<&std::path::Path>,
    architecture: Option<&str>,
) -> Result<ArtifactIr> {
    let bytes = read_artifact_input(path, max_bytes, "artifact")?;
    let (debug_companion, automatically_discovered) = match debug_file {
        Some(path) => (
            Some(read_artifact_input(
                path,
                max_bytes,
                "external debug companion",
            )?),
            None,
        ),
        None => match discover_macho_dsym(path, &bytes, max_bytes) {
            Some(companion) => (Some(companion.bytes), Some(companion.path)),
            None => (None, None),
        },
    };
    match parse_input_format(
        &bytes,
        required_format,
        debug_companion.as_deref(),
        architecture,
    ) {
        Ok(artifact) => Ok(artifact),
        Err(error) if let Some(path) = automatically_discovered => {
            // An automatically discovered bundle is optional evidence. Its
            // malformed bytes or a stale UUID must not make a valid artifact
            // unanalyzable; an explicitly supplied companion remains strict.
            let artifact = parse_input_format(&bytes, required_format, None, architecture)?;
            eprintln!(
                "warning: automatically discovered dSYM {} was ignored: {error}",
                path.display()
            );
            Ok(artifact)
        }
        Err(error) => Err(error),
    }
}

/// One conventional dSYM companion discovered next to a Mach-O artifact.
struct DiscoveredDsym {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
}

/// Read the conventional sibling dSYM image only when it stays within the
/// configured input limit. This performs no directory traversal: a Mach-O
/// artifact named `app` maps to exactly `app.dSYM/Contents/Resources/DWARF/app`.
fn discover_macho_dsym(path: &FilePath, artifact: &[u8], max_bytes: u64) -> Option<DiscoveredDsym> {
    if detect_format(artifact) != Some(BinaryFormat::MachO) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let candidate = path
        .with_file_name(format!("{name}.dSYM"))
        .join("Contents/Resources/DWARF")
        .join(name);
    read_artifact_input(&candidate, max_bytes, "automatically discovered dSYM")
        .ok()
        .map(|bytes| DiscoveredDsym {
            path: candidate,
            bytes,
        })
}

/// Read one regular artifact-side input under the same explicit size ceiling.
///
/// The byte count comes from the read itself, rather than filesystem metadata:
/// special files can report a misleading or zero length. Reading one extra
/// byte bounds memory before reporting an oversized regular file.
fn read_artifact_input(path: &std::path::Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("opening {label} {}", path.display()))?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!(
            "{label} {} exceeds the configured maximum of {max_bytes} bytes",
            path.display(),
        );
    }
    Ok(bytes)
}

/// Resolve source maps declared by a WASM artifact without ever fetching a URI.
///
/// Only a relative reference that resolves inside the artifact's directory is
/// read. The source map's source contents are deliberately neither loaded nor
/// included in the report.
fn resolve_wasm_source_maps(
    artifact_path: &FilePath,
    artifact: &ArtifactIr,
    max_bytes: u64,
) -> Vec<SourceMapResolution> {
    if artifact.format != BinaryFormat::Wasm {
        return Vec::new();
    }
    artifact
        .source_mappings
        .iter()
        .map(|mapping| resolve_wasm_source_map(artifact_path, &mapping.uri, max_bytes))
        .collect()
}

fn resolve_wasm_source_map(
    artifact_path: &FilePath,
    uri: &str,
    max_bytes: u64,
) -> SourceMapResolution {
    let unavailable = |reason| SourceMapResolution {
        uri: uri.to_owned(),
        status: SourceMapResolutionStatus::Unavailable { reason },
    };
    if uri.starts_with("data:")
        || uri.starts_with("//")
        || uri.contains("://")
        || FilePath::new(uri).is_absolute()
    {
        return unavailable("non_local_reference");
    }
    let Some(parent) = artifact_path.parent() else {
        return unavailable("artifact_parent_unavailable");
    };
    let Ok(root) = parent.canonicalize() else {
        return unavailable("artifact_parent_unavailable");
    };
    let Ok(path) = parent.join(uri).canonicalize() else {
        return unavailable("map_not_found");
    };
    if !path.starts_with(&root) {
        return unavailable("outside_artifact_directory");
    }
    let Ok(metadata) = fs::metadata(&path) else {
        return unavailable("map_not_readable");
    };
    if !metadata.is_file() {
        return unavailable("map_not_readable");
    }
    if metadata.len() > max_bytes {
        return unavailable("map_exceeds_size_limit");
    }
    let Ok(bytes) = read_artifact_input(&path, max_bytes, "source map") else {
        return unavailable("map_not_readable");
    };
    match sourcemap::decode_slice(&bytes) {
        Ok(sourcemap::DecodedMap::Regular(map)) => {
            let sources = map
                .sources()
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let locations = map
                .tokens()
                .filter(|token| token.get_dst_line() == 0)
                .filter_map(|token| {
                    token.get_source().map(|source_url| SourceMapLocation {
                        generated_offset: u64::from(token.get_dst_col()),
                        source_url: source_url.to_owned(),
                        source_line: token.get_src_line().checked_add(1),
                    })
                })
                .collect();
            SourceMapResolution {
                uri: uri.to_owned(),
                status: SourceMapResolutionStatus::Resolved {
                    local_path: path.display().to_string(),
                    sources,
                    locations,
                },
            }
        }
        Ok(_) => unavailable("unsupported_source_map_kind"),
        Err(_) => unavailable("invalid_source_map"),
    }
}

fn source_map_locations(source_maps: &[SourceMapResolution]) -> Vec<SourceMapLocation> {
    source_maps
        .iter()
        .flat_map(|resolution| match &resolution.status {
            SourceMapResolutionStatus::Resolved { locations, .. } => locations.iter(),
            SourceMapResolutionStatus::Unavailable { .. } => [].iter(),
        })
        .cloned()
        .collect()
}

fn parse_input_format(
    bytes: &[u8],
    required_format: Option<ArtifactInputFormat>,
    debug_companion: Option<&[u8]>,
    architecture: Option<&str>,
) -> Result<ArtifactIr> {
    let detected = detect_format(bytes).ok_or_else(|| {
        anyhow::anyhow!("could not recognise input as a supported artifact format")
    })?;
    let format = required_format.map_or(detected, input_format);
    if format != detected {
        bail!("detected input format {detected} conflicts with requested input format {format}");
    }
    parse(format, bytes, debug_companion, architecture)
}

const fn input_format(format: ArtifactInputFormat) -> BinaryFormat {
    match format {
        ArtifactInputFormat::Wasm => BinaryFormat::Wasm,
        ArtifactInputFormat::Elf => BinaryFormat::Elf,
        ArtifactInputFormat::MachO => BinaryFormat::MachO,
        ArtifactInputFormat::Archive => BinaryFormat::Archive,
        ArtifactInputFormat::PeCoff => BinaryFormat::PeCoff,
    }
}

fn parse(
    format: BinaryFormat,
    bytes: &[u8],
    debug_companion: Option<&[u8]>,
    architecture: Option<&str>,
) -> Result<ArtifactIr> {
    if architecture.is_some() && format != BinaryFormat::MachO {
        bail!("--arch is only supported for Mach-O artifacts");
    }
    match format {
        BinaryFormat::Wasm => {
            if debug_companion.is_some() {
                bail!("--debug-file is only supported for ELF, Mach-O, and PE artifacts");
            }
            WasmBackend.parse(bytes).map_err(Into::into)
        }
        BinaryFormat::Elf => ElfBackend
            .parse_with_debug_companion(bytes, debug_companion)
            .map_err(Into::into),
        BinaryFormat::MachO => MachOBackend
            .parse_with_architecture(bytes, debug_companion, architecture)
            .map_err(Into::into),
        BinaryFormat::PeCoff => PeCoffBackend
            .parse_with_pdb(bytes, debug_companion)
            .map_err(Into::into),
        BinaryFormat::Archive => {
            if debug_companion.is_some() {
                bail!("--debug-file is not supported for archive artifacts");
            }
            ArchiveBackend.parse(bytes).map_err(Into::into)
        }
    }
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
