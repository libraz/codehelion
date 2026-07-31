//! Compiled-artifact command wiring and report rendering.
//!
//! This module is intentionally above the source clone engine. It dispatches
//! a format-specific backend over bytes read from a named file and never
//! loads, instantiates, or otherwise executes the inspected artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::Path as FilePath;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use codehelion_artifact::{
    ArtifactBackend, ArtifactFormat as BinaryFormat, ArtifactIr, detect_format, metrics,
    metrics::EvidenceConfidence,
};
use codehelion_artifact_archive::ArchiveBackend;
use codehelion_artifact_elf::ElfBackend;
use codehelion_artifact_macho::MachOBackend;
use codehelion_artifact_pe::PeCoffBackend;
use codehelion_artifact_wasm::WasmBackend;
use codehelion_store::Store;
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisMapping, ArtifactAnalysisSavingsCalibration,
    ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSnapshot, ArtifactAnalysisSourceKind,
    ArtifactAnalysisSymbol, ArtifactAnalysisUnmappedReason, ArtifactAnalysisUnmappedSource,
    ArtifactAnalysisUnmappedSourceReason, ArtifactAnalysisUnmappedSymbol,
    ArtifactSavingsCalibrationStatistics, MappingEvidence, MappingEvidenceFact,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION, artifact_savings_calibration_statistics,
};
use codehelion_store::query::{
    SourceFragmentIdentity, SourceInstantiation, SourceResolvedCall, SourceResolvedSymbol,
    SourceUnitIdentity,
};
use serde::{Deserialize, Serialize};

use crate::Outcome;
use crate::cli::{
    ArtifactArgs, ArtifactCalibrationArgs, ArtifactCompareArgs, ArtifactFormat,
    ArtifactInputFormat, ArtifactIsolatedArgs,
};

/// JSON schema emitted by the artifact command.
pub const ARTIFACT_REPORT_SCHEMA_VERSION: &str = "artifact-report-v1";

/// JSON Schema for the versioned artifact-analysis report.
pub const ARTIFACT_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-report-v1.schema.json");

/// JSON Schema for the versioned calibration summary report.
pub const ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA: &str =
    include_str!("../schema/artifact-calibration-report-v1.schema.json");

/// JSON report schema emitted by artifact calibration.
const ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION: &str = "artifact-calibration-report-v1";

/// Number of fields in every artifact CSV record.
const ARTIFACT_CSV_COLUMNS: usize = 22;

/// Largest accepted local linker-map input.
const MAX_LINKER_MAP_BYTES: u64 = 64 * 1024 * 1024;

/// The exact request one parent sends to its private worker.
#[derive(Debug, Serialize, Deserialize)]
enum IsolatedArtifactRequest {
    Analyze(ArtifactArgs),
    Compare(ArtifactCompareArgs),
}

impl IsolatedArtifactRequest {
    fn set_output(&mut self, path: std::path::PathBuf) {
        match self {
            Self::Analyze(args) => args.output = Some(path),
            Self::Compare(args) => args.output = Some(path),
        }
    }
}

/// Inspect one artifact and render its observed facts and equality groups.
///
/// # Errors
///
/// Returns an error if the file cannot be read, its format is unknown or not
/// implemented, its parser rejects the bytes, or an output file cannot be
/// written. No error path executes the inspected input.
pub fn run(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    run_isolated(args, out)
}

/// Execute an artifact request in a separate process and relay its report.
///
/// The parser and its allocations live only in the worker. The parent owns the
/// wall-clock deadline and kills the worker if it expires, rather than leaving
/// an untrusted malformed input able to hold the CLI open indefinitely.
fn run_isolated(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    run_isolated_request(
        IsolatedArtifactRequest::Analyze(args.clone()),
        args.timeout_seconds,
        args.output.as_deref(),
        out,
    )
}

/// Run either public artifact operation under one worker deadline.
#[allow(clippy::disallowed_types)] // Artifact parsing, unlike source scanning, is intentionally isolated in a worker.
fn run_isolated_request(
    mut request: IsolatedArtifactRequest,
    timeout_seconds: u64,
    output: Option<&FilePath>,
    out: &mut impl Write,
) -> Result<Outcome> {
    let request_path = tempfile::NamedTempFile::new()
        .context("creating artifact worker request")?
        .into_temp_path();
    let report_path = tempfile::NamedTempFile::new()
        .context("creating artifact worker report")?
        .into_temp_path();
    request.set_output(report_path.to_path_buf());
    fs::write(&request_path, serde_json::to_vec(&request)?)
        .context("writing artifact worker request")?;

    let executable = std::env::current_exe().context("locating artifact worker executable")?;
    let mut child = std::process::Command::new(executable)
        .args([
            "artifact",
            "isolated",
            "--request",
            request_path
                .to_str()
                .context("encoding artifact worker request path")?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting isolated artifact worker")?;
    let status = wait_for_worker(&mut child, Duration::from_secs(timeout_seconds))?;
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .context("reading isolated artifact worker diagnostics")?;
    }
    if !status.success() {
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!("isolated artifact worker exited with {status}");
        }
        bail!("isolated artifact worker failed: {detail}");
    }
    let rendered = fs::read(&report_path).context("reading isolated artifact worker report")?;
    if let Some(path) = output {
        fs::write(path, &rendered).with_context(|| format!("writing {}", path.display()))?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

/// Run the request sent by [`run_isolated`] without starting another worker.
///
/// # Errors
///
/// Returns an error for a malformed private request or any error the normal
/// local-only artifact analysis reports.
pub fn run_isolated_worker(args: &ArtifactIsolatedArgs) -> Result<Outcome> {
    let request: IsolatedArtifactRequest =
        serde_json::from_slice(&fs::read(&args.request).with_context(|| {
            format!("reading artifact worker request {}", args.request.display())
        })?)
        .context("parsing artifact worker request")?;
    let output = match &request {
        IsolatedArtifactRequest::Analyze(args) => args.output.as_ref(),
        IsolatedArtifactRequest::Compare(args) => args.output.as_ref(),
    };
    if output.is_none() {
        bail!("artifact worker request must name a private output file");
    }
    enforce_memory_limit(match &request {
        IsolatedArtifactRequest::Analyze(args) => args.max_memory_bytes,
        IsolatedArtifactRequest::Compare(args) => args.max_memory_bytes,
    })?;
    match request {
        IsolatedArtifactRequest::Analyze(args) => run_direct(&args, &mut std::io::sink()),
        IsolatedArtifactRequest::Compare(args) => compare_direct(&args, &mut std::io::sink()),
    }
}

/// Install the caller's required OS memory ceiling before an artifact parser
/// reads untrusted bytes.
fn enforce_memory_limit(max_memory_bytes: Option<u64>) -> Result<()> {
    let Some(max_memory_bytes) = max_memory_bytes else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{Resource, rlim_t, setrlimit};

        let limit = rlim_t::try_from(max_memory_bytes)
            .context("converting artifact worker memory limit for this platform")?;
        setrlimit(Resource::RLIMIT_AS, limit, limit).with_context(|| {
            format!("enforcing artifact worker memory limit of {max_memory_bytes} bytes")
        })?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!(
            "cannot enforce the requested artifact worker memory limit of {max_memory_bytes} bytes on this platform"
        );
    }
}

/// Wait for an isolated worker, forcefully terminating it after `timeout`.
fn wait_for_worker(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("waiting for isolated artifact worker")?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .context("terminating timed-out artifact worker")?;
            let _ = child.wait().context("reaping timed-out artifact worker")?;
            bail!(
                "artifact analysis exceeded the configured timeout of {}s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Run the artifact pipeline in the already isolated worker process.
fn run_direct(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    let started_at = crate::scan::rfc3339_now();
    let artifact = inspect(
        &args.path,
        args.max_bytes,
        args.input_format,
        args.debug_file.as_deref(),
    )?;
    let source_maps = resolve_wasm_source_maps(&args.path, &artifact, args.max_bytes);
    let finished_at = crate::scan::rfc3339_now();
    let build_variant = read_build_variant(args.build_variant.as_deref())?;
    let (analysis_id, correlation) = record(
        &artifact,
        args,
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
    .with_source_maps(source_maps)
    .with_correlation(correlation);
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_text(&report, args.verbose, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        fs::write(path, &rendered).with_context(|| format!("writing {}", path.display()))?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

/// Summarize controlled before/after calibration measurements for one run.
///
/// # Errors
///
/// Returns database and output errors. This command only reads recorded local
/// measurements; it never opens or executes an artifact.
pub fn calibration(args: &ArtifactCalibrationArgs, out: &mut impl Write) -> Result<Outcome> {
    let db = crate::resolve_db(args.db.as_deref())?;
    let store = Store::open(&db)
        .with_context(|| format!("opening calibration database {}", db.display()))?;
    let measurements = store.artifact_savings_calibrations_for_run(args.source_run)?;
    let mut report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: args.source_run,
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
        fs::write(path, &rendered).with_context(|| format!("writing {}", path.display()))?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
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

fn calibration_comparison(
    current: &CalibrationSummaryReport,
    baseline_path: &FilePath,
) -> Result<CalibrationComparisonReport> {
    let bytes = fs::read(baseline_path)
        .with_context(|| format!("reading calibration baseline {}", baseline_path.display()))?;
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
                measurement.before_artifact_build_variant_fingerprint,
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

fn record(
    artifact: &ArtifactIr,
    args: &ArtifactArgs,
    build_variant: Option<&BuildVariantEvidence>,
    started_at: &str,
    finished_at: &str,
) -> Result<(i64, Option<ArtifactCorrelationReport>)> {
    let db = crate::resolve_db(args.db.as_deref())?;
    if let Some(parent) = db.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
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
    let mut store = Store::open(&db)?;
    let linker_map = read_linker_map(args.linker_map.as_deref())?;
    let correlation = correlate_source_run(
        artifact,
        args.source_run,
        build_variant,
        &linker_map,
        &store,
    )?;
    let ir_json = serde_json::to_string(artifact).context("serializing artifact IR for SQLite")?;
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

/// Mapping rows established by one explicit source-run correlation request.
#[derive(Debug, Clone, PartialEq, Default)]
struct CorrelationRows {
    mappings: Vec<ArtifactAnalysisMapping>,
    unmapped_symbols: Vec<ArtifactAnalysisUnmappedSymbol>,
    unmapped_sources: Vec<ArtifactAnalysisUnmappedSource>,
    clone_fragments: Vec<SourceFragmentIdentity>,
}

/// Correlation outcome for an explicit source scan.
#[derive(Debug, Clone, Serialize)]
struct ArtifactCorrelationReport {
    source_run: i64,
    mappings: usize,
    artifact_symbols: usize,
    mapped_symbols: usize,
    mapping_coverage: f64,
    mapped_symbol_bytes: u64,
    mapped_symbol_bytes_ratio: f64,
    unmapped_symbols: usize,
    unmapped_symbol_bytes: u64,
    unmapped_symbol_reasons: BTreeMap<String, usize>,
    source_entities: usize,
    unmapped_sources: usize,
    unmapped_source_reasons: BTreeMap<String, usize>,
    clone_group_attributions: Vec<CloneGroupAttributionReport>,
    estimated_refactor_savings: Vec<CloneGroupSavingsReport>,
    generic_origins: Vec<GenericOriginReport>,
    macro_origins: Vec<MacroOriginReport>,
}

/// Conservative observed bytes attributed to one source clone group.
#[derive(Debug, Clone, Serialize)]
struct CloneGroupAttributionReport {
    /// Content-derived stable clone-group identity.
    clone_group_fingerprint: String,
    /// Build variant that minted the group's member fingerprints.
    source_build_variant_fingerprint: String,
    /// Members recorded for the group under this variant.
    members: usize,
    /// Noncanonical members with at least one exact, unambiguous byte split.
    attributed_noncanonical_members: usize,
    /// Observed bytes attributable to all noncanonical members, when complete.
    ///
    /// This is an attribution observation, not an estimated refactoring saving.
    duplicated_bytes: Option<u64>,
    /// Source clone score kept separate from mapping and model confidence.
    clone_confidence: f64,
}

/// Versioned, deliberately conservative refactoring-cost assumptions.
#[derive(Debug, Clone, Serialize)]
struct RefactorSavingsModel {
    schema_version: &'static str,
    retained_copies: u64,
    call_overhead_per_replaced_member_bytes: i64,
    assumptions: Vec<RefactorSavingsAssumption>,
    confidence: EvidenceConfidence,
}

/// One versioned model row. Keeping the coefficients here makes changing a
/// model an explicit data/version change instead of a hidden arithmetic edit.
#[derive(Debug, Clone, Copy)]
struct RefactorSavingsModelSpec {
    schema_version: &'static str,
    retained_copies: u64,
    call_overhead_per_replaced_member_bytes: i64,
    assumptions: &'static [RefactorSavingsAssumptionSpec],
    confidence: EvidenceConfidence,
}

/// Serializable assumptions have a compact static-table counterpart.
#[derive(Debug, Clone, Copy)]
enum RefactorSavingsAssumptionSpec {
    SharedImplementationRetainsCopies { copies: u64 },
    CallOverheadPerReplacedMember { bytes: i64 },
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
}

const REFACTOR_SAVINGS_MODELS: &[RefactorSavingsModelSpec] = &[RefactorSavingsModelSpec {
    schema_version: "refactor-savings-model-v1",
    retained_copies: 1,
    call_overhead_per_replaced_member_bytes: 0,
    assumptions: &[
        RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies: 1 },
        RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember { bytes: 0 },
        RefactorSavingsAssumptionSpec::InliningOutcomeUnknown,
        RefactorSavingsAssumptionSpec::LinkerIcfOutcomeUnknown,
    ],
    confidence: EvidenceConfidence::Low,
}];

/// A machine-readable condition behind one refactoring estimate.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RefactorSavingsAssumption {
    SharedImplementationRetainsCopies { copies: u64 },
    CallOverheadPerReplacedMember { bytes: i64 },
    InliningOutcomeUnknown,
    LinkerIcfOutcomeUnknown,
}

/// A source/artifact-correlated refactoring estimate for one clone group.
#[derive(Debug, Clone, Serialize)]
struct CloneGroupSavingsReport {
    clone_group_fingerprint: String,
    source_build_variant_fingerprint: String,
    artifact_build_variant_fingerprint: String,
    duplicated_bytes: u64,
    estimated_refactor_savings_bytes: i64,
    mapping_confidence: EvidenceConfidence,
    clone_confidence: f64,
    model_confidence: EvidenceConfidence,
    savings_confidence: EvidenceConfidence,
    assumptions: Vec<RefactorSavingsAssumption>,
    model_schema_version: &'static str,
}

fn stored_clone_group_savings(
    source_scan_run_id: i64,
    estimates: &[CloneGroupSavingsReport],
) -> Result<Vec<ArtifactAnalysisCloneGroupSavings>> {
    estimates
        .iter()
        .map(|estimate| {
            let clone_group_fingerprint = hex_fingerprint(&estimate.clone_group_fingerprint)
                .context("encoding clone-group savings fingerprint")?;
            let source_build_variant_fingerprint =
                hex_fingerprint(&estimate.source_build_variant_fingerprint)
                    .context("encoding source savings build variant")?;
            let artifact_build_variant_fingerprint =
                hex_fingerprint(&estimate.artifact_build_variant_fingerprint)
                    .context("encoding artifact savings build variant")?;
            Ok(ArtifactAnalysisCloneGroupSavings {
                schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_owned(),
                source_scan_run_id,
                clone_group_fingerprint,
                source_build_variant_fingerprint,
                artifact_build_variant_fingerprint,
                duplicated_bytes: estimate.duplicated_bytes,
                estimated_refactor_savings_bytes: estimate.estimated_refactor_savings_bytes,
                mapping_confidence: stored_savings_confidence(estimate.mapping_confidence),
                clone_confidence: estimate.clone_confidence,
                model_confidence: stored_savings_confidence(estimate.model_confidence),
                savings_confidence: stored_savings_confidence(estimate.savings_confidence),
                model_schema_version: estimate.model_schema_version.to_owned(),
                assumptions_json: serde_json::to_string(&estimate.assumptions)
                    .context("serializing structured savings assumptions")?,
            })
        })
        .collect()
}

const fn stored_savings_confidence(
    confidence: EvidenceConfidence,
) -> ArtifactAnalysisSavingsConfidence {
    match confidence {
        EvidenceConfidence::High => ArtifactAnalysisSavingsConfidence::High,
        EvidenceConfidence::Medium => ArtifactAnalysisSavingsConfidence::Medium,
        EvidenceConfidence::Low => ArtifactAnalysisSavingsConfidence::Low,
        EvidenceConfidence::Unavailable => ArtifactAnalysisSavingsConfidence::Unavailable,
    }
}

/// Observed artifact symbols attributed to one generic definition origin.
#[derive(Debug, Clone, Serialize)]
struct GenericOriginReport {
    /// Compiler-confirmed definition spelling that distinguishes origins with
    /// otherwise identical source content.
    definition: String,
    /// Content-derived source unit identity of the generic definition.
    origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    origin_build_variant_fingerprint: String,
    /// Number of distinct compiler instantiation keys observed for this origin.
    instantiations: usize,
    /// Number of translation units that independently observed the origin.
    translation_units: usize,
    /// Number of distinct artifact symbols mapped to this origin.
    artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    observed_symbol_bytes: u64,
    /// Excess observed bytes in equal normalized instruction groups for this origin.
    ///
    /// This is a duplicate observation, not a claimed refactoring saving.
    normalized_instruction_duplicated_bytes: u64,
    /// Sum of per-symbol retained sizes when the call graph supports them.
    ///
    /// Retained regions overlap, so this value must not be treated as a total.
    retained_size_sum: Option<u64>,
    /// Observed artifact size split by exact compiler-reported specialization.
    specializations: Vec<GenericSpecializationReport>,
}

/// Observed artifact symbols attributed to one declarative macro definition.
#[derive(Debug, Clone, Serialize)]
struct MacroOriginReport {
    /// Content-derived identity of the source unit containing the macro body.
    origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    origin_build_variant_fingerprint: String,
    /// Macro definition paths retained as auditable evidence.
    definition_paths: Vec<String>,
    /// Number of distinct artifact symbols attributed to this macro body.
    artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    observed_symbol_bytes: u64,
}

/// One exact generic specialization contributing to an origin's artifact size.
#[derive(Debug, Clone, Serialize)]
struct GenericSpecializationReport {
    /// Versioned compiler-reported instantiation key.
    instantiation_key: String,
    /// Top-level type or value arguments parsed from the exact key.
    type_arguments: Vec<String>,
    /// Number of distinct artifact symbols attributed to this specialization.
    artifact_symbols: usize,
    /// Number of translation units that reported this specialization.
    translation_units: usize,
    /// Sum of observed sizes of those symbols.
    observed_symbol_bytes: u64,
}

/// Compiler observations accumulated for one exact specialization.
#[derive(Debug, Default)]
struct GenericSpecializationAggregate {
    symbols: BTreeSet<[u8; 16]>,
    translation_units: BTreeSet<String>,
}

impl ArtifactCorrelationReport {
    #[allow(clippy::too_many_lines)] // The serialized correlation schema is assembled in one place.
    fn from_rows(source_run: i64, artifact: &ArtifactIr, rows: &CorrelationRows) -> Self {
        let mapped_fingerprints = rows
            .mappings
            .iter()
            .map(|mapping| mapping.artifact_symbol_fingerprint)
            .collect::<BTreeSet<_>>();
        let artifact_symbols = artifact.symbols.len();
        let total_symbol_bytes = artifact
            .symbols
            .iter()
            .map(|symbol| symbol.size)
            .sum::<u64>();
        let mapped_symbols = artifact
            .symbols
            .iter()
            .filter(|symbol| mapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .count();
        let mapped_symbol_bytes = artifact
            .symbols
            .iter()
            .filter(|symbol| mapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .map(|symbol| symbol.size)
            .sum::<u64>();
        let unmapped_fingerprints = rows
            .unmapped_symbols
            .iter()
            .map(|unmapped| unmapped.artifact_symbol_fingerprint)
            .collect::<BTreeSet<_>>();
        let unmapped_symbol_bytes = artifact
            .symbols
            .iter()
            .filter(|symbol| unmapped_fingerprints.contains(&symbol.fingerprint.as_bytes()))
            .map(|symbol| symbol.size)
            .sum::<u64>();
        let mut unmapped_symbol_reasons = BTreeMap::new();
        for unmapped in &rows.unmapped_symbols {
            *unmapped_symbol_reasons
                .entry(unmapped_reason_label(unmapped.reason).to_owned())
                .or_default() += 1;
        }
        let source_entities = rows
            .mappings
            .iter()
            .map(|mapping| {
                (
                    source_kind_order(mapping.source_kind),
                    mapping.source_fingerprint,
                    mapping.source_instance_fingerprint,
                    mapping.source_build_variant_fingerprint,
                )
            })
            .chain(rows.unmapped_sources.iter().map(|source| {
                (
                    source_kind_order(source.source_kind),
                    source.source_fingerprint,
                    source.source_instance_fingerprint,
                    source.source_build_variant_fingerprint,
                )
            }))
            .collect::<BTreeSet<_>>()
            .len();
        let mut unmapped_source_reasons = BTreeMap::new();
        for source in &rows.unmapped_sources {
            *unmapped_source_reasons
                .entry(unmapped_source_reason_label(source.reason).to_owned())
                .or_default() += 1;
        }
        let mut generic_origins: BTreeMap<_, BTreeMap<String, GenericSpecializationAggregate>> =
            BTreeMap::new();
        for mapping in &rows.mappings {
            if mapping.source_kind != ArtifactAnalysisSourceKind::Unit {
                continue;
            }
            let keys = mapping.evidence.facts.iter().filter_map(|fact| match fact {
                MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units,
                } => Some((
                    definition.clone(),
                    instantiation_key.clone(),
                    translation_units,
                )),
                _ => None,
            });
            for (definition, key, translation_units) in keys {
                let entry = generic_origins
                    .entry((
                        mapping.source_fingerprint,
                        mapping.source_build_variant_fingerprint,
                        definition,
                    ))
                    .or_default();
                let specialization = entry.entry(key).or_default();
                specialization
                    .symbols
                    .insert(mapping.artifact_symbol_fingerprint);
                specialization
                    .translation_units
                    .extend(translation_units.iter().cloned());
            }
        }
        let mut generic_origins: Vec<_> = generic_origins
            .into_iter()
            .map(|((origin, variant, definition), specializations)| {
                let symbols = specializations
                    .values()
                    .flat_map(|specialization| specialization.symbols.iter().copied())
                    .collect::<BTreeSet<_>>();
                let translation_units = specializations
                    .values()
                    .flat_map(|specialization| specialization.translation_units.iter().cloned())
                    .collect::<BTreeSet<_>>();
                let (
                    observed_symbol_bytes,
                    normalized_instruction_duplicated_bytes,
                    retained_size_sum,
                ) = generic_origin_metrics(artifact, &symbols);
                let mut specializations: Vec<_> = specializations
                    .into_iter()
                    .map(
                        |(instantiation_key, aggregate)| GenericSpecializationReport {
                            type_arguments: generic_type_arguments(&instantiation_key),
                            observed_symbol_bytes: observed_symbol_bytes_for(
                                artifact,
                                &aggregate.symbols,
                            ),
                            artifact_symbols: aggregate.symbols.len(),
                            translation_units: aggregate.translation_units.len(),
                            instantiation_key,
                        },
                    )
                    .collect();
                specializations.sort_by(|left, right| {
                    right
                        .observed_symbol_bytes
                        .cmp(&left.observed_symbol_bytes)
                        .then_with(|| left.instantiation_key.cmp(&right.instantiation_key))
                });
                let origin_fingerprint =
                    fingerprint_hex(generic_origin_fingerprint(origin, &definition));
                GenericOriginReport {
                    definition,
                    origin_fingerprint,
                    origin_build_variant_fingerprint: fingerprint_hex(variant),
                    instantiations: specializations.len(),
                    translation_units: translation_units.len(),
                    artifact_symbols: symbols.len(),
                    observed_symbol_bytes,
                    normalized_instruction_duplicated_bytes,
                    retained_size_sum,
                    specializations,
                }
            })
            .collect();
        generic_origins.sort_by(|left, right| {
            right
                .observed_symbol_bytes
                .cmp(&left.observed_symbol_bytes)
                .then_with(|| left.origin_fingerprint.cmp(&right.origin_fingerprint))
                .then_with(|| {
                    left.origin_build_variant_fingerprint
                        .cmp(&right.origin_build_variant_fingerprint)
                })
                .then_with(|| left.definition.cmp(&right.definition))
        });
        let mut macro_origins: BTreeMap<_, (BTreeSet<String>, BTreeSet<[u8; 16]>)> =
            BTreeMap::new();
        for mapping in &rows.mappings {
            if mapping.source_kind != ArtifactAnalysisSourceKind::Unit {
                continue;
            }
            for definition_path in mapping.evidence.facts.iter().filter_map(|fact| match fact {
                MappingEvidenceFact::MacroOrigin { definition_path } => Some(definition_path),
                _ => None,
            }) {
                let entry = macro_origins
                    .entry((
                        mapping.source_fingerprint,
                        mapping.source_build_variant_fingerprint,
                    ))
                    .or_default();
                entry.0.insert(definition_path.clone());
                entry.1.insert(mapping.artifact_symbol_fingerprint);
            }
        }
        let mut macro_origins: Vec<_> = macro_origins
            .into_iter()
            .map(
                |((origin, variant), (definition_paths, symbols))| MacroOriginReport {
                    origin_fingerprint: fingerprint_hex(origin),
                    origin_build_variant_fingerprint: fingerprint_hex(variant),
                    definition_paths: definition_paths.into_iter().collect(),
                    artifact_symbols: symbols.len(),
                    observed_symbol_bytes: observed_symbol_bytes_for(artifact, &symbols),
                },
            )
            .collect();
        macro_origins.sort_by(|left, right| {
            right
                .observed_symbol_bytes
                .cmp(&left.observed_symbol_bytes)
                .then_with(|| left.origin_fingerprint.cmp(&right.origin_fingerprint))
        });
        Self {
            source_run,
            mappings: rows.mappings.len(),
            artifact_symbols,
            mapped_symbols,
            mapping_coverage: ratio(mapped_symbols, artifact_symbols),
            mapped_symbol_bytes,
            mapped_symbol_bytes_ratio: ratio_u64(mapped_symbol_bytes, total_symbol_bytes),
            unmapped_symbols: rows.unmapped_symbols.len(),
            unmapped_symbol_bytes,
            unmapped_symbol_reasons,
            source_entities,
            unmapped_sources: rows.unmapped_sources.len(),
            unmapped_source_reasons,
            clone_group_attributions: clone_group_attributions(rows),
            estimated_refactor_savings: clone_group_savings(rows),
            generic_origins,
            macro_origins,
        }
    }

    fn snapshot(&self, artifact: &ArtifactIr) -> ArtifactAnalysisCorrelation {
        ArtifactAnalysisCorrelation {
            schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
            source_scan_run_id: self.source_run,
            mapping_count: u64::try_from(self.mappings).unwrap_or(u64::MAX),
            artifact_symbol_count: u64::try_from(self.artifact_symbols).unwrap_or(u64::MAX),
            mapped_symbol_count: u64::try_from(self.mapped_symbols).unwrap_or(u64::MAX),
            artifact_symbol_bytes: artifact.symbols.iter().map(|symbol| symbol.size).sum(),
            mapped_symbol_bytes: self.mapped_symbol_bytes,
        }
    }
}

fn clone_group_attributions(rows: &CorrelationRows) -> Vec<CloneGroupAttributionReport> {
    let mut groups: BTreeMap<_, Vec<&SourceFragmentIdentity>> = BTreeMap::new();
    for fragment in &rows.clone_fragments {
        groups
            .entry((
                fragment.clone_group_fingerprint,
                fragment.build_variant_fingerprint,
            ))
            .or_default()
            .push(fragment);
    }
    groups
        .into_iter()
        .map(|((group_fingerprint, source_variant), members)| {
            let noncanonical = members
                .iter()
                .filter(|member| !member.is_canonical)
                .map(|member| member.finding_id)
                .collect::<BTreeSet<_>>();
            let mut bytes_by_member: BTreeMap<[u8; 16], u64> = BTreeMap::new();
            for mapping in &rows.mappings {
                if mapping.source_kind != ArtifactAnalysisSourceKind::Fragment
                    || mapping.source_build_variant_fingerprint != source_variant
                    || !noncanonical.contains(&mapping.source_instance_fingerprint)
                {
                    continue;
                }
                if let Some(bytes) = mapping.attributed_bytes {
                    let total = bytes_by_member
                        .entry(mapping.source_instance_fingerprint)
                        .or_default();
                    *total = total.saturating_add(bytes);
                }
            }
            let attributed_noncanonical_members = bytes_by_member.len();
            let duplicated_bytes = (attributed_noncanonical_members == noncanonical.len())
                .then(|| bytes_by_member.values().copied().sum());
            CloneGroupAttributionReport {
                clone_group_fingerprint: fingerprint_hex(group_fingerprint),
                source_build_variant_fingerprint: fingerprint_hex(source_variant),
                members: members.len(),
                attributed_noncanonical_members,
                duplicated_bytes,
                clone_confidence: members
                    .first()
                    .map_or(0.0, |member| member.clone_confidence),
            }
        })
        .collect()
}

fn refactor_savings_model() -> RefactorSavingsModel {
    let spec = REFACTOR_SAVINGS_MODELS
        .first()
        .copied()
        .unwrap_or(RefactorSavingsModelSpec {
            schema_version: "refactor-savings-model-unavailable",
            retained_copies: 0,
            call_overhead_per_replaced_member_bytes: 0,
            assumptions: &[],
            confidence: EvidenceConfidence::Unavailable,
        });
    RefactorSavingsModel {
        schema_version: spec.schema_version,
        retained_copies: spec.retained_copies,
        call_overhead_per_replaced_member_bytes: spec.call_overhead_per_replaced_member_bytes,
        assumptions: spec
            .assumptions
            .iter()
            .map(|assumption| match assumption {
                RefactorSavingsAssumptionSpec::SharedImplementationRetainsCopies { copies } => {
                    RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies: *copies }
                }
                RefactorSavingsAssumptionSpec::CallOverheadPerReplacedMember { bytes } => {
                    RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes: *bytes }
                }
                RefactorSavingsAssumptionSpec::InliningOutcomeUnknown => {
                    RefactorSavingsAssumption::InliningOutcomeUnknown
                }
                RefactorSavingsAssumptionSpec::LinkerIcfOutcomeUnknown => {
                    RefactorSavingsAssumption::LinkerIcfOutcomeUnknown
                }
            })
            .collect(),
        confidence: spec.confidence,
    }
}

fn clone_group_savings(rows: &CorrelationRows) -> Vec<CloneGroupSavingsReport> {
    let model = refactor_savings_model();
    clone_group_attributions(rows)
        .into_iter()
        .filter_map(|attribution| {
            let duplicated_bytes = attribution.duplicated_bytes?;
            let group_fingerprint = hex_fingerprint(&attribution.clone_group_fingerprint)?;
            let source_variant = hex_fingerprint(&attribution.source_build_variant_fingerprint)?;
            let members = rows
                .clone_fragments
                .iter()
                .filter(|fragment| {
                    fragment.clone_group_fingerprint == group_fingerprint
                        && fragment.build_variant_fingerprint == source_variant
                        && !fragment.is_canonical
                })
                .map(|fragment| fragment.finding_id)
                .collect::<BTreeSet<_>>();
            let artifact_variants = rows
                .mappings
                .iter()
                .filter(|mapping| {
                    mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
                        && mapping.source_build_variant_fingerprint == source_variant
                        && members.contains(&mapping.source_instance_fingerprint)
                        && mapping.attributed_bytes.is_some()
                })
                .map(|mapping| mapping.build_variant_fingerprint)
                .collect::<BTreeSet<_>>();
            let mut artifact_variants = artifact_variants.into_iter();
            let artifact_variant = artifact_variants.next()?;
            if artifact_variants.next().is_some() {
                return None;
            }
            let estimated_refactor_savings_bytes =
                estimate_refactor_savings_bytes(duplicated_bytes, members.len(), &model);
            Some(CloneGroupSavingsReport {
                clone_group_fingerprint: attribution.clone_group_fingerprint,
                source_build_variant_fingerprint: attribution.source_build_variant_fingerprint,
                artifact_build_variant_fingerprint: fingerprint_hex(artifact_variant),
                duplicated_bytes,
                estimated_refactor_savings_bytes,
                mapping_confidence: EvidenceConfidence::High,
                clone_confidence: attribution.clone_confidence,
                model_confidence: model.confidence,
                savings_confidence: model.confidence,
                assumptions: model.assumptions.clone(),
                model_schema_version: model.schema_version,
            })
        })
        .collect()
}

fn estimate_refactor_savings_bytes(
    duplicated_bytes: u64,
    replaced_members: usize,
    model: &RefactorSavingsModel,
) -> i64 {
    let replaced_members = i128::try_from(replaced_members).unwrap_or(i128::MAX);
    let estimate = i128::from(duplicated_bytes).saturating_sub(
        i128::from(model.call_overhead_per_replaced_member_bytes).saturating_mul(replaced_members),
    );
    match i64::try_from(estimate) {
        Ok(value) => value,
        Err(_) if estimate.is_negative() => i64::MIN,
        Err(_) => i64::MAX,
    }
}

fn hex_fingerprint(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn fingerprint_hex(fingerprint: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(fingerprint.len() * 2);
    for byte in fingerprint {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn generic_origin_metrics(
    artifact: &ArtifactIr,
    fingerprints: &BTreeSet<[u8; 16]>,
) -> (u64, u64, Option<u64>) {
    let symbols: Vec<_> = artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .collect();
    let observed_symbol_bytes = symbols
        .iter()
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add);
    let mut normalized_groups: BTreeMap<_, Vec<u64>> = BTreeMap::new();
    for symbol in &symbols {
        if let Some(normalized) = &symbol.normalized {
            normalized_groups
                .entry((normalized.version.clone(), normalized.bytes.clone()))
                .or_default()
                .push(symbol.size);
        }
    }
    let normalized_instruction_duplicated_bytes = normalized_groups
        .into_values()
        .filter(|sizes| sizes.len() > 1)
        .map(|sizes| {
            let total = sizes.iter().copied().fold(0_u64, u64::saturating_add);
            total.saturating_sub(sizes.into_iter().max().unwrap_or_default())
        })
        .fold(0_u64, u64::saturating_add);
    let retained_size_sum = metrics::retained_sizes(artifact).map(|sizes| {
        sizes
            .into_iter()
            .filter(|size| fingerprints.contains(&size.symbol.as_bytes()))
            .map(|size| size.retained_bytes)
            .fold(0_u64, u64::saturating_add)
    });
    (
        observed_symbol_bytes,
        normalized_instruction_duplicated_bytes,
        retained_size_sum,
    )
}

fn observed_symbol_bytes_for(artifact: &ArtifactIr, fingerprints: &BTreeSet<[u8; 16]>) -> u64 {
    artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add)
}

fn generic_type_arguments(instantiation_key: &str) -> Vec<String> {
    let Some(start) = instantiation_key.find('<') else {
        return Vec::new();
    };
    let Some(arguments) = instantiation_key
        .strip_suffix('>')
        .and_then(|key| key.get(start + 1..))
    else {
        return Vec::new();
    };
    let mut depth = 0_u32;
    let mut arguments_out = Vec::new();
    let mut argument_start = 0;
    for (index, character) in arguments.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return Vec::new(),
            },
            ',' if depth == 0 => {
                let argument = arguments[argument_start..index].trim();
                if argument.is_empty() {
                    return Vec::new();
                }
                arguments_out.push(argument.to_owned());
                argument_start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Vec::new();
    }
    let argument = arguments[argument_start..].trim();
    if argument.is_empty() {
        return Vec::new();
    }
    arguments_out.push(argument.to_owned());
    arguments_out
}

const fn unmapped_reason_label(reason: ArtifactAnalysisUnmappedReason) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedReason::DebugInfoMissing => "debug_info_missing",
        ArtifactAnalysisUnmappedReason::Stripped => "stripped",
        ArtifactAnalysisUnmappedReason::DemangleFailed => "demangle_failed",
        ArtifactAnalysisUnmappedReason::OutsideSourceScope => "outside_source_scope",
        ArtifactAnalysisUnmappedReason::EvidenceConflict => "evidence_conflict",
    }
}

const fn unmapped_source_reason_label(
    reason: ArtifactAnalysisUnmappedSourceReason,
) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence => "no_artifact_evidence",
        ArtifactAnalysisUnmappedSourceReason::DeadCode => "dead_code",
        ArtifactAnalysisUnmappedSourceReason::InlinedAway => "inlined_away",
        ArtifactAnalysisUnmappedSourceReason::LtoAbsorbed => "lto_absorbed",
        ArtifactAnalysisUnmappedSourceReason::NotCompiledForVariant => "not_compiled_for_variant",
        ArtifactAnalysisUnmappedSourceReason::EvidenceConflict => "evidence_conflict",
    }
}

const fn source_kind_order(kind: ArtifactAnalysisSourceKind) -> u8 {
    match kind {
        ArtifactAnalysisSourceKind::Unit => 0,
        ArtifactAnalysisSourceKind::Fragment => 1,
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    ratio_u64(
        u64::try_from(numerator).unwrap_or(u64::MAX),
        u64::try_from(denominator).unwrap_or(u64::MAX),
    )
}

fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
    ratio_u128(u128::from(numerator), u128::from(denominator))
}

fn ratio_u128(numerator: u128, denominator: u128) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        const BASIS_POINTS_PER_UNIT: u128 = 10_000;
        let basis_points = numerator
            .saturating_mul(BASIS_POINTS_PER_UNIT)
            .checked_div(denominator)
            .unwrap_or(BASIS_POINTS_PER_UNIT)
            .min(BASIS_POINTS_PER_UNIT);
        let basis_points = u32::try_from(basis_points).unwrap_or(10_000);
        f64::from(basis_points) / 10_000.0
    }
}

fn correlate_source_run(
    artifact: &ArtifactIr,
    source_run: Option<i64>,
    artifact_variant: Option<&BuildVariantEvidence>,
    linker_map: &[LinkerMapEntry],
    store: &Store,
) -> Result<CorrelationRows> {
    let Some(source_run) = source_run else {
        return Ok(CorrelationRows::default());
    };
    let artifact_variant = artifact_variant.ok_or_else(|| {
        anyhow::anyhow!("--source-run requires a build variant manifest for the artifact")
    })?;
    let origin = store
        .run_origin(source_run)
        .with_context(|| format!("loading source scan {source_run}"))?;
    let units = store
        .source_units(source_run)
        .with_context(|| format!("loading source units for scan {source_run}"))?;
    let fragments = store
        .source_clone_fragments(source_run)
        .with_context(|| format!("loading clone fragments for scan {source_run}"))?;
    let resolved_symbols = store
        .source_resolved_symbols(source_run)
        .with_context(|| format!("loading compiler symbols for scan {source_run}"))?;
    let instantiations = store
        .source_instantiations(source_run)
        .with_context(|| format!("loading compiler instantiations for scan {source_run}"))?;
    let resolved_calls = store
        .source_resolved_calls(source_run)
        .with_context(|| format!("loading compiler calls for scan {source_run}"))?;
    let mut rows = correlate_debug_locations(
        artifact,
        FilePath::new(&origin.root_path),
        &units,
        &fragments,
        &instantiations,
        &resolved_symbols,
        &resolved_calls,
        artifact_variant.fingerprint.as_bytes(),
    );
    enrich_linker_map_evidence(
        artifact,
        &units,
        linker_map,
        artifact_variant.fingerprint.as_bytes(),
        &mut rows,
    );
    Ok(rows)
}

/// One symbol-to-object placement recovered from a pre-existing linker map.
///
/// Linker addresses and map-line offsets deliberately do not leave this
/// boundary: the later correlation records only stable source and artifact
/// fingerprints plus this object-path evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LinkerMapEntry {
    symbol: String,
    object_path: String,
}

/// Read a bounded local linker map without invoking the linker that produced it.
fn read_linker_map(path: Option<&FilePath>) -> Result<Vec<LinkerMapEntry>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading metadata for linker map {}", path.display()))?;
    if metadata.len() > MAX_LINKER_MAP_BYTES {
        bail!(
            "linker map {} is {} bytes, exceeding the {} byte input limit",
            path.display(),
            metadata.len(),
            MAX_LINKER_MAP_BYTES
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading linker map {}", path.display()))?;
    Ok(parse_linker_map(&text))
}

/// Parse the symbol lines emitted by GNU-ld-compatible map files.
///
/// The parser intentionally accepts only a local object path paired with a
/// symbol. It does not infer a source identity from section addresses or a
/// linker-script expression.
fn parse_linker_map(text: &str) -> Vec<LinkerMapEntry> {
    let mut entries = BTreeSet::new();
    let mut current_object = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let object = fields
            .iter()
            .find_map(|field| linker_map_object_path(field));
        if let Some(object) = object {
            current_object = Some(object.clone());
            if let (Some(section), Some(symbol)) = (
                fields
                    .first()
                    .and_then(|field| field.strip_prefix(".text.")),
                current_object.as_ref(),
            ) {
                entries.insert(LinkerMapEntry {
                    symbol: section.to_owned(),
                    object_path: symbol.clone(),
                });
            }
        }
        let Some(object_path) = current_object.as_ref() else {
            continue;
        };
        let Some(address) = fields.first() else {
            continue;
        };
        let Some(symbol) = fields.get(1) else {
            continue;
        };
        if is_linker_address(address) && !is_linker_address(symbol) && !symbol.starts_with('.') {
            entries.insert(LinkerMapEntry {
                symbol: (*symbol).to_owned(),
                object_path: object_path.clone(),
            });
        }
    }
    entries.into_iter().collect()
}

fn linker_map_object_path(field: &str) -> Option<String> {
    let end = field.find(".o")?.checked_add(2)?;
    let path = field
        .get(..end)?
        .trim_matches(|character| matches!(character, '(' | ')'));
    (!path.is_empty()).then(|| path.to_owned())
}

fn is_linker_address(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_hexdigit())
    })
}

/// Add linker-map evidence to existing unit mappings or recover unmapped units.
///
/// A map object path must embed the scan-relative source path after removing
/// the final `.o` suffix, and the unit's declared name must agree with the
/// linker symbol. This covers conventional `CMake` and compiler output paths
/// without guessing from a basename. Equal candidates remain separate mappings
/// and therefore stay ambiguous.
#[allow(
    clippy::too_many_lines,
    reason = "linker-map candidates and existing mapping reconciliation share one evidence boundary"
)]
fn enrich_linker_map_evidence(
    artifact: &ArtifactIr,
    units: &[SourceUnitIdentity],
    entries: &[LinkerMapEntry],
    artifact_variant: [u8; 16],
    rows: &mut CorrelationRows,
) {
    for symbol in &artifact.symbols {
        let Some(symbol_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
            continue;
        };
        let mut candidates = BTreeMap::new();
        for entry in entries.iter().filter(|entry| {
            canonical_symbol_name(&entry.symbol).as_deref() == Some(symbol_name.as_str())
        }) {
            for unit in units.iter().filter(|unit| {
                linker_object_matches_source(&entry.object_path, &unit.file_path)
                    && unit
                        .name
                        .as_deref()
                        .and_then(canonical_symbol_name)
                        .as_deref()
                        == Some(symbol_name.as_str())
            }) {
                candidates
                    .entry((
                        unit.fingerprint,
                        source_unit_instance_fingerprint(unit),
                        unit.build_variant_fingerprint,
                    ))
                    .or_insert_with(|| (unit, entry.object_path.clone()));
            }
        }
        let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        if candidate_count == 0 {
            continue;
        }
        let candidate_keys: BTreeSet<_> = candidates.keys().copied().collect();
        let existing_indices: Vec<_> = rows
            .mappings
            .iter()
            .enumerate()
            .filter(|(_, mapping)| {
                mapping.artifact_symbol_fingerprint == symbol.fingerprint.as_bytes()
                    && mapping.source_kind == ArtifactAnalysisSourceKind::Unit
            })
            .map(|(index, _)| index)
            .collect();
        let existing_keys: BTreeSet<_> = existing_indices
            .iter()
            .map(|index| {
                let mapping = &rows.mappings[*index];
                (
                    mapping.source_fingerprint,
                    mapping.source_instance_fingerprint,
                    mapping.source_build_variant_fingerprint,
                )
            })
            .collect();
        let has_conflict = !existing_keys.is_empty() && existing_keys.is_disjoint(&candidate_keys);
        if has_conflict {
            for index in &existing_indices {
                rows.mappings[*index].evidence.has_conflict = true;
            }
        }
        for ((fingerprint, instance_fingerprint, build_variant_fingerprint), (unit, object_path)) in
            candidates
        {
            let existing = existing_indices.iter().copied().find(|index| {
                let mapping = &rows.mappings[*index];
                mapping.source_fingerprint == fingerprint
                    && mapping.source_instance_fingerprint == instance_fingerprint
                    && mapping.source_build_variant_fingerprint == build_variant_fingerprint
            });
            if let Some(index) = existing {
                let mapping = &mut rows.mappings[index];
                if !mapping.evidence.facts.iter().any(|fact| {
                    matches!(fact, MappingEvidenceFact::LinkerMap { object_path: existing } if existing == &object_path)
                }) {
                    mapping
                        .evidence
                        .facts
                        .push(MappingEvidenceFact::LinkerMap { object_path });
                }
                mapping.evidence.candidate_count =
                    mapping.evidence.candidate_count.max(candidate_count);
                mapping.evidence.has_conflict |= has_conflict;
            } else {
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Unit,
                    source_fingerprint: unit.fingerprint,
                    source_instance_fingerprint: source_unit_instance_fingerprint(unit),
                    source_build_variant_fingerprint: unit.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        linker_map_facts(unit, &symbol_name, object_path),
                        candidate_count,
                        has_conflict,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
            }
        }
        rows.unmapped_symbols.retain(|unmapped| {
            unmapped.artifact_symbol_fingerprint != symbol.fingerprint.as_bytes()
        });
    }
}

fn linker_map_facts(
    unit: &SourceUnitIdentity,
    artifact_symbol: &str,
    object_path: String,
) -> Vec<MappingEvidenceFact> {
    let source_symbol = unit.name.clone().unwrap_or_default();
    vec![
        MappingEvidenceFact::SymbolName {
            source_symbol,
            artifact_symbol: artifact_symbol.to_owned(),
        },
        MappingEvidenceFact::LinkerMap { object_path },
    ]
}

fn linker_object_matches_source(object_path: &str, source_path: &str) -> bool {
    let object_path = object_path.replace('\\', "/");
    let source_path = source_path.replace('\\', "/");
    let Some(object_without_suffix) = object_path.strip_suffix(".o") else {
        return false;
    };
    object_without_suffix == source_path
        || object_without_suffix.ends_with(&format!("/{source_path}"))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all correlation inputs stay at the source/artifact boundary"
)]
fn correlate_debug_locations(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    instantiations: &[SourceInstantiation],
    resolved_symbols: &[SourceResolvedSymbol],
    resolved_calls: &[SourceResolvedCall],
    artifact_variant: [u8; 16],
) -> CorrelationRows {
    let mut rows = CorrelationRows {
        clone_fragments: fragments.to_vec(),
        ..CorrelationRows::default()
    };
    for symbol in &artifact.symbols {
        let mut mapped = false;
        let mut seen_units = BTreeSet::new();
        let mut seen_fragments = BTreeSet::new();
        for frame in &symbol.inline_stack {
            let candidates: Vec<_> = units
                .iter()
                .filter(|unit| {
                    source_unit_matches(frame.source.as_str(), frame.line, scan_root, unit)
                })
                .collect();
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for unit in candidates {
                if !seen_units.insert((
                    source_unit_instance_fingerprint(unit),
                    unit.build_variant_fingerprint,
                )) {
                    continue;
                }
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Unit,
                    source_fingerprint: unit.fingerprint,
                    source_instance_fingerprint: source_unit_instance_fingerprint(unit),
                    source_build_variant_fingerprint: unit.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        vec![source_location_evidence(frame)],
                        candidate_count,
                        false,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
                mapped = true;
            }
            let candidates: Vec<_> = fragments
                .iter()
                .filter(|fragment| {
                    source_fragment_matches(frame.source.as_str(), frame.line, scan_root, fragment)
                })
                .collect();
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for fragment in candidates {
                if !seen_fragments.insert((fragment.finding_id, fragment.build_variant_fingerprint))
                {
                    continue;
                }
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Fragment,
                    source_fingerprint: fragment.fingerprint,
                    source_instance_fingerprint: fragment.finding_id,
                    source_build_variant_fingerprint: fragment.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        vec![source_location_evidence(frame)],
                        candidate_count,
                        false,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
                mapped = true;
            }
        }
        if !mapped {
            let generic_mappings = correlate_generic_origin(
                symbol,
                scan_root,
                units,
                fragments,
                instantiations,
                artifact_variant,
            );
            let name_mappings = correlate_symbol_name(
                symbol,
                scan_root,
                units,
                fragments,
                resolved_symbols,
                artifact_variant,
            );
            let fallback_mappings = combine_fallback_mappings(generic_mappings, name_mappings);
            mapped = !fallback_mappings.is_empty();
            rows.mappings.extend(fallback_mappings);
        }
        if !mapped {
            let reason = if symbol.inline_stack.is_empty() {
                ArtifactAnalysisUnmappedReason::DebugInfoMissing
            } else {
                ArtifactAnalysisUnmappedReason::OutsideSourceScope
            };
            rows.unmapped_symbols.push(ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                reason,
            });
        }
    }
    enrich_call_graph_evidence(
        artifact,
        scan_root,
        units,
        fragments,
        resolved_calls,
        &mut rows.mappings,
    );
    assign_unambiguous_fragment_bytes(artifact, &mut rows.mappings);
    // Artifact fingerprints deliberately describe stable symbol content rather
    // than a linker-local slot. A container can consequently expose the same
    // content identity through multiple symbol-table entries. The persistence
    // schema records one unmapped outcome per stable identity, so retain the
    // deterministic first reason instead of treating those entries as distinct
    // rows or leaking a SQLite uniqueness error.
    rows.unmapped_symbols.sort_by(|left, right| {
        left.artifact_symbol_fingerprint
            .cmp(&right.artifact_symbol_fingerprint)
            .then_with(|| {
                unmapped_reason_label(left.reason).cmp(unmapped_reason_label(right.reason))
            })
    });
    rows.unmapped_symbols
        .dedup_by_key(|unmapped| unmapped.artifact_symbol_fingerprint);
    let mapped_units = rows
        .mappings
        .iter()
        .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Unit)
        .map(|mapping| {
            (
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    rows.unmapped_sources = units
        .iter()
        .filter(|unit| {
            !mapped_units.contains(&(
                unit.fingerprint,
                source_unit_instance_fingerprint(unit),
                unit.build_variant_fingerprint,
            ))
        })
        .map(|unit| ArtifactAnalysisUnmappedSource {
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: unit.fingerprint,
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
        })
        .collect();
    let mapped_fragments = rows
        .mappings
        .iter()
        .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Fragment)
        .map(|mapping| {
            (
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    rows.unmapped_sources.extend(
        fragments
            .iter()
            .filter(|fragment| {
                !mapped_fragments.contains(&(
                    fragment.fingerprint,
                    fragment.finding_id,
                    fragment.build_variant_fingerprint,
                ))
            })
            .map(|fragment| ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Fragment,
                source_fingerprint: fragment.fingerprint,
                source_instance_fingerprint: fragment.finding_id,
                source_build_variant_fingerprint: fragment.build_variant_fingerprint,
                reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
            }),
    );
    rows
}

/// Preserve the parser-established debug metadata family in correlation
/// evidence. A source path alone cannot distinguish PDB and DWARF provenance.
fn source_location_evidence(
    frame: &codehelion_artifact::ArtifactInlineFrame,
) -> MappingEvidenceFact {
    match frame.evidence_kind {
        codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf => {
            MappingEvidenceFact::Dwarf {
                source_path: frame.source.clone(),
            }
        }
        codehelion_artifact::ArtifactSourceLocationEvidenceKind::Pdb => MappingEvidenceFact::Pdb {
            source_path: frame.source.clone(),
        },
    }
}

/// Derive an occurrence identity for one source unit without changing its
/// content-derived stable fingerprint. Equal source bodies can occur in more
/// than one file or declaration, and the `SQLite` correlation table retains each
/// occurrence independently.
fn source_unit_instance_fingerprint(unit: &SourceUnitIdentity) -> [u8; 16] {
    let mut bytes = Vec::new();
    for field in [
        unit.file_path.as_bytes(),
        unit.name.as_deref().unwrap_or_default().as_bytes(),
    ] {
        bytes.extend(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend(field);
    }
    bytes.extend(unit.start_line.unwrap_or_default().to_le_bytes());
    bytes.extend(unit.end_line.unwrap_or_default().to_le_bytes());
    bytes.extend(unit.build_variant_fingerprint);
    codehelion_artifact::ArtifactFingerprint::from_content("source-unit-instance", &bytes)
        .as_bytes()
}

/// Derive a generic-definition origin identity without merging distinct
/// compiler-confirmed definitions that happen to share normalized source
/// content.
fn generic_origin_fingerprint(source_fingerprint: [u8; 16], definition: &str) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(source_fingerprint.len() + definition.len() + 1);
    bytes.extend(source_fingerprint);
    bytes.push(0);
    bytes.extend(definition.as_bytes());
    codehelion_artifact::ArtifactFingerprint::from_content("generic-origin-v1", &bytes).as_bytes()
}

/// Attribute a symbol's observed bytes only when one exact fragment mapping
/// accounts for it. Units can contain fragments, so unit mappings neither
/// create nor block this fragment-level split.
fn assign_unambiguous_fragment_bytes(
    artifact: &ArtifactIr,
    mappings: &mut [ArtifactAnalysisMapping],
) {
    let mut fragment_mappings: BTreeMap<[u8; 16], Vec<usize>> = BTreeMap::new();
    for (index, mapping) in mappings.iter().enumerate() {
        if mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
            && mapping.evidence.confidence()
                == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Exact)
        {
            fragment_mappings
                .entry(mapping.artifact_symbol_fingerprint)
                .or_default()
                .push(index);
        }
    }
    for symbol in &artifact.symbols {
        let Some(indices) = fragment_mappings.get(&symbol.fingerprint.as_bytes()) else {
            continue;
        };
        if let [index] = indices.as_slice() {
            mappings[*index].attributed_bytes = Some(symbol.size);
        }
    }
}

fn enrich_call_graph_evidence(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    resolved_calls: &[SourceResolvedCall],
    mappings: &mut [ArtifactAnalysisMapping],
) {
    let symbol_names: BTreeMap<_, _> = artifact
        .symbols
        .iter()
        .filter_map(|symbol| {
            symbol
                .name
                .as_deref()
                .and_then(canonical_symbol_name)
                .map(|name| (symbol.fingerprint.as_bytes(), name))
        })
        .collect();
    let mut artifact_targets: BTreeMap<_, BTreeSet<String>> = BTreeMap::new();
    for call in &artifact.calls {
        let Some(target) = call
            .target
            .and_then(|target| symbol_names.get(&target.as_bytes()))
        else {
            continue;
        };
        artifact_targets
            .entry(call.caller.as_bytes())
            .or_default()
            .insert(target.clone());
    }
    let mut source_targets: BTreeMap<_, BTreeSet<String>> = BTreeMap::new();
    for call in resolved_calls {
        let Some(target) = canonical_symbol_name(&call.target_name) else {
            continue;
        };
        for unit in units
            .iter()
            .filter(|unit| source_unit_matches(&call.file_path, Some(call.line), scan_root, unit))
        {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Unit),
                    unit.fingerprint,
                    unit.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(&call.file_path, Some(call.line), scan_root, fragment)
        }) {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Fragment),
                    fragment.fingerprint,
                    fragment.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
    }
    for mapping in mappings {
        if mapping
            .evidence
            .facts
            .iter()
            .any(|fact| matches!(fact, MappingEvidenceFact::CallGraphNeighborhood))
        {
            continue;
        }
        let Some(artifact) = artifact_targets.get(&mapping.artifact_symbol_fingerprint) else {
            continue;
        };
        let Some(source) = source_targets.get(&(
            source_kind_order(mapping.source_kind),
            mapping.source_fingerprint,
            mapping.source_build_variant_fingerprint,
        )) else {
            continue;
        };
        if !artifact.is_disjoint(source) {
            mapping
                .evidence
                .facts
                .push(MappingEvidenceFact::CallGraphNeighborhood);
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate aggregation and mapping construction must share the exact same evidence scope"
)]
fn correlate_generic_origin(
    symbol: &codehelion_artifact::ArtifactSymbol,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    instantiations: &[SourceInstantiation],
    artifact_variant: [u8; 16],
) -> Vec<ArtifactAnalysisMapping> {
    let Some(artifact_name) = symbol.name.as_deref() else {
        return Vec::new();
    };
    let rust_key = normalized_generic_instantiation_key(artifact_name);
    let clang_key = normalized_clang_template_display_name(artifact_name);
    let clang_owner_key = normalized_clang_template_owner_name(artifact_name);
    if rust_key.is_none() && clang_key.is_none() && clang_owner_key.is_none() {
        return Vec::new();
    }
    let mut unit_candidates = BTreeMap::new();
    let mut fragment_candidates = BTreeMap::new();
    for instantiation in instantiations {
        let matches_rust_key = rust_key.as_deref().is_some_and(|artifact_key| {
            normalized_generic_instantiation_key(&instantiation.instantiation_key).as_deref()
                == Some(artifact_key)
        });
        let matches_clang_key = clang_key.as_deref().is_some_and(|artifact_key| {
            instantiation
                .artifact_match_key
                .as_deref()
                .and_then(normalized_clang_template_display_name)
                .as_deref()
                == Some(artifact_key)
        });
        let matches_clang_owner_key = clang_owner_key.as_deref().is_some_and(|artifact_key| {
            instantiation
                .artifact_match_key
                .as_deref()
                .and_then(normalized_clang_template_owner_name)
                .as_deref()
                == Some(artifact_key)
        });
        if !matches_rust_key && !matches_clang_key && !matches_clang_owner_key {
            continue;
        }
        for unit in units.iter().filter(|unit| {
            source_generic_unit_matches(
                &instantiation.file_path,
                Some(instantiation.line),
                scan_root,
                unit,
            ) || matches_clang_owner_key
                && source_template_definition_contains_unit(instantiation, scan_root, unit)
        }) {
            unit_candidates
                .entry((
                    unit.fingerprint,
                    unit.build_variant_fingerprint,
                    instantiation.instantiation_key.clone(),
                    instantiation.definition.clone(),
                ))
                .or_insert_with(|| (unit, BTreeSet::new()))
                .1
                .insert(instantiation.translation_unit.clone());
        }
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(
                &instantiation.file_path,
                Some(instantiation.line),
                scan_root,
                fragment,
            )
        }) {
            fragment_candidates
                .entry((
                    fragment.finding_id,
                    fragment.build_variant_fingerprint,
                    instantiation.instantiation_key.clone(),
                    instantiation.definition.clone(),
                ))
                .or_insert_with(|| (fragment, BTreeSet::new()))
                .1
                .insert(instantiation.translation_unit.clone());
        }
    }
    let unit_candidate_count = u32::try_from(
        unit_candidates
            .keys()
            .map(|(fingerprint, variant, _, _)| (*fingerprint, *variant))
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u32::MAX);
    let fragment_candidate_count = u32::try_from(
        fragment_candidates
            .keys()
            .map(|(finding, variant, _, _)| (*finding, *variant))
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u32::MAX);
    let mut mappings = Vec::new();
    for ((_, _, instantiation_key, definition), (unit, translation_units)) in unit_candidates {
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: unit.fingerprint,
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units: translation_units.into_iter().collect(),
                }],
                unit_candidate_count,
                false,
            ),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    for ((_, _, instantiation_key, definition), (fragment, translation_units)) in
        fragment_candidates
    {
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: fragment.fingerprint,
            source_instance_fingerprint: fragment.finding_id,
            source_build_variant_fingerprint: fragment.build_variant_fingerprint,
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units: translation_units.into_iter().collect(),
                }],
                fragment_candidate_count,
                false,
            ),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    mappings
}

#[allow(
    clippy::too_many_lines,
    reason = "name candidates retain macro provenance without collapsing competing source identities"
)]
fn correlate_symbol_name(
    symbol: &codehelion_artifact::ArtifactSymbol,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    resolved_symbols: &[SourceResolvedSymbol],
    artifact_variant: [u8; 16],
) -> Vec<ArtifactAnalysisMapping> {
    let Some(artifact_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
        return Vec::new();
    };
    let mut unit_candidates = Vec::new();
    let mut fragment_candidates = Vec::new();
    let mut seen_units = BTreeSet::new();
    let mut seen_fragments = BTreeSet::new();
    for source_symbol in resolved_symbols {
        let Some(source_name) = canonical_symbol_name(&source_symbol.name) else {
            continue;
        };
        if source_name != artifact_name {
            continue;
        }
        for unit in units.iter().filter(|unit| {
            source_unit_matches(
                &source_symbol.file_path,
                Some(source_symbol.line),
                scan_root,
                unit,
            )
        }) {
            if seen_units.insert((unit.fingerprint, unit.build_variant_fingerprint)) {
                unit_candidates.push((
                    unit,
                    source_name.clone(),
                    source_symbol
                        .macro_definition
                        .as_ref()
                        .map(|anchor| anchor.file_path.clone()),
                ));
            }
        }
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(
                &source_symbol.file_path,
                Some(source_symbol.line),
                scan_root,
                fragment,
            )
        }) {
            if seen_fragments.insert((fragment.finding_id, fragment.build_variant_fingerprint)) {
                fragment_candidates.push((
                    fragment,
                    source_name.clone(),
                    source_symbol
                        .macro_definition
                        .as_ref()
                        .map(|anchor| anchor.file_path.clone()),
                ));
            }
        }
    }
    if unit_candidates.is_empty() && fragment_candidates.is_empty() {
        unit_candidates.extend(units.iter().filter_map(|unit| {
            unit.name
                .as_deref()
                .and_then(canonical_symbol_name)
                .filter(|source_name| source_name == &artifact_name)
                .map(|source_name| (unit, source_name, None))
        }));
    }
    let unit_candidate_count = u32::try_from(unit_candidates.len()).unwrap_or(u32::MAX);
    let fragment_candidate_count = u32::try_from(fragment_candidates.len()).unwrap_or(u32::MAX);
    let mut mappings = Vec::new();
    for (unit, source_name, macro_definition) in unit_candidates {
        let mut facts = vec![MappingEvidenceFact::SymbolName {
            source_symbol: source_name,
            artifact_symbol: artifact_name.clone(),
        }];
        if let Some(definition_path) = macro_definition {
            facts.push(MappingEvidenceFact::MacroOrigin { definition_path });
        }
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: unit.fingerprint,
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            evidence: MappingEvidence::new(facts, unit_candidate_count, false),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    for (fragment, source_name, macro_definition) in fragment_candidates {
        let mut facts = vec![MappingEvidenceFact::SymbolName {
            source_symbol: source_name,
            artifact_symbol: artifact_name.clone(),
        }];
        if let Some(definition_path) = macro_definition {
            facts.push(MappingEvidenceFact::MacroOrigin { definition_path });
        }
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: fragment.fingerprint,
            source_instance_fingerprint: fragment.finding_id,
            source_build_variant_fingerprint: fragment.build_variant_fingerprint,
            evidence: MappingEvidence::new(facts, fragment_candidate_count, false),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    mappings
}

/// Merge independent fallback candidates without guessing which extractor won.
///
/// A compiler-reported generic origin and a demangled name normally reinforce
/// the same source identity. If their candidate sets are disjoint, both sets
/// remain visible and their evidence is marked as conflicting. This preserves
/// the many-to-many correspondence instead of selecting a plausible-looking
/// single best candidate.
fn combine_fallback_mappings(
    mut generic_mappings: Vec<ArtifactAnalysisMapping>,
    mut name_mappings: Vec<ArtifactAnalysisMapping>,
) -> Vec<ArtifactAnalysisMapping> {
    if generic_mappings.is_empty() {
        return name_mappings;
    }
    if name_mappings.is_empty() {
        return generic_mappings;
    }

    let generic_keys: BTreeSet<_> = generic_mappings.iter().map(mapping_source_key).collect();
    let name_keys: BTreeSet<_> = name_mappings.iter().map(mapping_source_key).collect();
    if generic_keys.is_disjoint(&name_keys) {
        for mapping in generic_mappings.iter_mut().chain(&mut name_mappings) {
            mapping.evidence.has_conflict = true;
        }
        generic_mappings.extend(name_mappings);
        return generic_mappings;
    }

    for generic in &mut generic_mappings {
        let generic_key = mapping_source_key(generic);
        for name in name_mappings
            .iter()
            .filter(|name| mapping_source_key(name) == generic_key)
        {
            generic.evidence.facts.extend(name.evidence.facts.clone());
            generic.evidence.candidate_count = generic
                .evidence
                .candidate_count
                .max(name.evidence.candidate_count);
        }
    }
    generic_mappings.extend(
        name_mappings
            .into_iter()
            .filter(|mapping| !generic_keys.contains(&mapping_source_key(mapping))),
    );
    generic_mappings
}

const fn mapping_source_key(
    mapping: &ArtifactAnalysisMapping,
) -> (u8, [u8; 16], [u8; 16], [u8; 16]) {
    (
        source_kind_order(mapping.source_kind),
        mapping.source_fingerprint,
        mapping.source_instance_fingerprint,
        mapping.source_build_variant_fingerprint,
    )
}

fn canonical_symbol_name(name: &str) -> Option<String> {
    let before_signature = name.trim().split('(').next()?.trim();
    let leaf = before_signature.rsplit("::").next()?.trim();
    let without_arguments = leaf.split('<').next()?.trim();
    (!without_arguments.is_empty()).then(|| without_arguments.to_owned())
}

fn normalized_generic_instantiation_key(name: &str) -> Option<String> {
    let compact: String = name
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (compact.contains('<') && compact.ends_with('>')).then(|| compact.replace("::<", "<"))
}

/// Normalize a C++ function-template display name for a source/artifact
/// comparison. Both inputs are compiler-produced: Clang's display name is
/// tagged by the helper, while the artifact backend has already demangled its
/// symbol. This deliberately rejects class templates and ordinary functions;
/// neither form has enough evidence to be a generic-origin correspondence.
fn normalized_clang_template_display_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let open = name.find('(')?;
    let close = name.rfind(')')?;
    if close < open || (!name[..open].contains('<') && !tagged_source) {
        return None;
    }
    let before_parameters = name[..open].trim();
    let qualified = qualified_cpp_symbol_name(before_parameters);
    let mut normalized = String::with_capacity(name.len());
    let mut depth = 0_u32;
    for character in qualified.chars() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => normalized.push(character),
            _ => {}
        }
    }
    normalized.push_str(name.get(open..=close)?);
    (!normalized.is_empty()).then_some(normalized)
}

/// Normalize a C++ class-template specialization that owns one demangled
/// member function. The source key is the fully qualified class display name;
/// the artifact key is the owner preceding the member name. The comparison is
/// exact after whitespace and integral-literal suffix normalization, so a
/// member of `Buffer<int, 8>` cannot be attributed to `Buffer<int, 4>`.
fn normalized_clang_template_owner_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let owner = if tagged_source {
        (name.contains('<') && name.ends_with('>')).then_some(name)
    } else {
        let open = cpp_member_parameter_open(name)?;
        let before_parameters = name[..open].trim();
        let qualified = qualified_cpp_symbol_name(before_parameters);
        let (owner, _) = qualified.rsplit_once("::")?;
        (owner.contains('<') && owner.ends_with('>')).then_some(owner)
    }?;
    Some(normalize_cpp_template_owner(owner))
}

/// Locate the member-function parameter list outside template arguments.
///
/// A non-type template argument may itself contain a cast such as
/// `(unsigned long)4`, which is not the member-function parameter list.
fn cpp_member_parameter_open(name: &str) -> Option<usize> {
    let mut template_depth = 0_u32;
    for (index, character) in name.char_indices() {
        match character {
            '<' => template_depth = template_depth.saturating_add(1),
            '>' => template_depth = template_depth.saturating_sub(1),
            '(' if template_depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// Remove a C++ return type without mistaking whitespace inside `<...>` for
/// the separator before the qualified function name.
fn qualified_cpp_symbol_name(spelling: &str) -> &str {
    let mut depth = 0_u32;
    let mut separator = None;
    for (index, character) in spelling.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 && character.is_whitespace() => separator = Some(index),
            _ => {}
        }
    }
    separator.map_or(spelling, |index| spelling[index..].trim_start())
}

/// Remove formatting and the ABI's harmless decimal integer literal suffixes.
fn normalize_cpp_template_owner(owner: &str) -> String {
    let compact: String = owner
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    // Demanglers may spell a non-type integral template argument with the
    // ABI's explicit type cast, e.g. `Buffer<int, (unsigned long)4>`.  This
    // function only receives the template owner (never parameter types), so
    // removing those integer casts leaves the specialization identity intact.
    let compact = [
        "(unsignedlonglong)",
        "(unsignedlong)",
        "(unsignedint)",
        "(longlong)",
        "(long)",
        "(int)",
    ]
    .into_iter()
    .fold(compact, |normalized, cast| normalized.replace(cast, ""));
    let characters: Vec<_> = compact.chars().collect();
    let mut normalized = String::with_capacity(compact.len());
    let mut index = 0;
    while index < characters.len() {
        if !characters[index].is_ascii_digit() {
            normalized.push(characters[index]);
            index += 1;
            continue;
        }
        let digits_start = index;
        while index < characters.len() && characters[index].is_ascii_digit() {
            index += 1;
        }
        normalized.extend(characters[digits_start..index].iter());
        let suffix_start = index;
        while index < characters.len() && matches!(characters[index], 'u' | 'U' | 'l' | 'L') {
            index += 1;
        }
        if suffix_start == index
            || index < characters.len() && !matches!(characters[index], ',' | '>' | ')')
        {
            normalized.extend(characters[suffix_start..index].iter());
        }
    }
    normalized
}

fn source_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    let source_path = FilePath::new(source_path);
    let unit_path = FilePath::new(&unit.file_path);
    if source_path != unit_path && source_path != scan_root.join(unit_path) {
        return false;
    }
    match (source_line, unit.start_line, unit.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        _ => true,
    }
}

/// Match a compiler's generic-definition anchor to a source unit.
///
/// Clang reports a function template at its declaration line, whereas the
/// structural frontend anchors its function unit at the opening brace on the
/// following line.  That one-line difference is syntax-derived rather than a
/// fuzzy location match, and is limited to generic-origin evidence.
fn source_generic_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    if source_unit_matches(source_path, source_line, scan_root, unit) {
        return true;
    }
    let (Some(line), Some(start_line)) = (source_line, unit.start_line) else {
        return false;
    };
    let source_path = FilePath::new(source_path);
    let unit_path = FilePath::new(&unit.file_path);
    (source_path == unit_path || source_path == scan_root.join(unit_path))
        && line.checked_add(1) == Some(start_line)
}

/// Whether a source unit is wholly inside a class-template definition.
///
/// Class template instantiations are anchored at the class declaration, while
/// emitted symbols commonly name an inline member body.  The compiler-supplied
/// definition extent lets this match that member without guessing from its
/// short name.  Both endpoints must be present, so a partial range remains
/// unmapped.
fn source_template_definition_contains_unit(
    instantiation: &SourceInstantiation,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    let (Some(definition_end_line), Some(unit_start_line), Some(unit_end_line)) = (
        instantiation.definition_end_line,
        unit.start_line,
        unit.end_line,
    ) else {
        return false;
    };
    let source_path = FilePath::new(&instantiation.file_path);
    let unit_path = FilePath::new(&unit.file_path);
    (source_path == unit_path || source_path == scan_root.join(unit_path))
        && instantiation.line <= unit_start_line
        && unit_end_line <= definition_end_line
}

fn source_fragment_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> bool {
    let source_path = FilePath::new(source_path);
    let fragment_path = FilePath::new(&fragment.file_path);
    if source_path != fragment_path && source_path != scan_root.join(fragment_path) {
        return false;
    }
    match (source_line, fragment.start_line, fragment.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        // A file path alone cannot select a clone fragment: treating every
        // fragment in the file as a DWARF match would make a missing line
        // look like evidence and could attribute bytes to an arbitrary
        // duplicate. Whole units may remain an explicitly ambiguous mapping,
        // but fragment-level attribution is fail-closed.
        _ => false,
    }
}

/// Compare two artifacts by their content-derived symbol identities.
///
/// # Errors
///
/// Returns an error under the same conditions as [`run`]. The artifacts are
/// read as bytes only; neither one is executed.
pub fn compare(args: &ArtifactCompareArgs, out: &mut impl Write) -> Result<Outcome> {
    run_isolated_request(
        IsolatedArtifactRequest::Compare(args.clone()),
        args.timeout_seconds,
        args.output.as_deref(),
        out,
    )
}

/// Run an artifact comparison in the already isolated worker process.
fn compare_direct(args: &ArtifactCompareArgs, out: &mut impl Write) -> Result<Outcome> {
    let before = inspect(&args.before, args.max_bytes, None, None)?;
    let after = inspect(&args.after, args.max_bytes, None, None)?;
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
    report.calibration = record_comparison_calibration(
        args,
        &before,
        &after,
        before_variant.as_ref(),
        after_variant.as_ref(),
    )?;
    let mut rendered = Vec::new();
    match args.format {
        ArtifactFormat::Json => serde_json::to_writer_pretty(&mut rendered, &report)?,
        ArtifactFormat::Csv => render_compare_csv(&report, &mut rendered)?,
        ArtifactFormat::Text => render_compare_text(&report, &mut rendered)?,
    }
    rendered.push(b'\n');
    if let Some(path) = &args.output {
        fs::write(path, &rendered).with_context(|| format!("writing {}", path.display()))?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

fn record_comparison_calibration(
    args: &ArtifactCompareArgs,
    before: &ArtifactIr,
    after: &ArtifactIr,
    before_variant: Option<&BuildVariantEvidence>,
    after_variant: Option<&BuildVariantEvidence>,
) -> Result<Option<CalibrationReport>> {
    let supplied = [
        args.source_run.is_some(),
        args.clone_group.is_some(),
        args.db.is_some(),
    ];
    if supplied.iter().any(|value| *value) && supplied.iter().any(|value| !*value) {
        bail!("calibration requires --source-run, --clone-group, and --db together");
    }
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
    let db = crate::resolve_db(args.db.as_deref())?;
    let mut store = Store::open(&db)
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
        estimated_refactor_savings_bytes: calibration.estimated_refactor_savings_bytes,
        verified_savings_bytes: verified,
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
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .with_context(|| format!("parsing build variant {} as JSON", path.display()))?;
    Ok(Some(BuildVariantEvidence {
        manifest_path: path.display().to_string(),
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "artifact-build-variant",
            &bytes,
        ),
    }))
}

fn inspect(
    path: &std::path::Path,
    max_bytes: u64,
    required_format: Option<ArtifactInputFormat>,
    debug_file: Option<&std::path::Path>,
) -> Result<ArtifactIr> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading metadata for artifact {}", path.display()))?;
    if metadata.len() > max_bytes {
        bail!(
            "artifact {} is {} bytes, exceeding the configured --max-bytes limit of {}",
            path.display(),
            metadata.len(),
            max_bytes
        );
    }
    let bytes = fs::read(path).with_context(|| format!("reading artifact {}", path.display()))?;
    let (debug_companion, automatically_discovered) = match debug_file {
        Some(path) => (
            Some(read_artifact_input(
                path,
                max_bytes,
                "external debug companion",
            )?),
            false,
        ),
        None => (discover_macho_dsym(path, &bytes, max_bytes), true),
    };
    match parse_input_format(&bytes, required_format, debug_companion.as_deref()) {
        Ok(artifact) => Ok(artifact),
        Err(_) if automatically_discovered && debug_companion.is_some() => {
            // An automatically discovered bundle is optional evidence. Its
            // malformed bytes or a stale UUID must not make a valid artifact
            // unanalyzable; an explicitly supplied companion remains strict.
            parse_input_format(&bytes, required_format, None)
        }
        Err(error) => Err(error),
    }
}

/// Read the conventional sibling dSYM image only when it stays within the
/// configured input limit. This performs no directory traversal: a Mach-O
/// artifact named `app` maps to exactly `app.dSYM/Contents/Resources/DWARF/app`.
fn discover_macho_dsym(path: &FilePath, artifact: &[u8], max_bytes: u64) -> Option<Vec<u8>> {
    if detect_format(artifact) != Some(BinaryFormat::MachO) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let candidate = path
        .with_file_name(format!("{name}.dSYM"))
        .join("Contents/Resources/DWARF")
        .join(name);
    let metadata = fs::metadata(&candidate).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    fs::read(candidate).ok()
}

/// Read an optional artifact-side input under the same explicit size ceiling.
fn read_artifact_input(path: &std::path::Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("reading {label} {}", path.display()))?;
    if metadata.len() > max_bytes {
        bail!(
            "{label} {} is {} bytes, above the configured maximum of {max_bytes}",
            path.display(),
            metadata.len(),
        );
    }
    fs::read(path).with_context(|| format!("reading {label} {}", path.display()))
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
    if metadata.len() > max_bytes {
        return unavailable("map_exceeds_size_limit");
    }
    let Ok(bytes) = fs::read(&path) else {
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
            SourceMapResolution {
                uri: uri.to_owned(),
                status: SourceMapResolutionStatus::Resolved {
                    local_path: path.display().to_string(),
                    sources,
                },
            }
        }
        Ok(_) => unavailable("unsupported_source_map_kind"),
        Err(_) => unavailable("invalid_source_map"),
    }
}

fn parse_input_format(
    bytes: &[u8],
    required_format: Option<ArtifactInputFormat>,
    debug_companion: Option<&[u8]>,
) -> Result<ArtifactIr> {
    let detected = detect_format(bytes).ok_or_else(|| {
        anyhow::anyhow!("could not recognise input as a supported artifact format")
    })?;
    let format = required_format.map_or(detected, input_format);
    if format != detected {
        bail!("detected input format {detected} conflicts with requested input format {format}");
    }
    parse(format, bytes, debug_companion)
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

fn parse(format: BinaryFormat, bytes: &[u8], debug_companion: Option<&[u8]>) -> Result<ArtifactIr> {
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
            .parse_with_debug_companion(bytes, debug_companion)
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

/// Stable summary of one artifact report, excluding raw code and data bytes.
#[derive(Debug, Serialize)]
struct ArtifactReport {
    schema_version: &'static str,
    path: String,
    analysis_id: Option<i64>,
    build_variant: Option<ComparisonBuildVariant>,
    correlation: Option<ArtifactCorrelationReport>,
    format: BinaryFormat,
    fingerprint: String,
    observed_bytes: u64,
    code_section_bytes: u64,
    data_segment_bytes: u64,
    sections: usize,
    imports: usize,
    symbols: Vec<SymbolReport>,
    entry_points: usize,
    calls: usize,
    relocations: usize,
    source_mappings: usize,
    source_maps: Vec<SourceMapResolution>,
    archive_members: Vec<ArchiveMemberReport>,
    data_segments: usize,
    capabilities: codehelion_artifact::ArtifactCapabilities,
    sizes: metrics::SizeClassification,
    dead_code: Option<metrics::DeadCodeReport>,
    retained_sizes: Option<Vec<metrics::RetainedSize>>,
    duplicates: DuplicateSummary,
    duplicate_groups: DuplicateGroups,
}

/// Display-safe provenance for one archive member.
#[derive(Debug, Serialize)]
struct ArchiveMemberReport {
    name: String,
    fingerprint: String,
    offset: u64,
    size: u64,
    format: Option<BinaryFormat>,
    thin: bool,
    parse_error: Option<String>,
}

/// Result of one locally declared WASM source-map reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SourceMapResolution {
    uri: String,
    #[serde(flatten)]
    status: SourceMapResolutionStatus,
}

/// A source-map outcome that does not require fetching or retaining source text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SourceMapResolutionStatus {
    Resolved {
        local_path: String,
        sources: Vec<String>,
    },
    Unavailable {
        reason: &'static str,
    },
}

impl ArtifactReport {
    fn from_ir(
        path: &std::path::Path,
        artifact: &ArtifactIr,
        analysis_id: Option<i64>,
        build_variant: Option<ComparisonBuildVariant>,
    ) -> Self {
        let duplicates = metrics::find_duplicates(artifact);
        let data =
            metrics::find_duplicate_data(artifact, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        Self {
            schema_version: ARTIFACT_REPORT_SCHEMA_VERSION,
            path: path.display().to_string(),
            analysis_id,
            build_variant,
            correlation: None,
            format: artifact.format,
            fingerprint: artifact.fingerprint.to_hex(),
            observed_bytes: artifact.observed_bytes,
            code_section_bytes: artifact
                .sections
                .iter()
                .filter(|section| section.executable)
                .map(|section| section.size)
                .sum(),
            data_segment_bytes: artifact
                .data_segments
                .iter()
                .map(|segment| segment.bytes.len() as u64)
                .sum(),
            sections: artifact.sections.len(),
            imports: artifact.imports.len(),
            symbols: artifact
                .symbols
                .iter()
                .map(|symbol| SymbolReport {
                    fingerprint: symbol.fingerprint.to_hex(),
                    name: symbol.name.clone(),
                    exported: symbol.exported,
                    offset: symbol.offset,
                    size: symbol.size,
                    size_inferred: symbol.size_inferred,
                })
                .collect(),
            entry_points: artifact.entry_points.len(),
            calls: artifact.calls.len(),
            relocations: artifact.relocations.len(),
            source_mappings: artifact.source_mappings.len(),
            source_maps: Vec::new(),
            archive_members: artifact
                .archive_members
                .iter()
                .map(|member| ArchiveMemberReport {
                    name: member.name.clone(),
                    fingerprint: member.fingerprint.to_hex(),
                    offset: member.offset,
                    size: member.size,
                    format: member.format,
                    thin: member.thin,
                    parse_error: member.parse_error.clone(),
                })
                .collect(),
            data_segments: artifact.data_segments.len(),
            capabilities: artifact.capabilities,
            sizes: metrics::classify_sizes(artifact),
            dead_code: metrics::dead_code_candidates(artifact),
            retained_sizes: metrics::retained_sizes(artifact),
            duplicates: DuplicateSummary {
                exact_groups: duplicates.exact.len(),
                exact_duplicated_bytes: duplicates
                    .exact
                    .iter()
                    .map(|group| group.duplicated_bytes)
                    .sum(),
                normalized_groups: duplicates.normalized.len(),
                normalized_duplicated_bytes: duplicates
                    .normalized
                    .iter()
                    .map(|group| group.duplicated_bytes)
                    .sum(),
            },
            duplicate_groups: DuplicateGroups {
                exact: duplicates.exact,
                normalized: duplicates.normalized,
                data,
            },
        }
    }

    fn with_correlation(mut self, correlation: Option<ArtifactCorrelationReport>) -> Self {
        self.correlation = correlation;
        self
    }

    fn with_source_maps(mut self, source_maps: Vec<SourceMapResolution>) -> Self {
        self.source_maps = source_maps;
        self
    }
}

#[derive(Debug, Serialize)]
struct SymbolReport {
    fingerprint: String,
    name: Option<String>,
    exported: bool,
    offset: u64,
    size: u64,
    size_inferred: bool,
}

#[derive(Debug, Serialize)]
struct DuplicateSummary {
    exact_groups: usize,
    exact_duplicated_bytes: u64,
    normalized_groups: usize,
    normalized_duplicated_bytes: u64,
}

/// Full equality groups, separate from the summary so clients cannot mistake
/// normalized similarity for byte-for-byte equality.
#[derive(Debug, Serialize)]
struct DuplicateGroups {
    exact: Vec<metrics::DuplicateGroup>,
    normalized: Vec<metrics::DuplicateGroup>,
    data: Vec<metrics::DuplicateGroup>,
}

/// Versioned before/after result based only on parser-observed facts.
#[derive(Debug, Serialize)]
struct ArtifactComparisonReport {
    schema_version: &'static str,
    before: ComparisonArtifact,
    after: ComparisonArtifact,
    size_delta_bytes: i128,
    duplicated_code_delta_bytes: i128,
    duplicated_data_delta_bytes: i128,
    verified_savings_bytes: Option<u64>,
    calibration: Option<CalibrationReport>,
    symbol_changes: SymbolChanges,
    symbol_deltas: Vec<SymbolDelta>,
    duplicate_group_deltas: Vec<DuplicateGroupDelta>,
    build_variant_warning: Option<String>,
    assumptions: Vec<String>,
}

/// One controlled group-level measurement persisted from this comparison.
#[derive(Debug, Serialize)]
struct CalibrationReport {
    source_run: i64,
    clone_group_fingerprint: String,
    estimated_refactor_savings_bytes: i64,
    verified_savings_bytes: i64,
    absolute_error_bytes: u64,
    relative_error: Option<f64>,
}

#[derive(Debug, Serialize)]
struct ComparisonArtifact {
    path: String,
    format: BinaryFormat,
    fingerprint: String,
    build_variant: Option<ComparisonBuildVariant>,
    sizes: metrics::SizeClassification,
}

/// User-provided build-configuration evidence associated with one artifact.
#[derive(Debug, Clone, Serialize)]
struct ComparisonBuildVariant {
    manifest_path: String,
    fingerprint: String,
}

/// Validated build-condition evidence that is safe to persist as a fingerprint.
#[derive(Debug, Clone)]
struct BuildVariantEvidence {
    manifest_path: String,
    fingerprint: codehelion_artifact::ArtifactFingerprint,
}

impl BuildVariantEvidence {
    fn for_report(&self) -> ComparisonBuildVariant {
        ComparisonBuildVariant {
            manifest_path: self.manifest_path.clone(),
            fingerprint: self.fingerprint.to_hex(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SymbolChanges {
    added: usize,
    removed: usize,
    modified_named_symbols: usize,
}

/// One changed parser-established symbol, ordered by absolute size delta.
#[derive(Debug, Serialize)]
struct SymbolDelta {
    kind: &'static str,
    name: Option<String>,
    fingerprint: String,
    size_delta_bytes: i128,
}

/// One equality-group change. `kind` identifies the independent equality
/// relation so a normalized match is never presented as an exact-byte match.
#[derive(Debug, Serialize)]
struct DuplicateGroupDelta {
    kind: &'static str,
    fingerprint: String,
    duplicated_bytes_delta: i128,
    members_delta: i128,
}

impl ArtifactComparisonReport {
    fn new(
        before_path: &std::path::Path,
        before: &ArtifactIr,
        before_variant: Option<ComparisonBuildVariant>,
        after_path: &std::path::Path,
        after: &ArtifactIr,
        after_variant: Option<ComparisonBuildVariant>,
    ) -> Self {
        let before_sizes = metrics::classify_sizes(before);
        let after_sizes = metrics::classify_sizes(after);
        let before_symbols = symbol_counts(before);
        let after_symbols = symbol_counts(after);
        let added = count_difference(&after_symbols, &before_symbols);
        let removed = count_difference(&before_symbols, &after_symbols);
        let modified_named_symbols = modified_named_symbols(before, after);
        let symbol_deltas = symbol_deltas(before, after);
        let duplicate_group_deltas = duplicate_group_deltas(before, after);
        let mut assumptions = vec![
            "symbol identity is content-derived; an equal name with a changed fingerprint is reported as modified"
                .to_owned(),
            "size_delta_bytes is a measured artifact-byte difference, not a refactoring estimate"
                .to_owned(),
        ];
        if before.format != after.format {
            assumptions.push(
                "the artifact formats differ; size and symbol changes may reflect format changes"
                    .to_owned(),
            );
        }
        let build_variant_warning =
            build_variant_warning(before_variant.as_ref(), after_variant.as_ref());
        if let Some(warning) = &build_variant_warning {
            assumptions.push(warning.clone());
        }
        Self {
            schema_version: ARTIFACT_REPORT_SCHEMA_VERSION,
            before: ComparisonArtifact {
                path: before_path.display().to_string(),
                format: before.format,
                fingerprint: before.fingerprint.to_hex(),
                build_variant: before_variant,
                sizes: before_sizes.clone(),
            },
            after: ComparisonArtifact {
                path: after_path.display().to_string(),
                format: after.format,
                fingerprint: after.fingerprint.to_hex(),
                build_variant: after_variant,
                sizes: after_sizes.clone(),
            },
            size_delta_bytes: difference(after_sizes.observed_bytes, before_sizes.observed_bytes),
            duplicated_code_delta_bytes: difference(
                after_sizes.duplicated_bytes,
                before_sizes.duplicated_bytes,
            ),
            duplicated_data_delta_bytes: difference(
                after_sizes.duplicated_data_bytes,
                before_sizes.duplicated_data_bytes,
            ),
            verified_savings_bytes: before_sizes
                .observed_bytes
                .checked_sub(after_sizes.observed_bytes),
            calibration: None,
            symbol_changes: SymbolChanges {
                added,
                removed,
                modified_named_symbols,
            },
            symbol_deltas,
            duplicate_group_deltas,
            build_variant_warning,
            assumptions,
        }
    }
}

fn build_variant_warning(
    before: Option<&ComparisonBuildVariant>,
    after: Option<&ComparisonBuildVariant>,
) -> Option<String> {
    match (before, after) {
        (Some(before), Some(after)) if before.fingerprint != after.fingerprint => Some(
            "build variants differ; size and symbol changes may reflect build-condition changes"
                .to_owned(),
        ),
        (Some(_), None) | (None, Some(_)) => Some(
            "only one build variant was supplied; build-condition differences cannot be assessed"
                .to_owned(),
        ),
        _ => None,
    }
}

fn duplicate_group_deltas(before: &ArtifactIr, after: &ArtifactIr) -> Vec<DuplicateGroupDelta> {
    let groups = |artifact: &ArtifactIr| {
        let duplicates = metrics::find_duplicates(artifact);
        let data =
            metrics::find_duplicate_data(artifact, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        [
            ("exact", duplicates.exact),
            ("normalized", duplicates.normalized),
            ("data", data),
        ]
        .into_iter()
        .flat_map(|(kind, groups)| {
            groups.into_iter().map(move |group| {
                (
                    (kind, group.fingerprint),
                    (group.duplicated_bytes, group.members.len()),
                )
            })
        })
        .collect::<BTreeMap<_, _>>()
    };
    let before_groups = groups(before);
    let after_groups = groups(after);
    let keys: BTreeSet<_> = before_groups
        .keys()
        .chain(after_groups.keys())
        .copied()
        .collect();
    keys.into_iter()
        .filter_map(|(kind, fingerprint)| {
            let (before_bytes, before_members) = before_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let (after_bytes, after_members) = after_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let duplicated_bytes_delta = difference(after_bytes, before_bytes);
            let members_delta =
                i128::try_from(after_members).ok()? - i128::try_from(before_members).ok()?;
            (duplicated_bytes_delta != 0 || members_delta != 0).then(|| DuplicateGroupDelta {
                kind,
                fingerprint: fingerprint.to_hex(),
                duplicated_bytes_delta,
                members_delta,
            })
        })
        .collect()
}

fn symbol_deltas(before: &ArtifactIr, after: &ArtifactIr) -> Vec<SymbolDelta> {
    let mut before_counts = symbol_counts(before);
    let mut after_counts = symbol_counts(after);
    let mut result = Vec::new();
    for symbol in &after.symbols {
        let Some(count) = after_counts.get_mut(&symbol.fingerprint) else {
            continue;
        };
        if *count == 0 {
            continue;
        }
        if let Some(prior) = before_counts.get_mut(&symbol.fingerprint) {
            if *prior > 0 {
                *prior -= 1;
            } else {
                result.push(SymbolDelta {
                    kind: "added",
                    name: symbol.name.clone(),
                    fingerprint: symbol.fingerprint.to_hex(),
                    size_delta_bytes: i128::from(symbol.size),
                });
            }
        } else {
            result.push(SymbolDelta {
                kind: "added",
                name: symbol.name.clone(),
                fingerprint: symbol.fingerprint.to_hex(),
                size_delta_bytes: i128::from(symbol.size),
            });
        }
        *count -= 1;
    }
    for symbol in &before.symbols {
        let Some(count) = before_counts.get_mut(&symbol.fingerprint) else {
            continue;
        };
        if *count == 0 {
            continue;
        }
        result.push(SymbolDelta {
            kind: "removed",
            name: symbol.name.clone(),
            fingerprint: symbol.fingerprint.to_hex(),
            size_delta_bytes: -i128::from(symbol.size),
        });
        *count -= 1;
    }
    result.sort_by(|left, right| {
        right
            .size_delta_bytes
            .unsigned_abs()
            .cmp(&left.size_delta_bytes.unsigned_abs())
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

fn symbol_counts(
    artifact: &ArtifactIr,
) -> BTreeMap<codehelion_artifact::ArtifactFingerprint, usize> {
    let mut counts = BTreeMap::new();
    for symbol in &artifact.symbols {
        *counts.entry(symbol.fingerprint).or_default() += 1;
    }
    counts
}

fn count_difference(
    left: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
    right: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
) -> usize {
    left.iter()
        .map(|(fingerprint, count)| count.saturating_sub(*right.get(fingerprint).unwrap_or(&0)))
        .sum()
}

fn modified_named_symbols(before: &ArtifactIr, after: &ArtifactIr) -> usize {
    let names = |artifact: &ArtifactIr| {
        let mut result: BTreeMap<String, BTreeSet<codehelion_artifact::ArtifactFingerprint>> =
            BTreeMap::new();
        for symbol in &artifact.symbols {
            if let Some(name) = symbol.name.as_deref() {
                result
                    .entry(name.to_owned())
                    .or_default()
                    .insert(symbol.fingerprint);
            }
        }
        result
    };
    let before_names = names(before);
    let after_names = names(after);
    before_names
        .iter()
        .filter(|(name, fingerprints)| {
            fingerprints.len() == 1
                && after_names.get(*name).is_some_and(|after_fingerprints| {
                    after_fingerprints.len() == 1 && after_fingerprints != *fingerprints
                })
        })
        .count()
}

fn difference(after: u64, before: u64) -> i128 {
    i128::from(after) - i128::from(before)
}

#[allow(clippy::too_many_lines)] // The report order is its public text contract.
fn render_text(report: &ArtifactReport, verbose: bool, out: &mut impl Write) -> Result<()> {
    writeln!(out, "artifact: {}", report.path)?;
    writeln!(out, "format: {}", report.format)?;
    writeln!(out, "fingerprint: {}", report.fingerprint)?;
    if let Some(variant) = &report.build_variant {
        writeln!(
            out,
            "build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    writeln!(out, "observed bytes: {}", report.observed_bytes)?;
    writeln!(out, "code section bytes: {}", report.code_section_bytes)?;
    writeln!(out, "data segment bytes: {}", report.data_segment_bytes)?;
    writeln!(out, "sections: {}", report.sections)?;
    writeln!(out, "imports: {}", report.imports)?;
    writeln!(out, "symbols: {}", report.symbols.len())?;
    writeln!(out, "entry points: {}", report.entry_points)?;
    writeln!(out, "calls: {}", report.calls)?;
    writeln!(out, "relocations: {}", report.relocations)?;
    writeln!(out, "source mappings: {}", report.source_mappings)?;
    if !report.archive_members.is_empty() {
        let failed = report
            .archive_members
            .iter()
            .filter(|member| member.parse_error.is_some())
            .count();
        writeln!(
            out,
            "archive members: {} parsed, {failed} unavailable",
            report.archive_members.len().saturating_sub(failed)
        )?;
        for member in report
            .archive_members
            .iter()
            .filter(|member| member.parse_error.is_some())
        {
            writeln!(
                out,
                "  {}: {}",
                member.name,
                member.parse_error.as_deref().unwrap_or_default()
            )?;
        }
    }
    if !report.source_maps.is_empty() {
        let resolved = report
            .source_maps
            .iter()
            .filter(|map| matches!(&map.status, SourceMapResolutionStatus::Resolved { .. }))
            .count();
        writeln!(
            out,
            "source maps: {resolved} resolved, {} unavailable",
            report.source_maps.len().saturating_sub(resolved)
        )?;
    }
    if let Some(correlation) = &report.correlation {
        writeln!(
            out,
            "source correlation: scan {}: {} mappings, {}/{} mapped symbols ({:.1}%), {} / {} mapped symbol bytes ({:.1}%), {} unmapped symbols ({} bytes)",
            correlation.source_run,
            correlation.mappings,
            correlation.mapped_symbols,
            correlation.artifact_symbols,
            correlation.mapping_coverage * 100.0,
            correlation.mapped_symbol_bytes,
            report.symbols.iter().map(|symbol| symbol.size).sum::<u64>(),
            correlation.mapped_symbol_bytes_ratio * 100.0,
            correlation.unmapped_symbols,
            correlation.unmapped_symbol_bytes,
        )?;
        if !correlation.unmapped_symbol_reasons.is_empty() {
            writeln!(out, "unmapped symbol reasons:")?;
            for (reason, count) in &correlation.unmapped_symbol_reasons {
                writeln!(out, "  {reason}: {count}")?;
            }
        }
        writeln!(
            out,
            "source identities: {}, {} without artifact evidence",
            correlation.source_entities, correlation.unmapped_sources
        )?;
        if !correlation.unmapped_source_reasons.is_empty() {
            writeln!(out, "unmapped source reasons:")?;
            for (reason, count) in &correlation.unmapped_source_reasons {
                writeln!(out, "  {reason}: {count}")?;
            }
        }
        if !correlation.clone_group_attributions.is_empty() {
            writeln!(
                out,
                "clone group byte attributions (observed, not savings):"
            )?;
            for attribution in &correlation.clone_group_attributions {
                writeln!(
                    out,
                    "  {} ({}): {} / {} noncanonical members attributed, duplicated bytes: {}",
                    attribution.clone_group_fingerprint,
                    attribution.source_build_variant_fingerprint,
                    attribution.attributed_noncanonical_members,
                    attribution.members.saturating_sub(1),
                    optional_bytes(attribution.duplicated_bytes),
                )?;
            }
        }
        if !correlation.estimated_refactor_savings.is_empty() {
            writeln!(out, "clone group refactoring estimates (not guaranteed):")?;
            for estimate in &correlation.estimated_refactor_savings {
                writeln!(
                    out,
                    "  {} (source {}, artifact {}): {} estimated bytes from {} attributed duplicate bytes; mapping {:?}, clone {:.3}, model {:?}, savings {:?}",
                    estimate.clone_group_fingerprint,
                    estimate.source_build_variant_fingerprint,
                    estimate.artifact_build_variant_fingerprint,
                    estimate.estimated_refactor_savings_bytes,
                    estimate.duplicated_bytes,
                    estimate.mapping_confidence,
                    estimate.clone_confidence,
                    estimate.model_confidence,
                    estimate.savings_confidence,
                )?;
                writeln!(out, "    model schema: {}", estimate.model_schema_version)?;
                for assumption in &estimate.assumptions {
                    writeln!(
                        out,
                        "    assumption: {}",
                        refactor_savings_assumption_text(assumption)
                    )?;
                }
            }
        }
        if !correlation.generic_origins.is_empty() {
            writeln!(out, "generic origins (observed symbol bytes):")?;
            for origin in &correlation.generic_origins {
                writeln!(
                    out,
                    "  {} [{}] ({}): {} observed bytes, {} normalized duplicate bytes, {} retained-size sum, {} symbols, {} instantiations across {} translation units",
                    origin.definition,
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    origin.observed_symbol_bytes,
                    origin.normalized_instruction_duplicated_bytes,
                    optional_bytes(origin.retained_size_sum),
                    origin.artifact_symbols,
                    origin.instantiations,
                    origin.translation_units,
                )?;
                for specialization in &origin.specializations {
                    let arguments = if specialization.type_arguments.is_empty() {
                        "unparsed arguments".to_owned()
                    } else {
                        specialization.type_arguments.join(", ")
                    };
                    writeln!(
                        out,
                        "    {}: {} observed bytes, {} symbols across {} translation units ({arguments})",
                        specialization.instantiation_key,
                        specialization.observed_symbol_bytes,
                        specialization.artifact_symbols,
                        specialization.translation_units,
                    )?;
                }
            }
        }
        if !correlation.macro_origins.is_empty() {
            writeln!(out, "macro origins (observed symbol bytes):")?;
            for origin in &correlation.macro_origins {
                writeln!(
                    out,
                    "  {} ({}): {} observed bytes across {} symbols ({})",
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    origin.observed_symbol_bytes,
                    origin.artifact_symbols,
                    origin.definition_paths.join(", "),
                )?;
            }
        }
    }
    writeln!(out, "data segments: {}", report.data_segments)?;
    writeln!(
        out,
        "duplicates: exact {} groups, {} observed duplicate bytes; normalized {} groups, {} observed duplicate bytes",
        report.duplicates.exact_groups,
        report.duplicates.exact_duplicated_bytes,
        report.duplicates.normalized_groups,
        report.duplicates.normalized_duplicated_bytes,
    )?;
    writeln!(out, "size categories:")?;
    writeln!(out, "  observed_bytes: {}", report.sizes.observed_bytes)?;
    writeln!(out, "  duplicated_bytes: {}", report.sizes.duplicated_bytes)?;
    writeln!(
        out,
        "  retained_bytes: {}",
        optional_bytes(report.sizes.retained_bytes)
    )?;
    writeln!(
        out,
        "  shared_dependency_bytes: {}",
        optional_bytes(report.sizes.shared_dependency_bytes)
    )?;
    writeln!(
        out,
        "  duplicated_data_bytes: {}",
        report.sizes.duplicated_data_bytes
    )?;
    writeln!(
        out,
        "  upper_bound_savings_bytes: {} (upper bound, not guaranteed)",
        optional_bytes(report.sizes.upper_bound_savings_bytes)
    )?;
    writeln!(
        out,
        "  estimated_refactor_savings_bytes: {}",
        optional_bytes(report.sizes.estimated_refactor_savings_bytes)
    )?;
    writeln!(
        out,
        "  verified_savings_bytes: {}",
        optional_bytes(report.sizes.verified_savings_bytes)
    )?;
    writeln!(
        out,
        "  clone_confidence: {:?}",
        report.sizes.clone_confidence
    )?;
    writeln!(
        out,
        "  savings_confidence: {:?}",
        report.sizes.savings_confidence
    )?;
    for assumption in &report.sizes.assumptions {
        writeln!(out, "  assumption: {assumption}")?;
    }
    if let Some(dead_code) = &report.dead_code {
        let verdict = if dead_code.definitive {
            "definitive"
        } else {
            "candidates"
        };
        writeln!(
            out,
            "dead code {verdict}: {} symbols",
            dead_code.symbols.len()
        )?;
        for symbol in &dead_code.symbols {
            writeln!(out, "  {symbol}")?;
        }
        for assumption in &dead_code.assumptions {
            writeln!(out, "  assumption: {assumption}")?;
        }
    } else {
        writeln!(
            out,
            "dead code: unavailable (no resolved exported root set)"
        )?;
    }
    if let Some(retained) = &report.retained_sizes {
        writeln!(out, "retained sizes (overlapping dominator regions):")?;
        for item in retained {
            writeln!(out, "  {} {} bytes", item.symbol, item.retained_bytes)?;
        }
    } else {
        writeln!(
            out,
            "retained sizes: unavailable (incomplete or ambiguous call graph)"
        )?;
    }
    render_groups("exact", &report.duplicate_groups.exact, out)?;
    render_groups("normalized", &report.duplicate_groups.normalized, out)?;
    render_groups("data", &report.duplicate_groups.data, out)?;
    if verbose {
        for symbol in &report.symbols {
            writeln!(
                out,
                "  symbol {} {} offset {} size {}{}",
                symbol.fingerprint,
                symbol.name.as_deref().unwrap_or("<unnamed>"),
                symbol.offset,
                symbol.size,
                if symbol.size_inferred {
                    " (inferred)"
                } else {
                    ""
                },
            )?;
        }
    }
    Ok(())
}

fn render_groups(
    kind: &str,
    groups: &[metrics::DuplicateGroup],
    out: &mut impl Write,
) -> Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    writeln!(out, "{kind} duplicate groups:")?;
    for group in groups {
        writeln!(
            out,
            "  {}: {} observed duplicate bytes, {} members",
            group.fingerprint,
            group.duplicated_bytes,
            group.members.len()
        )?;
        for member in &group.members {
            writeln!(
                out,
                "    {} offset {} size {}",
                member.symbol, member.offset, member.size
            )?;
        }
    }
    Ok(())
}

fn refactor_savings_assumption_text(assumption: &RefactorSavingsAssumption) -> String {
    match assumption {
        RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies } => {
            format!("shared implementation retains {copies} copy/copies")
        }
        RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes } => {
            format!("call overhead is {bytes} bytes per replaced member")
        }
        RefactorSavingsAssumption::InliningOutcomeUnknown => {
            "compiler inlining outcome is unknown".to_owned()
        }
        RefactorSavingsAssumption::LinkerIcfOutcomeUnknown => {
            "linker ICF outcome is unknown".to_owned()
        }
    }
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

#[allow(clippy::too_many_lines)] // CSV records intentionally remain together to preserve one fixed schema.
fn render_csv(report: &ArtifactReport, out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "record_type,path,format,kind,fingerprint,name,offset,size,duplicated_bytes,retained_bytes,dead_code_status,observed_bytes,source_run,mappings,mapped_symbols,unmapped_symbols,upper_bound_savings_bytes,estimated_refactor_savings_bytes,verified_savings_bytes,origin_build_variant_fingerprint,instantiations,translation_units"
    )?;
    let correlation = report.correlation.as_ref();
    let mut summary = artifact_csv_row();
    "summary".clone_into(&mut summary[0]);
    summary[1] = csv(&report.path);
    summary[2] = report.format.to_string();
    summary[4].clone_from(&report.fingerprint);
    summary[8] = report.sizes.duplicated_bytes.to_string();
    summary[9] = optional_bytes(report.sizes.retained_bytes);
    summary[11] = report.sizes.observed_bytes.to_string();
    summary[12] = correlation.map_or_else(String::new, |value| value.source_run.to_string());
    summary[13] = correlation.map_or_else(String::new, |value| value.mappings.to_string());
    summary[14] = correlation.map_or_else(String::new, |value| value.mapped_symbols.to_string());
    summary[15] = correlation.map_or_else(String::new, |value| value.unmapped_symbols.to_string());
    summary[16] = optional_bytes(report.sizes.upper_bound_savings_bytes);
    summary[17] = optional_bytes(report.sizes.estimated_refactor_savings_bytes);
    summary[18] = optional_bytes(report.sizes.verified_savings_bytes);
    write_artifact_csv_row(out, &summary)?;
    if let Some(variant) = &report.build_variant {
        let mut row = artifact_csv_row();
        "build-variant".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[4].clone_from(&variant.fingerprint);
        row[5] = csv(&variant.manifest_path);
        write_artifact_csv_row(out, &row)?;
    }
    for member in &report.archive_members {
        let mut row = artifact_csv_row();
        "archive-member".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[3] = member
            .format
            .map_or_else(|| "unknown".to_owned(), |format| format.to_string());
        row[4].clone_from(&member.fingerprint);
        row[5] = csv(&member.name);
        row[6] = member.offset.to_string();
        row[7] = member.size.to_string();
        row[10] = csv(member.parse_error.as_deref().unwrap_or("parsed"));
        write_artifact_csv_row(out, &row)?;
    }
    for (kind, groups) in [
        ("exact", &report.duplicate_groups.exact),
        ("normalized", &report.duplicate_groups.normalized),
        ("data", &report.duplicate_groups.data),
    ] {
        for group in groups {
            let mut row = artifact_csv_row();
            "duplicate-group".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            kind.clone_into(&mut row[3]);
            row[4] = group.fingerprint.to_string();
            row[8] = group.duplicated_bytes.to_string();
            write_artifact_csv_row(out, &row)?;
            for member in &group.members {
                let mut row = artifact_csv_row();
                "duplicate-member".clone_into(&mut row[0]);
                row[1] = csv(&report.path);
                row[2] = report.format.to_string();
                kind.clone_into(&mut row[3]);
                row[4] = member.symbol.to_string();
                row[6] = member.offset.to_string();
                row[7] = member.size.to_string();
                write_artifact_csv_row(out, &row)?;
            }
        }
    }
    if let Some(dead_code) = &report.dead_code {
        let status = if dead_code.definitive {
            "definitive"
        } else {
            "candidate"
        };
        for symbol in &dead_code.symbols {
            let mut row = artifact_csv_row();
            "dead-code".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            row[4] = symbol.to_string();
            status.clone_into(&mut row[10]);
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(retained) = &report.retained_sizes {
        for item in retained {
            let mut row = artifact_csv_row();
            "retained-size".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            row[4] = item.symbol.to_string();
            row[9] = item.retained_bytes.to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(correlation) = correlation {
        for origin in &correlation.generic_origins {
            let mut row = artifact_csv_row();
            "generic-origin".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            "generic-origin".clone_into(&mut row[3]);
            row[4].clone_from(&origin.origin_fingerprint);
            row[5].clone_from(&origin.definition);
            row[7] = origin.observed_symbol_bytes.to_string();
            row[8] = origin.normalized_instruction_duplicated_bytes.to_string();
            row[19].clone_from(&origin.origin_build_variant_fingerprint);
            row[20] = origin.instantiations.to_string();
            row[21] = origin.translation_units.to_string();
            write_artifact_csv_row(out, &row)?;
            for specialization in &origin.specializations {
                let mut row = artifact_csv_row();
                "generic-specialization".clone_into(&mut row[0]);
                row[1] = csv(&report.path);
                row[2] = report.format.to_string();
                "generic-origin".clone_into(&mut row[3]);
                row[4].clone_from(&origin.origin_fingerprint);
                row[5] = csv(&specialization.instantiation_key);
                row[7] = specialization.observed_symbol_bytes.to_string();
                row[19].clone_from(&origin.origin_build_variant_fingerprint);
                "1".clone_into(&mut row[20]);
                row[21] = specialization.translation_units.to_string();
                write_artifact_csv_row(out, &row)?;
            }
        }
        for origin in &correlation.macro_origins {
            let mut row = artifact_csv_row();
            "macro-origin".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            "macro-origin".clone_into(&mut row[3]);
            row[4].clone_from(&origin.origin_fingerprint);
            row[5] = csv(&origin.definition_paths.join(";"));
            row[7] = origin.observed_symbol_bytes.to_string();
            row[19].clone_from(&origin.origin_build_variant_fingerprint);
            row[20] = origin.artifact_symbols.to_string();
            row[21] = origin.definition_paths.len().to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    Ok(())
}

fn artifact_csv_row() -> Vec<String> {
    vec![String::new(); ARTIFACT_CSV_COLUMNS]
}

fn write_artifact_csv_row(out: &mut impl Write, row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), ARTIFACT_CSV_COLUMNS);
    writeln!(out, "{}", row.join(","))?;
    Ok(())
}

fn render_compare_csv(report: &ArtifactComparisonReport, out: &mut impl Write) -> Result<()> {
    writeln!(out, "kind,name,fingerprint,size_delta_bytes,members_delta")?;
    for delta in &report.symbol_deltas {
        writeln!(
            out,
            "{},{},{},{},",
            delta.kind,
            csv(delta.name.as_deref().unwrap_or("")),
            delta.fingerprint,
            delta.size_delta_bytes
        )?;
    }
    for delta in &report.duplicate_group_deltas {
        writeln!(
            out,
            "duplicate-{},,{},{},{}",
            delta.kind, delta.fingerprint, delta.duplicated_bytes_delta, delta.members_delta,
        )?;
    }
    if let Some(warning) = &report.build_variant_warning {
        writeln!(out, "build-variant-warning,{},,,", csv(warning))?;
    }
    if let Some(calibration) = &report.calibration {
        writeln!(
            out,
            "calibration,{},{},{},{}",
            calibration.source_run,
            calibration.clone_group_fingerprint,
            calibration.verified_savings_bytes,
            calibration.absolute_error_bytes,
        )?;
    }
    Ok(())
}

fn render_calibration_csv(report: &CalibrationSummaryReport, out: &mut impl Write) -> Result<()> {
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

fn render_calibration_text(report: &CalibrationSummaryReport, out: &mut impl Write) -> Result<()> {
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

fn csv(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.4}"))
}

fn signed_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| format!("{value:+.4}"))
}

fn render_compare_text(report: &ArtifactComparisonReport, out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "before: {} ({})",
        report.before.path, report.before.format
    )?;
    writeln!(
        out,
        "after: {} ({})",
        report.after.path, report.after.format
    )?;
    if let Some(variant) = &report.before.build_variant {
        writeln!(
            out,
            "before build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(variant) = &report.after.build_variant {
        writeln!(
            out,
            "after build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(warning) = &report.build_variant_warning {
        writeln!(out, "build variant warning: {warning}")?;
    }
    writeln!(out, "size_delta_bytes: {:+}", report.size_delta_bytes)?;
    writeln!(
        out,
        "verified_savings_bytes: {}",
        optional_bytes(report.verified_savings_bytes)
    )?;
    if let Some(calibration) = &report.calibration {
        writeln!(
            out,
            "calibration: scan {} group {} — estimated {} bytes, verified {} bytes, absolute error {} bytes, relative error {}",
            calibration.source_run,
            calibration.clone_group_fingerprint,
            calibration.estimated_refactor_savings_bytes,
            calibration.verified_savings_bytes,
            calibration.absolute_error_bytes,
            calibration
                .relative_error
                .map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.4}")),
        )?;
    }
    writeln!(
        out,
        "duplicated_code_delta_bytes: {:+}",
        report.duplicated_code_delta_bytes
    )?;
    writeln!(
        out,
        "duplicated_data_delta_bytes: {:+}",
        report.duplicated_data_delta_bytes
    )?;
    writeln!(
        out,
        "symbols: {} added, {} removed, {} named modified",
        report.symbol_changes.added,
        report.symbol_changes.removed,
        report.symbol_changes.modified_named_symbols,
    )?;
    for delta in &report.symbol_deltas {
        writeln!(
            out,
            "  {} {} {} {:+} bytes",
            delta.kind,
            delta.name.as_deref().unwrap_or("<unnamed>"),
            delta.fingerprint,
            delta.size_delta_bytes
        )?;
    }
    for delta in &report.duplicate_group_deltas {
        writeln!(
            out,
            "  duplicate {} {} {:+} bytes, {:+} members",
            delta.kind, delta.fingerprint, delta.duplicated_bytes_delta, delta.members_delta,
        )?;
    }
    for assumption in &report.assumptions {
        writeln!(out, "assumption: {assumption}")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use boon::{Compiler, Schemas};

    #[cfg(unix)]
    #[test]
    #[allow(clippy::disallowed_types)] // Exercises the actual worker-kill path.
    fn worker_deadline_terminates_a_nonresponsive_parser_process() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("start deliberately nonresponsive worker");
        let error = wait_for_worker(&mut child, Duration::from_millis(1))
            .expect_err("deadline must terminate the worker");
        assert!(
            error
                .to_string()
                .contains("exceeded the configured timeout"),
            "unexpected error: {error}"
        );
        assert!(child.try_wait().expect("query terminated worker").is_some());
    }

    fn assert_valid_schema(schema_uri: &str, schema: &str, value: &serde_json::Value) {
        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();
        let schema = serde_json::from_str(schema).unwrap();
        compiler.add_resource(schema_uri, schema).unwrap();
        let index = compiler.compile(schema_uri, &mut schemas).unwrap();
        schemas.validate(value, index).unwrap();
    }

    #[test]
    fn clang_template_display_names_match_only_demangled_function_templates() {
        assert_eq!(
            normalized_clang_template_display_name("clang-display-v1:templates::twice(int)"),
            normalized_clang_template_display_name("int templates::twice<int>(int)")
        );
        assert_eq!(
            normalized_clang_template_display_name("clang-display-v1:templates::twice(long)"),
            normalized_clang_template_display_name("long templates::twice<long>(long)")
        );
        assert_ne!(
            normalized_clang_template_display_name("clang-display-v1:templates::twice(int)"),
            normalized_clang_template_display_name("long templates::twice<long>(long)")
        );
        assert_ne!(
            normalized_clang_template_display_name("clang-display-v1:templates::twice<>(long)"),
            normalized_clang_template_display_name("int templates::twice<int>(int)")
        );
        assert_eq!(
            normalized_clang_template_display_name("templates::ordinary(int)"),
            None
        );
        assert_eq!(
            normalized_clang_template_display_name("templates::Buffer<int, 4>"),
            None
        );
        assert_eq!(
            normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
            normalized_clang_template_owner_name(
                "int templates::Buffer<int, 4ul>::at(unsigned long) const"
            )
        );
        assert_eq!(
            normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
            normalized_clang_template_owner_name(
                "int templates::Buffer<int, (unsigned long)4>::at(unsigned long) const"
            )
        );
        assert_ne!(
            normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
            normalized_clang_template_owner_name(
                "int templates::Buffer<int, 8ul>::at(unsigned long) const"
            )
        );
        assert_eq!(
            normalized_clang_template_owner_name("clang-display-v1:templates::twice<>(int)"),
            None
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the source-run boundary and all rejected candidates explicit"
    )]
    fn dwarf_locations_map_only_units_in_the_explicit_source_run() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("entry".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/main.cpp".to_owned(),
                line: Some(12),
                column: Some(3),
            }],
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol.clone());
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/main.cpp".to_owned(),
            name: Some("entry".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        }];
        let fragments = [SourceFragmentIdentity {
            fingerprint: [6; 16],
            finding_id: [16; 16],
            clone_group_fingerprint: [17; 16],
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/main.cpp".to_owned(),
            start_line: Some(11),
            end_line: Some(13),
        }];
        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert_eq!(rows.mappings.len(), 2);
        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(
            rows.mappings[0].artifact_symbol_fingerprint,
            symbol.fingerprint.as_bytes()
        );
        assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(rows.mappings[0].source_build_variant_fingerprint, [4; 16]);
        assert_eq!(rows.mappings[0].build_variant_fingerprint, [5; 16]);
        assert_eq!(
            rows.mappings[0].evidence.confidence(),
            Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Exact)
        );
        assert_eq!(
            rows.mappings[1].source_kind,
            ArtifactAnalysisSourceKind::Fragment
        );
        assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);
        assert_eq!(rows.mappings[1].attributed_bytes, Some(8));
        let report =
            ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, Some(10), None)
                .with_correlation(Some(ArtifactCorrelationReport::from_rows(
                    7, &artifact, &rows,
                )));
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"schema_version\":\"artifact-report-v1\""));
        assert!(json.contains("\"source_run\":7"));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains(
            "source correlation: scan 7: 2 mappings, 1/1 mapped symbols (100.0%), 8 / 8 mapped symbol bytes (100.0%), 0 unmapped symbols (0 bytes)"
        ));
        assert!(text.contains("source identities: 2, 0 without artifact evidence"));
        let mut csv_out = Vec::new();
        render_csv(&report, &mut csv_out).unwrap();
        let csv = String::from_utf8(csv_out).unwrap();
        assert!(csv.contains("source_run,mappings,mapped_symbols,unmapped_symbols"));
        let mut rows = csv.lines();
        let header: Vec<_> = rows.next().unwrap().split(',').collect();
        let summary: Vec<_> = rows.next().unwrap().split(',').collect();
        for (field, expected) in [
            ("source_run", "7"),
            ("mappings", "2"),
            ("mapped_symbols", "1"),
            ("unmapped_symbols", "0"),
        ] {
            let index = header.iter().position(|value| *value == field).unwrap();
            assert_eq!(summary[index], expected, "unexpected {field} value");
        }
    }

    #[test]
    fn pdb_location_maps_with_pdb_evidence() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                b"pdb-location",
            ),
            name: Some("entry".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Pdb,
                source: "/work/src/main.cpp".to_owned(),
                line: Some(12),
                column: Some(3),
            }],
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::PeCoff, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/main.cpp".to_owned(),
            name: Some("entry".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert_eq!(rows.mappings.len(), 1);
        assert_eq!(
            rows.mappings[0].evidence.facts,
            vec![MappingEvidenceFact::Pdb {
                source_path: "/work/src/main.cpp".to_owned(),
            }]
        );
    }

    #[test]
    fn dwarf_frame_without_line_does_not_map_clone_fragments() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                b"missing-line",
            ),
            name: Some("entry".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/main.cpp".to_owned(),
                line: None,
                column: None,
            }],
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/main.cpp".to_owned(),
            name: Some("entry".to_owned()),
            start_line: Some(1),
            end_line: Some(40),
        }];
        let fragments = [
            SourceFragmentIdentity {
                fingerprint: [6; 16],
                finding_id: [16; 16],
                clone_group_fingerprint: [17; 16],
                is_canonical: false,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/main.cpp".to_owned(),
                start_line: Some(10),
                end_line: Some(13),
            },
            SourceFragmentIdentity {
                fingerprint: [7; 16],
                finding_id: [18; 16],
                clone_group_fingerprint: [17; 16],
                is_canonical: true,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/main.cpp".to_owned(),
                start_line: Some(20),
                end_line: Some(23),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert_eq!(rows.mappings.len(), 1);
        assert_eq!(
            rows.mappings[0].source_kind,
            ArtifactAnalysisSourceKind::Unit
        );
        assert!(
            rows.mappings
                .iter()
                .all(|mapping| mapping.source_kind != ArtifactAnalysisSourceKind::Fragment)
        );
        assert_eq!(
            rows.unmapped_sources
                .iter()
                .filter(|source| source.source_kind == ArtifactAnalysisSourceKind::Fragment)
                .map(|source| source.source_instance_fingerprint)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[16; 16], [18; 16]])
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps every multi-origin assertion together"
    )]
    fn inline_stack_retains_every_source_origin_without_double_counting_symbol_bytes() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol", b"inlined",
            ),
            name: Some("combined".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 12,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: vec![
                codehelion_artifact::ArtifactInlineFrame {
                    evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                    source: "/work/src/a.cpp".to_owned(),
                    line: Some(10),
                    column: None,
                },
                codehelion_artifact::ArtifactInlineFrame {
                    evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                    source: "/work/src/b.cpp".to_owned(),
                    line: Some(20),
                    column: None,
                },
            ],
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [
            SourceUnitIdentity {
                fingerprint: [1; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/a.cpp".to_owned(),
                name: Some("a".to_owned()),
                start_line: Some(1),
                end_line: Some(15),
            },
            SourceUnitIdentity {
                fingerprint: [2; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/b.cpp".to_owned(),
                name: Some("b".to_owned()),
                start_line: Some(16),
                end_line: Some(25),
            },
        ];
        let fragments = [
            SourceFragmentIdentity {
                fingerprint: [5; 16],
                finding_id: [6; 16],
                clone_group_fingerprint: [7; 16],
                is_canonical: false,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/a.cpp".to_owned(),
                start_line: Some(9),
                end_line: Some(11),
            },
            SourceFragmentIdentity {
                fingerprint: [8; 16],
                finding_id: [9; 16],
                clone_group_fingerprint: [7; 16],
                is_canonical: true,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/b.cpp".to_owned(),
                start_line: Some(19),
                end_line: Some(21),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &[],
            &[],
            [10; 16],
        );

        assert_eq!(rows.mappings.len(), 4);
        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(
            rows.mappings
                .iter()
                .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Unit)
                .map(|mapping| mapping.source_fingerprint)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[1; 16], [2; 16]])
        );
        assert_eq!(
            rows.mappings
                .iter()
                .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Fragment)
                .map(|mapping| mapping.source_instance_fingerprint)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[6; 16], [9; 16]])
        );
        assert!(
            rows.mappings
                .iter()
                .all(|mapping| mapping.attributed_bytes.is_none())
        );
    }

    #[test]
    fn source_findings_without_artifact_evidence_are_explicitly_unmapped() {
        let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/unmatched.cpp".to_owned(),
            name: Some("unmatched".to_owned()),
            start_line: Some(1),
            end_line: Some(2),
        }];
        let fragments = [SourceFragmentIdentity {
            fingerprint: [6; 16],
            finding_id: [16; 16],
            clone_group_fingerprint: [17; 16],
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/unmatched.cpp".to_owned(),
            start_line: Some(1),
            end_line: Some(2),
        }];
        let unit_instance = source_unit_instance_fingerprint(&units[0]);

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.mappings.is_empty());
        assert_eq!(
            rows.unmapped_sources,
            vec![
                ArtifactAnalysisUnmappedSource {
                    source_kind: ArtifactAnalysisSourceKind::Unit,
                    source_fingerprint: [3; 16],
                    source_instance_fingerprint: unit_instance,
                    source_build_variant_fingerprint: [4; 16],
                    reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
                },
                ArtifactAnalysisUnmappedSource {
                    source_kind: ArtifactAnalysisSourceKind::Fragment,
                    source_fingerprint: [6; 16],
                    source_instance_fingerprint: [16; 16],
                    source_build_variant_fingerprint: [4; 16],
                    reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
                },
            ]
        );
        let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
        assert_eq!(correlation.source_entities, 2);
        assert_eq!(correlation.unmapped_sources, 2);
        assert_eq!(
            correlation.unmapped_source_reasons,
            BTreeMap::from([("no_artifact_evidence".to_owned(), 2)])
        );
    }

    #[test]
    fn equal_content_source_units_keep_distinct_unmapped_occurrences() {
        let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        let units = [
            SourceUnitIdentity {
                fingerprint: [3; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/left.cpp".to_owned(),
                name: Some("duplicate".to_owned()),
                start_line: Some(1),
                end_line: Some(3),
            },
            SourceUnitIdentity {
                fingerprint: [3; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/right.cpp".to_owned(),
                name: Some("duplicate".to_owned()),
                start_line: Some(1),
                end_line: Some(3),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert_eq!(rows.unmapped_sources.len(), 2);
        assert_ne!(
            rows.unmapped_sources[0].source_instance_fingerprint,
            rows.unmapped_sources[1].source_instance_fingerprint
        );
    }

    #[test]
    fn demangled_name_maps_one_named_unit_as_weak_evidence() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("project::Widget::render(int)".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/widget.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 1);
        assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(
            rows.mappings[0].evidence.confidence(),
            Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Weak)
        );
        assert_eq!(
            rows.mappings[0].evidence.facts,
            vec![MappingEvidenceFact::SymbolName {
                source_symbol: "render".to_owned(),
                artifact_symbol: "render".to_owned(),
            }]
        );
    }

    #[test]
    fn macro_definition_anchor_beats_an_unrelated_unit_label() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("project::render()".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/widget.cpp".to_owned(),
            name: Some("unrelated".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        }];
        let resolved = [SourceResolvedSymbol {
            name: "project::render".to_owned(),
            file_path: "/work/src/widget.cpp".to_owned(),
            line: 12,
            macro_definition: Some(codehelion_store::query::SourceMacroDefinition {
                file_path: "/work/src/widget.cpp".to_owned(),
                line: 12,
            }),
        }];
        let fragments = [SourceFragmentIdentity {
            fingerprint: [6; 16],
            finding_id: [16; 16],
            clone_group_fingerprint: [17; 16],
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/widget.cpp".to_owned(),
            start_line: Some(11),
            end_line: Some(13),
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &resolved,
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 2);
        assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(
            rows.mappings[0].evidence.facts,
            vec![
                MappingEvidenceFact::SymbolName {
                    source_symbol: "render".to_owned(),
                    artifact_symbol: "render".to_owned(),
                },
                MappingEvidenceFact::MacroOrigin {
                    definition_path: "/work/src/widget.cpp".to_owned(),
                },
            ]
        );
        assert_eq!(
            rows.mappings[1].source_kind,
            ArtifactAnalysisSourceKind::Fragment
        );
        assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);
        let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
        assert_eq!(correlation.macro_origins.len(), 1);
        assert_eq!(correlation.macro_origins[0].artifact_symbols, 1);
        assert_eq!(correlation.macro_origins[0].observed_symbol_bytes, 8);
        assert_eq!(
            correlation.macro_origins[0].definition_paths,
            vec!["/work/src/widget.cpp"]
        );
        let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
            .with_correlation(Some(correlation));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("macro origins (observed symbol bytes):")
        );
        let mut csv_output = Vec::new();
        render_csv(&report, &mut csv_output).unwrap();
        assert!(
            String::from_utf8(csv_output)
                .unwrap()
                .contains("macro-origin,fixture.so,elf,macro-origin")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The fixture keeps both call-graph sides visible.
    fn matching_static_calls_add_independent_neighborhood_evidence() {
        let caller = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol", b"caller",
            ),
            name: Some("crate::render()".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let target = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol", b"target",
            ),
            name: Some("crate::escape()".to_owned()),
            exported: false,
            section: Some(1),
            offset: 8,
            size: 4,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols = vec![caller.clone(), target.clone()];
        artifact.calls.push(codehelion_artifact::ArtifactCall {
            caller: caller.fingerprint,
            target: Some(target.fingerprint),
            unresolved: None,
        });
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/render.rs".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(1),
            end_line: Some(20),
        }];
        let resolved_symbols = [SourceResolvedSymbol {
            name: "crate::render".to_owned(),
            file_path: "/work/src/render.rs".to_owned(),
            line: 1,
            macro_definition: None,
        }];
        let resolved_calls = [SourceResolvedCall {
            target_name: "crate::escape".to_owned(),
            file_path: "/work/src/render.rs".to_owned(),
            line: 3,
        }];
        let fragments = [SourceFragmentIdentity {
            fingerprint: [6; 16],
            finding_id: [16; 16],
            clone_group_fingerprint: [17; 16],
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/render.rs".to_owned(),
            start_line: Some(1),
            end_line: Some(10),
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &[],
            &resolved_symbols,
            &resolved_calls,
            [5; 16],
        );

        let mapping = rows
            .mappings
            .iter()
            .find(|mapping| mapping.artifact_symbol_fingerprint == caller.fingerprint.as_bytes())
            .unwrap();
        assert_eq!(
            mapping.evidence.facts,
            vec![
                MappingEvidenceFact::SymbolName {
                    source_symbol: "render".to_owned(),
                    artifact_symbol: "render".to_owned(),
                },
                MappingEvidenceFact::CallGraphNeighborhood,
            ]
        );
        assert_eq!(
            mapping.evidence.confidence(),
            Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
        );
        let fragment_mapping = rows
            .mappings
            .iter()
            .find(|mapping| {
                mapping.artifact_symbol_fingerprint == caller.fingerprint.as_bytes()
                    && mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
            })
            .unwrap();
        assert_eq!(
            fragment_mapping.evidence.confidence(),
            Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps source-unit, fragment, and translation-unit assertions together"
    )]
    fn exact_generic_instantiation_key_maps_the_definition_origin() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("crate::Buffer::push::<String>".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/generic.rs".to_owned(),
            name: Some("unrelated".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        }];
        let instantiations = [
            SourceInstantiation {
                definition: "crate::Buffer::push".to_owned(),
                artifact_match_key: None,
                instantiation_key: "crate::Buffer::push<String>".to_owned(),
                file_path: "/work/src/generic.rs".to_owned(),
                line: 12,
                definition_end_line: None,
                translation_unit: "src/one.rs".to_owned(),
            },
            SourceInstantiation {
                definition: "crate::Buffer::push".to_owned(),
                artifact_match_key: None,
                instantiation_key: "crate::Buffer::push<String>".to_owned(),
                file_path: "/work/src/generic.rs".to_owned(),
                line: 12,
                definition_end_line: None,
                translation_unit: "src/two.rs".to_owned(),
            },
        ];
        let fragments = [SourceFragmentIdentity {
            fingerprint: [6; 16],
            finding_id: [16; 16],
            clone_group_fingerprint: [17; 16],
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/generic.rs".to_owned(),
            start_line: Some(11),
            end_line: Some(13),
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &fragments,
            &instantiations,
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 2);
        assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(
            rows.mappings[0].evidence.facts,
            vec![MappingEvidenceFact::GenericOrigin {
                definition: "crate::Buffer::push".to_owned(),
                instantiation_key: "crate::Buffer::push<String>".to_owned(),
                translation_units: vec!["src/one.rs".to_owned(), "src/two.rs".to_owned()],
            }]
        );
        assert_eq!(
            rows.mappings[1].source_kind,
            ArtifactAnalysisSourceKind::Fragment
        );
        assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);

        let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
        assert_eq!(correlation.generic_origins.len(), 1);
        assert_eq!(
            correlation.generic_origins[0].origin_fingerprint,
            fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
        );
        assert_eq!(
            correlation.generic_origins[0].definition,
            "crate::Buffer::push"
        );
        assert_eq!(correlation.generic_origins[0].instantiations, 1);
        assert_eq!(correlation.generic_origins[0].translation_units, 2);
        assert_eq!(correlation.generic_origins[0].artifact_symbols, 1);
        assert_eq!(correlation.generic_origins[0].observed_symbol_bytes, 8);
        assert_eq!(
            correlation.generic_origins[0].normalized_instruction_duplicated_bytes,
            0
        );
        assert_eq!(correlation.generic_origins[0].retained_size_sum, None);
        assert_eq!(correlation.generic_origins[0].specializations.len(), 1);
        assert_eq!(
            correlation.generic_origins[0].specializations[0].translation_units,
            2
        );
        assert_eq!(
            correlation.generic_origins[0].specializations[0].instantiation_key,
            "crate::Buffer::push<String>"
        );
        assert_eq!(
            correlation.generic_origins[0].specializations[0].type_arguments,
            vec!["String"]
        );
        let mut text = Vec::new();
        render_text(
            &ArtifactReport::from_ir(std::path::Path::new("fixture.so"), &artifact, None, None)
                .with_correlation(Some(correlation.clone())),
            false,
            &mut text,
        )
        .unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("1 instantiations across 2 translation units")
        );
        assert_eq!(
            correlation.generic_origins[0].specializations[0].observed_symbol_bytes,
            8
        );

        let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
            .with_correlation(Some(correlation));
        let mut csv_output = Vec::new();
        render_csv(&report, &mut csv_output).unwrap();
        let csv_output = String::from_utf8(csv_output).unwrap();
        let mut csv_rows = csv_output.lines();
        let width = csv_rows.next().unwrap().split(',').count();
        assert!(csv_rows.all(|row| row.split(',').count() == width));
        assert!(csv_output.contains(&format!(
            "generic-origin,fixture.so,elf,generic-origin,{},crate::Buffer::push,,8,0",
            fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
        )));
        assert!(csv_output.contains(
            &format!(
                "generic-specialization,fixture.so,elf,generic-origin,{},crate::Buffer::push<String>,,8",
                fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
            )
        ));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("generic origins (observed symbol bytes):")
        );
    }

    #[test]
    fn generic_origin_maps_one_source_to_each_instantiated_symbol() {
        let first = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"u8"),
            name: Some("crate::render<u8>".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let second = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"u16"),
            name: Some("crate::render<u16>".to_owned()),
            offset: 8,
            ..first.clone()
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols = vec![first.clone(), second.clone()];
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "src/generic.rs".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        }];
        let instantiations = [
            SourceInstantiation {
                definition: "crate::render".to_owned(),
                artifact_match_key: None,
                instantiation_key: "crate::render<u8>".to_owned(),
                file_path: "/work/src/generic.rs".to_owned(),
                line: 2,
                definition_end_line: None,
                translation_unit: "src/first.rs".to_owned(),
            },
            SourceInstantiation {
                definition: "crate::render".to_owned(),
                artifact_match_key: None,
                instantiation_key: "crate::render<u16>".to_owned(),
                file_path: "/work/src/generic.rs".to_owned(),
                line: 2,
                definition_end_line: None,
                translation_unit: "src/second.rs".to_owned(),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &instantiations,
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 2);
        assert!(
            rows.mappings
                .iter()
                .all(|mapping| mapping.source_fingerprint == [3; 16])
        );
        assert_eq!(
            rows.mappings
                .iter()
                .map(|mapping| mapping.artifact_symbol_fingerprint)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first.fingerprint.as_bytes(), second.fingerprint.as_bytes()])
        );
        assert!(rows.mappings.iter().all(|mapping| {
            mapping
                .evidence
                .facts
                .iter()
                .any(|fact| matches!(fact, MappingEvidenceFact::GenericOrigin { .. }))
        }));
    }

    #[test]
    fn clang_template_display_key_maps_only_its_demangled_specialization() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                b"twice-int",
            ),
            name: Some("int templates::twice<int>(int)".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "include/templates.hpp".to_owned(),
            name: Some("unrelated".to_owned()),
            start_line: Some(1),
            end_line: Some(20),
        }];
        let instantiations = [
            SourceInstantiation {
                definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
                artifact_match_key: Some("clang-display-v1:templates::twice<>(int)".to_owned()),
                instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#I>#I#".to_owned(),
                file_path: "/work/include/templates.hpp".to_owned(),
                line: 4,
                definition_end_line: None,
                translation_unit: "src/templates.cpp".to_owned(),
            },
            SourceInstantiation {
                definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
                artifact_match_key: Some("clang-display-v1:templates::twice<>(long)".to_owned()),
                instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#L>#L#".to_owned(),
                file_path: "/work/include/templates.hpp".to_owned(),
                line: 4,
                definition_end_line: None,
                translation_unit: "src/templates.cpp".to_owned(),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &instantiations,
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 1);
        assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(
            rows.mappings[0].evidence.facts,
            vec![MappingEvidenceFact::GenericOrigin {
                definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
                instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#I>#I#".to_owned(),
                translation_units: vec!["src/templates.cpp".to_owned()],
            }]
        );
    }

    #[test]
    fn clang_template_owner_key_maps_only_its_member_specialization() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                b"buffer-int-four",
            ),
            name: Some("int templates::Buffer<int, 4ul>::at(unsigned long) const".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let units = [SourceUnitIdentity {
            fingerprint: [3; 16],
            build_variant_fingerprint: [4; 16],
            file_path: "include/templates.hpp".to_owned(),
            name: Some("unrelated".to_owned()),
            start_line: Some(10),
            end_line: Some(15),
        }];
        let instantiations = [
            SourceInstantiation {
                definition: "c:@N@templates@S@Buffer>#I#VI4".to_owned(),
                artifact_match_key: Some("clang-display-v1:templates::Buffer<int, 4>".to_owned()),
                instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI4".to_owned(),
                file_path: "/work/include/templates.hpp".to_owned(),
                line: 8,
                definition_end_line: Some(20),
                translation_unit: "src/templates.cpp".to_owned(),
            },
            SourceInstantiation {
                definition: "c:@N@templates@S@Buffer>#I#VI8".to_owned(),
                artifact_match_key: Some("clang-display-v1:templates::Buffer<int, 8>".to_owned()),
                instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI8".to_owned(),
                file_path: "/work/include/templates.hpp".to_owned(),
                line: 8,
                definition_end_line: Some(20),
                translation_unit: "src/templates.cpp".to_owned(),
            },
        ];

        let mappings = correlate_generic_origin(
            &symbol,
            FilePath::new("/work"),
            &units,
            &[],
            &instantiations,
            [5; 16],
        );

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].source_fingerprint, [3; 16]);
        assert_eq!(
            mappings[0].evidence.facts,
            vec![MappingEvidenceFact::GenericOrigin {
                definition: "c:@N@templates@S@Buffer>#I#VI4".to_owned(),
                instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI4".to_owned(),
                translation_units: vec!["src/templates.cpp".to_owned()],
            }]
        );
    }

    #[test]
    fn conflicting_generic_origin_and_name_candidates_remain_ambiguous() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("crate::render<u8>".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [
            SourceUnitIdentity {
                fingerprint: [3; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/generic.rs".to_owned(),
                name: Some("generic_origin".to_owned()),
                start_line: Some(1),
                end_line: Some(10),
            },
            SourceUnitIdentity {
                fingerprint: [6; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/named.rs".to_owned(),
                name: Some("render".to_owned()),
                start_line: Some(1),
                end_line: Some(10),
            },
        ];
        let instantiations = [SourceInstantiation {
            definition: "crate::render".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::render<u8>".to_owned(),
            file_path: "/work/src/generic.rs".to_owned(),
            line: 2,
            definition_end_line: None,
            translation_unit: "src/lib.rs".to_owned(),
        }];
        let resolved_symbols = [SourceResolvedSymbol {
            name: "crate::render".to_owned(),
            file_path: "/work/src/named.rs".to_owned(),
            line: 2,
            macro_definition: None,
        }];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &instantiations,
            &resolved_symbols,
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 2);
        assert_eq!(
            rows.mappings
                .iter()
                .map(|mapping| mapping.source_fingerprint)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[3; 16], [6; 16]])
        );
        assert!(rows.mappings.iter().all(|mapping| {
            mapping.evidence.has_conflict
                && mapping.evidence.confidence()
                    == Some(
                        codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous,
                    )
        }));
    }

    #[test]
    fn linker_map_recovers_an_unmapped_unit_without_basename_guessing() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("render".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol.clone());
        let units = [
            SourceUnitIdentity {
                fingerprint: [3; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/render.cpp".to_owned(),
                name: Some("render".to_owned()),
                start_line: Some(1),
                end_line: Some(10),
            },
            SourceUnitIdentity {
                fingerprint: [6; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "other/render.cpp".to_owned(),
                name: Some("unrelated".to_owned()),
                start_line: Some(1),
                end_line: Some(10),
            },
        ];
        let entries = parse_linker_map(
            " .text.render 0x0000000000001000 0x8 build/CMakeFiles/app.dir/src/render.cpp.o\n\
             0x0000000000001000                render\n",
        );
        assert_eq!(
            entries,
            vec![LinkerMapEntry {
                symbol: "render".to_owned(),
                object_path: "build/CMakeFiles/app.dir/src/render.cpp.o".to_owned(),
            }]
        );
        let mut rows = CorrelationRows {
            unmapped_symbols: vec![ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
            }],
            ..CorrelationRows::default()
        };

        enrich_linker_map_evidence(&artifact, &units, &entries, [5; 16], &mut rows);

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 1);
        let mapping = &rows.mappings[0];
        assert_eq!(mapping.source_fingerprint, [3; 16]);
        assert_eq!(mapping.evidence.candidate_count, 1);
        assert_eq!(
            mapping.evidence.facts,
            vec![
                MappingEvidenceFact::SymbolName {
                    source_symbol: "render".to_owned(),
                    artifact_symbol: "render".to_owned(),
                },
                MappingEvidenceFact::LinkerMap {
                    object_path: "build/CMakeFiles/app.dir/src/render.cpp.o".to_owned(),
                },
            ]
        );
        assert_eq!(
            mapping.evidence.confidence(),
            Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
        );
    }

    #[test]
    fn generic_origin_metrics_keep_normalized_duplicates_separate_from_savings() {
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        for (name, size) in [("one", 8), ("two", 4)] {
            artifact.symbols.push(codehelion_artifact::ArtifactSymbol {
                fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                    "symbol",
                    name.as_bytes(),
                ),
                name: Some(name.to_owned()),
                exported: false,
                section: Some(1),
                offset: 0,
                size,
                size_inferred: false,
                code: Vec::new(),
                normalized: Some(codehelion_artifact::NormalizedInstructions {
                    version: "test-normalization-v1".to_owned(),
                    bytes: vec![1, 2, 3],
                }),
                inline_stack: Vec::new(),
            });
        }
        let fingerprints = artifact
            .symbols
            .iter()
            .map(|symbol| symbol.fingerprint.as_bytes())
            .collect();

        assert_eq!(
            generic_origin_metrics(&artifact, &fingerprints),
            (12, 4, None)
        );
    }

    #[test]
    fn generic_type_arguments_keep_nested_specializations_intact() {
        assert_eq!(
            generic_type_arguments("crate::make<Vec<Result<String, Error>>, 4>"),
            vec!["Vec<Result<String, Error>>", "4"]
        );
        assert!(generic_type_arguments("crate::make<>").is_empty());
        assert!(generic_type_arguments("crate::make<String").is_empty());
    }

    #[test]
    fn group_attribution_reports_exact_noncanonical_byte_splits() {
        let fragments = vec![
            SourceFragmentIdentity {
                fingerprint: [2; 16],
                finding_id: [10; 16],
                clone_group_fingerprint: [7; 16],
                is_canonical: true,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/one.rs".to_owned(),
                start_line: Some(1),
                end_line: Some(3),
            },
            SourceFragmentIdentity {
                fingerprint: [2; 16],
                finding_id: [11; 16],
                clone_group_fingerprint: [7; 16],
                is_canonical: false,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: "src/two.rs".to_owned(),
                start_line: Some(1),
                end_line: Some(3),
            },
        ];
        let rows = CorrelationRows {
            mappings: vec![ArtifactAnalysisMapping {
                schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                artifact_symbol_fingerprint: [3; 16],
                source_kind: ArtifactAnalysisSourceKind::Fragment,
                source_fingerprint: [2; 16],
                source_instance_fingerprint: [11; 16],
                source_build_variant_fingerprint: [4; 16],
                evidence: MappingEvidence::new(
                    vec![MappingEvidenceFact::Dwarf {
                        source_path: "src/two.rs".to_owned(),
                    }],
                    1,
                    false,
                ),
                attributed_bytes: Some(9),
                build_variant_fingerprint: [5; 16],
            }],
            unmapped_symbols: Vec::new(),
            unmapped_sources: Vec::new(),
            clone_fragments: fragments,
        };

        assert_eq!(
            clone_group_attributions(&rows)
                .into_iter()
                .map(|attribution| (
                    attribution.members,
                    attribution.attributed_noncanonical_members,
                    attribution.duplicated_bytes,
                ))
                .collect::<Vec<_>>(),
            vec![(2, 1, Some(9))]
        );
        let savings = clone_group_savings(&rows);
        assert_eq!(savings.len(), 1);
        assert_eq!(savings[0].duplicated_bytes, 9);
        assert_eq!(savings[0].estimated_refactor_savings_bytes, 9);
        assert_eq!(savings[0].mapping_confidence, EvidenceConfidence::High);
        assert_eq!(savings[0].model_confidence, EvidenceConfidence::Low);
        assert_eq!(savings[0].savings_confidence, EvidenceConfidence::Low);
        assert_eq!(
            serde_json::to_value(&savings[0]).unwrap()["assumptions"][0]["kind"],
            "shared_implementation_retains_copies"
        );
        assert_eq!(
            savings[0].source_build_variant_fingerprint,
            fingerprint_hex([4; 16])
        );
        assert_eq!(
            savings[0].artifact_build_variant_fingerprint,
            fingerprint_hex([5; 16])
        );
        let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
            .with_correlation(Some(ArtifactCorrelationReport::from_rows(
                7, &artifact, &rows,
            )));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("source 04040404040404040404040404040404"));
        assert!(text.contains("artifact 05050505050505050505050505050505"));
        assert!(text.contains("model schema: refactor-savings-model-v1"));
        assert!(text.contains("shared implementation retains 1 copy/copies"));
        assert_eq!(
            serde_json::to_vec(&savings).unwrap(),
            serde_json::to_vec(&clone_group_savings(&rows)).unwrap()
        );
    }

    #[test]
    fn refactoring_estimate_keeps_negative_overhead_outcomes_visible() {
        let mut model = refactor_savings_model();
        model.call_overhead_per_replaced_member_bytes = 12;
        assert_eq!(estimate_refactor_savings_bytes(9, 1, &model), -3);
    }

    #[test]
    fn same_named_units_remain_ambiguous_name_candidates() {
        let symbol = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("project::render()".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 8,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols.push(symbol);
        let units = [
            SourceUnitIdentity {
                fingerprint: [3; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/left.cpp".to_owned(),
                name: Some("render".to_owned()),
                start_line: Some(10),
                end_line: Some(20),
            },
            SourceUnitIdentity {
                fingerprint: [6; 16],
                build_variant_fingerprint: [4; 16],
                file_path: "src/right.cpp".to_owned(),
                name: Some("render".to_owned()),
                start_line: Some(30),
                end_line: Some(40),
            },
        ];

        let rows = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &[],
            &[],
            &[],
            [5; 16],
        );

        assert!(rows.unmapped_symbols.is_empty());
        assert_eq!(rows.mappings.len(), 2);
        assert!(rows.mappings.iter().all(|mapping| {
            mapping.evidence.confidence()
                == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous)
                && mapping.evidence.candidate_count == 2
        }));

        let repeated = correlate_debug_locations(
            &artifact,
            FilePath::new("/work"),
            &units,
            &[],
            &[],
            &[],
            &[],
            [5; 16],
        );
        assert_eq!(rows, repeated);
        assert_eq!(
            serde_json::to_vec(&ArtifactCorrelationReport::from_rows(7, &artifact, &rows)).unwrap(),
            serde_json::to_vec(&ArtifactCorrelationReport::from_rows(
                7, &artifact, &repeated
            ))
            .unwrap()
        );
    }

    #[test]
    fn correlation_report_keeps_unmapped_bytes_and_reasons_visible() {
        let first = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
            name: Some("one".to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size: 5,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let second = codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"two"),
            name: Some("two".to_owned()),
            exported: false,
            section: Some(1),
            offset: 5,
            size: 7,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            inline_stack: Vec::new(),
        };
        let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
        artifact.symbols = vec![first.clone(), second.clone()];
        let rows = CorrelationRows {
            mappings: Vec::new(),
            unmapped_symbols: vec![
                ArtifactAnalysisUnmappedSymbol {
                    artifact_symbol_fingerprint: first.fingerprint.as_bytes(),
                    reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
                },
                ArtifactAnalysisUnmappedSymbol {
                    artifact_symbol_fingerprint: second.fingerprint.as_bytes(),
                    reason: ArtifactAnalysisUnmappedReason::OutsideSourceScope,
                },
            ],
            unmapped_sources: Vec::new(),
            clone_fragments: Vec::new(),
        };
        let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
            .with_correlation(Some(ArtifactCorrelationReport::from_rows(
                11, &artifact, &rows,
            )));

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"unmapped_symbol_bytes\":12"));
        assert!(json.contains("\"debug_info_missing\":1"));
        assert!(json.contains("\"outside_source_scope\":1"));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("2 unmapped symbols (12 bytes)"));
        assert!(text.contains("unmapped symbol reasons:"));
        assert!(text.contains("debug_info_missing: 1"));
        assert!(text.contains("outside_source_scope: 1"));
    }

    #[test]
    fn wasm_report_is_versioned_and_does_not_expose_code_bytes() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(ARTIFACT_REPORT_SCHEMA_VERSION));
        assert!(json.contains("fixture.wasm"));
        assert!(!json.contains("\"code\": ["));
    }

    #[test]
    fn artifact_and_calibration_json_reports_validate_against_shipped_schemas() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let artifact_report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
        assert_valid_schema(
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v1.schema.json",
            ARTIFACT_REPORT_JSON_SCHEMA,
            &serde_json::to_value(artifact_report).unwrap(),
        );
        let calibration_report = CalibrationSummaryReport {
            schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
            source_run: 1,
            statistics: artifact_savings_calibration_statistics(&[]),
            strata: Vec::new(),
            comparison: None,
        };
        assert_valid_schema(
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-calibration-report-v1.schema.json",
            ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA,
            &serde_json::to_value(calibration_report).unwrap(),
        );
    }

    #[test]
    fn wasm_source_maps_are_read_only_from_the_artifact_directory() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_path = directory.path().join("module.wasm");
        fs::write(&artifact_path, b"\0asm\x01\0\0\0").unwrap();
        fs::write(
            directory.path().join("module.wasm.map"),
            br#"{"version":3,"sources":["src/lib.rs"],"names":[],"mappings":""}"#,
        )
        .unwrap();
        let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
        artifact
            .source_mappings
            .push(codehelion_artifact::ArtifactSourceMapping {
                uri: "module.wasm.map".to_owned(),
            });
        artifact
            .source_mappings
            .push(codehelion_artifact::ArtifactSourceMapping {
                uri: "https://example.invalid/module.wasm.map".to_owned(),
            });

        let maps = resolve_wasm_source_maps(&artifact_path, &artifact, 1024);

        assert_eq!(maps.len(), 2);
        assert!(matches!(
            &maps[0].status,
            SourceMapResolutionStatus::Resolved { sources, .. }
                if sources == &["src/lib.rs".to_owned()]
        ));
        assert_eq!(
            maps[1].status,
            SourceMapResolutionStatus::Unavailable {
                reason: "non_local_reference"
            }
        );
    }

    #[test]
    fn text_report_calls_duplicate_bytes_observed_not_savings() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        for category in [
            "observed_bytes",
            "duplicated_bytes",
            "retained_bytes",
            "shared_dependency_bytes",
            "duplicated_data_bytes",
            "upper_bound_savings_bytes",
            "estimated_refactor_savings_bytes",
            "verified_savings_bytes",
        ] {
            assert!(
                text.contains(category),
                "missing {category} from text report"
            );
        }
        assert!(text.contains("observed duplicate bytes"));
        assert!(text.contains("upper bound, not guaranteed"));
        assert!(text.contains("estimated_refactor_savings_bytes: unavailable"));
        assert!(text.contains("clone_confidence: High"));
        assert!(text.contains("savings_confidence: Unavailable"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], ARTIFACT_REPORT_SCHEMA_VERSION);
        for category in [
            "observed_bytes",
            "duplicated_bytes",
            "retained_bytes",
            "shared_dependency_bytes",
            "duplicated_data_bytes",
            "upper_bound_savings_bytes",
            "estimated_refactor_savings_bytes",
            "verified_savings_bytes",
            "clone_confidence",
            "savings_confidence",
            "assumptions",
        ] {
            assert!(
                json["sizes"].get(category).is_some(),
                "missing {category} from JSON report"
            );
        }

        let mut csv = Vec::new();
        render_csv(&report, &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        let mut lines = csv.lines();
        let header: Vec<_> = lines.next().unwrap().split(',').collect();
        let summary: Vec<_> = lines.next().unwrap().split(',').collect();
        assert_eq!(header.len(), summary.len());
        for (field, expected) in [
            ("observed_bytes", "8"),
            ("duplicated_bytes", "0"),
            ("upper_bound_savings_bytes", "0"),
            ("estimated_refactor_savings_bytes", "unavailable"),
            ("verified_savings_bytes", "unavailable"),
        ] {
            let index = header.iter().position(|value| *value == field).unwrap();
            assert_eq!(summary[index], expected, "unexpected {field} value");
        }
    }

    #[test]
    fn savings_categories_remain_distinct_in_every_artifact_report_format() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let mut report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
        report.sizes = metrics::SizeClassification {
            observed_bytes: 100,
            duplicated_bytes: 80,
            retained_bytes: Some(60),
            shared_dependency_bytes: Some(40),
            duplicated_data_bytes: 30,
            upper_bound_savings_bytes: Some(20),
            estimated_refactor_savings_bytes: Some(10),
            verified_savings_bytes: Some(5),
            clone_confidence: EvidenceConfidence::High,
            savings_confidence: EvidenceConfidence::Low,
            assumptions: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        for (field, expected) in [
            ("observed_bytes", 100),
            ("duplicated_bytes", 80),
            ("retained_bytes", 60),
            ("shared_dependency_bytes", 40),
            ("duplicated_data_bytes", 30),
            ("upper_bound_savings_bytes", 20),
            ("estimated_refactor_savings_bytes", 10),
            ("verified_savings_bytes", 5),
        ] {
            assert_eq!(json["sizes"][field], expected, "unexpected {field}");
        }
        let mut csv = Vec::new();
        render_csv(&report, &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        let mut rows = csv.lines();
        let header: Vec<_> = rows.next().unwrap().split(',').collect();
        let summary: Vec<_> = rows.next().unwrap().split(',').collect();
        for (field, expected) in [
            ("observed_bytes", "100"),
            ("duplicated_bytes", "80"),
            ("retained_bytes", "60"),
            ("upper_bound_savings_bytes", "20"),
            ("estimated_refactor_savings_bytes", "10"),
            ("verified_savings_bytes", "5"),
        ] {
            let index = header.iter().position(|value| *value == field).unwrap();
            assert_eq!(summary[index], expected, "unexpected {field}");
        }
    }

    #[test]
    fn artifact_report_exposes_build_variant_evidence_in_every_format() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let report = ArtifactReport::from_ir(
            std::path::Path::new("fixture.wasm"),
            &artifact,
            None,
            Some(ComparisonBuildVariant {
                manifest_path: "build-variant.json".to_owned(),
                fingerprint: "variant-fingerprint".to_owned(),
            }),
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("build-variant.json"));
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("build variant: build-variant.json")
        );
        let mut csv = Vec::new();
        render_csv(&report, &mut csv).unwrap();
        assert!(String::from_utf8(csv).unwrap().contains("build-variant,"));
    }

    #[test]
    fn comparison_uses_fingerprint_for_additions_and_names_for_modifications() {
        let mut before = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        before.symbols = vec![codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("test", b"before"),
            name: Some("same_name".to_owned()),
            exported: false,
            section: None,
            offset: 0,
            size: 1,
            size_inferred: false,
            code: vec![1],
            normalized: None,
            inline_stack: Vec::new(),
        }];
        let mut after = before.clone();
        after.observed_bytes = 7;
        after.symbols[0].fingerprint =
            codehelion_artifact::ArtifactFingerprint::from_content("test", b"after");
        let mut report = ArtifactComparisonReport::new(
            std::path::Path::new("before.wasm"),
            &before,
            None,
            std::path::Path::new("after.wasm"),
            &after,
            None,
        );
        assert_eq!(report.symbol_changes.added, 1);
        assert_eq!(report.symbol_changes.removed, 1);
        assert_eq!(report.symbol_changes.modified_named_symbols, 1);
        assert_eq!(report.verified_savings_bytes, Some(1));
        assert_eq!(report.symbol_deltas.len(), 2);
        assert!(report.duplicate_group_deltas.is_empty());
        assert!(
            report
                .symbol_deltas
                .iter()
                .any(|delta| delta.kind == "added" && delta.size_delta_bytes == 1)
        );
        assert!(
            report
                .symbol_deltas
                .iter()
                .any(|delta| delta.kind == "removed" && delta.size_delta_bytes == -1)
        );
        report.calibration = Some(CalibrationReport {
            source_run: 7,
            clone_group_fingerprint: "ab".repeat(16),
            estimated_refactor_savings_bytes: -2,
            verified_savings_bytes: 1,
            absolute_error_bytes: 3,
            relative_error: Some(3.0),
        });
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["calibration"]["absolute_error_bytes"], 3);
        let mut text = Vec::new();
        render_compare_text(&report, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("calibration: scan 7")
        );
        let mut csv = Vec::new();
        render_compare_csv(&report, &mut csv).unwrap();
        assert!(String::from_utf8(csv).unwrap().contains("calibration,7,"));
    }

    #[test]
    fn comparison_reports_individual_duplicate_group_changes() {
        let mut before = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        before.symbols = [10_u64, 20]
            .into_iter()
            .map(|offset| codehelion_artifact::ArtifactSymbol {
                fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                    "symbol",
                    &offset.to_le_bytes(),
                ),
                name: None,
                exported: false,
                section: None,
                offset,
                size: 2,
                size_inferred: false,
                code: vec![1, 2],
                normalized: None,
                inline_stack: Vec::new(),
            })
            .collect();
        let mut after = before.clone();
        after.symbols.pop();
        let report = ArtifactComparisonReport::new(
            std::path::Path::new("before.wasm"),
            &before,
            None,
            std::path::Path::new("after.wasm"),
            &after,
            None,
        );
        assert!(report.duplicate_group_deltas.iter().any(|delta| {
            delta.kind == "exact" && delta.duplicated_bytes_delta == -2 && delta.members_delta == -2
        }));
        let mut csv = Vec::new();
        render_compare_csv(&report, &mut csv).unwrap();
        assert!(
            String::from_utf8(csv)
                .unwrap()
                .contains("duplicate-exact,,")
        );
    }

    #[test]
    fn comparison_warns_when_build_variant_evidence_differs() {
        let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        let report = ArtifactComparisonReport::new(
            std::path::Path::new("before.wasm"),
            &artifact,
            Some(ComparisonBuildVariant {
                manifest_path: "debug.json".to_owned(),
                fingerprint: "before".to_owned(),
            }),
            std::path::Path::new("after.wasm"),
            &artifact,
            Some(ComparisonBuildVariant {
                manifest_path: "release.json".to_owned(),
                fingerprint: "after".to_owned(),
            }),
        );
        assert_eq!(
            report.build_variant_warning.as_deref(),
            Some(
                "build variants differ; size and symbol changes may reflect build-condition changes"
            )
        );
        let mut text = Vec::new();
        render_compare_text(&report, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("build variant warning: build variants differ")
        );
        let mut csv = Vec::new();
        render_compare_csv(&report, &mut csv).unwrap();
        assert!(
            String::from_utf8(csv)
                .unwrap()
                .contains("build-variant-warning")
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["before"]["build_variant"]["manifest_path"],
            "debug.json"
        );
    }

    #[test]
    fn build_variant_input_must_be_valid_json() {
        let manifest = tempfile::NamedTempFile::new().unwrap();
        fs::write(manifest.path(), b"not JSON").unwrap();
        let error = read_build_variant(Some(manifest.path())).unwrap_err();
        assert!(error.to_string().contains("as JSON"));
    }

    #[test]
    fn report_keeps_duplicate_group_members_without_emitting_code() {
        let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
        artifact.symbols = [10_u64, 20]
            .into_iter()
            .map(|offset| codehelion_artifact::ArtifactSymbol {
                fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                    "symbol",
                    &offset.to_le_bytes(),
                ),
                name: None,
                exported: false,
                section: None,
                offset,
                size: 2,
                size_inferred: false,
                code: vec![1, 2],
                normalized: None,
                inline_stack: Vec::new(),
            })
            .collect();
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        let report =
            ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
        assert_eq!(report.duplicate_groups.exact.len(), 1);
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("exact duplicate groups:"));
        assert!(text.contains("offset 10 size 2"));
        assert!(text.contains("dead code definitive: 1 symbols"));
        assert!(!text.contains("[1, 2]"));
        let mut csv = Vec::new();
        render_csv(&report, &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        assert!(csv.contains("duplicate-group,fixture.wasm,wasm,exact,"));
        assert!(csv.contains("duplicate-member,fixture.wasm,wasm,exact,"));
        assert!(csv.contains("dead-code,fixture.wasm,wasm,"));
        let mut rows = csv.lines();
        let columns = rows.next().unwrap().split(',').count();
        let widths: Vec<_> = rows.map(|row| row.split(',').count()).collect();
        assert_eq!(widths, vec![columns; widths.len()]);
    }

    #[test]
    fn input_limit_is_checked_before_reading_or_parsing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"more than eight bytes").unwrap();
        let error = inspect(file.path(), 8, None, None).unwrap_err();
        assert!(error.to_string().contains("--max-bytes limit"));
    }

    #[test]
    fn csv_quotes_delimiters_and_embedded_quotes() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn calibration_summary_keeps_absolute_and_relative_statistics_separate() {
        let report = CalibrationSummaryReport {
            schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
            source_run: 7,
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 4,
                median_absolute_error_bytes: Some(5.5),
                p90_absolute_error_bytes: Some(10),
                relative_error_samples: 3,
                median_relative_error: Some(0.8),
                p90_relative_error: Some(1.0),
            },
            strata: vec![CalibrationStratumReport {
                dimension: "artifact_format",
                key: "elf".to_owned(),
                statistics: ArtifactSavingsCalibrationStatistics {
                    samples: 2,
                    median_absolute_error_bytes: Some(4.0),
                    p90_absolute_error_bytes: Some(7),
                    relative_error_samples: 2,
                    median_relative_error: Some(0.5),
                    p90_relative_error: Some(0.7),
                },
            }],
            comparison: None,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["statistics"]["samples"], 4);
        assert_eq!(json["statistics"]["relative_error_samples"], 3);
        assert_eq!(json["strata"][0]["dimension"], "artifact_format");
        let mut text = Vec::new();
        render_calibration_text(&report, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("absolute error: median 5.5000 bytes"));
        assert!(text.contains("artifact_format elf"));
        let mut csv = Vec::new();
        render_calibration_csv(&report, &mut csv).unwrap();
        assert!(
            String::from_utf8(csv)
                .unwrap()
                .contains("7,overall,,,,4,5.5000,10,3,0.8000,1.0000")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two reports and every comparison outcome remain visible together"
    )]
    fn calibration_comparison_reports_deltas_without_a_threshold_gate() {
        let mut report = CalibrationSummaryReport {
            schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
            source_run: 7,
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 4,
                median_absolute_error_bytes: Some(5.5),
                p90_absolute_error_bytes: Some(10),
                relative_error_samples: 3,
                median_relative_error: Some(0.8),
                p90_relative_error: Some(1.0),
            },
            strata: vec![CalibrationStratumReport {
                dimension: "artifact_format",
                key: "elf".to_owned(),
                statistics: ArtifactSavingsCalibrationStatistics {
                    samples: 4,
                    median_absolute_error_bytes: Some(5.5),
                    p90_absolute_error_bytes: Some(10),
                    relative_error_samples: 3,
                    median_relative_error: Some(0.8),
                    p90_relative_error: Some(1.0),
                },
            }],
            comparison: None,
        };
        let baseline = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            baseline.path(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
                "source_run": 6,
                "statistics": {
                    "samples": 2,
                    "median_absolute_error_bytes": 3.0,
                    "p90_absolute_error_bytes": 7,
                    "relative_error_samples": 2,
                    "median_relative_error": 0.5,
                    "p90_relative_error": 0.7
                },
                "strata": [
                    {
                        "dimension": "artifact_format",
                        "key": "elf",
                        "statistics": {
                            "samples": 2,
                            "median_absolute_error_bytes": 3.0,
                            "p90_absolute_error_bytes": 7,
                            "relative_error_samples": 2,
                            "median_relative_error": 0.5,
                            "p90_relative_error": 0.7
                        }
                    },
                    {
                        "dimension": "clone_type",
                        "key": "type-2",
                        "statistics": {
                            "samples": 1,
                            "median_absolute_error_bytes": 2.0,
                            "p90_absolute_error_bytes": 2,
                            "relative_error_samples": 1,
                            "median_relative_error": 0.4,
                            "p90_relative_error": 0.4
                        }
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let comparison = calibration_comparison(&report, baseline.path()).unwrap();
        assert_eq!(
            comparison.baseline_schema_version,
            ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION
        );
        assert_eq!(comparison.baseline_source_run, 6);
        assert_eq!(comparison.overall.samples, 2);
        assert_eq!(comparison.overall.median_absolute_error_bytes, Some(2.5));
        assert_eq!(comparison.strata.len(), 2);
        assert!(comparison.strata.iter().any(|stratum| {
            stratum.dimension == "clone_type"
                && stratum.key == "type-2"
                && stratum.current.is_none()
                && stratum.delta.is_none()
        }));
        report.comparison = Some(comparison);

        let value = serde_json::to_value(&report).unwrap();
        assert_valid_schema(
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-calibration-report-v1.schema.json",
            ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA,
            &value,
        );
        assert_eq!(value["comparison"]["overall"]["samples"], 2);
        let mut text = Vec::new();
        render_calibration_text(&report, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("baseline comparison (informational; no threshold)"));
        assert!(text.contains("overall: samples +2"));
        assert!(text.contains("only one report contains this stratum"));
        let mut csv = Vec::new();
        render_calibration_csv(&report, &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        let mut rows = csv.lines();
        let width = rows.next().unwrap().split(',').count();
        assert!(rows.all(|row| row.split(',').count() == width));
        assert!(csv.contains("7,comparison-overall,,,6,,,,,,,2,2.5000,3,1,0.3000,0.3000"));
    }

    #[test]
    fn forced_input_format_must_agree_with_magic_detection() {
        let error = parse_input_format(b"\0asm\x01\0\0\0", Some(ArtifactInputFormat::Elf), None)
            .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }

    #[test]
    fn debug_companion_is_rejected_for_wasm() {
        let error = parse_input_format(b"\0asm\x01\0\0\0", None, Some(b"debug")).unwrap_err();
        assert!(error.to_string().contains("only supported for ELF"));
    }

    #[test]
    fn empty_archive_input_is_parsed_without_treating_it_as_unknown() {
        let archive = parse_input_format(b"!<arch>\n", None, None).expect("parse archive");
        assert_eq!(archive.format, BinaryFormat::Archive);
        assert!(archive.archive_members.is_empty());
    }

    #[test]
    fn archive_report_retains_member_failures_without_raw_member_bytes() {
        let mut archive = ArtifactIr::empty(BinaryFormat::Archive, b"archive");
        archive
            .archive_members
            .push(codehelion_artifact::ArtifactArchiveMember {
                name: "thin-member.o".to_owned(),
                fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                    "archive-member",
                    b"member",
                ),
                offset: 32,
                size: 0,
                format: Some(BinaryFormat::Elf),
                thin: true,
                parse_error: Some("external member paths are not followed".to_owned()),
            });

        let report = ArtifactReport::from_ir(FilePath::new("fixture.a"), &archive, None, None);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["archive_members"][0]["name"], "thin-member.o");
        assert_eq!(json["archive_members"][0]["thin"], true);
        assert!(
            json["archive_members"][0]["parse_error"]
                .as_str()
                .unwrap()
                .contains("not followed")
        );
        let mut text = Vec::new();
        render_text(&report, false, &mut text).unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("archive members: 0 parsed, 1 unavailable")
        );
        let mut csv = Vec::new();
        render_csv(&report, &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        assert!(csv.contains("archive-member,fixture.a,archive,elf"));
        assert!(csv.contains("thin-member.o"));
        assert!(csv.contains("external member paths are not followed"));
    }
}
