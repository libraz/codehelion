//! Persisting one artifact analysis and reading its recorded facts back.

use std::path::Path as FilePath;

use anyhow::{Context, Result, bail};
use codehelion_artifact::{ARTIFACT_IR_SCHEMA_VERSION, ArtifactIr};
use codehelion_store::artifact::{
    ArtifactAnalysisContainment, ArtifactAnalysisMapping, ArtifactAnalysisSnapshot,
    ArtifactAnalysisSourceMap, ArtifactAnalysisSourceMapOutcome,
    ArtifactAnalysisSourceMapReason as SourceMapReason, ArtifactAnalysisSymbol,
    ArtifactAnalysisUnmappedSource, ArtifactAnalysisUnmappedSymbol,
};
use codehelion_store::{BuildVariantFingerprint, Store};

use super::correlation::{
    ArtifactCorrelationReport, CorrelationRows, correlate_source_run, read_linker_map,
    stored_clone_group_savings,
};
use super::input::source_map_locations;
use super::output::serialize_artifact_ir;
use super::{
    AnalysisFacts, ArtifactContainment, BuildVariantEvidence, SourceMapResolution,
    SourceMapResolutionStatus,
};
use crate::cli::ArtifactArgs;

/// The correlation one saved analysis recorded, read back from its own rows.
///
/// An analysis run without `--source-run` recorded no correlation at all and
/// keeps `None`; the summary row is what says which of the two it was, and it
/// also names the source scan the rows are about.
///
/// Nothing here is correlated again: the correspondences, the symbols and
/// sources left unmatched, and the clone members they were matched against are
/// each read from the database, and the same projection the analysis rendered
/// with turns them into the report. Re-deriving them from the artifact instead
/// would let a re-render disagree with the analysis it claims to show.
pub(super) fn recorded_correlation(
    store: &Store,
    analysis_id: i64,
    artifact: &ArtifactIr,
) -> Result<Option<ArtifactCorrelationReport>> {
    let Some(summary) = store.artifact_correlation(analysis_id)? else {
        return Ok(None);
    };
    let source_run = summary.source_scan_run_id;
    let rows = CorrelationRows {
        mappings: store
            .artifact_mappings(analysis_id)?
            .into_iter()
            .map(|mapping| ArtifactAnalysisMapping {
                schema_version: mapping.schema_version,
                artifact_symbol_fingerprint: mapping.artifact_symbol_fingerprint,
                source_kind: mapping.source_kind,
                source_fingerprint: mapping.source_fingerprint,
                source_instance_fingerprint: mapping.source_instance_fingerprint,
                source_build_variant_fingerprint: mapping.source_build_variant_fingerprint,
                evidence: mapping.evidence,
                attributed_bytes: mapping.attributed_bytes,
                build_variant_fingerprint: mapping.build_variant_fingerprint,
            })
            .collect(),
        unmapped_symbols: store
            .artifact_unmapped_symbols(analysis_id)?
            .into_iter()
            .map(|unmapped| ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: unmapped.artifact_symbol_fingerprint,
                reason: unmapped.reason,
            })
            .collect(),
        unmapped_sources: store
            .artifact_unmapped_sources(analysis_id)?
            .into_iter()
            .map(|unmapped| ArtifactAnalysisUnmappedSource {
                source_kind: unmapped.source_kind,
                source_fingerprint: unmapped.source_fingerprint,
                source_instance_fingerprint: unmapped.source_instance_fingerprint,
                source_build_variant_fingerprint: unmapped.source_build_variant_fingerprint,
                reason: unmapped.reason,
            })
            .collect(),
        clone_fragments: store
            .source_clone_fragments(source_run)
            .with_context(|| format!("loading clone fragments for scan {source_run}"))?,
    };
    Ok(Some(ArtifactCorrelationReport::from_rows(
        source_run, artifact, &rows,
    )))
}

pub(super) fn record(
    artifact: &ArtifactIr,
    facts: &AnalysisFacts<'_>,
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
        &source_map_locations(facts.source_maps),
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
        build_variant_fingerprint: build_variant
            .map(|value| BuildVariantFingerprint::from_bytes(value.fingerprint.as_bytes())),
        started_at,
        finished_at,
        symbols: &symbols,
        source_maps: &stored_source_maps(facts.source_maps)?,
        containment: facts.containment.map(stored_containment),
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

/// The persisted form of every resolved reference, keeping the outcome the
/// analysis reported.
///
/// The token positions are deliberately left out: they are evidence for the
/// correlation running now, and the mapping rows retain the stable identities
/// that outlive them.
pub(super) fn stored_source_maps(
    source_maps: &[SourceMapResolution],
) -> Result<Vec<ArtifactAnalysisSourceMap>> {
    source_maps
        .iter()
        .map(|resolution| {
            let outcome = match &resolution.status {
                SourceMapResolutionStatus::Resolved {
                    local_path,
                    sources,
                    ..
                } => ArtifactAnalysisSourceMapOutcome::Resolved {
                    local_path: local_path.clone(),
                    sources: sources.clone(),
                },
                SourceMapResolutionStatus::Unavailable { reason } => {
                    ArtifactAnalysisSourceMapOutcome::Unavailable {
                        reason: SourceMapReason::from_sql(reason)?,
                    }
                }
            };
            Ok(ArtifactAnalysisSourceMap {
                uri: resolution.uri.clone(),
                outcome,
            })
        })
        .collect()
}

/// The source-map outcomes one saved analysis recorded, read back from its own
/// rows.
///
/// Resolving the references again would let a re-render disagree with the
/// analysis it claims to show: the artifact's directory can have changed since,
/// and a reference that resolved then may not now.
pub(super) fn recorded_source_maps(
    store: &Store,
    analysis_id: i64,
) -> Result<Vec<SourceMapResolution>> {
    store
        .artifact_source_maps(analysis_id)?
        .into_iter()
        .map(|source_map| {
            let status = match source_map.outcome {
                ArtifactAnalysisSourceMapOutcome::Resolved {
                    local_path,
                    sources,
                } => SourceMapResolutionStatus::Resolved {
                    local_path,
                    sources,
                    // Correlation happened when the analysis ran, and its
                    // result is read from the mapping rows.
                    locations: Vec::new(),
                },
                ArtifactAnalysisSourceMapOutcome::Unavailable { reason } => {
                    SourceMapResolutionStatus::Unavailable {
                        reason: reason.as_sql(),
                    }
                }
            };
            Ok(SourceMapResolution {
                uri: source_map.uri,
                status,
            })
        })
        .collect()
}

/// The persisted form of the ceilings an untrusted run installed.
pub(super) const fn stored_containment(
    containment: &ArtifactContainment,
) -> ArtifactAnalysisContainment {
    ArtifactAnalysisContainment {
        max_input_bytes: containment.max_input_bytes,
        worker_timeout_seconds: containment.worker_timeout_seconds,
        worker_memory_limit_bytes: containment.worker_memory_limit_bytes,
    }
}

/// The ceilings one saved analysis ran under, read back from its own row.
pub(super) fn recorded_containment(
    store: &Store,
    analysis_id: i64,
) -> Result<Option<ArtifactContainment>> {
    Ok(store
        .artifact_containment(analysis_id)?
        .map(|containment| ArtifactContainment {
            max_input_bytes: containment.max_input_bytes,
            worker_timeout_seconds: containment.worker_timeout_seconds,
            worker_memory_limit_bytes: containment.worker_memory_limit_bytes,
            // Derived from the input ceiling rather than stored beside it,
            // because that is what it was derived from when the analysis ran:
            // storing it would be a second copy of one decision, and the copy
            // is what a replay would eventually disagree with.
            max_debug_derived_items: containment.max_input_bytes,
        }))
}
