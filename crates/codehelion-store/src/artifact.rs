//! Atomic persistence for standalone compiled-artifact analyses.
//!
//! These rows deliberately do not pretend to be source scans. The existing
//! source-linked artifact tables remain available for later source-artifact
//! mapping; this module records the parser evidence available now.

use rusqlite::{Transaction, params};

use crate::{Store, StoreError};

mod calibration;
mod mapping;
mod rows;

pub use calibration::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisSavingsCalibration, ArtifactAnalysisSavingsConfidence,
    ArtifactSavingsCalibrationStatistics, artifact_savings_calibration_statistics,
};
pub use mapping::{
    ArtifactAnalysisMapping, ArtifactAnalysisMappingConfidence, ArtifactAnalysisSourceKind,
    FUNCTION_RECIPE_VERSION, MAPPING_EVIDENCE_SCHEMA_VERSION, MappingEvidence, MappingEvidenceFact,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
};
pub use rows::{
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisContainment,
    ArtifactAnalysisCorrelation, ArtifactAnalysisSnapshot, ArtifactAnalysisSourceMap,
    ArtifactAnalysisSourceMapOutcome, ArtifactAnalysisSourceMapReason, ArtifactAnalysisSymbol,
    ArtifactAnalysisUnmappedReason, ArtifactAnalysisUnmappedSource,
    ArtifactAnalysisUnmappedSourceReason, ArtifactAnalysisUnmappedSymbol,
};

use mapping::supported_mapping_schema;

/// Largest versioned artifact IR document retained for one analysis.
///
/// The relational rows retain the queryable summary independently. This cap
/// prevents a single parser result from growing the local audit database
/// without bound while preserving enough IR for `artifact report` to
/// faithfully re-render ordinary analyses.
pub const MAX_ARTIFACT_IR_JSON_BYTES: usize = 64 * 1024 * 1024;

impl Store {
    /// Record one complete artifact analysis and return its row id.
    ///
    /// # Errors
    ///
    /// All rows are written in one transaction; a failed symbol write leaves
    /// no parent analysis behind.
    pub fn record_artifact_analysis(
        &mut self,
        snapshot: &ArtifactAnalysisSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        validate_artifact_ir_size(snapshot.ir_json.len())?;
        validate_artifact_ir_schema(snapshot)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO artifact_analysis
                 (schema_version, path, format, content_fingerprint, observed_bytes,
                  ir_json, build_variant_manifest_path, build_variant_fingerprint,
                  started_at, finished_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'completed')",
            params![
                snapshot.schema_version,
                snapshot.path,
                snapshot.format,
                snapshot.content_fingerprint.as_slice(),
                i64::try_from(snapshot.observed_bytes).unwrap_or(i64::MAX),
                snapshot.ir_json,
                snapshot.build_variant_manifest_path,
                snapshot.build_variant_fingerprint,
                snapshot.started_at,
                snapshot.finished_at,
            ],
        )?;
        let analysis_id = tx.last_insert_rowid();
        for (ordinal, symbol) in snapshot.symbols.iter().enumerate() {
            tx.execute(
                "INSERT INTO artifact_analysis_symbol
                     (analysis_id, ordinal, fingerprint, name, exported, section_index, offset, size_bytes,
                      size_inferred, code_fingerprint, normalization_version, normalization_fingerprint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    analysis_id,
                    i64::try_from(ordinal).unwrap_or(i64::MAX),
                    symbol.fingerprint.as_slice(),
                    symbol.name,
                    i64::from(symbol.exported),
                    symbol.section_index.map(i64::from),
                    i64::try_from(symbol.offset).unwrap_or(i64::MAX),
                    i64::try_from(symbol.size_bytes).unwrap_or(i64::MAX),
                    i64::from(symbol.size_inferred),
                    symbol.code_fingerprint.as_slice(),
                    symbol.normalization_version,
                    symbol.normalization_fingerprint.map(|value| value.to_vec()),
                ],
            )?;
        }
        record_source_maps(&tx, analysis_id, snapshot.source_maps)?;
        record_containment(&tx, analysis_id, snapshot.containment)?;
        record_mappings(&tx, analysis_id, snapshot.mappings)?;
        for unmapped in snapshot.unmapped_symbols {
            tx.execute(
                "INSERT INTO artifact_analysis_unmapped_symbol
                     (artifact_analysis_id, artifact_symbol_fingerprint, reason)
                 VALUES (?1, ?2, ?3)",
                params![
                    analysis_id,
                    unmapped.artifact_symbol_fingerprint.as_slice(),
                    unmapped.reason.as_sql(),
                ],
            )?;
        }
        for unmapped in snapshot.unmapped_sources {
            tx.execute(
                "INSERT INTO artifact_analysis_unmapped_source
                     (artifact_analysis_id, source_kind, source_fingerprint, reason,
                      source_build_variant_fingerprint, source_instance_fingerprint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    analysis_id,
                    unmapped.source_kind.as_sql(),
                    unmapped.source_fingerprint.as_slice(),
                    unmapped.reason.as_sql(),
                    unmapped.source_build_variant_fingerprint,
                    unmapped.source_instance_fingerprint.as_slice(),
                ],
            )?;
        }
        if let Some(correlation) = snapshot.correlation {
            tx.execute(
                "INSERT INTO artifact_analysis_correlation
                     (artifact_analysis_id, schema_version, source_scan_run_id, mapping_count,
                      artifact_symbol_count, mapped_symbol_count, artifact_symbol_bytes,
                      mapped_symbol_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    analysis_id,
                    correlation.schema_version,
                    correlation.source_scan_run_id,
                    i64::try_from(correlation.mapping_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.artifact_symbol_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.mapped_symbol_count).unwrap_or(i64::MAX),
                    i64::try_from(correlation.artifact_symbol_bytes).unwrap_or(i64::MAX),
                    i64::try_from(correlation.mapped_symbol_bytes).unwrap_or(i64::MAX),
                ],
            )?;
        }
        record_clone_group_savings(&tx, analysis_id, snapshot.clone_group_savings)?;
        tx.commit()?;
        Ok(analysis_id)
    }
}

/// Ensure the storage-column schema and the self-describing IR agree before
/// either can become durable state.
fn validate_artifact_ir_schema(snapshot: &ArtifactAnalysisSnapshot<'_>) -> Result<(), StoreError> {
    let value: serde_json::Value = serde_json::from_str(snapshot.ir_json).map_err(|error| {
        StoreError::InvalidArtifactIrSchema {
            reason: format!("IR JSON does not parse: {error}"),
        }
    })?;
    let Some(document_schema) = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(StoreError::InvalidArtifactIrSchema {
            reason: "IR JSON has no string schema_version".to_owned(),
        });
    };
    if document_schema != snapshot.schema_version {
        return Err(StoreError::InvalidArtifactIrSchema {
            reason: format!(
                "row declares {}, but IR JSON declares {document_schema}",
                snapshot.schema_version
            ),
        });
    }
    Ok(())
}

const fn validate_artifact_ir_size(size_bytes: usize) -> Result<(), StoreError> {
    if size_bytes > MAX_ARTIFACT_IR_JSON_BYTES {
        return Err(StoreError::ArtifactIrTooLarge {
            size_bytes,
            maximum_bytes: MAX_ARTIFACT_IR_JSON_BYTES,
        });
    }
    Ok(())
}

fn record_clone_group_savings(
    tx: &Transaction<'_>,
    analysis_id: i64,
    savings: &[ArtifactAnalysisCloneGroupSavings],
) -> Result<(), StoreError> {
    for estimate in savings {
        if estimate.schema_version != ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown artifact clone-group savings schema".to_owned(),
            });
        }
        let assumptions: serde_json::Value = serde_json::from_str(&estimate.assumptions_json)
            .map_err(|_| StoreError::InvalidMappingEvidence {
                reason: "savings assumptions are not valid JSON".to_owned(),
            })?;
        if !assumptions.is_array() {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "savings assumptions are not a JSON array".to_owned(),
            });
        }
        tx.execute(
            "INSERT INTO artifact_analysis_clone_group_savings
                 (schema_version, artifact_analysis_id, source_scan_run_id,
                  clone_group_fingerprint, source_build_variant_fingerprint,
                  artifact_build_variant_fingerprint, duplicated_bytes,
                  estimated_refactor_savings_bytes, mapping_confidence,
                  clone_confidence, model_confidence, savings_confidence,
                  model_schema_version, assumptions_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                estimate.schema_version,
                analysis_id,
                estimate.source_scan_run_id,
                estimate.clone_group_fingerprint.as_slice(),
                estimate.source_build_variant_fingerprint,
                estimate.artifact_build_variant_fingerprint,
                i64::try_from(estimate.duplicated_bytes).unwrap_or(i64::MAX),
                estimate.estimated_refactor_savings_bytes,
                estimate.mapping_confidence.as_sql(),
                estimate.clone_confidence,
                estimate.model_confidence.as_sql(),
                estimate.savings_confidence.as_sql(),
                estimate.model_schema_version,
                estimate.assumptions_json,
            ],
        )?;
    }
    Ok(())
}

/// Persist the ceilings an untrusted analysis installed.
///
/// An analysis that ran without the preset writes no row, which is what keeps
/// a later report from presenting the reading build's defaults as limits some
/// earlier run was held to.
fn record_containment(
    tx: &Transaction<'_>,
    analysis_id: i64,
    containment: Option<ArtifactAnalysisContainment>,
) -> Result<(), StoreError> {
    let Some(containment) = containment else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO artifact_analysis_containment
             (artifact_analysis_id, max_input_bytes, worker_timeout_seconds,
              worker_memory_limit_bytes)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            analysis_id,
            i64::try_from(containment.max_input_bytes).unwrap_or(i64::MAX),
            i64::try_from(containment.worker_timeout_seconds).unwrap_or(i64::MAX),
            i64::try_from(containment.worker_memory_limit_bytes).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

/// Persist the outcome of each declared source-map reference, in the order the
/// analysis reported them.
///
/// The ordinal is the reference's position in that report and nothing else: it
/// keeps the list in the order the artifact declared it, so a re-render prints
/// the same sequence.
fn record_source_maps(
    tx: &Transaction<'_>,
    analysis_id: i64,
    source_maps: &[ArtifactAnalysisSourceMap],
) -> Result<(), StoreError> {
    for (ordinal, source_map) in source_maps.iter().enumerate() {
        let ordinal = i64::try_from(ordinal).unwrap_or(i64::MAX);
        let (local_path, reason) = match &source_map.outcome {
            ArtifactAnalysisSourceMapOutcome::Resolved { local_path, .. } => {
                (Some(local_path.as_str()), None)
            }
            ArtifactAnalysisSourceMapOutcome::Unavailable { reason } => {
                (None, Some(reason.as_sql()))
            }
        };
        tx.execute(
            "INSERT INTO artifact_analysis_source_map_resolution
                 (artifact_analysis_id, ordinal, uri, local_path, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![analysis_id, ordinal, source_map.uri, local_path, reason],
        )?;
        let ArtifactAnalysisSourceMapOutcome::Resolved { sources, .. } = &source_map.outcome else {
            continue;
        };
        for (position, source) in sources.iter().enumerate() {
            tx.execute(
                "INSERT INTO artifact_analysis_source_map_resolution_source
                     (artifact_analysis_id, ordinal, position, source_name)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    analysis_id,
                    ordinal,
                    i64::try_from(position).unwrap_or(i64::MAX),
                    source,
                ],
            )?;
        }
    }
    Ok(())
}

fn record_mappings(
    tx: &Transaction<'_>,
    analysis_id: i64,
    mappings: &[ArtifactAnalysisMapping],
) -> Result<(), StoreError> {
    for mapping in mappings {
        if !supported_mapping_schema(&mapping.schema_version) {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown source-artifact mapping schema".to_owned(),
            });
        }
        let confidence =
            mapping
                .evidence
                .confidence()
                .ok_or_else(|| StoreError::InvalidMappingEvidence {
                    reason: "unknown schema, no facts, or no remaining candidate".to_owned(),
                })?;
        tx.execute(
            "INSERT INTO artifact_analysis_source_mapping
                 (schema_version, artifact_analysis_id, artifact_symbol_fingerprint,
                  source_kind, source_fingerprint, evidence_json, mapping_confidence,
                  attributed_bytes, build_variant_fingerprint, source_build_variant_fingerprint,
                  source_instance_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                mapping.schema_version,
                analysis_id,
                mapping.artifact_symbol_fingerprint.as_slice(),
                mapping.source_kind.as_sql(),
                mapping.source_fingerprint.as_slice(),
                mapping.evidence.json()?,
                confidence.as_sql(),
                mapping
                    .attributed_bytes
                    .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                mapping.build_variant_fingerprint,
                mapping.source_build_variant_fingerprint,
                mapping.source_instance_fingerprint.as_slice(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]
mod tests;
