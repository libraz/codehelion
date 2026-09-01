use std::collections::BTreeMap;

use crate::lifecycle::{ARTIFACT_ANALYSIS_RECENCY, SelectedCloneGroupEstimate};

use super::common::{
    decode_artifact_mapping, fingerprint_from_blob, nonnegative_u64, parse_hex_id,
};
use super::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisSavingsCalibration, ArtifactAnalysisSavingsConfidence,
    ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSourceReason, ArtifactMappingSqlRow, OptionalExtension, Store,
    StoreError, StoredArtifactAnalysis, StoredArtifactAnalysisCorrelation,
    StoredArtifactAnalysisIdentity, StoredArtifactMapping, StoredArtifactUnmappedSource,
    StoredArtifactUnmappedSymbol, params,
};

impl Store {
    /// Every mapping recorded for one artifact analysis, in stable evidence order.
    ///
    /// The result retains all ambiguous candidates. Callers must not collapse
    /// them to a single source merely because they share an artifact symbol.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer mapping vocabulary.
    pub fn artifact_mappings(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactMapping>, StoreError> {
        self.read_artifact_mappings(
            "SELECT artifact_analysis_id, schema_version, artifact_symbol_fingerprint, source_kind,
                    source_fingerprint, source_instance_fingerprint, evidence_json, mapping_confidence,
                    attributed_bytes, build_variant_fingerprint, source_build_variant_fingerprint
             FROM artifact_analysis_source_mapping
             WHERE artifact_analysis_id = ?1
             ORDER BY artifact_symbol_fingerprint ASC, source_kind ASC,
                      source_fingerprint ASC, source_instance_fingerprint ASC, evidence_json ASC",
            params![analysis_id],
        )
    }

    /// Identity facts for one standalone artifact analysis.
    ///
    /// # Errors
    ///
    /// Returns malformed stored fingerprints rather than using an analysis
    /// whose content or `BuildVariant` cannot be established.
    pub fn artifact_analysis_identity(
        &self,
        analysis_id: i64,
    ) -> Result<Option<StoredArtifactAnalysisIdentity>, StoreError> {
        self.conn
            .query_row(
                "SELECT format, content_fingerprint, build_variant_fingerprint
                 FROM artifact_analysis WHERE id = ?1",
                [analysis_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(format, content_fingerprint, build_variant_fingerprint)| {
                Ok(StoredArtifactAnalysisIdentity {
                    analysis_id,
                    format,
                    content_fingerprint: fingerprint_from_blob(
                        "artifact_analysis.content_fingerprint",
                        content_fingerprint,
                    )?,
                    build_variant_fingerprint: build_variant_fingerprint
                        .map(|value| {
                            fingerprint_from_blob(
                                "artifact_analysis.build_variant_fingerprint",
                                value,
                            )
                        })
                        .transpose()?,
                })
            })
            .transpose()
    }

    /// Read the persisted IR and provenance needed to re-render one artifact analysis.
    ///
    /// # Errors
    ///
    /// Returns malformed stored fingerprints rather than assigning a build
    /// identity to an analysis whose provenance cannot be established.
    pub fn artifact_analysis(
        &self,
        analysis_id: i64,
    ) -> Result<Option<StoredArtifactAnalysis>, StoreError> {
        self.conn
            .query_row(
                "SELECT schema_version, path, ir_json, build_variant_manifest_path, build_variant_fingerprint
                 FROM artifact_analysis WHERE id = ?1",
                [analysis_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(schema_version, path, ir_json, build_variant_manifest_path, build_variant_fingerprint)| {
                    Ok(StoredArtifactAnalysis {
                        analysis_id,
                        schema_version,
                        path,
                        ir_json,
                        build_variant_manifest_path,
                        build_variant_fingerprint: build_variant_fingerprint
                            .map(|value| {
                                fingerprint_from_blob(
                                    "artifact_analysis.build_variant_fingerprint",
                                    value,
                                )
                            })
                            .transpose()?,
                    })
                },
            )
            .transpose()
    }

    /// Clone classification recorded for one source-run group.
    ///
    /// # Errors
    ///
    /// Returns malformed group identities rather than assigning a calibration
    /// measurement to a guessed stratum.
    pub fn clone_group_type(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Option<String>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        self.conn
            .query_row(
                "SELECT clone_group.clone_type
                 FROM clone_group
                 JOIN fingerprint ON fingerprint.id = clone_group.group_fingerprint_id
                 WHERE clone_group.scan_run_id = ?1 AND fingerprint.hash = ?2
                 ORDER BY clone_group.id ASC
                 LIMIT 1",
                params![source_scan_run_id, fingerprint.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Every fragment mapping whose stable occurrence discriminator is
    /// `finding_hex`, across every artifact analysis.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `finding_hex` is not a stable ID;
    /// otherwise the same errors as [`Self::artifact_mappings`].
    pub fn artifact_fragment_mappings(
        &self,
        finding_hex: &str,
    ) -> Result<Vec<StoredArtifactMapping>, StoreError> {
        let finding_id = parse_hex_id(finding_hex)?;
        self.read_artifact_mappings(
            "SELECT artifact_analysis_id, schema_version, artifact_symbol_fingerprint, source_kind,
                    source_fingerprint, source_instance_fingerprint, evidence_json, mapping_confidence,
                    attributed_bytes, build_variant_fingerprint, source_build_variant_fingerprint
             FROM artifact_analysis_source_mapping
             WHERE source_kind = 'fragment' AND source_instance_fingerprint = ?1
             ORDER BY artifact_analysis_id ASC, artifact_symbol_fingerprint ASC,
                      source_fingerprint ASC, evidence_json ASC",
            params![finding_id.as_slice()],
        )
    }

    /// Read precisely the mapping rows selected by one indexable query.
    fn read_artifact_mappings<P: rusqlite::Params>(
        &self,
        query: &str,
        parameters: P,
    ) -> Result<Vec<StoredArtifactMapping>, StoreError> {
        let mut statement = self.conn.prepare(query)?;
        let rows = statement
            .query_map(parameters, |row| {
                Ok(ArtifactMappingSqlRow {
                    analysis_id: row.get(0)?,
                    schema_version: row.get(1)?,
                    artifact_symbol_fingerprint: row.get(2)?,
                    source_kind: row.get(3)?,
                    source_fingerprint: row.get(4)?,
                    source_instance_fingerprint: row.get(5)?,
                    evidence_json: row.get(6)?,
                    confidence: row.get(7)?,
                    attributed_bytes: row.get(8)?,
                    build_variant_fingerprint: row.get(9)?,
                    source_build_variant_fingerprint: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(decode_artifact_mapping).collect()
    }

    /// Select the one saved estimate a controlled measurement evaluates.
    ///
    /// Analysing one artifact twice under one build variant leaves two rows
    /// describing the same measurement, and a third analysis is the natural
    /// reaction to an error about the second. They are the same estimate, so
    /// the newest matching analysis is taken — under the same recency order
    /// the rest of the lifecycle uses — and named in the result, rather than
    /// leaving the calibration path unusable with no way to disambiguate it.
    ///
    /// # Errors
    ///
    /// Returns a malformed group identity or an unreadable stored row rather
    /// than measuring against an estimate that cannot be established.
    pub fn select_clone_group_estimate(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
        artifact_content_fingerprint: [u8; 16],
        artifact_build_variant_fingerprint: [u8; 16],
    ) -> Result<Option<SelectedCloneGroupEstimate>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        // The analysis columns are aliased so the shared recency order names
        // result columns rather than repeating a table qualifier.
        let columns = clone_group_savings_columns("savings");
        let query = format!(
            "SELECT analysis.id AS id, analysis.started_at AS started_at, {columns}
             FROM artifact_analysis_clone_group_savings AS savings
             JOIN artifact_analysis AS analysis ON analysis.id = savings.artifact_analysis_id
             WHERE savings.source_scan_run_id = ?1
               AND savings.clone_group_fingerprint = ?2
               AND savings.artifact_build_variant_fingerprint = ?3
               AND analysis.content_fingerprint = ?4
               AND analysis.build_variant_fingerprint = ?3
             ORDER BY {ARTIFACT_ANALYSIS_RECENCY}"
        );
        let mut statement = self.conn.prepare(&query)?;
        let rows = statement
            .query_map(
                params![
                    source_scan_run_id,
                    fingerprint.as_slice(),
                    artifact_build_variant_fingerprint.as_slice(),
                    artifact_content_fingerprint.as_slice(),
                ],
                |row| Ok((row.get::<_, i64>(0)?, clone_group_savings_row(row, 2)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let matching_analyses = rows.len();
        let Some((artifact_analysis_id, selected)) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(SelectedCloneGroupEstimate {
            artifact_analysis_id,
            matching_analyses,
            estimate: selected.decode()?,
        }))
    }

    /// Every persisted savings record for one source run and clone group.
    ///
    /// The scope is the whole selection: only the rows matching it are read
    /// and decoded, so a report iterating groups pays for its own group and
    /// not for every estimate the analysis holds.
    ///
    /// # Errors
    ///
    /// Returns an error when the group fingerprint is malformed or a stored
    /// savings row carries unknown vocabulary.
    pub fn clone_group_savings(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Vec<(i64, ArtifactAnalysisCloneGroupSavings)>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        let mut statement = self.conn.prepare(&format!(
            "SELECT artifact_analysis_id, {CLONE_GROUP_SAVINGS_COLUMNS}
             FROM artifact_analysis_clone_group_savings
             WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2
             ORDER BY artifact_analysis_id ASC, source_build_variant_fingerprint ASC,
                      artifact_build_variant_fingerprint ASC"
        ))?;
        let rows = statement
            .query_map(params![source_scan_run_id, fingerprint.as_slice()], |row| {
                Ok((row.get::<_, i64>(0)?, clone_group_savings_row(row, 1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(analysis_id, raw)| Ok((analysis_id, raw.decode()?)))
            .collect()
    }

    /// Every persisted savings record for one source run, grouped by the
    /// stable clone-group identity it belongs to.
    ///
    /// A report renders every group of one run, so it reads the run's
    /// estimates once instead of asking per group.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored savings row carries a malformed
    /// identity or unknown vocabulary.
    pub fn clone_group_savings_for_run(
        &self,
        source_scan_run_id: i64,
    ) -> Result<BTreeMap<String, Vec<(i64, ArtifactAnalysisCloneGroupSavings)>>, StoreError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT artifact_analysis_id, {CLONE_GROUP_SAVINGS_COLUMNS}
             FROM artifact_analysis_clone_group_savings
             WHERE source_scan_run_id = ?1
             ORDER BY clone_group_fingerprint ASC, artifact_analysis_id ASC,
                      source_build_variant_fingerprint ASC,
                      artifact_build_variant_fingerprint ASC"
        ))?;
        let rows = statement
            .query_map(params![source_scan_run_id], |row| {
                Ok((row.get::<_, i64>(0)?, clone_group_savings_row(row, 1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut grouped: BTreeMap<String, Vec<(i64, ArtifactAnalysisCloneGroupSavings)>> =
            BTreeMap::new();
        for (analysis_id, raw) in rows {
            let estimate = raw.decode()?;
            grouped
                .entry(crate::fingerprint_hex(estimate.clone_group_fingerprint))
                .or_default()
                .push((analysis_id, estimate));
        }
        Ok(grouped)
    }

    /// Symbols that one artifact analysis explicitly left unmapped.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer unmapped-reason vocabulary.
    pub fn artifact_unmapped_symbols(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactUnmappedSymbol>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT artifact_symbol_fingerprint, reason
             FROM artifact_analysis_unmapped_symbol
             WHERE artifact_analysis_id = ?1
             ORDER BY artifact_symbol_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(fingerprint, reason)| {
                Ok(StoredArtifactUnmappedSymbol {
                    artifact_symbol_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_symbol.artifact_symbol_fingerprint",
                        fingerprint,
                    )?,
                    reason: ArtifactAnalysisUnmappedReason::from_sql(&reason)?,
                })
            })
            .collect()
    }

    /// Source identities that one artifact analysis explicitly left unmatched.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains a value
    /// from a newer unmapped-source vocabulary.
    pub fn artifact_unmapped_sources(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<StoredArtifactUnmappedSource>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT source_kind, source_fingerprint, source_instance_fingerprint, reason,
                    source_build_variant_fingerprint
             FROM artifact_analysis_unmapped_source
             WHERE artifact_analysis_id = ?1
             ORDER BY source_kind ASC, source_fingerprint ASC, source_instance_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(source_kind, source_fingerprint, source_instance_fingerprint, reason, source_build_variant_fingerprint)| {
                Ok(StoredArtifactUnmappedSource {
                    source_kind: ArtifactAnalysisSourceKind::from_sql(&source_kind)?,
                    source_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_source.source_fingerprint",
                        source_fingerprint,
                    )?,
                    source_instance_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_unmapped_source.source_instance_fingerprint",
                        source_instance_fingerprint,
                    )?,
                    source_build_variant_fingerprint: source_build_variant_fingerprint
                        .ok_or_else(|| StoreError::InvalidMappingEvidence {
                            reason: "source build variant is absent".to_owned(),
                        })
                        .and_then(|value| {
                            fingerprint_from_blob(
                                "artifact_analysis_unmapped_source.source_build_variant_fingerprint",
                                value,
                            )
                        })?,
                    reason: ArtifactAnalysisUnmappedSourceReason::from_sql(&reason)?,
                })
            })
            .collect()
    }

    /// Persisted clone-group refactoring estimates for one artifact analysis.
    ///
    /// # Errors
    ///
    /// Returns an error when a row carries an unknown schema or vocabulary.
    pub fn artifact_clone_group_savings(
        &self,
        analysis_id: i64,
    ) -> Result<Vec<ArtifactAnalysisCloneGroupSavings>, StoreError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {CLONE_GROUP_SAVINGS_COLUMNS}
             FROM artifact_analysis_clone_group_savings
             WHERE artifact_analysis_id = ?1
             ORDER BY clone_group_fingerprint ASC, source_build_variant_fingerprint ASC,
                      artifact_build_variant_fingerprint ASC"
        ))?;
        let rows = statement
            .query_map([analysis_id], |row| clone_group_savings_row(row, 0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(CloneGroupSavingsSqlRow::decode)
            .collect()
    }

    /// Controlled before/after measurements recorded for one source group.
    ///
    /// # Errors
    ///
    /// Returns malformed IDs, unknown schema versions, and invalid numeric
    /// values instead of silently treating them as calibration data.
    pub fn artifact_savings_calibrations(
        &self,
        source_scan_run_id: i64,
        clone_group_fingerprint_hex: &str,
    ) -> Result<Vec<ArtifactAnalysisSavingsCalibration>, StoreError> {
        let fingerprint = parse_hex_id(clone_group_fingerprint_hex)?;
        let mut stmt = self.conn.prepare(
            "SELECT schema_version, artifact_analysis_id, source_build_variant_fingerprint,
                    before_artifact_build_variant_fingerprint, after_artifact_fingerprint,
                    after_artifact_build_variant_fingerprint, estimated_refactor_savings_bytes,
                    verified_savings_bytes, absolute_error_bytes, relative_error, recorded_at
             FROM artifact_analysis_savings_calibration
             WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2
             ORDER BY artifact_analysis_id ASC, after_artifact_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map(params![source_scan_run_id, fingerprint.as_slice()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<f64>>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(
                schema_version,
                artifact_analysis_id,
                source_build_variant_fingerprint,
                before_artifact_build_variant_fingerprint,
                after_artifact_fingerprint,
                after_artifact_build_variant_fingerprint,
                estimated_refactor_savings_bytes,
                verified_savings_bytes,
                absolute_error_bytes,
                relative_error,
                recorded_at,
            )| {
                if schema_version != ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "unknown artifact savings calibration schema".to_owned(),
                    });
                }
                if relative_error
                    .is_some_and(|value| !value.is_finite() || value.is_sign_negative())
                {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "calibration relative error must be finite and nonnegative"
                            .to_owned(),
                    });
                }
                Ok(ArtifactAnalysisSavingsCalibration {
                    schema_version,
                    artifact_analysis_id,
                    source_scan_run_id,
                    clone_group_fingerprint: fingerprint,
                    source_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.source_build_variant_fingerprint",
                        source_build_variant_fingerprint,
                    )?,
                    before_artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.before_artifact_build_variant_fingerprint",
                        before_artifact_build_variant_fingerprint,
                    )?,
                    after_artifact_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.after_artifact_fingerprint",
                        after_artifact_fingerprint,
                    )?,
                    after_artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_savings_calibration.after_artifact_build_variant_fingerprint",
                        after_artifact_build_variant_fingerprint,
                    )?,
                    estimated_refactor_savings_bytes,
                    verified_savings_bytes,
                    absolute_error_bytes: nonnegative_u64(
                        "artifact_analysis_savings_calibration.absolute_error_bytes",
                        absolute_error_bytes,
                    )?,
                    relative_error,
                    recorded_at,
                })
            })
            .collect()
    }

    /// Every controlled calibration retained for one source run, ordered by
    /// stable clone-group fingerprint and then by artifact identity.
    ///
    /// # Errors
    ///
    /// Returns malformed stored group identities rather than omitting their
    /// measurements from a corpus-level statistic.
    pub fn artifact_savings_calibrations_for_run(
        &self,
        source_scan_run_id: i64,
    ) -> Result<Vec<ArtifactAnalysisSavingsCalibration>, StoreError> {
        let groups: Vec<Vec<u8>> = self
            .conn
            .prepare(
                "SELECT DISTINCT clone_group_fingerprint
                 FROM artifact_analysis_savings_calibration
                 WHERE source_scan_run_id = ?1
                 ORDER BY clone_group_fingerprint ASC",
            )?
            .query_map([source_scan_run_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let mut calibrations = Vec::new();
        for group in groups {
            let fingerprint = fingerprint_from_blob(
                "artifact_analysis_savings_calibration.clone_group_fingerprint",
                group,
            )?;
            let hex = crate::fingerprint_hex(fingerprint);
            calibrations.extend(self.artifact_savings_calibrations(source_scan_run_id, &hex)?);
        }
        Ok(calibrations)
    }

    /// Coverage figures recorded with one explicit source-run correlation.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or contains an
    /// unknown correlation-summary schema.
    pub fn artifact_correlation(
        &self,
        analysis_id: i64,
    ) -> Result<Option<StoredArtifactAnalysisCorrelation>, StoreError> {
        self.conn
            .query_row(
                "SELECT schema_version, source_scan_run_id, mapping_count, artifact_symbol_count,
                        mapped_symbol_count, artifact_symbol_bytes, mapped_symbol_bytes
                 FROM artifact_analysis_correlation
                 WHERE artifact_analysis_id = ?1",
                [analysis_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    schema_version,
                    source_scan_run_id,
                    mapping_count,
                    artifact_symbol_count,
                    mapped_symbol_count,
                    artifact_symbol_bytes,
                    mapped_symbol_bytes,
                )| {
                    if schema_version != ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION {
                        return Err(StoreError::InvalidMappingEvidence {
                            reason: "unknown artifact correlation summary schema".to_owned(),
                        });
                    }
                    Ok(StoredArtifactAnalysisCorrelation {
                        schema_version,
                        source_scan_run_id,
                        mapping_count: nonnegative_u64(
                            "artifact_analysis_correlation.mapping_count",
                            mapping_count,
                        )?,
                        artifact_symbol_count: nonnegative_u64(
                            "artifact_analysis_correlation.artifact_symbol_count",
                            artifact_symbol_count,
                        )?,
                        mapped_symbol_count: nonnegative_u64(
                            "artifact_analysis_correlation.mapped_symbol_count",
                            mapped_symbol_count,
                        )?,
                        artifact_symbol_bytes: nonnegative_u64(
                            "artifact_analysis_correlation.artifact_symbol_bytes",
                            artifact_symbol_bytes,
                        )?,
                        mapped_symbol_bytes: nonnegative_u64(
                            "artifact_analysis_correlation.mapped_symbol_bytes",
                            mapped_symbol_bytes,
                        )?,
                    })
                },
            )
            .transpose()
    }
}

/// The savings columns, in the one order every reader of this table binds
/// them. One decoder then serves every scope a caller can ask for.
const CLONE_GROUP_SAVINGS_COLUMNS: &str = "schema_version, source_scan_run_id, \
     clone_group_fingerprint, source_build_variant_fingerprint, \
     artifact_build_variant_fingerprint, duplicated_bytes, \
     estimated_refactor_savings_bytes, mapping_confidence, clone_confidence, \
     model_confidence, savings_confidence, model_schema_version, assumptions_json";

/// The same columns qualified with a table alias, for a query that joins.
fn clone_group_savings_columns(alias: &str) -> String {
    CLONE_GROUP_SAVINGS_COLUMNS
        .split(',')
        .map(|column| format!("{alias}.{}", column.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One savings row as `SQLite` returned it, before its vocabulary and stored
/// identities have been established.
struct CloneGroupSavingsSqlRow {
    schema_version: String,
    source_scan_run_id: i64,
    clone_group_fingerprint: Vec<u8>,
    source_build_variant_fingerprint: Vec<u8>,
    artifact_build_variant_fingerprint: Vec<u8>,
    duplicated_bytes: i64,
    estimated_refactor_savings_bytes: i64,
    mapping_confidence: String,
    clone_confidence: f64,
    model_confidence: String,
    savings_confidence: String,
    model_schema_version: String,
    assumptions_json: String,
}

/// Read the savings columns starting at `offset`, so a query may select its
/// own columns before them.
fn clone_group_savings_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<CloneGroupSavingsSqlRow> {
    Ok(CloneGroupSavingsSqlRow {
        schema_version: row.get(offset)?,
        source_scan_run_id: row.get(offset + 1)?,
        clone_group_fingerprint: row.get(offset + 2)?,
        source_build_variant_fingerprint: row.get(offset + 3)?,
        artifact_build_variant_fingerprint: row.get(offset + 4)?,
        duplicated_bytes: row.get(offset + 5)?,
        estimated_refactor_savings_bytes: row.get(offset + 6)?,
        mapping_confidence: row.get(offset + 7)?,
        clone_confidence: row.get(offset + 8)?,
        model_confidence: row.get(offset + 9)?,
        savings_confidence: row.get(offset + 10)?,
        model_schema_version: row.get(offset + 11)?,
        assumptions_json: row.get(offset + 12)?,
    })
}

impl CloneGroupSavingsSqlRow {
    /// Establish the stored row's schema, identities, and vocabulary.
    fn decode(self) -> Result<ArtifactAnalysisCloneGroupSavings, StoreError> {
        if self.schema_version != ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "unknown artifact clone-group savings schema".to_owned(),
            });
        }
        let assumptions: serde_json::Value =
            serde_json::from_str(&self.assumptions_json).map_err(|_| {
                StoreError::InvalidMappingEvidence {
                    reason: "savings assumptions are not valid JSON".to_owned(),
                }
            })?;
        if !assumptions.is_array() {
            return Err(StoreError::InvalidMappingEvidence {
                reason: "savings assumptions are not a JSON array".to_owned(),
            });
        }
        Ok(ArtifactAnalysisCloneGroupSavings {
            schema_version: self.schema_version,
            source_scan_run_id: self.source_scan_run_id,
            clone_group_fingerprint: fingerprint_from_blob(
                "artifact_analysis_clone_group_savings.clone_group_fingerprint",
                self.clone_group_fingerprint,
            )?,
            source_build_variant_fingerprint: fingerprint_from_blob(
                "artifact_analysis_clone_group_savings.source_build_variant_fingerprint",
                self.source_build_variant_fingerprint,
            )?,
            artifact_build_variant_fingerprint: fingerprint_from_blob(
                "artifact_analysis_clone_group_savings.artifact_build_variant_fingerprint",
                self.artifact_build_variant_fingerprint,
            )?,
            duplicated_bytes: nonnegative_u64(
                "artifact_analysis_clone_group_savings.duplicated_bytes",
                self.duplicated_bytes,
            )?,
            estimated_refactor_savings_bytes: self.estimated_refactor_savings_bytes,
            mapping_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                &self.mapping_confidence,
            )?,
            clone_confidence: self.clone_confidence,
            model_confidence: ArtifactAnalysisSavingsConfidence::from_sql(&self.model_confidence)?,
            savings_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                &self.savings_confidence,
            )?,
            model_schema_version: self.model_schema_version,
            assumptions_json: self.assumptions_json,
        })
    }
}
