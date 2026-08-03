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
    /// The newest saved artifact analysis, if one exists.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_artifact_analysis_id(&self) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                "SELECT id FROM artifact_analysis
                 ORDER BY finished_at DESC, id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

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

    /// Every persisted savings record for one source run and clone group.
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
        let analysis_ids: Vec<i64> = self
            .conn
            .prepare(
                "SELECT DISTINCT artifact_analysis_id
                 FROM artifact_analysis_clone_group_savings
                 WHERE source_scan_run_id = ?1 AND clone_group_fingerprint = ?2
                 ORDER BY artifact_analysis_id ASC",
            )?
            .query_map(params![source_scan_run_id, fingerprint.as_slice()], |row| {
                row.get(0)
            })?
            .collect::<Result<_, _>>()?;
        let mut savings = Vec::new();
        for analysis_id in analysis_ids {
            savings.extend(
                self.artifact_clone_group_savings(analysis_id)?
                    .into_iter()
                    .filter(|estimate| {
                        estimate.source_scan_run_id == source_scan_run_id
                            && estimate.clone_group_fingerprint == fingerprint
                    })
                    .map(|estimate| (analysis_id, estimate)),
            );
        }
        Ok(savings)
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
        let mut stmt = self.conn.prepare(
            "SELECT schema_version, source_scan_run_id, clone_group_fingerprint,
                    source_build_variant_fingerprint, artifact_build_variant_fingerprint,
                    duplicated_bytes, estimated_refactor_savings_bytes,
                    mapping_confidence, clone_confidence, model_confidence,
                    savings_confidence, model_schema_version, assumptions_json
             FROM artifact_analysis_clone_group_savings
             WHERE artifact_analysis_id = ?1
             ORDER BY clone_group_fingerprint ASC, source_build_variant_fingerprint ASC,
                      artifact_build_variant_fingerprint ASC",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, f64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(
                schema_version,
                source_scan_run_id,
                clone_group_fingerprint,
                source_build_variant_fingerprint,
                artifact_build_variant_fingerprint,
                duplicated_bytes,
                estimated_refactor_savings_bytes,
                mapping_confidence,
                clone_confidence,
                model_confidence,
                savings_confidence,
                model_schema_version,
                assumptions_json,
            )| {
                if schema_version != ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "unknown artifact clone-group savings schema".to_owned(),
                    });
                }
                let assumptions: serde_json::Value = serde_json::from_str(&assumptions_json)
                    .map_err(|_| StoreError::InvalidMappingEvidence {
                        reason: "savings assumptions are not valid JSON".to_owned(),
                    })?;
                if !assumptions.is_array() {
                    return Err(StoreError::InvalidMappingEvidence {
                        reason: "savings assumptions are not a JSON array".to_owned(),
                    });
                }
                Ok(ArtifactAnalysisCloneGroupSavings {
                    schema_version,
                    source_scan_run_id,
                    clone_group_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.clone_group_fingerprint",
                        clone_group_fingerprint,
                    )?,
                    source_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.source_build_variant_fingerprint",
                        source_build_variant_fingerprint,
                    )?,
                    artifact_build_variant_fingerprint: fingerprint_from_blob(
                        "artifact_analysis_clone_group_savings.artifact_build_variant_fingerprint",
                        artifact_build_variant_fingerprint,
                    )?,
                    duplicated_bytes: nonnegative_u64(
                        "artifact_analysis_clone_group_savings.duplicated_bytes",
                        duplicated_bytes,
                    )?,
                    estimated_refactor_savings_bytes,
                    mapping_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &mapping_confidence,
                    )?,
                    clone_confidence,
                    model_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &model_confidence,
                    )?,
                    savings_confidence: ArtifactAnalysisSavingsConfidence::from_sql(
                        &savings_confidence,
                    )?,
                    model_schema_version,
                    assumptions_json,
                })
            })
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
