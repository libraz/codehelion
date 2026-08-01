use super::common::{fingerprint_from_blob, parse_build_variant_reference, positive_line};
use super::{
    FeatureKind, FeatureOccurrence, SourceFragmentIdentity, SourceInstantiation,
    SourceMacroDefinition, SourceResolvedCall, SourceResolvedSymbol, SourceUnitIdentity, Store,
    StoreError, params,
};

impl Store {
    /// Source units recorded by one scan, in deterministic path and anchor order.
    ///
    /// The returned identities carry their own build variants. A caller must
    /// retain that value when it turns a path match into a correspondence.
    ///
    /// # Errors
    ///
    /// Returns an error when stored fingerprints cannot be represented by
    /// this build's stable fingerprint schema.
    pub fn source_units(&self, scan_run_id: i64) -> Result<Vec<SourceUnitIdentity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT f.hash, bv.variant_fingerprint, u.file_path, u.name, u.unit_kind,
                    ROW_NUMBER() OVER (
                        PARTITION BY u.file_path, u.name, u.unit_kind, f.hash, bv.variant_fingerprint
                        ORDER BY u.id ASC
                    ),
                    u.start_line, u.end_line
             FROM source_unit u
             JOIN fingerprint f ON f.id = u.fingerprint_id
             JOIN build_variant bv ON bv.id = f.build_variant_id
             WHERE u.scan_run_id = ?1
             ORDER BY u.file_path ASC, u.start_line ASC, u.end_line ASC, f.hash ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    fingerprint,
                    build_variant,
                    file_path,
                    name,
                    unit_kind,
                    occurrence_ordinal,
                    start_line,
                    end_line,
                )| {
                    Ok(SourceUnitIdentity {
                        fingerprint: fingerprint_from_blob("fingerprint.hash", fingerprint)?,
                        build_variant_fingerprint: parse_build_variant_reference(&build_variant)?,
                        file_path,
                        name,
                        unit_kind,
                        occurrence_ordinal: u32::try_from(occurrence_ordinal).map_err(|_| {
                            StoreError::UnknownVocabulary {
                                field: "source_unit.occurrence_ordinal",
                                value: occurrence_ordinal.to_string(),
                            }
                        })?,
                        start_line: positive_line("source_unit.start_line", start_line)?,
                        end_line: positive_line("source_unit.end_line", end_line)?,
                    })
                },
            )
            .collect()
    }

    /// Clone finding fragments recorded by one scan, in stable identity order.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored fingerprint cannot be represented by
    /// this build's stable fingerprint schema.
    pub fn source_clone_fragments(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceFragmentIdentity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT f.hash, m.finding_id, gf.hash, m.is_canonical, g.score,
                    bv.variant_fingerprint, r.file_path,
                    r.start_line, r.end_line
             FROM fragment r
             JOIN clone_group_member m ON m.fragment_id = r.id
             JOIN clone_group g ON g.id = m.clone_group_id
             JOIN fingerprint f ON f.id = r.fingerprint_id
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             JOIN build_variant bv ON bv.id = f.build_variant_id
             WHERE r.scan_run_id = ?1 AND g.scan_run_id = ?1
             ORDER BY gf.hash ASC, m.is_canonical DESC, m.finding_id ASC,
                      f.hash ASC, bv.variant_fingerprint ASC, r.file_path ASC,
                      r.start_line ASC, r.end_line ASC, r.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    fingerprint,
                    finding_id,
                    clone_group_fingerprint,
                    is_canonical,
                    clone_confidence,
                    build_variant,
                    file_path,
                    start_line,
                    end_line,
                )| {
                    Ok(SourceFragmentIdentity {
                        fingerprint: fingerprint_from_blob("fingerprint.hash", fingerprint)?,
                        finding_id: fingerprint_from_blob(
                            "clone_group_member.finding_id",
                            finding_id,
                        )?,
                        clone_group_fingerprint: fingerprint_from_blob(
                            "clone_group.group_fingerprint",
                            clone_group_fingerprint,
                        )?,
                        is_canonical: is_canonical != 0,
                        clone_confidence,
                        build_variant_fingerprint: parse_build_variant_reference(&build_variant)?,
                        file_path,
                        start_line: positive_line("fragment.start_line", start_line)?,
                        end_line: positive_line("fragment.end_line", end_line)?,
                    })
                },
            )
            .collect()
    }

    /// Local compiler-resolved function anchors from one source scan.
    ///
    /// Only symbols the compiler marked as belonging to the scanned tree are
    /// returned. The source unit relationship remains a caller-side
    /// containment check rather than a persisted assertion.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded compiler anchor has an invalid line.
    pub fn source_resolved_symbols(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceResolvedSymbol>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.name, COALESCE(s.definition_file, s.expansion_file),
                    COALESCE(s.definition_start_line, s.expansion_start_line),
                    s.definition_file, s.definition_start_line,
                    s.expansion_file, s.expansion_start_line
             FROM compiler_symbol s
             JOIN compiler_unit u ON u.id = s.compiler_unit_id
             WHERE u.scan_run_id = ?1
               AND s.symbol_kind = 'function'
               AND s.external = 0
             ORDER BY s.name ASC, COALESCE(s.definition_file, s.expansion_file) ASC,
                      COALESCE(s.definition_start_line, s.expansion_start_line) ASC, s.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    name,
                    file_path,
                    line,
                    definition_file,
                    definition_line,
                    expansion_file,
                    expansion_line,
                )| {
                    let line = positive_line("compiler_symbol.definition_start_line", Some(line))?
                        .ok_or_else(|| StoreError::UnknownVocabulary {
                            field: "compiler_symbol.definition_start_line",
                            value: "NULL".to_owned(),
                        })?;
                    let macro_definition = match (
                        definition_file,
                        definition_line,
                        expansion_file,
                        expansion_line,
                    ) {
                        (
                            Some(definition_file),
                            Some(definition_line),
                            Some(expansion_file),
                            Some(expansion_line),
                        ) if definition_file != expansion_file
                            || definition_line != expansion_line =>
                        {
                            Some(SourceMacroDefinition {
                                line: positive_line(
                                    "compiler_symbol.definition_start_line",
                                    Some(definition_line),
                                )?
                                .ok_or_else(|| {
                                    StoreError::UnknownVocabulary {
                                        field: "compiler_symbol.definition_start_line",
                                        value: "NULL".to_owned(),
                                    }
                                })?,
                                file_path: definition_file,
                            })
                        }
                        _ => None,
                    };
                    Ok(SourceResolvedSymbol {
                        name,
                        file_path,
                        line,
                        macro_definition,
                    })
                },
            )
            .collect()
    }

    /// Statically resolved local call anchors from one source scan.
    ///
    /// Dynamic and unresolved dispatch cannot establish an independent
    /// call-graph correspondence, so they are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded compiler call anchor has an invalid line.
    pub fn source_resolved_calls(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceResolvedCall>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.target_symbol, COALESCE(c.definition_file, c.expansion_file),
                    COALESCE(c.definition_start_line, c.expansion_start_line)
             FROM compiler_call c
             JOIN compiler_unit u ON u.id = c.compiler_unit_id
             WHERE u.scan_run_id = ?1 AND c.resolution = 'static'
             ORDER BY c.target_symbol ASC,
                      COALESCE(c.definition_file, c.expansion_file) ASC,
                      COALESCE(c.definition_start_line, c.expansion_start_line) ASC, c.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(target_name, file_path, line)| {
                let line = positive_line("compiler_call.definition_start_line", Some(line))?
                    .ok_or_else(|| StoreError::UnknownVocabulary {
                        field: "compiler_call.definition_start_line",
                        value: "NULL".to_owned(),
                    })?;
                Ok(SourceResolvedCall {
                    target_name,
                    file_path,
                    line,
                })
            })
            .collect()
    }

    /// Local compiler-reported generic and template instantiation anchors.
    ///
    /// These rows remain separate from source units; correlation performs the
    /// containment check and only accepts a key that agrees with an artifact's
    /// demangled full name.
    ///
    /// # Errors
    ///
    /// Returns an error when a recorded instantiation anchor has an invalid line.
    pub fn source_instantiations(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<SourceInstantiation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT i.definition, i.artifact_match_key, i.instantiation_key, u.file_path,
                    COALESCE(i.definition_file, i.expansion_file),
                    COALESCE(i.definition_start_line, i.expansion_start_line),
                    i.definition_end_line
             FROM compiler_instantiation i
             JOIN compiler_unit u ON u.id = i.compiler_unit_id
             WHERE u.scan_run_id = ?1
             ORDER BY i.instantiation_key ASC,
                      COALESCE(i.definition_file, i.expansion_file) ASC,
                      COALESCE(i.definition_start_line, i.expansion_start_line) ASC, i.id ASC",
        )?;
        let rows = stmt
            .query_map([scan_run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    definition,
                    artifact_match_key,
                    instantiation_key,
                    translation_unit,
                    file_path,
                    line,
                    definition_end_line,
                )| {
                    let line =
                        positive_line("compiler_instantiation.definition_start_line", Some(line))?
                            .ok_or_else(|| StoreError::UnknownVocabulary {
                                field: "compiler_instantiation.definition_start_line",
                                value: "NULL".to_owned(),
                            })?;
                    Ok(SourceInstantiation {
                        definition,
                        artifact_match_key,
                        instantiation_key,
                        file_path,
                        line,
                        definition_end_line: positive_line(
                            "compiler_instantiation.definition_end_line",
                            definition_end_line,
                        )?,
                        translation_unit,
                    })
                },
            )
            .collect()
    }

    /// The posting list of one feature hash: every occurrence of `kind`/`hash`,
    /// deterministically ordered by run, unit and anchor. This is the read the
    /// candidate index builds on.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn feature_posting_list(
        &self,
        kind: FeatureKind,
        hash: &[u8; 16],
    ) -> Result<Vec<FeatureOccurrence>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT o.scan_run_id, o.source_unit_id, o.start_byte, o.end_byte, o.extent
             FROM feature_occurrence o
             JOIN feature_fingerprint f ON f.id = o.feature_fingerprint_id
             WHERE f.kind = ?1 AND f.hash = ?2
             ORDER BY o.scan_run_id ASC, o.source_unit_id ASC, o.start_byte ASC, o.id ASC",
        )?;
        let rows = stmt
            .query_map(params![kind.name(), hash.as_slice()], |row| {
                Ok(FeatureOccurrence {
                    scan_run_id: row.get(0)?,
                    source_unit_id: row.get(1)?,
                    start_byte: row.get(2)?,
                    end_byte: row.get(3)?,
                    extent: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}
