use super::BuildVariantFingerprint;
use super::{
    ArtifactMappingSqlRow, CrossLanguageGroupDetail, CrossLanguageGroupMember,
    CrossVariantGroupDetail, CrossVariantGroupMember, OccurrenceDetail, StoredArtifactMapping,
    StoredMember, StoredPriority, StoredRankingFacts, StoredSuppressionRef,
    stored_test_code_evidence,
};
use crate::artifact::{
    ArtifactAnalysisMappingConfidence, ArtifactAnalysisSourceKind, MappingEvidence,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
};
use crate::{Store, StoreError};
use rusqlite::{OptionalExtension, Row, params};
use std::collections::BTreeSet;

pub(super) use crate::fingerprint::{parse_build_variant_reference, parse_hex_id};

/// Join a clone group to a completed source scan.
///
/// Every query whose answer names a clone group must use this exact fragment;
/// incomplete snapshots are rolled back or retained only as implementation
/// state and must never be visible to explain or ID completion.
pub(super) const COMPLETED_CLONE_GROUP_RUN_JOIN: &str =
    "JOIN scan_run r ON r.id = g.scan_run_id AND r.status = 'completed'";

impl Store {
    /// Number of rows in `table` — a diagnostic for `doctor`/`cache status`
    /// and tests. The name is validated against the schema first, so this
    /// never interpolates arbitrary input into SQL.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownTable`] when `table` is not a known table;
    /// otherwise any underlying database error.
    pub fn table_count(&self, table: &str) -> Result<i64, StoreError> {
        let known: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )?;
        if known != 1 {
            return Err(StoreError::UnknownTable {
                table: table.to_string(),
            });
        }
        Ok(self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?)
    }

    /// Look up one occurrence by the hex form of its finding id.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `finding_hex` is not 32 hex digits;
    /// otherwise any underlying database error.
    pub fn occurrence(&self, finding_hex: &str) -> Result<Option<OccurrenceDetail>, StoreError> {
        let bytes = parse_hex_id(finding_hex)?;
        let found = self
            .conn
            .query_row(
                "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                        fr.token_count, u.name, m.is_canonical,
                        lower(hex(gf.hash)), g.clone_type, g.score, g.scan_run_id,
                        g.member_count, g.boilerplate, s.scope, s.pattern, s.reason, s.active,
                        g.id, g.member_scope, g.test_code, g.test_code_evidence, g.split_pair,
                        lower(hex(ff.hash)), ff.language, m.boilerplate, g.entropy_bits,
                        g.suppress_reason
                 FROM clone_group_member m
                 JOIN fragment fr ON fr.id = m.fragment_id
                 JOIN fingerprint ff ON ff.id = fr.fingerprint_id
                 LEFT JOIN source_unit u ON u.id = fr.source_unit_id
                 JOIN clone_group g ON g.id = m.clone_group_id
                 JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
                 LEFT JOIN finding fi ON fi.clone_group_id = g.id
                                     AND fi.scan_run_id = g.scan_run_id
                 LEFT JOIN suppression s ON s.id = fi.suppression_id
                 JOIN scan_run r ON r.id = g.scan_run_id
                 WHERE m.finding_id = ?1
                   AND r.status = 'completed'
                 ORDER BY g.scan_run_id DESC
                 LIMIT 1",
                params![bytes.as_slice()],
                |row| {
                    let suppression = row
                        .get::<_, Option<String>>(13)?
                        .map(|scope| -> Result<_, rusqlite::Error> {
                            Ok(StoredSuppressionRef {
                                scope,
                                pattern: row.get(14)?,
                                reason: row.get(15)?,
                                active: row.get(16)?,
                            })
                        })
                        .transpose()?;
                    Ok((
                        OccurrenceDetail {
                            member: map_member(row, 22)?,
                            group_fingerprint_hex: row.get(7)?,
                            clone_type: row.get(8)?,
                            member_scope: row.get(18)?,
                            score: row.get(9)?,
                            entropy_bits: row.get(25)?,
                            scan_run_id: row.get(10)?,
                            member_count: row.get(11)?,
                            boilerplate: row.get(12)?,
                            test_code: row.get(19)?,
                            test_code_evidence: stored_test_code_evidence(row, 20)?,
                            split_pair: row.get(21)?,
                            similarity: None,
                            semantic: None,
                            priority: None,
                            suppress_reason: row.get(26)?,
                            suppression,
                        },
                        row.get::<_, i64>(17)?,
                    ))
                },
            )
            .optional()?;
        let Some((mut detail, group_row_id)) = found else {
            return Ok(None);
        };
        detail.similarity = self.group_similarity(group_row_id)?;
        detail.semantic = self.group_semantic_evidence(group_row_id)?;
        detail.priority = self.group_priority(group_row_id, detail.scan_run_id)?;
        Ok(Some(detail))
    }

    /// Look up one explicit Rust-to-C++ semantic comparison group by its
    /// stable comparison-domain id.
    ///
    /// The newest persisted comparison wins when the same deterministic group
    /// identity was recorded more than once. This does not merge comparisons:
    /// the returned origin variants remain those of that one invocation.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `group_hex` is not 32 hex digits;
    /// otherwise any underlying database or persisted-SOG validation error.
    pub fn cross_language_group(
        &self,
        group_hex: &str,
    ) -> Result<Option<CrossLanguageGroupDetail>, StoreError> {
        let group_id = parse_hex_id(group_hex)?;
        let Some((group_row_id, comparison_row_id, mut detail)) =
            self.cross_language_group_header(group_id)?
        else {
            return Ok(None);
        };
        detail.origin_variants = self.cross_language_origins(comparison_row_id)?;
        detail.members = self.cross_language_members(group_row_id)?;
        Ok(Some(detail))
    }

    /// Look up one explicit cross-build-variant clone group by its stable id.
    ///
    /// The newest persisted comparison wins when the same deterministic group
    /// identity was recorded more than once.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `group_hex` is not 32 hex digits;
    /// otherwise any underlying database or stored-vocabulary error.
    pub fn cross_variant_group(
        &self,
        group_hex: &str,
    ) -> Result<Option<CrossVariantGroupDetail>, StoreError> {
        let group_id = parse_hex_id(group_hex)?;
        let Some((group_row_id, comparison_row_id, mut detail)) = self
            .conn
            .query_row(
                "SELECT g.id, c.id, lower(hex(c.comparison_id)), c.policy_version, c.root_path,
                        lower(hex(g.group_id)), g.clone_type
                 FROM cross_variant_clone_group g
                 JOIN cross_variant_comparison c ON c.id = g.comparison_id
                 WHERE g.group_id = ?1
                 ORDER BY c.started_at DESC, c.id DESC
                 LIMIT 1",
                params![group_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        CrossVariantGroupDetail {
                            comparison_id_hex: row.get(2)?,
                            policy_version: row.get(3)?,
                            root_path: row.get(4)?,
                            origin_variants: Vec::new(),
                            group_id_hex: row.get(5)?,
                            clone_type: row.get(6)?,
                            members: Vec::new(),
                        },
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        detail.origin_variants = self
            .conn
            .prepare(
                "SELECT build_variant_fingerprint
                 FROM cross_variant_comparison_origin
                 WHERE comparison_id = ?1
                 ORDER BY build_variant_fingerprint ASC",
            )?
            .query_map(params![comparison_row_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let rows = self
            .conn
            .prepare(
                "SELECT origin_variant_fingerprint, language, file_path, start_line, end_line,
                        unit_name, token_count
                 FROM cross_variant_clone_member
                 WHERE group_id = ?1
                 ORDER BY origin_variant_fingerprint ASC, language ASC, file_path ASC,
                          start_line ASC, end_line ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        detail.members = rows
            .into_iter()
            .map(
                |(origin_variant, language, file_path, start_line, end_line, unit_name, tokens)| {
                    Ok(CrossVariantGroupMember {
                        origin_variant,
                        language,
                        file_path,
                        start_line: positive_cross_variant_value("start_line", start_line)?,
                        end_line: positive_cross_variant_value("end_line", end_line)?,
                        unit_name,
                        token_count: usize::try_from(tokens).map_err(|_| {
                            StoreError::UnknownVocabulary {
                                field: "cross_variant_clone_member.token_count",
                                value: tokens.to_string(),
                            }
                        })?,
                    })
                },
            )
            .collect::<Result<_, StoreError>>()?;
        Ok(Some(detail))
    }

    fn cross_language_group_header(
        &self,
        group_id: [u8; 16],
    ) -> Result<Option<(i64, i64, CrossLanguageGroupDetail)>, StoreError> {
        self.conn
            .query_row(
                "SELECT g.id, c.id, lower(hex(c.comparison_id)), c.policy_version, c.root_path,
                        lower(hex(g.group_id)), g.rule_id, g.rule_version, g.semantic_confidence,
                        g.correspondence_ids_json
                 FROM cross_language_semantic_group g
                 JOIN cross_language_comparison c ON c.id = g.comparison_id
                 WHERE g.group_id = ?1
                 ORDER BY c.started_at DESC, c.id DESC
                 LIMIT 1",
                params![group_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        CrossLanguageGroupDetail {
                            comparison_id_hex: row.get(2)?,
                            policy_version: row.get(3)?,
                            root_path: row.get(4)?,
                            origin_variants: Vec::new(),
                            group_id_hex: row.get(5)?,
                            rule_id: row.get(6)?,
                            rule_version: row.get(7)?,
                            semantic_confidence: row.get(8)?,
                            correspondence_ids: serde_json::from_str::<Vec<String>>(
                                &row.get::<_, String>(9)?,
                            )
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    9,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                            members: Vec::new(),
                        },
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn cross_language_origins(&self, comparison_row_id: i64) -> Result<Vec<String>, StoreError> {
        self.conn
            .prepare(
                "SELECT build_variant_fingerprint
                 FROM cross_language_comparison_origin
                 WHERE comparison_id = ?1
                 ORDER BY build_variant_fingerprint ASC",
            )?
            .query_map(params![comparison_row_id], |row| row.get(0))?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    fn cross_language_members(
        &self,
        group_row_id: i64,
    ) -> Result<Vec<CrossLanguageGroupMember>, StoreError> {
        let members: Vec<StoredCrossLanguageMemberRow> = self
            .conn
            .prepare(
                "SELECT origin_variant_fingerprint, language, file_path, start_line, end_line,
                        unit_name, graph_schema_version, graph_json
                 FROM cross_language_semantic_member
                 WHERE group_id = ?1
                 ORDER BY origin_variant_fingerprint ASC, language ASC, file_path ASC,
                          start_line ASC, end_line ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        members
            .into_iter()
            .map(decode_cross_language_member)
            .collect()
    }

    /// Where a run ranked one group's finding, with the facts behind it.
    pub(super) fn group_priority(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<Option<StoredPriority>, StoreError> {
        let facts = self.ranking_facts(group_row_id, run_id)?;
        Ok(self
            .conn
            .query_row(
                "SELECT clone_confidence, maintenance_risk, refactoring_difficulty,
                        final_priority, semantic_confidence,
                        source_artifact_mapping_confidence, savings_confidence
                 FROM finding
                 WHERE clone_group_id = ?1 AND scan_run_id = ?2",
                params![group_row_id, run_id],
                |row| {
                    Ok(StoredPriority {
                        clone_confidence: row.get(0)?,
                        maintenance_risk: row.get(1)?,
                        refactoring_difficulty: row.get(2)?,
                        final_priority: row.get(3)?,
                        semantic_confidence: row.get(4)?,
                        source_artifact_confidence: row.get(5)?,
                        savings_confidence: row.get(6)?,
                        facts,
                    })
                },
            )
            .optional()?)
    }

    /// One stored group as the ranking reads it.
    ///
    /// The directory count is taken in Rust rather than in SQL: splitting a
    /// path is not something an expression over `TEXT` does readably, and the
    /// member count of a group is small enough that reading the paths costs
    /// nothing.
    pub(super) fn ranking_facts(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<StoredRankingFacts, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT fr.file_path, fr.token_count, ff.language
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             WHERE m.clone_group_id = ?1",
        )?;
        let rows = statement.query_map(params![group_row_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut tokens: Vec<i64> = Vec::new();
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut directories: BTreeSet<String> = BTreeSet::new();
        let mut languages: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let (path, token_count, language) = row?;
            tokens.push(token_count);
            directories.insert(crate::directory_of(&path).to_string());
            files.insert(path);
            languages.insert(language);
        }
        let min_clone_tokens = self.conn.query_row(
            "SELECT min_clone_tokens FROM scan_run WHERE id = ?1",
            params![run_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(StoredRankingFacts {
            smallest_member_tokens: tokens.iter().copied().min().unwrap_or(0),
            largest_member_tokens: tokens.iter().copied().max().unwrap_or(0),
            instances: i64::try_from(tokens.len()).unwrap_or(i64::MAX),
            files: i64::try_from(files.len()).unwrap_or(i64::MAX),
            directories: i64::try_from(directories.len()).unwrap_or(i64::MAX),
            languages: i64::try_from(languages.len()).unwrap_or(i64::MAX),
            min_clone_tokens,
        })
    }
}

/// Read one member from a row whose first seven columns are the member's, and
/// whose content and language columns start at `content` — the two queries
/// that select members place the pair differently but always adjacently.
pub(super) fn map_member(row: &Row<'_>, content: usize) -> Result<StoredMember, rusqlite::Error> {
    Ok(StoredMember {
        finding_hex: row.get(0)?,
        content_hex: row.get(content)?,
        language: row.get(content + 1)?,
        file_path: row.get(1)?,
        start_line: row.get(2)?,
        end_line: row.get(3)?,
        token_count: row.get(4)?,
        unit_name: row.get(5)?,
        boilerplate: row.get(content + 2)?,
        is_canonical: row.get::<_, i64>(6)? != 0,
    })
}

type StoredCrossLanguageMemberRow = (
    String,
    String,
    String,
    i64,
    i64,
    Option<String>,
    String,
    String,
);

fn decode_cross_language_member(
    (origin_variant, language, file_path, start_line, end_line, unit_name, schema, graph):
        StoredCrossLanguageMemberRow,
) -> Result<CrossLanguageGroupMember, StoreError> {
    Ok(CrossLanguageGroupMember {
        origin_variant,
        language,
        file_path,
        start_line: positive_cross_language_line("start_line", start_line)?,
        end_line: positive_cross_language_line("end_line", end_line)?,
        unit_name,
        graph: Store::decode_stored_sog(&schema, &graph)?,
    })
}

fn positive_cross_language_line(field: &'static str, value: i64) -> Result<u32, StoreError> {
    u32::try_from(value)
        .ok()
        .filter(|line| *line > 0)
        .ok_or_else(|| StoreError::UnknownVocabulary {
            field: match field {
                "start_line" => "cross_language_semantic_member.start_line",
                "end_line" => "cross_language_semantic_member.end_line",
                _ => "cross_language_semantic_member.line",
            },
            value: value.to_string(),
        })
}

fn positive_cross_variant_value(field: &'static str, value: i64) -> Result<u32, StoreError> {
    u32::try_from(value)
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| StoreError::UnknownVocabulary {
            field: match field {
                "start_line" => "cross_variant_clone_member.start_line",
                "end_line" => "cross_variant_clone_member.end_line",
                _ => "cross_variant_clone_member.value",
            },
            value: value.to_string(),
        })
}

pub(super) fn decode_artifact_mapping(
    ArtifactMappingSqlRow {
        analysis_id,
        schema_version,
        artifact_symbol_fingerprint,
        source_kind,
        source_fingerprint,
        source_instance_fingerprint,
        evidence_json,
        confidence,
        attributed_bytes,
        build_variant_fingerprint,
        source_build_variant_fingerprint,
    }: ArtifactMappingSqlRow,
) -> Result<StoredArtifactMapping, StoreError> {
    if schema_version != SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION {
        return Err(StoreError::InvalidMappingEvidence {
            reason: "unknown source-artifact mapping schema".to_owned(),
        });
    }
    Ok(StoredArtifactMapping {
        analysis_id,
        schema_version,
        artifact_symbol_fingerprint: fingerprint_from_blob(
            "artifact_analysis_source_mapping.artifact_symbol_fingerprint",
            artifact_symbol_fingerprint,
        )?,
        source_kind: ArtifactAnalysisSourceKind::from_sql(&source_kind)?,
        source_fingerprint: fingerprint_from_blob(
            "artifact_analysis_source_mapping.source_fingerprint",
            source_fingerprint,
        )?,
        source_instance_fingerprint: fingerprint_from_blob(
            "artifact_analysis_source_mapping.source_instance_fingerprint",
            source_instance_fingerprint,
        )?,
        source_build_variant_fingerprint: source_build_variant_fingerprint
            .ok_or_else(|| StoreError::InvalidMappingEvidence {
                reason: "source build variant is absent".to_owned(),
            })
            .and_then(|value| {
                build_variant_from_blob(
                    "artifact_analysis_source_mapping.source_build_variant_fingerprint",
                    value,
                )
            })?,
        evidence: MappingEvidence::from_json(&evidence_json)?,
        confidence: ArtifactAnalysisMappingConfidence::from_sql(&confidence)?,
        attributed_bytes: attributed_bytes
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::UnknownVocabulary {
                field: "artifact_analysis_source_mapping.attributed_bytes",
                value: attributed_bytes.unwrap_or_default().to_string(),
            })?,
        build_variant_fingerprint: build_variant_from_blob(
            "artifact_analysis_source_mapping.build_variant_fingerprint",
            build_variant_fingerprint,
        )?,
    })
}

/// The same read, for the one digest that names a build rather than code.
///
/// A separate entry point instead of a cast at each call: the point of the
/// type is that a reader can see which digest is being treated as which, and
/// a conversion spelled the same way for both would put that back where it
/// was.
pub(super) fn build_variant_from_blob(
    field: &'static str,
    value: Vec<u8>,
) -> Result<BuildVariantFingerprint, StoreError> {
    fingerprint_from_blob(field, value).map(BuildVariantFingerprint::from_bytes)
}

pub(super) fn fingerprint_from_blob(
    field: &'static str,
    value: Vec<u8>,
) -> Result<[u8; 16], StoreError> {
    let length = value.len();
    value
        .try_into()
        .map_err(|_| StoreError::MalformedFingerprint { field, length })
}

pub(super) fn positive_line(
    field: &'static str,
    value: Option<i64>,
) -> Result<Option<u32>, StoreError> {
    value
        .map(|line| {
            u32::try_from(line)
                .ok()
                .filter(|line| *line > 0)
                .ok_or_else(|| StoreError::UnknownVocabulary {
                    field,
                    value: line.to_string(),
                })
        })
        .transpose()
}

pub(super) fn nonnegative_u64(field: &'static str, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::UnknownVocabulary {
        field,
        value: value.to_string(),
    })
}
