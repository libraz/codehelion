use super::common::{COMPLETED_CLONE_GROUP_RUN_JOIN, map_member};
use super::{
    BTreeMap, BTreeSet, FileCountsRow, FunnelDropRow, FunnelStageRow, GuardrailsRow, IdKind,
    IdMatch, OptionalExtension, Row, SOG_SCHEMA_VERSION, SemanticOperationGraph, Store, StoreError,
    StoredFinding, StoredGroup, StoredGroupDetail, StoredGroupOrigin, StoredLineageParent,
    StoredMember, StoredNearMiss, StoredNearMissUnit, StoredPriority, StoredSemanticEvidence,
    StoredSemanticNodeMapping, StoredSibling, StoredSiblingDetail, StoredSimilarity,
    StoredSuppressionRef, SummaryRow, UnparsedRow, UnusedRuleRow, params,
    stored_test_code_evidence,
};

impl Store {
    /// Look up one supplemental sibling by the finding id exported in reports.
    ///
    /// # Errors
    ///
    /// Returns malformed ids and underlying database failures.
    pub fn sibling(&self, finding_hex: &str) -> Result<Option<StoredSiblingDetail>, StoreError> {
        let finding_id = super::common::parse_hex_id(finding_hex)?;
        self.conn
            .query_row(
                "SELECT g.scan_run_id, lower(hex(group_fp.hash)),
                        lower(hex(s.finding_id)), lower(hex(s.fragment_fingerprint)),
                        u.language, u.file_path, u.start_line, u.end_line, u.token_count,
                        u.name, s.boilerplate, s.clone_type, s.confidence_band,
                        s.weight_version, s.lexical, s.structural, s.control_flow,
                        s.type_similarity, s.api, s.composite,
                        sup.scope, sup.pattern, sup.reason, sup.active,
                        s.basis, s.signature, s.signature_units
                 FROM clone_group_sibling s
                 JOIN clone_group g ON g.id = s.clone_group_id
                 JOIN fingerprint group_fp ON group_fp.id = g.group_fingerprint_id
                 JOIN source_unit u ON u.id = s.source_unit_id
                 LEFT JOIN suppression sup ON sup.id = s.suppression_id
                 JOIN scan_run r ON r.id = g.scan_run_id AND r.status = 'completed'
                 WHERE s.finding_id = ?1
                 ORDER BY g.scan_run_id DESC
                 LIMIT 1",
                params![finding_id.as_slice()],
                |row| {
                    Ok(StoredSiblingDetail {
                        run_id: row.get(0)?,
                        group_fingerprint_hex: row.get(1)?,
                        sibling: StoredSibling {
                            member: StoredMember {
                                finding_hex: row.get(2)?,
                                content_hex: row.get(3)?,
                                language: row.get(4)?,
                                file_path: row.get(5)?,
                                start_line: row.get(6)?,
                                end_line: row.get(7)?,
                                token_count: row.get(8)?,
                                unit_name: row.get(9)?,
                                boilerplate: row.get(10)?,
                                is_canonical: false,
                            },
                            clone_type: row.get(11)?,
                            confidence_band: row.get(12)?,
                            weight_version: row.get(13)?,
                            lexical: row.get(14)?,
                            structural: row.get(15)?,
                            control_flow: row.get(16)?,
                            type_similarity: row.get(17)?,
                            api: row.get(18)?,
                            composite: row.get(19)?,
                            suppressed_by: stored_suppression(row, 20)?,
                            basis: row.get(24)?,
                            signature: row.get(25)?,
                            signature_units: row.get(26)?,
                        },
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// The presentation rank-down verdict recorded for every group in a run.
    ///
    /// # Errors
    ///
    /// Returns an underlying database error, or refuses an incomplete run.
    pub fn run_group_ranked_down(&self, run_id: i64) -> Result<BTreeMap<String, bool>, StoreError> {
        self.ensure_completed_run(run_id)?;
        let mut statement = self.conn.prepare(
            "SELECT lower(hex(f.hash)), g.ranked_down
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        )?;
        statement
            .query_map(params![run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// Bounded, run-scoped LSH diagnostics in the order the scan retained
    /// them. They are deliberately read outside `run_groups`: a near miss has
    /// no primary group ownership or finding identity.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_near_misses(&self, run_id: i64) -> Result<Vec<StoredNearMiss>, StoreError> {
        self.conn
            .prepare(
                "SELECT n.estimated_jaccard,
                        lower(hex(left_fp.hash)), left_unit.language, left_unit.file_path,
                        left_unit.start_line, left_unit.end_line, left_unit.token_count,
                        left_unit.name,
                        lower(hex(right_fp.hash)), right_unit.language, right_unit.file_path,
                        right_unit.start_line, right_unit.end_line, right_unit.token_count,
                        right_unit.name, sup.scope, sup.pattern, sup.reason, sup.active
                 FROM near_match_near_miss n
                 JOIN source_unit left_unit ON left_unit.id = n.left_source_unit_id
                 JOIN fingerprint left_fp ON left_fp.id = left_unit.fingerprint_id
                 JOIN source_unit right_unit ON right_unit.id = n.right_source_unit_id
                 JOIN fingerprint right_fp ON right_fp.id = right_unit.fingerprint_id
                 LEFT JOIN suppression sup ON sup.id = n.suppression_id
                 WHERE n.scan_run_id = ?1
                 ORDER BY n.ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok(StoredNearMiss {
                    estimated_jaccard: row.get(0)?,
                    left: StoredNearMissUnit {
                        fingerprint_hex: row.get(1)?,
                        language: row.get(2)?,
                        file_path: row.get(3)?,
                        start_line: row.get(4)?,
                        end_line: row.get(5)?,
                        token_count: row.get(6)?,
                        unit_name: row.get(7)?,
                    },
                    right: StoredNearMissUnit {
                        fingerprint_hex: row.get(8)?,
                        language: row.get(9)?,
                        file_path: row.get(10)?,
                        start_line: row.get(11)?,
                        end_line: row.get(12)?,
                        token_count: row.get(13)?,
                        unit_name: row.get(14)?,
                    },
                    suppressed_by: stored_suppression(row, 15)?,
                })
            })?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// Number of separately recorded cross-build-variant comparisons.
    ///
    /// This deliberately reads a table outside `scan_run`: normal scan
    /// history must not be interpreted as comparison history.
    ///
    /// # Errors
    ///
    /// Returns an error when the comparison table cannot be read.
    pub fn cross_variant_comparison_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM cross_variant_comparison", [], |row| {
                row.get(0)
            })?)
    }

    /// Every clone group of `run_id`, deterministically ordered by
    /// fingerprint bytes, each with its members.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_groups(&self, run_id: i64) -> Result<Vec<StoredGroup>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT g.id, lower(hex(f.hash)), g.clone_type, g.score, g.entropy_bits,
                    g.suppress_reason, g.boilerplate, g.member_scope, g.test_code,
                    g.test_code_evidence, g.split_pair, s.scope, s.pattern, s.reason, s.active,
                    g.width_family, g.statements, g.identifier_jaccard, g.has_loop,
                    g.has_dynamic_allocation, g.call_count
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             LEFT JOIN finding fi ON fi.clone_group_id = g.id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             {COMPLETED_CLONE_GROUP_RUN_JOIN}
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        ))?;
        let rows: Vec<(i64, StoredGroup)> = stmt
            .query_map(params![run_id], |row| {
                let scope: Option<String> = row.get(11)?;
                let pattern: Option<String> = row.get(12)?;
                let reason: Option<String> = row.get(13)?;
                let active: Option<bool> = row.get(14)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    StoredGroup {
                        fingerprint_hex: row.get(1)?,
                        clone_type: row.get(2)?,
                        member_scope: row.get(7)?,
                        score: row.get(3)?,
                        entropy_bits: row.get(4)?,
                        suppress_reason: row.get(5)?,
                        boilerplate: row.get(6)?,
                        test_code: row.get(8)?,
                        test_code_evidence: stored_test_code_evidence(row, 9)?,
                        split_pair: row.get(10)?,
                        width_family: row.get(15)?,
                        statements: row.get(16)?,
                        identifier_jaccard: row.get(17)?,
                        has_loop: row.get(18)?,
                        has_dynamic_allocation: row.get(19)?,
                        call_count: row.get(20)?,
                        similarity: None,
                        semantic: None,
                        suppressed_by: scope.zip(pattern).map(|(scope, pattern)| {
                            StoredSuppressionRef {
                                scope,
                                pattern,
                                reason,
                                active,
                            }
                        }),
                        members: Vec::new(),
                        siblings: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut groups = Vec::with_capacity(rows.len());
        for (group_row_id, mut group) in rows {
            group.similarity = self.group_similarity(group_row_id)?;
            group.semantic = self.group_semantic_evidence(group_row_id)?;
            group.members = self.group_members(group_row_id)?;
            group.siblings = self.group_siblings(group_row_id)?;
            groups.push(group);
        }
        Ok(groups)
    }

    /// Local incomplete mirrors attached to one primary group, in stored
    /// deterministic order. They intentionally do not flow through
    /// `group_members`.
    fn group_siblings(&self, group_row_id: i64) -> Result<Vec<StoredSibling>, StoreError> {
        self.conn
            .prepare(
                "SELECT lower(hex(s.finding_id)), lower(hex(s.fragment_fingerprint)),
                        u.language, u.file_path, u.start_line, u.end_line, u.token_count,
                        u.name, s.boilerplate, s.clone_type, s.confidence_band,
                        s.weight_version, s.lexical, s.structural, s.control_flow,
                        s.type_similarity, s.api, s.composite,
                        sup.scope, sup.pattern, sup.reason, sup.active,
                        s.basis, s.signature, s.signature_units
                 FROM clone_group_sibling s
                 JOIN source_unit u ON u.id = s.source_unit_id
                 LEFT JOIN suppression sup ON sup.id = s.suppression_id
                 WHERE s.clone_group_id = ?1
                 ORDER BY s.fragment_fingerprint ASC, u.fingerprint_id ASC, u.id ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok(StoredSibling {
                    member: StoredMember {
                        finding_hex: row.get(0)?,
                        content_hex: row.get(1)?,
                        language: row.get(2)?,
                        file_path: row.get(3)?,
                        start_line: row.get(4)?,
                        end_line: row.get(5)?,
                        token_count: row.get(6)?,
                        unit_name: row.get(7)?,
                        boilerplate: row.get(8)?,
                        is_canonical: false,
                    },
                    clone_type: row.get(9)?,
                    confidence_band: row.get(10)?,
                    weight_version: row.get(11)?,
                    lexical: row.get(12)?,
                    structural: row.get(13)?,
                    control_flow: row.get(14)?,
                    type_similarity: row.get(15)?,
                    api: row.get(16)?,
                    composite: row.get(17)?,
                    suppressed_by: stored_suppression(row, 18)?,
                    basis: row.get(22)?,
                    signature: row.get(23)?,
                    signature_units: row.get(24)?,
                })
            })?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// One clone group by the hex form of its fingerprint, from the most
    /// recent run that recorded it, with the run it came from.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn group(&self, fingerprint_hex: &str) -> Result<Option<StoredGroupDetail>, StoreError> {
        let run_id: Option<i64> = self
            .conn
            .query_row(
                &format!(
                    "SELECT g.scan_run_id
                 FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 {COMPLETED_CLONE_GROUP_RUN_JOIN}
                 WHERE lower(hex(f.hash)) = ?1
                 ORDER BY g.scan_run_id DESC
                 LIMIT 1",
                ),
                params![fingerprint_hex],
                |row| row.get(0),
            )
            .optional()?;
        let Some(run_id) = run_id else {
            return Ok(None);
        };
        // Read through the run's groups rather than assembling one here: a
        // group's members, similarity and evidence are gathered in one place,
        // and a second gatherer is a second answer waiting to disagree.
        Ok(self
            .run_groups(run_id)?
            .into_iter()
            .find(|group| group.fingerprint_hex == fingerprint_hex)
            .map(|group| StoredGroupDetail { run_id, group }))
    }

    /// Whether one completed run records the clone group named by the hex form
    /// of its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_holds_group(&self, run_id: i64, fingerprint_hex: &str) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .conn
            .query_row(
                &format!(
                    "SELECT 1
                 FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 {COMPLETED_CLONE_GROUP_RUN_JOIN}
                 WHERE g.scan_run_id = ?1
                   AND lower(hex(f.hash)) = ?2
                 LIMIT 1",
                ),
                params![run_id, fingerprint_hex],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Every recorded id starting with `prefix`, across the kinds a lookup can
    /// name.
    ///
    /// Returned in full rather than capped: an abbreviated id is only accepted
    /// above a length that makes a collision unlikely, and a caller reporting
    /// an ambiguity has to be able to list all of it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn ids_starting_with(&self, prefix: &str) -> Result<Vec<IdMatch>, StoreError> {
        let prefix = prefix.to_ascii_lowercase();
        let pattern = format!("{}%", escape_like_prefix(&prefix));
        let mut matches = Vec::new();
        let mut collect = |sql: &str, kind: IdKind| -> Result<(), StoreError> {
            let mut stmt = self.conn.prepare(sql)?;
            let ids: Vec<String> = stmt
                .query_map(params![pattern], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            matches.extend(ids.into_iter().map(|id| IdMatch { kind, id }));
            Ok(())
        };
        collect(
            &format!(
                "SELECT DISTINCT lower(hex(m.finding_id)) AS hex_id
             FROM clone_group_member m
             JOIN clone_group g ON g.id = m.clone_group_id
             {COMPLETED_CLONE_GROUP_RUN_JOIN}
             WHERE hex_id LIKE ?1 ESCAPE '\\' ORDER BY hex_id",
            ),
            IdKind::Occurrence,
        )?;
        collect(
            &format!(
                "SELECT DISTINCT lower(hex(s.finding_id)) AS hex_id
                 FROM clone_group_sibling s
                 JOIN clone_group g ON g.id = s.clone_group_id
                 {COMPLETED_CLONE_GROUP_RUN_JOIN}
                 WHERE hex_id LIKE ?1 ESCAPE '\\' ORDER BY hex_id",
            ),
            IdKind::Sibling,
        )?;
        collect(
            &format!(
                "SELECT DISTINCT lower(hex(f.hash)) AS hex_id
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             {COMPLETED_CLONE_GROUP_RUN_JOIN}
             WHERE hex_id LIKE ?1 ESCAPE '\\' ORDER BY hex_id",
            ),
            IdKind::CloneGroup,
        )?;
        collect(
            "SELECT DISTINCT lower(hex(group_id)) AS hex_id
             FROM cross_language_semantic_group
             WHERE hex_id LIKE ?1 ESCAPE '\\' ORDER BY hex_id",
            IdKind::CrossLanguageGroup,
        )?;
        collect(
            "SELECT DISTINCT lower(hex(group_id)) AS hex_id
             FROM cross_variant_clone_group
             WHERE hex_id LIKE ?1 ESCAPE '\\' ORDER BY hex_id",
            IdKind::CrossVariantGroup,
        )?;
        Ok(matches)
    }

    /// The priority a recorded run assigned one clone group.
    ///
    /// This intentionally reads the stored values instead of applying the
    /// current ranking configuration. Reformatting a run must describe the
    /// decision that run made.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_group_priority(
        &self,
        run_id: i64,
        group_fingerprint_hex: &str,
    ) -> Result<Option<StoredPriority>, StoreError> {
        let group_id = self
            .conn
            .query_row(
                "SELECT g.id
                 FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 WHERE g.scan_run_id = ?1 AND lower(hex(f.hash)) = ?2",
                params![run_id, group_fingerprint_hex],
                |row| row.get(0),
            )
            .optional()?;
        group_id.map_or_else(|| Ok(None), |id| self.group_priority(id, run_id))
    }

    /// Registered SOG evidence attached to one clone group, when the group
    /// was recorded by restricted semantic detection.
    pub(super) fn group_semantic_evidence(
        &self,
        group_row_id: i64,
    ) -> Result<Option<StoredSemanticEvidence>, StoreError> {
        let evidence = self
            .conn
            .query_row(
                "SELECT schema_version, rule_id, rule_version, rule_confidence
                 FROM semantic_group_evidence
                 WHERE clone_group_id = ?1",
                params![group_row_id],
                |row| {
                    Ok(StoredSemanticEvidence {
                        schema_version: row.get(0)?,
                        rule_id: row.get(1)?,
                        rule_version: row.get(2)?,
                        rule_confidence: row.get(3)?,
                        graphs: Vec::new(),
                        node_mappings: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut evidence) = evidence else {
            return Ok(None);
        };
        evidence.node_mappings = self
            .conn
            .prepare(
                "SELECT corresponding_member, canonical_node, corresponding_node
                 FROM semantic_node_mapping
                 WHERE clone_group_id = ?1
                 ORDER BY corresponding_member ASC, canonical_node ASC, corresponding_node ASC",
            )?
            .query_map(params![group_row_id], |row| {
                Ok(StoredSemanticNodeMapping {
                    corresponding_member: row.get(0)?,
                    canonical: row.get(1)?,
                    corresponding: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        let graph_json: Vec<String> = self
            .conn
            .prepare(
                "SELECT sog.graph_json
                 FROM semantic_operation_graph sog
                 JOIN clone_group_member member ON member.fragment_id = sog.fragment_id
                 WHERE member.clone_group_id = ?1
                 ORDER BY sog.member_position ASC",
            )?
            .query_map(params![group_row_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        evidence.graphs = graph_json
            .into_iter()
            .map(|graph| Self::decode_stored_sog(&evidence.schema_version, &graph))
            .collect::<Result<_, _>>()?;
        Ok(Some(evidence))
    }

    /// Decode and revalidate stored graph JSON before handing it to a report.
    pub(super) fn decode_stored_sog(
        evidence_schema_version: &str,
        graph_json: &str,
    ) -> Result<SemanticOperationGraph, StoreError> {
        if evidence_schema_version != SOG_SCHEMA_VERSION {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: format!(
                    "stored group schema {evidence_schema_version} is not supported ({SOG_SCHEMA_VERSION})"
                ),
            });
        }
        let graph: SemanticOperationGraph = serde_json::from_str(graph_json).map_err(|error| {
            StoreError::InvalidSemanticEvidence {
                reason: format!("decoding stored SOG: {error}"),
            }
        })?;
        if graph.schema_version != evidence_schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "stored graph schema does not match group evidence".to_string(),
            });
        }
        SemanticOperationGraph::new(
            graph.language,
            graph.build_variant_fingerprint,
            graph.nodes,
            graph.edges,
        )
        .map_err(|error| StoreError::InvalidSemanticEvidence {
            reason: format!("stored graph violates the SOG contract: {error}"),
        })
    }

    /// What the run reported about itself beyond its findings, or `None` for a
    /// run recorded before runs stored it.
    ///
    /// Absent means the run cannot be described again, not that it measured
    /// nothing — a caller rebuilding a report from a stored run has to treat
    /// the two differently.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    #[allow(
        clippy::too_many_lines,
        reason = "the persisted summary columns and their row offsets remain adjacent"
    )]
    pub fn run_summary_row(&self, run_id: i64) -> Result<Option<SummaryRow>, StoreError> {
        let summary = self
            .conn
            .query_row(
                "SELECT analyzed_total, analyzed_rust, analyzed_c, analyzed_cpp,
                        lines, tokens, lexer_diagnostics, unparsed_files,
                        unparsed_tokens, excluded_generated, excluded_by_glob,
                        excluded_too_large, excluded_binary, excluded_unreadable,
                        excluded_symlinks, excluded_walk_errors, excluded_timed_out,
                        excluded_skipped,
                        guardrail_profile, guardrail_max_file_bytes,
                        guardrail_parse_timeout_ms, guardrail_helper_timeout_ms,
                        guardrail_posting_cap, guardrail_pair_budget,
                        guardrail_sibling_candidate_budget,
                        guardrail_sibling_per_group_cap, guardrail_sibling_total_cap,
                        guardrail_signature_sibling_candidate_budget,
                        guardrail_signature_sibling_per_group_cap,
                        guardrail_signature_sibling_total_cap,
                        guardrail_max_component, folded_runs, subsumed_runs,
                        split_components, pair_budget_exhausted, baseline_digest,
                        excluded_language, excluded_symlink_files,
                        excluded_symlink_directories, guardrail_near_miss_delta,
                        guardrail_near_miss_cap, guardrail_verification_budget,
                        guardrail_max_alignment_cells,
                        guardrail_signature_sibling_max_units_per_signature,
                        common_signatures_skipped, largest_skipped_signature_units
                 FROM run_summary WHERE scan_run_id = ?1",
                params![run_id],
                |row| {
                    let count = |value: i64| u64::try_from(value).unwrap_or(0);
                    let files: Option<i64> = row.get(7)?;
                    let tokens: Option<i64> = row.get(8)?;
                    let profile: Option<String> = row.get(18)?;
                    let guardrail_max_file_bytes: Option<i64> = row.get(19)?;
                    let guardrail_parse_timeout_ms: Option<i64> = row.get(20)?;
                    let guardrail_helper_timeout_ms: Option<i64> = row.get(21)?;
                    let guardrail_posting_cap: Option<i64> = row.get(22)?;
                    let guardrail_pair_budget: Option<i64> = row.get(23)?;
                    let guardrail_sibling_candidate_budget: Option<i64> = row.get(24)?;
                    let guardrail_sibling_per_group_cap: Option<i64> = row.get(25)?;
                    let guardrail_sibling_total_cap: Option<i64> = row.get(26)?;
                    let guardrail_signature_sibling_candidate_budget: Option<i64> = row.get(27)?;
                    let guardrail_signature_sibling_per_group_cap: Option<i64> = row.get(28)?;
                    let guardrail_signature_sibling_total_cap: Option<i64> = row.get(29)?;
                    let guardrail_max_component: Option<i64> = row.get(30)?;
                    let guardrail_near_miss_delta: Option<i64> = row.get(39)?;
                    let guardrail_near_miss_cap: Option<i64> = row.get(40)?;
                    let guardrail_verification_budget: Option<i64> = row.get(41)?;
                    let guardrail_max_alignment_cells: Option<i64> = row.get(42)?;
                    let guardrail_signature_sibling_max_units_per_signature: Option<i64> =
                        row.get(43)?;
                    Ok(SummaryRow {
                        analyzed_files: FileCountsRow {
                            total: count(row.get(0)?),
                            rust: count(row.get(1)?),
                            c: count(row.get(2)?),
                            cpp: count(row.get(3)?),
                        },
                        lines: count(row.get(4)?),
                        tokens: count(row.get(5)?),
                        lexer_diagnostics: count(row.get(6)?),
                        unparsed: files.zip(tokens).map(|(files, tokens)| UnparsedRow {
                            files: count(files),
                            tokens: count(tokens),
                        }),
                        excluded_generated: count(row.get(9)?),
                        excluded_by_glob: count(row.get(10)?),
                        excluded_too_large: count(row.get(11)?),
                        excluded_binary: count(row.get(12)?),
                        excluded_unreadable: count(row.get(13)?),
                        excluded_symlinks: count(row.get(14)?),
                        excluded_walk_errors: count(row.get(15)?),
                        excluded_timed_out: count(row.get(16)?),
                        excluded_skipped: count(row.get(17)?),
                        guardrails: profile.map(|profile| GuardrailsRow {
                            profile,
                            max_file_bytes: count(guardrail_max_file_bytes.unwrap_or(0)),
                            parse_timeout_ms: count(guardrail_parse_timeout_ms.unwrap_or(0)),
                            helper_timeout_ms: count(guardrail_helper_timeout_ms.unwrap_or(0)),
                            posting_cap: count(guardrail_posting_cap.unwrap_or(0)),
                            pair_budget: count(guardrail_pair_budget.unwrap_or(0)),
                            near_miss_delta_bits: count(guardrail_near_miss_delta.unwrap_or(0)),
                            near_miss_cap: count(guardrail_near_miss_cap.unwrap_or(0)),
                            verification_budget: count(guardrail_verification_budget.unwrap_or(0)),
                            max_alignment_cells: count(guardrail_max_alignment_cells.unwrap_or(0)),
                            sibling_candidate_budget: count(
                                guardrail_sibling_candidate_budget.unwrap_or(0),
                            ),
                            sibling_per_group_cap: count(
                                guardrail_sibling_per_group_cap.unwrap_or(0),
                            ),
                            sibling_total_cap: count(guardrail_sibling_total_cap.unwrap_or(0)),
                            signature_sibling_candidate_budget: count(
                                guardrail_signature_sibling_candidate_budget.unwrap_or(0),
                            ),
                            signature_sibling_per_group_cap: count(
                                guardrail_signature_sibling_per_group_cap.unwrap_or(0),
                            ),
                            signature_sibling_total_cap: count(
                                guardrail_signature_sibling_total_cap.unwrap_or(0),
                            ),
                            signature_sibling_max_units_per_signature: count(
                                guardrail_signature_sibling_max_units_per_signature.unwrap_or(0),
                            ),
                            max_component: count(guardrail_max_component.unwrap_or(0)),
                        }),
                        folded_runs: count(row.get(31)?),
                        subsumed_runs: count(row.get(32)?),
                        split_components: count(row.get(33)?),
                        common_signatures_skipped: count(row.get(44)?),
                        largest_skipped_signature_units: count(row.get(45)?),
                        pair_budget_exhausted: row.get(34)?,
                        baseline_digest: row.get(35)?,
                        excluded_language: count(row.get(36)?),
                        excluded_symlink_files: count(row.get(37)?),
                        excluded_symlink_directories: count(row.get(38)?),
                        funnel: Vec::new(),
                        unused_suppressions: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut summary) = summary else {
            return Ok(None);
        };
        summary.funnel = self.run_funnel(run_id)?;
        summary.unused_suppressions = self.run_unused_suppressions(run_id)?;
        Ok(Some(summary))
    }

    /// The run's candidate pipeline, stage by stage in run order, each stage
    /// carrying what it dropped.
    fn run_funnel(&self, run_id: i64) -> Result<Vec<FunnelStageRow>, StoreError> {
        let mut stages = self
            .conn
            .prepare(
                "SELECT position, name, passed FROM run_funnel_stage
                 WHERE scan_run_id = ?1 ORDER BY position ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelStageRow {
                        name: row.get(1)?,
                        passed: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                        dropped: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let drops = self
            .conn
            .prepare(
                "SELECT position, cause, dropped FROM run_funnel_drop
                 WHERE scan_run_id = ?1 ORDER BY position ASC, ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelDropRow {
                        cause: row.get(1)?,
                        count: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (position, drop) in drops {
            if let Some((_, stage)) = stages.iter_mut().find(|(at, _)| *at == position) {
                stage.dropped.push(drop);
            }
        }
        Ok(stages.into_iter().map(|(_, stage)| stage).collect())
    }

    /// The configured rules the run found nothing for, in the order it named
    /// them.
    fn run_unused_suppressions(&self, run_id: i64) -> Result<Vec<UnusedRuleRow>, StoreError> {
        Ok(self
            .conn
            .prepare(
                "SELECT scope, pattern FROM run_unused_suppression
                 WHERE scan_run_id = ?1 ORDER BY ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok(UnusedRuleRow {
                    scope: row.get(0)?,
                    pattern: row.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }

    /// The similarity breakdown of one group row, or `None` when the mode
    /// measured none (Fast).
    pub(super) fn group_similarity(
        &self,
        group_row_id: i64,
    ) -> Result<Option<StoredSimilarity>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT weight_version, lexical, structural, control_flow,
                        type_similarity, api, composite, min_pairwise,
                        confidence_band
                 FROM clone_group_similarity
                 WHERE clone_group_id = ?1",
                params![group_row_id],
                |row| {
                    Ok(StoredSimilarity {
                        weight_version: row.get(0)?,
                        lexical: row.get(1)?,
                        structural: row.get(2)?,
                        control_flow: row.get(3)?,
                        type_similarity: row.get(4)?,
                        api: row.get(5)?,
                        composite: row.get(6)?,
                        min_pairwise: row.get(7)?,
                        confidence_band: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// The members of one group row, in the order the run recorded them.
    ///
    /// Fragment rows are written as the run listed the occurrences, so their
    /// row ids carry that order and the canonical instance comes first. Any
    /// other ordering would be this layer's opinion rather than the run's, and
    /// a report rebuilt from these rows has to list what the run listed.
    fn group_members(&self, group_row_id: i64) -> Result<Vec<StoredMember>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                    fr.token_count, u.name, m.is_canonical, lower(hex(ff.hash)),
                    ff.language, m.boilerplate
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             LEFT JOIN source_unit u ON u.id = fr.source_unit_id
             WHERE m.clone_group_id = ?1
             ORDER BY fr.id ASC",
        )?;
        let members = stmt
            .query_map(params![group_row_id], |row| map_member(row, 7))?
            .collect::<Result<_, _>>()?;
        Ok(members)
    }

    /// Every finding of `run_id`, ordered by group fingerprint bytes.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_findings(&self, run_id: i64) -> Result<Vec<StoredFinding>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(gf.hash)), fi.clone_confidence, fi.final_priority,
                    s.scope
             FROM finding fi
             JOIN clone_group g ON g.id = fi.clone_group_id
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             WHERE fi.scan_run_id = ?1
             ORDER BY gf.hash ASC",
        )?;
        let findings = stmt
            .query_map(params![run_id], |row| {
                Ok(StoredFinding {
                    group_fingerprint_hex: row.get(0)?,
                    clone_confidence: row.get(1)?,
                    final_priority: row.get(2)?,
                    suppression_scope: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(findings)
    }
}

/// Escape a literal prefix for `SQLite` `LIKE`, using backslash as the explicit
/// escape character in every id lookup query above.
fn escape_like_prefix(prefix: &str) -> String {
    prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn stored_suppression(
    row: &Row<'_>,
    start: usize,
) -> rusqlite::Result<Option<StoredSuppressionRef>> {
    let scope: Option<String> = row.get(start)?;
    let pattern: Option<String> = row.get(start + 1)?;
    let reason: Option<String> = row.get(start + 2)?;
    let active: Option<bool> = row.get(start + 3)?;
    Ok(scope
        .zip(pattern)
        .map(|(scope, pattern)| StoredSuppressionRef {
            scope,
            pattern,
            reason,
            active,
        }))
}

impl Store {
    /// How each group of a completed run came by its history.
    ///
    /// Only groups that connect to a predecessor are returned: a run with no
    /// predecessor connects nothing, and listing every group of a first scan
    /// as unconnected states the obvious at the length of the report.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_group_origins(&self, run_id: i64) -> Result<Vec<StoredGroupOrigin>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT lower(hex(f.hash)), lower(hex(p.parent_fingerprint)), p.shared_content
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             JOIN clone_group_lineage_parent p
                  ON p.clone_group_id = g.id AND p.is_primary = 1
             JOIN scan_run r ON r.id = g.scan_run_id AND r.status = 'completed'
             WHERE g.scan_run_id = ?1
             ORDER BY lower(hex(f.hash))",
        )?;
        let origins = statement
            .query_map(params![run_id], |row| {
                Ok(StoredGroupOrigin {
                    group_fingerprint_hex: row.get(0)?,
                    adopted_from: Some(StoredLineageParent {
                        fingerprint_hex: row.get(1)?,
                        shared_content: row.get(2)?,
                    }),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(origins)
    }

    /// Every clone-group fingerprint a completed run recorded.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_group_fingerprints(&self, run_id: i64) -> Result<BTreeSet<String>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT lower(hex(f.hash))
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             JOIN scan_run r ON r.id = g.scan_run_id AND r.status = 'completed'
             WHERE g.scan_run_id = ?1",
        )?;
        let fingerprints = statement
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(fingerprints)
    }
}

impl Store {
    /// The `limit` highest-ranked group fingerprints of a completed run, in
    /// the order that run ranked them.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_top_group_fingerprints(
        &self,
        run_id: i64,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT lower(hex(f.hash))
             FROM finding n
             JOIN clone_group g ON g.id = n.clone_group_id
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             JOIN scan_run r ON r.id = g.scan_run_id AND r.status = 'completed'
             WHERE n.scan_run_id = ?1
             ORDER BY n.final_priority DESC, lower(hex(f.hash)) ASC
             LIMIT ?2",
        )?;
        let fingerprints = statement
            .query_map(params![run_id, limit], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(fingerprints)
    }
}
