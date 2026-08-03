use super::variant::{upsert_fingerprint, upsert_group_fingerprint};
use super::{
    BTreeMap, BTreeSet, Boilerplate, CrossLanguageComparisonSnapshot,
    CrossLanguageSemanticGroupRow, CrossVariantComparisonSnapshot, GroupRow, Language, MemberRow,
    NearMissRow, SOG_SCHEMA_VERSION, SemanticEvidenceRow, SemanticOperationGraph, SiblingGroupRow,
    SimilarityBreakdownRow, Snapshot, Store, StoreError, TestCodeEvidence, Transaction, params,
};
use rusqlite::OptionalExtension;

use crate::snapshot::{AuditState, LineageAdoption, LineageAdoptionResult};

impl Store {
    /// Atomically extend new groups with evidence-backed predecessor lineages.
    ///
    /// Every identifier is validated before the transaction starts. A failed
    /// request therefore cannot leave an earlier edge from the same request
    /// committed while a later edge is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, non-finite overlap, an
    /// absent or incomplete run, unsupported predecessor evidence, or an
    /// underlying database failure.
    pub fn adopt_lineage(
        &mut self,
        newer_run: i64,
        predecessor_run: i64,
        adoptions: &[LineageAdoption],
    ) -> Result<LineageAdoptionResult, StoreError> {
        let parsed = adoptions
            .iter()
            .map(ParsedAdoption::parse)
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_completed_run(newer_run)?;
        self.ensure_completed_run(predecessor_run)?;

        let tx = self.conn.transaction()?;
        let mut result = LineageAdoptionResult::default();
        for adoption in parsed {
            let newer = tx
                .query_row(
                    "SELECT id, lineage_state FROM clone_group
                     WHERE scan_run_id = ?1 AND group_fingerprint_id =
                           (SELECT id FROM fingerprint WHERE hash = ?2 LIMIT 1)",
                    params![newer_run, adoption.group.as_slice()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let predecessor = tx
                .query_row(
                    "SELECT lineage FROM clone_group
                     WHERE scan_run_id = ?1 AND group_fingerprint_id =
                           (SELECT id FROM fingerprint WHERE hash = ?2 LIMIT 1)",
                    params![predecessor_run, adoption.previous_group.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            let (Some((newer_group_id, state)), Some(previous_lineage)) = (newer, predecessor)
            else {
                result.unknown.push(adoption.group_hex);
                continue;
            };
            if state != "new" {
                result.already_connected.push(adoption.group_hex);
                continue;
            }
            if previous_lineage.as_slice() != adoption.lineage.as_slice() {
                return Err(StoreError::InvalidLineageEvidence {
                    reason: format!(
                        "predecessor {} does not belong to requested lineage {}",
                        adoption.previous_group_hex, adoption.lineage_hex
                    ),
                });
            }
            tx.execute(
                "UPDATE clone_group SET lineage = ?2, lineage_state = 'expanded' WHERE id = ?1",
                params![newer_group_id, adoption.lineage.as_slice()],
            )?;
            tx.execute(
                "INSERT INTO clone_group_lineage_parent
                     (clone_group_id, ordinal, parent_fingerprint, parent_lineage, is_primary,
                      shared_content, overlap)
                 VALUES (?1, 0, ?2, ?3, 1, ?4, ?5)",
                params![
                    newer_group_id,
                    adoption.previous_group.as_slice(),
                    adoption.lineage.as_slice(),
                    adoption.shared,
                    adoption.overlap,
                ],
            )?;
            result.taken.push(adoption.group_hex);
        }
        tx.commit()?;
        Ok(result)
    }

    /// Connect new clone groups to the strongest predecessor with enough
    /// shared member content.
    ///
    /// One shared content identity alone is often incidental in a large
    /// group. A predecessor must therefore account for at least half of the
    /// new group's distinct member content before its lineage is adopted.
    ///
    /// # Errors
    ///
    /// Returns an error for absent or incomplete runs, or an underlying
    /// database failure while reading or atomically recording the evidence.
    pub fn adopt_matching_lineages(
        &mut self,
        newer_run: i64,
        predecessor_run: i64,
    ) -> Result<LineageAdoptionResult, StoreError> {
        self.ensure_completed_run(newer_run)?;
        self.ensure_completed_run(predecessor_run)?;
        let newer = lineage_candidates(&self.conn, newer_run)?;
        let predecessors = lineage_candidates(&self.conn, predecessor_run)?;
        let mut adoptions = Vec::new();
        for (group, candidate) in &newer {
            if candidate.state != "new" || candidate.contents.is_empty() {
                continue;
            }
            let Some((previous_group, previous, _)) = predecessors
                .iter()
                .filter_map(|(fingerprint, prior)| {
                    let shared = candidate.contents.intersection(&prior.contents).count();
                    (fingerprint != group && shared > 0).then_some((fingerprint, prior, shared))
                })
                .filter(|(_, _, shared)| shared.saturating_mul(2) >= candidate.contents.len())
                .max_by(|(left_id, _, left_shared), (right_id, _, right_shared)| {
                    left_shared
                        .cmp(right_shared)
                        .then_with(|| right_id.cmp(left_id))
                })
            else {
                continue;
            };
            let shared = candidate.contents.intersection(&previous.contents).count();
            adoptions.push(LineageAdoption {
                group: group.clone(),
                previous_group: previous_group.clone(),
                lineage: previous.lineage.clone(),
                shared: u64::try_from(shared).unwrap_or(u64::MAX),
                overlap: overlap_fraction(shared, candidate.contents.len()),
            });
        }
        self.adopt_lineage(newer_run, predecessor_run, &adoptions)
    }

    /// Persist one opt-in cross-build-variant comparison.
    ///
    /// Every invocation gets a row even when its comparison identity repeats,
    /// so an explicit comparison always describes the inputs it received.
    ///
    /// # Errors
    ///
    /// Returns an error when the comparison cannot be written atomically.
    pub fn record_cross_variant_comparison(
        &mut self,
        comparison: &CrossVariantComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO cross_variant_comparison
                 (comparison_id, policy_version, root_path, started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                comparison.comparison_id.as_bytes().as_slice(),
                comparison.policy_version,
                comparison.root_path,
                comparison.started_at,
                comparison.finished_at,
            ],
        )?;
        let comparison_row = tx.last_insert_rowid();
        for origin in comparison.origins {
            tx.execute(
                "INSERT INTO cross_variant_comparison_origin
                     (comparison_id, build_variant_fingerprint) VALUES (?1, ?2)",
                params![comparison_row, origin],
            )?;
        }
        for group in comparison.groups {
            tx.execute(
                "INSERT INTO cross_variant_clone_group
                     (comparison_id, group_id, clone_type, member_count)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    comparison_row,
                    group.group_id.as_bytes().as_slice(),
                    group.clone_type.name(),
                    i64::try_from(group.members.len()).unwrap_or(i64::MAX),
                ],
            )?;
            let group_row = tx.last_insert_rowid();
            for member in &group.members {
                tx.execute(
                    "INSERT INTO cross_variant_clone_member
                         (group_id, member_id, origin_variant_fingerprint, language, file_path,
                          start_line, end_line, unit_name, token_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        group_row,
                        member.member_id.as_bytes().as_slice(),
                        member.origin_variant,
                        member.language.name(),
                        member.file_path,
                        i64::from(member.start_line),
                        i64::from(member.end_line),
                        member.unit_name,
                        i64::try_from(member.token_count).unwrap_or(i64::MAX),
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(comparison_row)
    }

    /// Persist one opt-in Rust-to-C++ semantic comparison.
    ///
    /// This uses tables distinct from both normal snapshots and exact
    /// cross-build comparisons, so the result domains stay separate.
    ///
    /// # Errors
    ///
    /// Returns an error when a group lacks its closed evidence or when the
    /// comparison cannot be written atomically.
    pub fn record_cross_language_comparison(
        &mut self,
        comparison: &CrossLanguageComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO cross_language_comparison
                 (comparison_id, policy_version, root_path, started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                comparison.comparison_id.as_bytes().as_slice(),
                comparison.policy_version,
                comparison.root_path,
                comparison.started_at,
                comparison.finished_at,
            ],
        )?;
        let comparison_row = tx.last_insert_rowid();
        for origin in comparison.origins {
            tx.execute(
                "INSERT INTO cross_language_comparison_origin
                     (comparison_id, build_variant_fingerprint) VALUES (?1, ?2)",
                params![comparison_row, origin],
            )?;
        }
        for group in comparison.groups {
            validate_cross_language_group(group)?;
            let correspondence_ids =
                serde_json::to_string(&group.correspondence_ids).map_err(|error| {
                    StoreError::InvalidSemanticEvidence {
                        reason: format!(
                            "serializing cross-language API correspondence IDs: {error}"
                        ),
                    }
                })?;
            tx.execute(
                "INSERT INTO cross_language_semantic_group
                     (comparison_id, group_id, rule_id, rule_version, semantic_confidence,
                      correspondence_ids_json, member_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    comparison_row,
                    group.group_id.as_bytes().as_slice(),
                    group.rule_id,
                    i64::from(group.rule_version),
                    group.semantic_confidence,
                    correspondence_ids,
                    i64::try_from(group.members.len()).unwrap_or(i64::MAX),
                ],
            )?;
            let group_row = tx.last_insert_rowid();
            for member in &group.members {
                tx.execute(
                    "INSERT INTO cross_language_semantic_member
                         (group_id, member_id, origin_variant_fingerprint, language, file_path,
                          start_line, end_line, unit_name, graph_schema_version, graph_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        group_row,
                        member.member_id.as_bytes().as_slice(),
                        member.origin_variant,
                        member.language.name(),
                        member.file_path,
                        i64::from(member.start_line),
                        i64::from(member.end_line),
                        member.unit_name,
                        member.graph_schema_version,
                        member.graph_json,
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(comparison_row)
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "the ratio is report evidence; set cardinalities are bounded by one scan"
)]
fn overlap_fraction(shared: usize, total: usize) -> f64 {
    shared as f64 / total as f64
}

struct LineageCandidate {
    state: String,
    lineage: String,
    contents: BTreeSet<String>,
}

fn lineage_candidates(
    conn: &rusqlite::Connection,
    run_id: i64,
) -> Result<BTreeMap<String, LineageCandidate>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT lower(hex(group_fingerprint.hash)), g.lineage_state, lower(hex(g.lineage)),
                lower(hex(content_fingerprint.hash))
         FROM clone_group g
         JOIN fingerprint group_fingerprint ON group_fingerprint.id = g.group_fingerprint_id
         JOIN clone_group_member member ON member.clone_group_id = g.id
         JOIN fragment fragment ON fragment.id = member.fragment_id
         JOIN fingerprint content_fingerprint ON content_fingerprint.id = fragment.fingerprint_id
         WHERE g.scan_run_id = ?1
         ORDER BY group_fingerprint.hash ASC, content_fingerprint.hash ASC",
    )?;
    let mut candidates = BTreeMap::new();
    for row in statement.query_map(params![run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (group, state, lineage, content) = row?;
        let candidate = candidates.entry(group).or_insert_with(|| LineageCandidate {
            state,
            lineage,
            contents: BTreeSet::new(),
        });
        candidate.contents.insert(content);
    }
    Ok(candidates)
}

struct ParsedAdoption {
    group_hex: String,
    group: [u8; 16],
    previous_group_hex: String,
    previous_group: [u8; 16],
    lineage_hex: String,
    lineage: [u8; 16],
    shared: i64,
    overlap: f64,
}

impl ParsedAdoption {
    fn parse(adoption: &LineageAdoption) -> Result<Self, StoreError> {
        if !adoption.overlap.is_finite() || !(0.0..=1.0).contains(&adoption.overlap) {
            return Err(StoreError::InvalidLineageEvidence {
                reason: format!("overlap for group {} is outside 0..=1", adoption.group),
            });
        }
        Ok(Self {
            group_hex: adoption.group.clone(),
            group: parse_stable_id(&adoption.group)?,
            previous_group_hex: adoption.previous_group.clone(),
            previous_group: parse_stable_id(&adoption.previous_group)?,
            lineage_hex: adoption.lineage.clone(),
            lineage: parse_stable_id(&adoption.lineage)?,
            shared: i64::try_from(adoption.shared).unwrap_or(i64::MAX),
            overlap: adoption.overlap,
        })
    }
}

fn parse_stable_id(hex: &str) -> Result<[u8; 16], StoreError> {
    let malformed = || StoreError::MalformedId {
        id: hex.to_string(),
    };
    if hex.len() != 32 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut bytes = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let digit = core::str::from_utf8(chunk).map_err(|_| malformed())?;
        bytes[index] = u8::from_str_radix(digit, 16).map_err(|_| malformed())?;
    }
    Ok(bytes)
}

fn validate_cross_language_group(group: &CrossLanguageSemanticGroupRow) -> Result<(), StoreError> {
    if !group.semantic_confidence.is_finite()
        || !(0.0..=1.0).contains(&group.semantic_confidence)
        || group.rule_id.is_empty()
        || group.correspondence_ids.is_empty()
        || group.members.len() != 2
    {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: "cross-language group lacks bounded rule evidence".to_string(),
        });
    }
    let mut has_rust = false;
    let mut has_cpp = false;
    let mut origins = BTreeSet::new();
    for member in &group.members {
        if !matches!(member.language, Language::Rust | Language::Cpp)
            || member.graph_schema_version != SOG_SCHEMA_VERSION
        {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member has an unsupported language or graph schema"
                    .to_string(),
            });
        }
        let graph: SemanticOperationGraph =
            serde_json::from_str(&member.graph_json).map_err(|error| {
                StoreError::InvalidSemanticEvidence {
                    reason: format!("decoding cross-language member graph: {error}"),
                }
            })?;
        if graph.schema_version != member.graph_schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member graph schema disagrees with its stored metadata"
                    .to_string(),
            });
        }
        if graph.language != member.language {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "cross-language member graph language disagrees with its stored metadata"
                    .to_string(),
            });
        }
        has_rust |= member.language == Language::Rust;
        has_cpp |= member.language == Language::Cpp;
        origins.insert(member.origin_variant.as_str());
    }
    if !has_rust || !has_cpp || origins.len() != 2 {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: "cross-language group must contain one Rust and one C++ origin".to_string(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // transaction hand-off, one call site
/// The persisted ranking for one group in one scan.
fn write_finding(
    tx: &Transaction<'_>,
    run_id: i64,
    group_row_id: i64,
    group: &GroupRow,
    suppression_row_ids: &[i64],
) -> Result<i64, StoreError> {
    let suppression_row_id = match group.suppressed_by {
        Some(index) => Some(*suppression_row_ids.get(index).ok_or(
            StoreError::UnknownSuppressionIndex {
                index,
                rules: suppression_row_ids.len(),
            },
        )?),
        None => None,
    };
    tx.execute(
        "INSERT INTO finding
             (scan_run_id, clone_group_id, suppression_id,
              clone_confidence, maintenance_risk, refactoring_difficulty,
              final_priority, semantic_confidence,
              source_artifact_mapping_confidence, savings_confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            group_row_id,
            suppression_row_id,
            group.priority.clone_confidence,
            group.priority.maintenance_risk,
            group.priority.refactoring_difficulty,
            group.priority.final_priority,
            group.priority.semantic_confidence,
            group.priority.source_artifact_confidence,
            group.priority.savings_confidence,
        ],
    )?;
    Ok(group_row_id)
}

/// Persist supplemental local mirrors without adding them to group membership.
pub(super) fn write_sibling_groups(
    tx: &Transaction<'_>,
    sibling_groups: &[SiblingGroupRow],
    unit_row_ids: &[i64],
    group_row_ids: &BTreeMap<[u8; 16], i64>,
    suppression_row_ids: &[i64],
) -> Result<(), StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO clone_group_sibling
             (clone_group_id, scan_run_id, source_unit_id, fragment_fingerprint, finding_id,
              clone_type, confidence_band, weight_version, lexical, structural,
              control_flow, type_similarity, api, composite, boilerplate, suppression_id)
         VALUES (?1, (SELECT scan_run_id FROM clone_group WHERE id = ?1),
                 ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    for siblings in sibling_groups {
        let group_row_id = *group_row_ids
            .get(siblings.group.as_bytes())
            .ok_or_else(|| StoreError::UnknownGroupFingerprint {
                fingerprint: siblings.group.to_hex(),
            })?;
        for sibling in &siblings.siblings {
            let source_unit_id =
                *unit_row_ids
                    .get(sibling.unit)
                    .ok_or(StoreError::UnknownUnitIndex {
                        index: sibling.unit,
                        units: unit_row_ids.len(),
                    })?;
            insert.execute(params![
                group_row_id,
                source_unit_id,
                sibling.content.as_bytes().as_slice(),
                sibling.finding.as_bytes().as_slice(),
                sibling.clone_type.name(),
                sibling.confidence.name(),
                sibling.similarity.weight_version,
                sibling.similarity.lexical,
                sibling.similarity.structural,
                sibling.similarity.control_flow,
                sibling.similarity.type_similarity,
                sibling.similarity.api,
                sibling.similarity.composite,
                sibling.boilerplate.map(Boilerplate::name),
                suppression_row_id(sibling.suppressed_by, suppression_row_ids)?,
            ])?;
        }
    }
    Ok(())
}

/// Persist bounded LSH diagnostics without creating findings or attaching
/// them to a primary clone group.
pub(super) fn write_near_misses(
    tx: &Transaction<'_>,
    run_id: i64,
    near_misses: &[NearMissRow],
    unit_row_ids: &[i64],
    suppression_row_ids: &[i64],
) -> Result<(), StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO near_match_near_miss
             (scan_run_id, ordinal, left_source_unit_id, right_source_unit_id, estimated_jaccard,
              suppression_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (ordinal, near_miss) in near_misses.iter().enumerate() {
        let left = *unit_row_ids
            .get(near_miss.left)
            .ok_or(StoreError::UnknownUnitIndex {
                index: near_miss.left,
                units: unit_row_ids.len(),
            })?;
        let right = *unit_row_ids
            .get(near_miss.right)
            .ok_or(StoreError::UnknownUnitIndex {
                index: near_miss.right,
                units: unit_row_ids.len(),
            })?;
        insert.execute(params![
            run_id,
            i64::try_from(ordinal).unwrap_or(i64::MAX),
            left,
            right,
            near_miss.estimated_jaccard,
            suppression_row_id(near_miss.suppressed_by, suppression_row_ids)?,
        ])?;
    }
    Ok(())
}

fn suppression_row_id(
    index: Option<usize>,
    suppression_row_ids: &[i64],
) -> Result<Option<i64>, StoreError> {
    index
        .map(|index| {
            suppression_row_ids
                .get(index)
                .copied()
                .ok_or(StoreError::UnknownSuppressionIndex {
                    index,
                    rules: suppression_row_ids.len(),
                })
        })
        .transpose()
}

pub(super) fn write_group(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
    group: &GroupRow,
    unit_row_ids: &[i64],
    suppression_row_ids: &[i64],
) -> Result<i64, StoreError> {
    let group_fp_id =
        upsert_group_fingerprint(tx, group.fingerprint.as_bytes(), snapshot, variant_id)?;
    tx.execute(
        "INSERT INTO clone_group
             (scan_run_id, group_fingerprint_id, lineage, lineage_state, clone_type, member_scope,
              member_count, score, entropy_bits, suppress_reason, boilerplate,
              test_code, test_code_evidence, split_pair, width_family, statements, identifier_jaccard,
              has_loop, has_dynamic_allocation, call_count, ranked_down)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            run_id,
            group_fp_id,
            group.history.lineage.as_bytes().as_slice(),
            lineage_state_name(group.history.state),
            group.clone_type.name(),
            group.member_scope.name(),
            i64::try_from(group.members.len()).unwrap_or(i64::MAX),
            group.score,
            group.entropy_bits,
            group.suppress_reason,
            group.boilerplate.map(Boilerplate::name),
            group.test_code,
            group.test_code_evidence.map(TestCodeEvidence::name),
            group.split_pair,
            group.width_family,
            group.statements,
            group.identifier_jaccard,
            group.has_loop,
            group.has_dynamic_allocation,
            group
                .call_count
                .map(|count| i64::try_from(count).unwrap_or(i64::MAX)),
            group.ranked_down,
        ],
    )?;
    let group_row_id = tx.last_insert_rowid();
    write_lineage_parents(tx, group_row_id, group)?;

    write_finding(tx, run_id, group_row_id, group, suppression_row_ids)?;
    write_group_similarity(tx, group_row_id, group.similarity.as_ref())?;

    let fragment_row_ids = write_fragments(
        tx,
        snapshot,
        run_id,
        variant_id,
        group_row_id,
        &group.members,
        unit_row_ids,
    )?;
    if let Some(evidence) = &group.semantic {
        write_semantic_evidence(tx, group_row_id, &fragment_row_ids, evidence)?;
    }
    Ok(group_row_id)
}

const fn lineage_state_name(state: AuditState) -> &'static str {
    match state {
        AuditState::New => "new",
        AuditState::Expanded => "expanded",
    }
}

fn write_lineage_parents(
    tx: &Transaction<'_>,
    group_row_id: i64,
    group: &GroupRow,
) -> Result<(), StoreError> {
    for (ordinal, parent) in group.history.parents.iter().enumerate() {
        tx.execute(
            "INSERT INTO clone_group_lineage_parent
                 (clone_group_id, ordinal, parent_fingerprint, parent_lineage, is_primary,
                  shared_content, overlap)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                group_row_id,
                i64::try_from(ordinal).unwrap_or(i64::MAX),
                parent.fingerprint.as_bytes().as_slice(),
                parent.lineage.as_bytes().as_slice(),
                parent.primary,
                i64::try_from(parent.shared_content).unwrap_or(i64::MAX),
                parent.overlap,
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // transaction hand-off, one call site
fn write_fragments(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
    group_row_id: i64,
    members: &[MemberRow],
    unit_row_ids: &[i64],
) -> Result<Vec<i64>, StoreError> {
    // Repeated clone members often carry the same content fingerprint. The
    // vocabulary row is content-addressed, so resolve each distinct
    // `(language, fingerprint)` once before inserting the positional fragment
    // rows that deliberately retain every occurrence.
    let mut fragment_fingerprints = BTreeMap::new();
    let mut fragments = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let host_row_id = match member.host_unit {
            Some(unit_index) => Some(*unit_row_ids.get(unit_index).ok_or(
                StoreError::UnknownUnitIndex {
                    index: unit_index,
                    units: unit_row_ids.len(),
                },
            )?),
            None => None,
        };
        let key = (member.language.name(), *member.content.as_bytes());
        let fragment_fp_id = if let Some(id) = fragment_fingerprints.get(&key) {
            *id
        } else {
            let id = upsert_fingerprint(
                tx,
                "fragment",
                member.content.as_bytes(),
                snapshot,
                variant_id,
                member.language,
            )?;
            fragment_fingerprints.insert(key, id);
            id
        };
        fragments.push((index, member, host_row_id, fragment_fp_id));
    }
    let mut fragment_row_ids = Vec::with_capacity(fragments.len());
    let mut insert_fragment = tx.prepare_cached(
        "INSERT INTO fragment
             (scan_run_id, source_unit_id, fingerprint_id, fragment_kind,
              file_path, start_line, end_line, token_count)
         VALUES (?1, ?2, ?3, 'matched_run', ?4, ?5, ?6, ?7)",
    )?;
    let mut insert_member = tx.prepare_cached(
        "INSERT INTO clone_group_member
             (clone_group_id, scan_run_id, fragment_id, finding_id, is_canonical, boilerplate)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (index, member, host_row_id, fragment_fp_id) in fragments {
        let fragment_row_id = insert_fragment.insert(params![
            run_id,
            host_row_id,
            fragment_fp_id,
            member.file_path,
            member.start_line,
            member.end_line,
            i64::try_from(member.token_count).unwrap_or(i64::MAX),
        ])?;
        fragment_row_ids.push(fragment_row_id);
        insert_member.execute(params![
            group_row_id,
            run_id,
            fragment_row_id,
            member.finding.as_bytes().as_slice(),
            i64::from(index == 0),
            member.boilerplate.map(Boilerplate::name),
        ])?;
    }
    Ok(fragment_row_ids)
}

/// Persist the graph and rule evidence that makes a restricted semantic group
/// explainable. Member graph order is the group's canonical member order.
fn write_semantic_evidence(
    tx: &Transaction<'_>,
    group_row_id: i64,
    fragment_row_ids: &[i64],
    evidence: &SemanticEvidenceRow,
) -> Result<(), StoreError> {
    if evidence.schema_version != SOG_SCHEMA_VERSION {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: format!(
                "group evidence schema {} is not supported ({SOG_SCHEMA_VERSION})",
                evidence.schema_version
            ),
        });
    }
    if evidence.graphs.len() != fragment_row_ids.len() {
        return Err(StoreError::InvalidSemanticEvidence {
            reason: format!(
                "{} graphs for {} group members",
                evidence.graphs.len(),
                fragment_row_ids.len()
            ),
        });
    }
    tx.execute(
        "INSERT INTO semantic_group_evidence
             (clone_group_id, schema_version, rule_id, rule_version, rule_confidence)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            group_row_id,
            evidence.schema_version,
            evidence.rule_id,
            evidence.rule_version,
            evidence.rule_confidence,
        ],
    )?;
    for (member_position, (fragment_row_id, graph)) in
        fragment_row_ids.iter().zip(&evidence.graphs).enumerate()
    {
        if graph.schema_version != evidence.schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "member graph schema does not match group evidence".to_string(),
            });
        }
        let parsed: SemanticOperationGraph =
            serde_json::from_str(&graph.graph_json).map_err(|error| {
                StoreError::InvalidSemanticEvidence {
                    reason: format!("decoding member graph JSON: {error}"),
                }
            })?;
        if parsed.schema_version != graph.schema_version {
            return Err(StoreError::InvalidSemanticEvidence {
                reason: "member graph JSON schema does not match its row".to_string(),
            });
        }
        SemanticOperationGraph::new(
            parsed.language,
            parsed.build_variant_fingerprint,
            parsed.nodes,
            parsed.edges,
        )
        .map_err(|error| StoreError::InvalidSemanticEvidence {
            reason: format!("member graph violates the SOG contract: {error}"),
        })?;
        let member_position =
            i64::try_from(member_position).map_err(|_| StoreError::InvalidSemanticEvidence {
                reason: "semantic group has more graph positions than SQLite can store".to_owned(),
            })?;
        tx.execute(
            "INSERT INTO semantic_operation_graph
                 (fragment_id, member_position, schema_version, graph_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fragment_row_id,
                member_position,
                graph.schema_version,
                graph.graph_json
            ],
        )?;
    }
    for mapping in &evidence.node_mappings {
        tx.execute(
            "INSERT INTO semantic_node_mapping
                 (clone_group_id, corresponding_member, canonical_node, corresponding_node)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group_row_id,
                mapping.corresponding_member,
                mapping.canonical,
                mapping.corresponding
            ],
        )?;
    }
    Ok(())
}

/// Persist a group's similarity breakdown, when the mode measured one.
fn write_group_similarity(
    tx: &Transaction<'_>,
    group_row_id: i64,
    similarity: Option<&SimilarityBreakdownRow>,
) -> Result<(), StoreError> {
    let Some(similarity) = similarity else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO clone_group_similarity
             (clone_group_id, weight_version, lexical, structural,
              control_flow, type_similarity, api, composite, min_pairwise,
              confidence_band)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            group_row_id,
            similarity.weight_version,
            similarity.lexical,
            similarity.structural,
            similarity.control_flow,
            similarity.type_similarity,
            similarity.api,
            similarity.composite,
            similarity.min_pairwise,
            similarity.confidence_band.name(),
        ],
    )?;
    Ok(())
}
