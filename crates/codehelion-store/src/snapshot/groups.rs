use super::{
    CrossLanguageComparisonSnapshot, CrossVariantComparisonSnapshot, Store, StoreError,
    Transaction, params,
};

use crate::lifecycle::ensure_completed_run;
use crate::snapshot::{LineageAdoption, LineageAdoptionResult};

mod lineage;
mod write;

pub(super) use lineage::{apply_lineage_adoptions_tx, plan_matching_lineages_tx};
pub(super) use write::{write_group, write_near_misses, write_sibling_groups};

use lineage::{ParsedAdoption, lineage_candidates, matching_adoptions};
use write::validate_cross_language_group;

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
        let tx = self.conn.transaction()?;
        ensure_completed_run(&tx, newer_run)?;
        ensure_completed_run(&tx, predecessor_run)?;
        let result = apply_lineage_adoptions_tx(&tx, newer_run, predecessor_run, &parsed)?;
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
        let newer = lineage_candidates(&self.conn, newer_run)?;
        let predecessors = lineage_candidates(&self.conn, predecessor_run)?;
        let adoptions = matching_adoptions(&newer, &predecessors)?;
        let tx = self.conn.transaction()?;
        ensure_completed_run(&tx, newer_run)?;
        ensure_completed_run(&tx, predecessor_run)?;
        let result = apply_lineage_adoptions_tx(&tx, newer_run, predecessor_run, &adoptions)?;
        tx.commit()?;
        Ok(result)
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
        let comparison_row = Self::write_cross_variant_comparison_tx(&tx, comparison)?;
        tx.commit()?;
        Ok(comparison_row)
    }

    /// Write one cross-build comparison into an existing transaction.
    pub(super) fn write_cross_variant_comparison_tx(
        tx: &Transaction<'_>,
        comparison: &CrossVariantComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
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
        let comparison_row = Self::write_cross_language_comparison_tx(&tx, comparison)?;
        tx.commit()?;
        Ok(comparison_row)
    }

    /// Write one cross-language comparison into an existing transaction.
    pub(super) fn write_cross_language_comparison_tx(
        tx: &Transaction<'_>,
        comparison: &CrossLanguageComparisonSnapshot<'_>,
    ) -> Result<i64, StoreError> {
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
        Ok(comparison_row)
    }
}
