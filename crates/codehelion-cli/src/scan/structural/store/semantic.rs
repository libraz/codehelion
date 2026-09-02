//! Store rows for the restricted-semantic finding family.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use codehelion_core::clone_class::CloneClass;
use codehelion_core::engine;
use codehelion_core::stable_id::{self, CloneGroupFingerprint};
use codehelion_store::snapshot::{
    GroupRow, MemberRow, SemanticEvidenceRow, SemanticNodeMappingRow, SemanticOperationGraphRow,
};

use super::rows::{recorded_ranked_down, recorded_ranking};
use crate::report;
use crate::scan::shared;
use crate::scan::structural::{
    ReportInputs, SemanticUnitGraph, aggregate_test_code_evidence,
    semantic_group_member_fingerprints, semantic_member_ranks, semantic_scope,
};

/// Store one restricted semantic pair with its normalized graphs and rule
/// evidence. It remains a pair for the same non-transitivity reason the
/// report names with `split_pair`.
pub(super) fn semantic_pair_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let pair = &inputs.semantic_pairs[index];
    let members = [&pair.canonical, &pair.corresponding];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        pair.rule.id,
        pair.rule.version,
        &semantic_group_member_fingerprints(members, inputs.analysis),
    );
    let test_code_evidence =
        aggregate_test_code_evidence(inputs.analysis, members.iter().map(|member| member.unit));
    let graph_json = semantic_graph_json(inputs, members.iter().copied())?;
    let node_mappings = (0..pair.canonical.graph.nodes.len())
        .filter_map(|index| {
            let index = u32::try_from(index).ok()?;
            Some(SemanticNodeMappingRow {
                corresponding_member: 1,
                canonical: index,
                corresponding: index,
            })
        })
        .collect();
    let canonical_unit = &inputs.analysis.units[pair.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: CloneClass::RestrictedSemantic,
        scope: semantic_scope(members.iter().copied(), inputs.analysis),
        statements: None,
        score: pair.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(canonical_tokens, inputs.literals),
        suppressed_by: inputs.semantic_pair_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        members: semantic_member_rows(inputs, host_index, &fingerprint, members.iter().copied()),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.split_pair = true;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical_tokens.len());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: pair.canonical.graph.schema_version.clone(),
        rule_id: pair.rule.id.to_string(),
        rule_version: pair.rule.version,
        rule_confidence: pair.rule.confidence,
        graphs: graph_json
            .into_iter()
            .map(|graph_json| SemanticOperationGraphRow {
                schema_version: pair.canonical.graph.schema_version.clone(),
                graph_json,
            })
            .collect(),
        node_mappings,
    });
    Ok(row)
}

/// Store one cohesive restricted-semantic group with member-qualified SOG
/// node correspondences.
pub(super) fn semantic_group_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let group = &inputs.semantic_groups[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        group.rule.id,
        group.rule.version,
        &semantic_group_member_fingerprints(group.members.iter(), inputs.analysis),
    );
    let test_code_evidence = aggregate_test_code_evidence(
        inputs.analysis,
        group.members.iter().map(|member| member.unit),
    );
    let graph_json = semantic_graph_json(inputs, group.members.iter())?;
    let node_mappings = semantic_store_node_mappings(&group.canonical, &group.members);
    let canonical_unit = &inputs.analysis.units[group.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: CloneClass::RestrictedSemantic,
        scope: semantic_scope(group.members.iter(), inputs.analysis),
        statements: None,
        score: group.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(canonical_tokens, inputs.literals),
        suppressed_by: inputs.semantic_group_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        members: semantic_member_rows(inputs, host_index, &fingerprint, group.members.iter()),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical_tokens.len());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: group.canonical.graph.schema_version.clone(),
        rule_id: group.rule.id.to_string(),
        rule_version: group.rule.version,
        rule_confidence: group.rule.confidence,
        graphs: graph_json
            .into_iter()
            .map(|graph_json| SemanticOperationGraphRow {
                schema_version: group.canonical.graph.schema_version.clone(),
                graph_json,
            })
            .collect(),
        node_mappings,
    });
    Ok(row)
}

/// Serialize each member's normalized SOG, naming the file whose graph could
/// not be written.
fn semantic_graph_json<'a>(
    inputs: &ReportInputs<'_>,
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
) -> Result<Vec<String>> {
    members
        .into_iter()
        .map(|member| {
            serde_json::to_string(&member.graph).with_context(|| {
                format!(
                    "serializing normalized SOG for {}",
                    inputs.files[inputs.analysis.units[member.unit].file].relative_path
                )
            })
        })
        .collect()
}

/// The recorded occurrences of one restricted-semantic finding.
///
/// A semantic window keeps its own span and token count, and takes the shape
/// and the host from the unit it sits in. The canonical member is first, which
/// is how both a verified pair and a cohesive group arrive here.
fn semantic_member_rows<'a>(
    inputs: &ReportInputs<'_>,
    host_index: &BTreeMap<usize, usize>,
    fingerprint: &CloneGroupFingerprint,
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
) -> Vec<MemberRow> {
    let members: Vec<&SemanticUnitGraph> = members.into_iter().collect();
    members
        .iter()
        .zip(semantic_member_ranks(members.iter().copied()))
        .map(|(member, rank)| {
            let unit = &inputs.analysis.units[member.unit];
            let file = &inputs.files[unit.file];
            MemberRow {
                content: member.content,
                finding: stable_id::finding_id(
                    fingerprint,
                    stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                    rank,
                ),
                language: file.language,
                host_unit: Some(host_index[&member.unit]),
                boilerplate: unit.boilerplate,
                file_path: file.relative_path.clone(),
                start_line: member.start_line,
                end_line: member.end_line,
                token_count: member.token_count,
            }
        })
        .collect()
}

/// Store canonical node correspondences once for each non-canonical member.
fn semantic_store_node_mappings(
    canonical: &SemanticUnitGraph,
    members: &[SemanticUnitGraph],
) -> Vec<SemanticNodeMappingRow> {
    members
        .iter()
        .enumerate()
        .skip(1)
        .flat_map(|(member, corresponding)| {
            (0..canonical
                .graph
                .nodes
                .len()
                .min(corresponding.graph.nodes.len()))
                .filter_map(move |node| {
                    let node = u32::try_from(node).ok()?;
                    Some(SemanticNodeMappingRow {
                        corresponding_member: u32::try_from(member).ok()?,
                        canonical: node,
                        corresponding: node,
                    })
                })
        })
        .collect()
}
