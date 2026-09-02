//! Identity-based folding of durable snapshot rows.
//!
//! Every persisted field of a group or a finding takes part in a typed
//! descriptor, so two rows carrying one stable identifier collapse only when
//! the store would hold exactly the same thing twice. Anything else is an
//! invariant error rather than a silently retained copy.

use std::collections::BTreeSet;

use anyhow::Result;
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::Language;
use codehelion_core::frontend::UnitKind;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, GroupLineageId, UnitFingerprint,
};
use codehelion_core::test_code::TestCodeEvidence;
use codehelion_core::verify::Confidence;
use codehelion_store::snapshot::{
    AuditState, GroupRow, MemberRow, SemanticNodeMappingRow, UnitRow,
};

/// IEEE-754 identity payload for one persisted measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredFloatBits(u64);

impl From<f64> for StoredFloatBits {
    fn from(value: f64) -> Self {
        Self(value.to_bits())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredLineageParentDescriptor {
    fingerprint: CloneGroupFingerprint,
    lineage: GroupLineageId,
    primary: bool,
    shared_content: u64,
    overlap: StoredFloatBits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredHistoryDescriptor {
    state: AuditState,
    lineage: GroupLineageId,
    parents: Vec<StoredLineageParentDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredPriorityDescriptor {
    clone_confidence: StoredFloatBits,
    maintenance_risk: StoredFloatBits,
    refactoring_difficulty: StoredFloatBits,
    final_priority: StoredFloatBits,
    semantic_confidence: Option<StoredFloatBits>,
    source_artifact_confidence: Option<StoredFloatBits>,
    savings_confidence: Option<StoredFloatBits>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSimilarityDescriptor {
    weight_version: String,
    lexical: StoredFloatBits,
    structural: StoredFloatBits,
    control_flow: Option<StoredFloatBits>,
    type_similarity: Option<StoredFloatBits>,
    api: Option<StoredFloatBits>,
    composite: StoredFloatBits,
    min_pairwise: StoredFloatBits,
    confidence_band: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSemanticGraphDescriptor {
    schema_version: String,
    graph_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSemanticDescriptor {
    schema_version: String,
    rule_id: String,
    rule_version: u32,
    rule_confidence: StoredFloatBits,
    graphs: Vec<StoredSemanticGraphDescriptor>,
    node_mappings: Vec<SemanticNodeMappingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredMemberDescriptor {
    content: FragmentFingerprint,
    finding: FindingId,
    language: Language,
    host_unit: Option<StoredUnitDescriptor>,
    boilerplate: Option<Boilerplate>,
    file_path: String,
    start_line: u32,
    end_line: u32,
    token_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredUnitDescriptor {
    fingerprint: UnitFingerprint,
    language: Language,
    kind: UnitKind,
    name: Option<String>,
    file_path: String,
    start_line: u32,
    end_line: u32,
    token_count: usize,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the identity payload mirrors independent durable group fields"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredGroupDescriptor {
    history: StoredHistoryDescriptor,
    clone_type: CloneClass,
    member_scope: CloneScope,
    test_code: bool,
    test_code_evidence: Option<TestCodeEvidence>,
    split_pair: bool,
    score: StoredFloatBits,
    entropy_bits: StoredFloatBits,
    suppress_reason: Option<String>,
    boilerplate: Option<Boilerplate>,
    identifier_jaccard: Option<StoredFloatBits>,
    has_loop: Option<bool>,
    has_dynamic_allocation: Option<bool>,
    call_count: Option<u64>,
    width_family: bool,
    ranked_down: bool,
    statements: Option<u32>,
    suppressed_by: Option<usize>,
    priority: StoredPriorityDescriptor,
    similarity: Option<StoredSimilarityDescriptor>,
    semantic: Option<StoredSemanticDescriptor>,
    members: Vec<StoredMemberDescriptor>,
}

fn stored_unit_descriptor(unit: &UnitRow) -> StoredUnitDescriptor {
    StoredUnitDescriptor {
        fingerprint: unit.fingerprint,
        language: unit.language,
        kind: unit.kind,
        name: unit.name.clone(),
        file_path: unit.file_path.clone(),
        start_line: unit.start_line,
        end_line: unit.end_line,
        token_count: unit.token_count,
    }
}

fn stored_member_descriptor(
    member: &MemberRow,
    units: &[UnitRow],
) -> Result<StoredMemberDescriptor> {
    let host_unit = member
        .host_unit
        .map(|index| {
            units.get(index).map(stored_unit_descriptor).ok_or_else(|| {
                anyhow::anyhow!(
                    "stable stored finding identity {} references out-of-range host unit {}",
                    member.finding,
                    index
                )
            })
        })
        .transpose()?;
    Ok(StoredMemberDescriptor {
        content: member.content,
        finding: member.finding,
        language: member.language,
        host_unit,
        boilerplate: member.boilerplate,
        file_path: member.file_path.clone(),
        start_line: member.start_line,
        end_line: member.end_line,
        token_count: member.token_count,
    })
}

fn stored_group_descriptor(group: &GroupRow, units: &[UnitRow]) -> Result<StoredGroupDescriptor> {
    Ok(StoredGroupDescriptor {
        history: StoredHistoryDescriptor {
            state: group.history.state,
            lineage: group.history.lineage,
            parents: group
                .history
                .parents
                .iter()
                .map(|parent| StoredLineageParentDescriptor {
                    fingerprint: parent.fingerprint,
                    lineage: parent.lineage,
                    primary: parent.primary,
                    shared_content: parent.shared_content,
                    overlap: StoredFloatBits::from(parent.overlap),
                })
                .collect(),
        },
        clone_type: group.clone_type,
        member_scope: group.member_scope,
        test_code: group.test_code,
        test_code_evidence: group.test_code_evidence,
        split_pair: group.split_pair,
        score: StoredFloatBits::from(group.score),
        entropy_bits: StoredFloatBits::from(group.entropy_bits),
        suppress_reason: group.suppress_reason.clone(),
        boilerplate: group.boilerplate,
        identifier_jaccard: group.identifier_jaccard.map(StoredFloatBits::from),
        has_loop: group.has_loop,
        has_dynamic_allocation: group.has_dynamic_allocation,
        call_count: group.call_count,
        width_family: group.width_family,
        ranked_down: group.ranked_down,
        statements: group.statements,
        suppressed_by: group.suppressed_by,
        priority: StoredPriorityDescriptor {
            clone_confidence: StoredFloatBits::from(group.priority.clone_confidence),
            maintenance_risk: StoredFloatBits::from(group.priority.maintenance_risk),
            refactoring_difficulty: StoredFloatBits::from(group.priority.refactoring_difficulty),
            final_priority: StoredFloatBits::from(group.priority.final_priority),
            semantic_confidence: group
                .priority
                .semantic_confidence
                .map(StoredFloatBits::from),
            source_artifact_confidence: group
                .priority
                .source_artifact_confidence
                .map(StoredFloatBits::from),
            savings_confidence: group.priority.savings_confidence.map(StoredFloatBits::from),
        },
        similarity: group
            .similarity
            .as_ref()
            .map(|similarity| StoredSimilarityDescriptor {
                weight_version: similarity.weight_version.clone(),
                lexical: StoredFloatBits::from(similarity.lexical),
                structural: StoredFloatBits::from(similarity.structural),
                control_flow: similarity.control_flow.map(StoredFloatBits::from),
                type_similarity: similarity.type_similarity.map(StoredFloatBits::from),
                api: similarity.api.map(StoredFloatBits::from),
                composite: StoredFloatBits::from(similarity.composite),
                min_pairwise: StoredFloatBits::from(similarity.min_pairwise),
                confidence_band: similarity.confidence_band,
            }),
        semantic: group
            .semantic
            .as_ref()
            .map(|semantic| StoredSemanticDescriptor {
                schema_version: semantic.schema_version.clone(),
                rule_id: semantic.rule_id.clone(),
                rule_version: semantic.rule_version,
                rule_confidence: StoredFloatBits::from(semantic.rule_confidence),
                graphs: semantic
                    .graphs
                    .iter()
                    .map(|graph| StoredSemanticGraphDescriptor {
                        schema_version: graph.schema_version.clone(),
                        graph_json: graph.graph_json.clone(),
                    })
                    .collect(),
                node_mappings: semantic.node_mappings.clone(),
            }),
        members: group
            .members
            .iter()
            .map(|member| stored_member_descriptor(member, units))
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Collapse raw durable group rows using a typed descriptor that includes
/// every persisted field. Equal identifiers with unequal measurements remain
/// an invariant error; no debug rendering or position-based tie-breaker is
/// involved.
pub(super) fn collapse_stored_group_rows(
    groups: Vec<GroupRow>,
    units: &[UnitRow],
) -> Result<Vec<GroupRow>> {
    let descriptors = groups
        .iter()
        .map(|group| {
            stored_group_descriptor(group, units).map(|descriptor| (group.fingerprint, descriptor))
        })
        .collect::<Result<Vec<_>>>()?;
    let collapsed = codehelion_core::identity::collapse_exact(&descriptors).map_err(|error| {
        anyhow::anyhow!(
            "stable stored clone-group identity {} has unequal durable payloads",
            error.identity
        )
    })?;
    let retained = collapsed.retained.into_iter().collect::<BTreeSet<_>>();
    Ok(groups
        .into_iter()
        .enumerate()
        .filter_map(|(index, group)| retained.contains(&index).then_some(group))
        .collect())
}

/// Collapse exact duplicate members inside one durable group, rejecting
/// storage-only differences for a reused finding identity.
pub(super) fn collapse_stored_member_rows(group: &mut GroupRow, units: &[UnitRow]) -> Result<()> {
    let descriptors = group
        .members
        .iter()
        .map(|member| {
            stored_member_descriptor(member, units).map(|descriptor| (member.finding, descriptor))
        })
        .collect::<Result<Vec<_>>>()?;
    let collapsed = codehelion_core::identity::collapse_exact(&descriptors).map_err(|error| {
        anyhow::anyhow!(
            "stable stored finding identity {} has unequal durable payloads",
            error.identity
        )
    })?;
    let retained = collapsed.retained.into_iter().collect::<BTreeSet<_>>();
    group.members = std::mem::take(&mut group.members)
        .into_iter()
        .enumerate()
        .filter_map(|(index, member)| retained.contains(&index).then_some(member))
        .collect();
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use codehelion_core::clone_class::{CloneClass, CloneScope};
    use codehelion_core::discovery::Language;
    use codehelion_core::frontend::UnitKind;
    use codehelion_core::stable_id::{
        CloneGroupFingerprint, FindingId, FragmentFingerprint, UnitFingerprint,
    };
    use codehelion_store::snapshot::{MemberRow, PriorityRow, UnitRow};

    use super::{collapse_stored_group_rows, collapse_stored_member_rows, stored_unit_descriptor};
    use crate::scan::shared;

    fn group(score: f64) -> codehelion_store::snapshot::GroupRow {
        group_with_members(score, Vec::new())
    }

    fn group_with_members(
        score: f64,
        members: Vec<MemberRow>,
    ) -> codehelion_store::snapshot::GroupRow {
        shared::stored_group(shared::StoredGroupCore {
            fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            clone_type: CloneClass::Type1,
            scope: CloneScope::Unit,
            statements: None,
            score,
            entropy_bits: 1.0,
            suppressed_by: None,
            ranked_down: false,
            priority: PriorityRow {
                clone_confidence: 1.0,
                maintenance_risk: 0.0,
                refactoring_difficulty: 0.0,
                final_priority: 1.0,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            members,
        })
    }

    fn units_with_same_semantics() -> Vec<UnitRow> {
        vec![unit("src/unit.rs"), unit("src/unit.rs")]
    }

    fn units_with_different_semantics() -> Vec<UnitRow> {
        vec![unit("src/first.rs"), unit("src/second.rs")]
    }

    fn unit(file_path: &str) -> UnitRow {
        UnitRow {
            fingerprint: UnitFingerprint::from_bytes([4; 16]),
            language: Language::Rust,
            kind: UnitKind::Function,
            name: Some("unit".to_string()),
            file_path: file_path.to_string(),
            start_line: 1,
            end_line: 10,
            token_count: 20,
        }
    }

    fn member(file_path: &str) -> MemberRow {
        member_at(file_path, Some(0))
    }

    fn member_at(file_path: &str, host_unit: Option<usize>) -> MemberRow {
        MemberRow {
            content: FragmentFingerprint::from_bytes([8; 16]),
            finding: FindingId::from_bytes([9; 16]),
            language: Language::Rust,
            host_unit,
            boilerplate: None,
            file_path: file_path.to_string(),
            start_line: 4,
            end_line: 8,
            token_count: 12,
        }
    }

    #[test]
    fn exact_duplicate_stored_groups_collapse_once() {
        let rows = collapse_stored_group_rows(vec![group(1.0), group(1.0)], &[])
            .expect("exact duplicate durable rows should collapse");
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn unequal_durable_payload_for_one_group_identity_is_an_error() {
        let error = collapse_stored_group_rows(vec![group(1.0), group(2.0)], &[])
            .expect_err("storage-only payload differences must not be hidden");
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn exact_duplicate_stored_members_with_same_host_semantics_collapse_once() {
        let units = units_with_same_semantics();
        let mut row = group_with_members(
            1.0,
            vec![
                member_at("src/a.rs", Some(0)),
                member_at("src/a.rs", Some(1)),
            ],
        );
        collapse_stored_member_rows(&mut row, &units)
            .expect("exact duplicate members should collapse");
        assert_eq!(row.members.len(), 1);
    }

    #[test]
    fn unequal_durable_payload_for_one_finding_identity_is_an_error() {
        let mut row = group_with_members(1.0, vec![member("src/a.rs"), member("src/b.rs")]);
        let error = collapse_stored_member_rows(&mut row, &units_with_same_semantics())
            .expect_err("storage-only member differences must not be hidden");
        assert!(error.to_string().contains("stable stored finding identity"));
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn stored_unit_descriptor_keeps_durable_semantics() {
        let units = units_with_different_semantics();
        assert_ne!(
            stored_unit_descriptor(&units[0]),
            stored_unit_descriptor(&units[1]),
            "distinct resolved units must not compare equal through an ordinal"
        );
    }

    #[test]
    fn unequal_resolved_host_semantics_for_one_finding_is_an_error() {
        let units = units_with_different_semantics();
        let mut row = group_with_members(
            1.0,
            vec![
                member_at("src/a.rs", Some(0)),
                member_at("src/a.rs", Some(1)),
            ],
        );
        let error = collapse_stored_member_rows(&mut row, &units)
            .expect_err("different resolved host units must not be hidden");
        assert!(error.to_string().contains("stable stored finding identity"));
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn out_of_range_host_unit_is_an_explicit_finding_identity_error() {
        let mut row = group_with_members(1.0, vec![member_at("src/a.rs", Some(9))]);
        let error = collapse_stored_member_rows(&mut row, &units_with_same_semantics())
            .expect_err("an invalid host-unit ordinal must not be silently accepted");
        let message = error.to_string();
        assert!(message.contains(&FindingId::from_bytes([9; 16]).to_string()));
        assert!(message.contains("out-of-range host unit 9"));
    }
}
