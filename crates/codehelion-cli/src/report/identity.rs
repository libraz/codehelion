//! Stable-identity normalization at the report boundary.
//!
//! Exact duplicate group and finding records are collapsed here, against a
//! typed payload rather than against serialized JSON, so that two records
//! JSON would render alike are still compared by what they measure.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the normalization boundary is crate-internal and reaches the rest of the crate through the report module's re-export"
)]

use super::{
    Group, Member, Priority, PriorityInputs, SemanticEvidence, Similarity, SuppressionKind,
};
use anyhow::Result;
use codehelion_core::semantic::SemanticOperationGraph;
use codehelion_core::test_code::TestCodeEvidence;
use std::collections::BTreeSet;

/// A report's groups after the stable-identity boundary has been normalized.
#[derive(Debug)]
pub(crate) struct NormalizedGroups {
    /// Groups retained in their deterministic input order.
    pub groups: Vec<Group>,
    /// Number of stable identity records removed by exact collapse.
    ///
    /// A duplicate whole group counts as one record and its members are not
    /// counted again. Otherwise, exact duplicate member findings count one
    /// record each.
    pub identity_collapsed: u64,
}

/// IEEE-754 identity payload for a report measurement.
///
/// JSON has no representation for NaN or infinities and therefore turns
/// distinct non-finite values into the same `null` payload. Stable-identity
/// normalization compares the original bits instead, including the sign of
/// zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReportFloatBits(u64);

impl From<f64> for ReportFloatBits {
    fn from(value: f64) -> Self {
        Self(value.to_bits())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportPriorityInputsIdentity {
    smallest_member_tokens: u64,
    largest_member_tokens: u64,
    instances: u64,
    similarity: ReportFloatBits,
    files: u64,
    directories: u64,
    languages: u64,
    min_clone_tokens: u64,
    identifier_jaccard: Option<ReportFloatBits>,
    api_similarity: Option<ReportFloatBits>,
    has_loop: Option<bool>,
    has_dynamic_allocation: Option<bool>,
    call_count: Option<u64>,
    churn: Option<ReportFloatBits>,
    ownership_spread: Option<ReportFloatBits>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportPriorityIdentity {
    value: ReportFloatBits,
    clone_confidence: ReportFloatBits,
    maintenance_risk: ReportFloatBits,
    refactoring_difficulty: ReportFloatBits,
    semantic_confidence: Option<ReportFloatBits>,
    source_artifact_confidence: Option<ReportFloatBits>,
    savings_confidence: Option<ReportFloatBits>,
    inputs: ReportPriorityInputsIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportSimilarityIdentity {
    weight_version: String,
    lexical: ReportFloatBits,
    structural: ReportFloatBits,
    control_flow: Option<ReportFloatBits>,
    type_similarity: Option<ReportFloatBits>,
    api: Option<ReportFloatBits>,
    composite: ReportFloatBits,
    min_pairwise: ReportFloatBits,
    confidence_band: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportBodyMaterialityIdentity {
    has_loop: bool,
    has_dynamic_allocation: bool,
    call_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportSuppressionIdentity {
    kind: SuppressionKind,
    reason: Option<String>,
    scope: Option<String>,
    pattern: Option<String>,
    active: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportBaselineIdentity {
    state: String,
    added_instances: Option<u64>,
    derived_from: Option<ReportDerivationIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportDerivationIdentity {
    group: String,
    shared_sites: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportRuleIdentity {
    id: String,
    version: u32,
    confidence: ReportFloatBits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReportNodeMappingIdentity {
    corresponding_member: u32,
    canonical: u32,
    corresponding: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportSemanticIdentity {
    schema_version: String,
    rules: Vec<ReportRuleIdentity>,
    graphs: Vec<SemanticOperationGraph>,
    node_mappings: Vec<ReportNodeMappingIdentity>,
}

/// Exact identity representation for structured JSON assumptions.
///
/// `serde_json::Value` deliberately treats some numerically distinct source
/// representations as equal and its floating-point equality loses the sign
/// of zero. The identity boundary keeps JSON's value kinds explicit, stores
/// object members in sorted key order, and compares finite floating-point
/// values by their IEEE bits.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonIdentity {
    Null,
    Bool(bool),
    String(String),
    I64(i64),
    U64(u64),
    F64(ReportFloatBits),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

fn json_identity(value: &serde_json::Value) -> Result<JsonIdentity> {
    match value {
        serde_json::Value::Null => Ok(JsonIdentity::Null),
        serde_json::Value::Bool(value) => Ok(JsonIdentity::Bool(*value)),
        serde_json::Value::String(value) => Ok(JsonIdentity::String(value.clone())),
        serde_json::Value::Number(number) => {
            if number.is_i64() {
                return number
                    .as_i64()
                    .map(JsonIdentity::I64)
                    .ok_or_else(|| anyhow::anyhow!("JSON i64 identity conversion failed"));
            }
            if number.is_u64() {
                return number
                    .as_u64()
                    .map(JsonIdentity::U64)
                    .ok_or_else(|| anyhow::anyhow!("JSON u64 identity conversion failed"));
            }
            if number.is_f64() {
                return number
                    .as_f64()
                    .map(report_float)
                    .map(JsonIdentity::F64)
                    .ok_or_else(|| anyhow::anyhow!("JSON f64 identity conversion failed"));
            }
            Err(anyhow::anyhow!(
                "JSON number cannot be represented by the supported identity variants"
            ))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .map(json_identity)
            .collect::<Result<Vec<_>>>()
            .map(JsonIdentity::Array),
        serde_json::Value::Object(values) => {
            let mut entries = values
                .iter()
                .map(|(key, value)| json_identity(value).map(|value| (key.clone(), value)))
                .collect::<Result<Vec<_>>>()?;
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Ok(JsonIdentity::Object(entries))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportArtifactSavingsIdentity {
    artifact_analysis_id: i64,
    source_build_variant_fingerprint: String,
    artifact_build_variant_fingerprint: String,
    duplicated_bytes: u64,
    estimated_refactor_savings_bytes: i64,
    mapping_confidence: String,
    clone_confidence: ReportFloatBits,
    model_confidence: String,
    savings_confidence: String,
    model_schema_version: String,
    assumptions: JsonIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportMemberIdentity {
    finding_id: String,
    content: String,
    file: String,
    language: String,
    start_line: u32,
    end_line: u32,
    unit: Option<String>,
    boilerplate: Option<String>,
    tokens: u64,
    canonical: bool,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the identity payload mirrors independent report classification fields"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportGroupIdentity {
    clone_type: String,
    scope: String,
    statements: Option<u64>,
    confidence: ReportFloatBits,
    entropy_bits: ReportFloatBits,
    priority: ReportPriorityIdentity,
    similarity: Option<ReportSimilarityIdentity>,
    identifier_jaccard: Option<ReportFloatBits>,
    body_materiality: Option<ReportBodyMaterialityIdentity>,
    boilerplate: Option<String>,
    test_code: bool,
    test_code_evidence: Option<TestCodeEvidence>,
    width_family: bool,
    split_pair: bool,
    ranked_down: bool,
    suppressed: Option<ReportSuppressionIdentity>,
    baseline: Option<ReportBaselineIdentity>,
    semantic: Option<ReportSemanticIdentity>,
    artifact_savings: Vec<ReportArtifactSavingsIdentity>,
    members: Vec<ReportMemberIdentity>,
}

fn report_float(value: f64) -> ReportFloatBits {
    ReportFloatBits::from(value)
}

fn report_priority_inputs(inputs: &PriorityInputs) -> ReportPriorityInputsIdentity {
    ReportPriorityInputsIdentity {
        smallest_member_tokens: inputs.smallest_member_tokens,
        largest_member_tokens: inputs.largest_member_tokens,
        instances: inputs.instances,
        similarity: report_float(inputs.similarity),
        files: inputs.files,
        directories: inputs.directories,
        languages: inputs.languages,
        min_clone_tokens: inputs.min_clone_tokens,
        identifier_jaccard: inputs.identifier_jaccard.map(report_float),
        api_similarity: inputs.api_similarity.map(report_float),
        has_loop: inputs.has_loop,
        has_dynamic_allocation: inputs.has_dynamic_allocation,
        call_count: inputs.call_count,
        churn: inputs.churn.map(report_float),
        ownership_spread: inputs.ownership_spread.map(report_float),
    }
}

fn report_priority(priority: &Priority) -> ReportPriorityIdentity {
    ReportPriorityIdentity {
        value: report_float(priority.value),
        clone_confidence: report_float(priority.clone_confidence),
        maintenance_risk: report_float(priority.maintenance_risk),
        refactoring_difficulty: report_float(priority.refactoring_difficulty),
        semantic_confidence: priority.semantic_confidence.map(report_float),
        source_artifact_confidence: priority.source_artifact_confidence.map(report_float),
        savings_confidence: priority.savings_confidence.map(report_float),
        inputs: report_priority_inputs(&priority.inputs),
    }
}

fn report_similarity(similarity: &Similarity) -> ReportSimilarityIdentity {
    ReportSimilarityIdentity {
        weight_version: similarity.weight_version.clone(),
        lexical: report_float(similarity.lexical),
        structural: report_float(similarity.structural),
        control_flow: similarity.control_flow.map(report_float),
        type_similarity: similarity.type_similarity.map(report_float),
        api: similarity.api.map(report_float),
        composite: report_float(similarity.composite),
        min_pairwise: report_float(similarity.min_pairwise),
        confidence_band: similarity.confidence_band.clone(),
    }
}

fn report_member(member: &Member) -> ReportMemberIdentity {
    ReportMemberIdentity {
        finding_id: member.finding_id.clone(),
        content: member.content.clone(),
        file: member.file.clone(),
        language: member.language.clone(),
        start_line: member.start_line,
        end_line: member.end_line,
        unit: member.unit.clone(),
        boilerplate: member.boilerplate.clone(),
        tokens: member.tokens,
        canonical: member.canonical,
    }
}

fn report_semantic(semantic: &SemanticEvidence) -> ReportSemanticIdentity {
    ReportSemanticIdentity {
        schema_version: semantic.schema_version.clone(),
        rules: semantic
            .rules
            .iter()
            .map(|rule| ReportRuleIdentity {
                id: rule.id.clone(),
                version: rule.version,
                confidence: report_float(rule.confidence),
            })
            .collect(),
        graphs: semantic.graphs.clone(),
        node_mappings: semantic
            .node_mappings
            .iter()
            .map(|mapping| ReportNodeMappingIdentity {
                corresponding_member: mapping.corresponding_member,
                canonical: mapping.canonical,
                corresponding: mapping.corresponding,
            })
            .collect(),
    }
}

fn report_group(group: &Group) -> Result<ReportGroupIdentity> {
    Ok(ReportGroupIdentity {
        clone_type: group.clone_type.clone(),
        scope: group.scope.clone(),
        statements: group.statements,
        confidence: report_float(group.confidence),
        entropy_bits: report_float(group.entropy_bits),
        priority: report_priority(&group.priority),
        similarity: group.similarity.as_ref().map(report_similarity),
        identifier_jaccard: group.identifier_jaccard.map(report_float),
        body_materiality: group
            .body_materiality
            .map(|body| ReportBodyMaterialityIdentity {
                has_loop: body.has_loop,
                has_dynamic_allocation: body.has_dynamic_allocation,
                call_count: body.call_count,
            }),
        boilerplate: group.boilerplate.clone(),
        test_code: group.test_code,
        test_code_evidence: group.test_code_evidence,
        width_family: group.width_family,
        split_pair: group.split_pair,
        ranked_down: group.ranked_down,
        suppressed: group
            .suppressed
            .as_ref()
            .map(|suppression| ReportSuppressionIdentity {
                kind: suppression.kind,
                reason: suppression.reason.clone(),
                scope: suppression.scope.clone(),
                pattern: suppression.pattern.clone(),
                active: suppression.active,
            }),
        baseline: group
            .baseline
            .as_ref()
            .map(|baseline| ReportBaselineIdentity {
                state: baseline.state.clone(),
                added_instances: baseline.added_instances,
                derived_from: baseline.derived_from.as_ref().map(|derived| {
                    ReportDerivationIdentity {
                        group: derived.group.clone(),
                        shared_sites: derived.shared_sites,
                    }
                }),
            }),
        semantic: group.semantic.as_ref().map(report_semantic),
        artifact_savings: group
            .artifact_savings
            .iter()
            .map(|savings| {
                Ok(ReportArtifactSavingsIdentity {
                    artifact_analysis_id: savings.artifact_analysis_id,
                    source_build_variant_fingerprint: savings
                        .source_build_variant_fingerprint
                        .clone(),
                    artifact_build_variant_fingerprint: savings
                        .artifact_build_variant_fingerprint
                        .clone(),
                    duplicated_bytes: savings.duplicated_bytes,
                    estimated_refactor_savings_bytes: savings.estimated_refactor_savings_bytes,
                    mapping_confidence: savings.mapping_confidence.clone(),
                    clone_confidence: report_float(savings.clone_confidence),
                    model_confidence: savings.model_confidence.clone(),
                    savings_confidence: savings.savings_confidence.clone(),
                    model_schema_version: savings.model_schema_version.clone(),
                    assumptions: json_identity(&savings.assumptions)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        members: group.members.iter().map(report_member).collect(),
    })
}

/// Collapse exact duplicate group and finding records at the report boundary.
///
/// The stable identifier is the key and a typed payload compares every report
/// field. Floating-point measurements use their IEEE bits, so JSON's `null`
/// representation for non-finite values cannot make unequal records collapse.
/// Equal identifiers with unequal payloads are an invariant error; source
/// anchors are therefore never silently selected as a tie-breaker.
/// Whole-group removal takes precedence over member removal so
/// `identity_collapsed` cannot count the same evidence twice.
pub(crate) fn normalize_identities(groups: Vec<Group>) -> Result<NormalizedGroups> {
    let group_records = groups
        .iter()
        .map(|group| report_group(group).map(|identity| (group.fingerprint.clone(), identity)))
        .collect::<Result<Vec<_>>>()?;
    let collapsed_groups =
        codehelion_core::identity::collapse_exact(&group_records).map_err(|error| {
            anyhow::anyhow!(
                "stable clone-group identity {} has unequal payloads",
                error.identity
            )
        })?;
    let retained = collapsed_groups
        .retained
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    // First validate finding ids globally. The group fingerprint is part of
    // the payload because a finding id emitted under two different group ids
    // is an invariant conflict, even when the member anchors happen to match.
    let mut finding_keys = Vec::new();
    for &group_index in &collapsed_groups.retained {
        let group_fingerprint = groups[group_index].fingerprint.clone();
        for member in &groups[group_index].members {
            finding_keys.push((
                member.finding_id.clone(),
                (group_fingerprint.clone(), report_member(member)),
            ));
        }
    }
    codehelion_core::identity::collapse_exact(&finding_keys).map_err(|error| {
        anyhow::anyhow!(
            "stable finding identity {} has unequal payloads",
            error.identity
        )
    })?;
    let mut normalized = Vec::with_capacity(retained.len());
    let mut identity_collapsed = collapsed_groups.collapsed;
    for (index, mut group) in groups.into_iter().enumerate() {
        if !retained.contains(&index) {
            continue;
        }
        let member_keys = group
            .members
            .iter()
            .map(|member| (member.finding_id.clone(), report_member(member)))
            .collect::<Vec<_>>();
        let collapsed_members =
            codehelion_core::identity::collapse_exact(&member_keys).map_err(|error| {
                anyhow::anyhow!(
                    "stable finding identity {} has unequal payloads",
                    error.identity
                )
            })?;
        identity_collapsed = identity_collapsed.saturating_add(collapsed_members.collapsed);
        let retained_members = collapsed_members
            .retained
            .into_iter()
            .collect::<BTreeSet<_>>();
        group.members = group
            .members
            .into_iter()
            .enumerate()
            .filter_map(|(member_index, member)| {
                retained_members.contains(&member_index).then_some(member)
            })
            .collect();
        normalized.push(group);
    }
    Ok(NormalizedGroups {
        groups: normalized,
        identity_collapsed,
    })
}
