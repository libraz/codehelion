//! Reading what the tool actually reports, as something scorable.
//!
//! The harness scores a [`DetectionResult`]: a flat list of findings, each
//! relating the fragments it claims are copies of one another. What the tool
//! emits is `scan-report-v1`, a far richer document written for people and for
//! static-analysis consumers. This module is the one place that knows how to
//! read the second as the first.
//!
//! Only the fields a score depends on are declared here, so an additive change
//! to the report — a new field, a new summary counter — leaves this module
//! alone. A change that is *not* additive moves the report's own schema
//! version, which [`from_report_json`] checks and refuses. That check is the
//! point of the module: without it the two formats drift apart silently and
//! the measurement stops happening while every test stays green.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::schema::{Axes, CloneType, DetectionResult, Finding, Fragment, SiblingBasis};

/// Report schema version this adapter reads.
///
/// The report's version covers its shape, not its content: findings move with
/// every detector change, and that is what the harness exists to measure. Only
/// a change to the document's structure lands here.
pub const SUPPORTED_REPORT_SCHEMA: u32 = 1;

/// What went wrong turning a report into a scorable result.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The document did not parse as a scan report.
    Parse(serde_json::Error),
    /// The document is a scan report of a version this adapter does not read.
    Version {
        /// The version the document declared.
        found: u32,
    },
    /// A field guaranteed by the current report contract was omitted.
    MissingField {
        /// Dot-separated field path.
        path: String,
    },
    /// A sibling section refers to an absent group or violates the report's
    /// basis/signature contract.
    InvalidSibling {
        /// Dot-separated field path or owner fingerprint.
        path: String,
        /// Why the sibling entry cannot be scored safely.
        reason: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "parsing scan report: {error}"),
            Self::Version { found } => write!(
                f,
                "scan report schema_version {found} (expected \
                 {SUPPORTED_REPORT_SCHEMA}): the report shape moved and this \
                 adapter has not followed it"
            ),
            Self::MissingField { path } => {
                write!(f, "scan report v1 omits required field {path}")
            }
            Self::InvalidSibling { path, reason } => {
                write!(f, "invalid scan report sibling {path}: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Version { .. } | Self::MissingField { .. } | Self::InvalidSibling { .. } => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Parse(error)
    }
}

/// The scan report, reduced to what scoring reads.
#[derive(Debug, Deserialize)]
struct ScanReport {
    schema_version: u32,
    summary: Summary,
    groups: Vec<Group>,
    siblings: Vec<SiblingGroup>,
}

#[derive(Debug, Deserialize)]
struct Summary {
    files: FileCounts,
    lines: u32,
}

#[derive(Debug, Deserialize)]
struct FileCounts {
    rust: u32,
    c: u32,
    cpp: u32,
}

#[derive(Debug, Deserialize)]
struct Group {
    fingerprint: String,
    clone_type: CloneType,
    priority: Priority,
    /// `null` when the group was not hidden by a suppression rule. Its shape
    /// does not matter here, only whether there is one.
    suppressed: Option<Value>,
    /// `null` for a group whose similarity was never scored.
    similarity: Option<Similarity>,
    /// The report's effective policy decision, persisted beside each group so
    /// consumers do not need to reconstruct configuration defaults.
    ranked_down: bool,
    /// Whether the detector read the group as one routine written once per
    /// integer width.
    width_family: bool,
    /// Registered-rule evidence for a restricted-semantic group.
    semantic: Option<SemanticEvidence>,
    members: Vec<Member>,
}

/// One owning group and its supplemental local mirrors in the report wire
/// shape.
#[derive(Debug, Deserialize)]
struct SiblingGroup {
    group_fingerprint: String,
    siblings: Vec<ReportSibling>,
}

/// One supplemental mirror in the report wire shape.
#[derive(Debug, Deserialize)]
struct ReportSibling {
    clone_type: CloneType,
    confidence_band: String,
    basis: SiblingBasis,
    signature: Option<String>,
    similarity: Similarity,
    member: Member,
    #[allow(dead_code)]
    suppressed: Option<Value>,
}

/// A primary group and the exact members attached to it by the sibling
/// channel. This is deliberately outside [`DetectionResult`]: siblings are
/// supplemental evidence, not primary findings.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedSiblingGroup {
    /// Fingerprint of the primary group that owns these mirrors.
    pub owner_group_fingerprint: String,
    /// Primary group members copied from the report for owner matching.
    pub owner_members: Vec<Fragment>,
    /// Supplemental mirrors attached to the owner.
    pub siblings: Vec<DetectedSibling>,
}

/// One rich sibling entry exposed to evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedSibling {
    /// Classification measured by the verifier.
    pub clone_type: CloneType,
    /// Confidence band recorded by the report.
    pub confidence_band: String,
    /// Independent candidate channel that supplied this sibling.
    pub basis: SiblingBasis,
    /// Exact normalized signature for signature-channel siblings.
    pub signature: Option<String>,
    /// Full verifier evidence, including the composite used for reporting.
    pub similarity: DetectedSiblingSimilarity,
    /// Ungrouped sibling occurrence.
    pub member: Fragment,
}

/// Similarity evidence retained for a rich sibling entry.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedSiblingSimilarity {
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: Option<f64>,
    /// Rename-invariant structural agreement.
    pub structural: Option<f64>,
    /// Control-flow-profile agreement.
    pub control_flow: Option<f64>,
    /// Call-surface agreement.
    pub api: Option<f64>,
    /// Weighted composite evidence.
    pub composite: f64,
}

/// The subset of semantic report evidence used by per-rule evaluation.
#[derive(Debug, Deserialize)]
struct SemanticEvidence {
    rules: Vec<SemanticRuleEvidence>,
}

/// One rule contributing to a semantic finding.
#[derive(Debug, Deserialize)]
struct SemanticRuleEvidence {
    id: String,
}

/// Whether the report puts a group forward or files it below the findings
/// that carry behaviour.
const fn put_forward(group: &Group) -> bool {
    !group.ranked_down
}

#[derive(Debug, Deserialize)]
struct Similarity {
    confidence_band: Option<String>,
    lexical: Option<f64>,
    structural: Option<f64>,
    control_flow: Option<f64>,
    api: Option<f64>,
    composite: Option<f64>,
}

impl Similarity {
    /// The axes, in the shape scoring reads them.
    const fn axes(&self) -> Axes {
        Axes {
            lexical: self.lexical,
            structural: self.structural,
            control_flow: self.control_flow,
            api: self.api,
            composite: self.composite,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Priority {
    value: f64,
    inputs: PriorityInputs,
}

#[derive(Debug, Deserialize)]
struct PriorityInputs {
    largest_member_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct Member {
    file: String,
    #[allow(dead_code)]
    language: Option<String>,
    start_line: u32,
    end_line: u32,
    tokens: u64,
}

/// The additive envelope emitted by `scan --compare-languages --format json`.
///
/// Cross-language comparisons are deliberately outside ordinary scan history,
/// so they have no scan-report schema version to borrow. The small dedicated
/// adapter below reads only the explicit comparison evidence and the measured
/// partition line counts used for a corpus rate.
#[derive(Debug, Deserialize)]
struct CrossLanguageOutput {
    partitions: Vec<CrossLanguagePartition>,
    cross_language_comparison: CrossLanguageComparison,
}

#[derive(Debug, Deserialize)]
struct CrossLanguagePartition {
    summary: CrossLanguageSummary,
}

#[derive(Debug, Deserialize)]
struct CrossLanguageSummary {
    lines: u32,
}

#[derive(Debug, Deserialize)]
struct CrossLanguageComparison {
    groups: Vec<CrossLanguageGroup>,
}

#[derive(Debug, Deserialize)]
struct CrossLanguageGroup {
    id: String,
    rule_id: String,
    semantic_confidence: f64,
    members: Vec<CrossLanguageMember>,
}

/// A member of the explicit comparison envelope.
///
/// Unlike ordinary scan-report members it carries the normalized graph, not a
/// token count. Cross-language evaluation has no token-size metric, so it
/// records zero rather than pretending this field belongs to that format.
#[derive(Debug, Deserialize)]
struct CrossLanguageMember {
    file: String,
    start_line: u32,
    end_line: u32,
}

/// A scan report, read as a scorable detection result.
///
/// Returns the result together with the line count the scan itself measured,
/// which is the denominator for the per-kLOC rates — taking it from the report
/// keeps the caller from counting the same lines a second time and disagreeing.
///
/// # Errors
///
/// Returns [`Error::Parse`] when `json` is not a scan report, and
/// [`Error::Version`] when it is one of a version this adapter does not read.
pub fn from_report_json_with_siblings(
    json: &str,
) -> Result<(DetectionResult, u32, Vec<DetectedSiblingGroup>), Error> {
    let value: Value = serde_json::from_str(json)?;
    validate_current_report_contract(&value)?;
    let report: ScanReport = serde_json::from_value(value)?;
    if report.schema_version != SUPPORTED_REPORT_SCHEMA {
        return Err(Error::Version {
            found: report.schema_version,
        });
    }

    // A suppressed group is not something the report puts in front of anyone,
    // so scoring it would credit or blame the tool for a finding it withheld.
    // The two lists are read the same way and kept apart.
    let (withheld, findings) = report
        .groups
        .iter()
        .map(|group| {
            (
                group.suppressed.is_some(),
                Finding {
                    id: group.fingerprint.clone(),
                    clone_type: group.clone_type,
                    rule_ids: group.semantic.as_ref().map_or_else(Vec::new, |semantic| {
                        semantic.rules.iter().map(|rule| rule.id.clone()).collect()
                    }),
                    // The ranking the tool would show, which is what
                    // precision@k is a statement about. The metrics read it for
                    // order alone.
                    score: group.priority.value,
                    size_tokens: group.priority.inputs.largest_member_tokens,
                    band: group
                        .similarity
                        .as_ref()
                        .and_then(|similarity| similarity.confidence_band.clone()),
                    actionable: put_forward(group),
                    axes: group
                        .similarity
                        .as_ref()
                        .map(Similarity::axes)
                        .unwrap_or_default(),
                    width_family: group.width_family,
                    fragments: group
                        .members
                        .iter()
                        .map(|member| Fragment {
                            file: member.file.clone(),
                            start_line: member.start_line,
                            end_line: member.end_line,
                            tokens: member.tokens,
                        })
                        .collect(),
                },
            )
        })
        .partition::<Vec<_>, _>(|(hidden, _)| *hidden);
    let strip = |list: Vec<(bool, Finding)>| list.into_iter().map(|(_, f)| f).collect();

    let result = DetectionResult {
        schema_version: crate::schema::SCHEMA_VERSION,
        language: language_of(&report.summary.files),
        findings: strip(findings),
        withheld: strip(withheld),
    };
    let siblings = rich_siblings(&report.groups, &report.siblings)?;
    Ok((result, report.summary.lines, siblings))
}

/// Read a report using the original primary-only adapter contract.
///
/// # Errors
///
/// Returns the same parse, schema, and current-contract errors as
/// [`from_report_json_with_siblings`].
pub fn from_report_json(json: &str) -> Result<(DetectionResult, u32), Error> {
    let (result, lines, _) = from_report_json_with_siblings(json)?;
    Ok((result, lines))
}

/// Validate and convert the report's supplemental sibling section.
#[allow(clippy::too_many_lines)]
fn rich_siblings(
    groups: &[Group],
    sibling_groups: &[SiblingGroup],
) -> Result<Vec<DetectedSiblingGroup>, Error> {
    let mut owners: BTreeMap<String, Vec<Fragment>> = BTreeMap::new();
    for group in groups {
        if owners
            .insert(
                group.fingerprint.clone(),
                group.members.iter().map(member_fragment).collect(),
            )
            .is_some()
        {
            return Err(Error::InvalidSibling {
                path: group.fingerprint.clone(),
                reason: "duplicate primary group fingerprint".to_string(),
            });
        }
    }
    let mut seen_owners = BTreeSet::new();
    sibling_groups
        .iter()
        .enumerate()
        .map(|(group_index, group)| {
            let owner_members =
                owners
                    .get(&group.group_fingerprint)
                    .ok_or_else(|| Error::InvalidSibling {
                        path: format!("siblings[{group_index}].group_fingerprint"),
                        reason: format!("unknown primary group `{}`", group.group_fingerprint),
                    })?;
            if !seen_owners.insert(group.group_fingerprint.clone()) {
                return Err(Error::InvalidSibling {
                    path: format!("siblings[{group_index}].group_fingerprint"),
                    reason: "duplicate sibling owner".to_string(),
                });
            }
            let mut seen_members = BTreeSet::new();
            let siblings = group
                .siblings
                .iter()
                .enumerate()
                .map(|(sibling_index, sibling)| {
                    let path = format!("siblings[{group_index}].siblings[{sibling_index}]");
                    let key = (
                        sibling.member.file.clone(),
                        sibling.member.start_line,
                        sibling.member.end_line,
                    );
                    if !seen_members.insert(key.clone()) {
                        return Err(Error::InvalidSibling {
                            path,
                            reason: "duplicate sibling member".to_string(),
                        });
                    }
                    if owner_members.iter().any(|member| {
                        member.file == key.0
                            && member.start_line == key.1
                            && member.end_line == key.2
                    }) {
                        return Err(Error::InvalidSibling {
                            path,
                            reason: "sibling member is already a primary member".to_string(),
                        });
                    }
                    if sibling.confidence_band.is_empty() {
                        return Err(Error::InvalidSibling {
                            path,
                            reason: "confidence_band must not be empty".to_string(),
                        });
                    }
                    match sibling.basis {
                        SiblingBasis::Signature => {
                            if sibling.signature.as_deref().is_none_or(str::is_empty) {
                                return Err(Error::InvalidSibling {
                                    path,
                                    reason: "signature basis requires a non-empty signature"
                                        .to_string(),
                                });
                            }
                            if sibling.confidence_band != "low" {
                                return Err(Error::InvalidSibling {
                                    path,
                                    reason: "signature siblings must have low confidence"
                                        .to_string(),
                                });
                            }
                        }
                        SiblingBasis::Similarity => {
                            if sibling.signature.is_some() {
                                return Err(Error::InvalidSibling {
                                    path,
                                    reason: "similarity siblings must not carry a signature"
                                        .to_string(),
                                });
                            }
                        }
                    }
                    let composite =
                        sibling
                            .similarity
                            .composite
                            .ok_or_else(|| Error::InvalidSibling {
                                path: path.clone(),
                                reason: "sibling similarity must include composite".to_string(),
                            })?;
                    Ok(DetectedSibling {
                        clone_type: sibling.clone_type,
                        confidence_band: sibling.confidence_band.clone(),
                        basis: sibling.basis,
                        signature: sibling.signature.clone(),
                        similarity: DetectedSiblingSimilarity {
                            lexical: sibling.similarity.lexical,
                            structural: sibling.similarity.structural,
                            control_flow: sibling.similarity.control_flow,
                            api: sibling.similarity.api,
                            composite,
                        },
                        member: member_fragment(&sibling.member),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DetectedSiblingGroup {
                owner_group_fingerprint: group.group_fingerprint.clone(),
                owner_members: owner_members.clone(),
                siblings,
            })
        })
        .collect()
}

fn member_fragment(member: &Member) -> Fragment {
    Fragment {
        file: member.file.clone(),
        start_line: member.start_line,
        end_line: member.end_line,
        tokens: member.tokens,
    }
}

/// Reject reports that silently omit a field produced by the current report
/// writer.
///
/// `Option<T>` accepts an absent key as well as `null`. That is useful for a
/// genuinely optional field such as non-semantic groups' `semantic` evidence,
/// but it must not make this evaluator accept a stale pre-release report
/// shape. The checked fields are the complete subset this adapter reads and
/// the writer always emits them, including as `null` when no value exists.
#[allow(clippy::too_many_lines)]
fn validate_current_report_contract(value: &Value) -> Result<(), Error> {
    require_fields(
        value,
        "report",
        &["schema_version", "summary", "groups", "siblings"],
    )?;
    let Some(summary) = value.get("summary") else {
        return Ok(());
    };
    require_fields(summary, "summary", &["files", "lines", "search_truncated"])?;
    if let Some(files) = summary.get("files") {
        require_fields(files, "summary.files", &["rust", "c", "cpp"])?;
    }

    let Some(groups) = value.get("groups").and_then(Value::as_array) else {
        return Ok(());
    };
    for (group_index, group) in groups.iter().enumerate() {
        let group_path = format!("groups[{group_index}]");
        require_fields(
            group,
            &group_path,
            &[
                "fingerprint",
                "clone_type",
                "priority",
                "similarity",
                "boilerplate",
                "test_code",
                "test_code_evidence",
                "width_family",
                "split_pair",
                "ranked_down",
                "suppressed",
                "members",
            ],
        )?;
        if let Some(priority) = group.get("priority") {
            require_fields(
                priority,
                &format!("{group_path}.priority"),
                &["value", "inputs"],
            )?;
            if let Some(inputs) = priority.get("inputs") {
                require_fields(
                    inputs,
                    &format!("{group_path}.priority.inputs"),
                    &["largest_member_tokens"],
                )?;
            }
        }
        if let Some(similarity) = group.get("similarity").filter(|value| !value.is_null()) {
            require_fields(
                similarity,
                &format!("{group_path}.similarity"),
                &[
                    "confidence_band",
                    "lexical",
                    "structural",
                    "control_flow",
                    "api",
                    "composite",
                ],
            )?;
        }
        if group.get("clone_type").and_then(Value::as_str) == Some("restricted-semantic") {
            require_fields(group, &group_path, &["semantic"])?;
            let Some(semantic) = group.get("semantic").filter(|value| !value.is_null()) else {
                return Err(Error::MissingField {
                    path: format!("{group_path}.semantic"),
                });
            };
            require_fields(semantic, &format!("{group_path}.semantic"), &["rules"])?;
        }
        if let Some(members) = group.get("members").and_then(Value::as_array) {
            for (member_index, member) in members.iter().enumerate() {
                require_fields(
                    member,
                    &format!("{group_path}.members[{member_index}]"),
                    &["file", "start_line", "end_line", "tokens"],
                )?;
            }
        }
    }
    if let Some(sibling_groups) = value.get("siblings").and_then(Value::as_array) {
        for (group_index, sibling_group) in sibling_groups.iter().enumerate() {
            let group_path = format!("siblings[{group_index}]");
            require_fields(
                sibling_group,
                &group_path,
                &["group_fingerprint", "siblings"],
            )?;
            if let Some(siblings) = sibling_group.get("siblings").and_then(Value::as_array) {
                for (sibling_index, sibling) in siblings.iter().enumerate() {
                    let sibling_path = format!("{group_path}.siblings[{sibling_index}]");
                    require_fields(
                        sibling,
                        &sibling_path,
                        &[
                            "clone_type",
                            "confidence_band",
                            "basis",
                            "signature",
                            "similarity",
                            "member",
                            "suppressed",
                        ],
                    )?;
                    if let Some(similarity) = sibling.get("similarity") {
                        require_fields(
                            similarity,
                            &format!("{sibling_path}.similarity"),
                            &[
                                "weight_version",
                                "lexical",
                                "structural",
                                "control_flow",
                                "type_similarity",
                                "api",
                                "composite",
                            ],
                        )?;
                    }
                    if let Some(member) = sibling.get("member") {
                        require_fields(
                            member,
                            &format!("{sibling_path}.member"),
                            &["file", "start_line", "end_line", "tokens"],
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Require keys only once the surrounding value is an object; type errors are
/// intentionally left to serde so their diagnostics retain the actual value.
fn require_fields(value: &Value, path: &str, fields: &[&str]) -> Result<(), Error> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for field in fields {
        if !object.contains_key(*field) {
            return Err(Error::MissingField {
                path: format!("{path}.{field}"),
            });
        }
    }
    Ok(())
}

/// Read an explicit Rust-to-C++ comparison as restricted-semantic findings.
///
/// The returned line count is the sum of selected partition reports. Corpus
/// fixtures use one Rust and one C++ partition; callers comparing repeated
/// C++ build variants should treat this denominator as comparison work, not a
/// count of unique source lines.
///
/// # Errors
///
/// Returns [`Error::Parse`] when the document lacks the dedicated comparison
/// envelope or its members cannot be decoded.
pub fn from_cross_language_comparison_json(json: &str) -> Result<(DetectionResult, u32), Error> {
    let output: CrossLanguageOutput = serde_json::from_str(json)?;
    let lines = output.partitions.iter().fold(0_u32, |total, partition| {
        total.saturating_add(partition.summary.lines)
    });
    let findings = output
        .cross_language_comparison
        .groups
        .into_iter()
        .map(|group| Finding {
            id: group.id,
            clone_type: CloneType::RestrictedSemantic,
            rule_ids: vec![group.rule_id],
            score: group.semantic_confidence,
            size_tokens: 0,
            band: None,
            actionable: true,
            axes: Axes::default(),
            width_family: false,
            fragments: group
                .members
                .into_iter()
                .map(|member| Fragment {
                    file: member.file,
                    start_line: member.start_line,
                    end_line: member.end_line,
                    tokens: 0,
                })
                .collect(),
        })
        .collect();
    Ok((
        DetectionResult {
            schema_version: crate::schema::SCHEMA_VERSION,
            language: "mixed".to_string(),
            findings,
            withheld: Vec::new(),
        },
        lines,
    ))
}

/// The corpus language, as the file counts describe it. A corpus that mixes
/// languages says so rather than picking whichever was counted first.
fn language_of(files: &FileCounts) -> String {
    let present: Vec<&str> = [("rust", files.rust), ("c", files.c), ("cpp", files.cpp)]
        .into_iter()
        .filter(|&(_, count)| count > 0)
        .map(|(name, _)| name)
        .collect();
    match present.as_slice() {
        [single] => (*single).to_string(),
        [] => "none".to_string(),
        _ => "mixed".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    const CROSS_LANGUAGE_REPORT: &str = r#"{
      "partitions": [{"summary":{"lines":3}}, {"summary":{"lines":5}}],
      "cross_language_comparison": {
        "groups": [{
          "id":"cross-1", "rule_id":"cross-language-sequence-pipeline-v1", "semantic_confidence":0.55,
          "members":[
            {"file":"src/lib.rs","start_line":1,"end_line":3},
            {"file":"cpp/copied.cpp","start_line":4,"end_line":8}
          ]
        }]
      }
    }"#;

    #[test]
    fn a_cross_language_comparison_is_read_as_restricted_semantic() {
        let (result, lines) =
            from_cross_language_comparison_json(CROSS_LANGUAGE_REPORT).expect("comparison reads");
        assert_eq!(lines, 8);
        assert_eq!(result.language, "mixed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].clone_type, CloneType::RestrictedSemantic);
        assert_eq!(
            result.findings[0].rule_ids,
            ["cross-language-sequence-pipeline-v1"]
        );
        assert!((result.findings[0].score - 0.55).abs() < f64::EPSILON);
        assert_eq!(result.findings[0].fragments[1].file, "cpp/copied.cpp");
    }

    /// A report with one reported group and one the tool suppressed.
    const REPORT: &str = r#"{
      "schema_version": 1,
      "run": {"id": 1},
      "summary": {
        "files": {"total": 2, "rust": 2, "c": 0, "cpp": 0},
        "lines": 240,
        "search_truncated": false,
        "groups": {"total": 2}
      },
      "groups": [
        {
          "fingerprint": "abc",
          "clone_type": "type-2",
          "scope": "unit",
          "priority": {"value": 0.62, "inputs": {"largest_member_tokens": 120}},
          "similarity": {
            "lexical": null,
            "structural": null,
            "control_flow": null,
            "api": null,
            "composite": 0.91,
            "confidence_band": "high"
          },
          "boilerplate": null,
          "test_code": false,
          "test_code_evidence": null,
          "width_family": false,
          "split_pair": false,
          "ranked_down": false,
          "suppressed": null,
          "members": [
            {"finding_id": "m1", "file": "a.rs", "start_line": 10, "end_line": 24, "tokens": 12},
            {"finding_id": "m2", "file": "b.rs", "start_line": 5, "end_line": 19, "tokens": 14}
          ]
        },
        {
          "fingerprint": "def",
          "clone_type": "type-1",
          "scope": "unit",
          "priority": {"value": 0.41, "inputs": {"largest_member_tokens": 90}},
          "similarity": null,
          "boilerplate": null,
          "test_code": false,
          "test_code_evidence": null,
          "width_family": false,
          "split_pair": false,
          "ranked_down": true,
          "suppressed": {"kind": "rule", "detail": "path"},
          "members": [
            {"finding_id": "m3", "file": "c.rs", "start_line": 1, "end_line": 4, "tokens": 4}
          ]
        }
      ],
      "siblings": []
    }"#;

    fn report_with_siblings() -> String {
        let mut report: Value = serde_json::from_str(REPORT).expect("report fixture parses");
        report["siblings"] = json!([{
            "group_fingerprint": "abc",
            "siblings": [{
                "clone_type": "type-3",
                "confidence_band": "low",
                "basis": "similarity",
                "signature": null,
                "similarity": {
                    "weight_version": "structural-verify-v1",
                    "lexical": 0.72,
                    "structural": 0.91,
                    "control_flow": 0.8,
                    "type_similarity": null,
                    "api": 0.7,
                    "composite": 0.76
                },
                "member": {
                    "finding_id": "f0",
                    "content": "f1",
                    "file": "c.rs",
                    "language": "rust",
                    "start_line": 30,
                    "end_line": 36,
                    "tokens": 7
                },
                "suppressed": null
            }]
        }]);
        serde_json::to_string(&report).expect("report fixture serializes")
    }

    #[test]
    fn rich_adapter_keeps_primary_findings_separate_from_sibling_evidence() {
        let report = report_with_siblings();
        let (result, lines, siblings) =
            from_report_json_with_siblings(&report).expect("rich report reads");
        assert_eq!(lines, 240);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].owner_group_fingerprint, "abc");
        assert_eq!(siblings[0].owner_members.len(), 2);
        let sibling = &siblings[0].siblings[0];
        assert_eq!(sibling.basis, SiblingBasis::Similarity);
        assert_eq!(sibling.confidence_band, "low");
        assert_eq!(sibling.signature, None);
        assert!((sibling.similarity.composite - 0.76).abs() < f64::EPSILON);
        assert_eq!(sibling.member.file, "c.rs");
        assert_eq!(sibling.member.tokens, 7);
    }

    #[test]
    fn rich_adapter_requires_signature_evidence_for_signature_siblings() {
        let mut report: Value = serde_json::from_str(&report_with_siblings()).expect("parses");
        report["siblings"][0]["siblings"][0]["basis"] = json!("signature");
        report["siblings"][0]["siblings"][0]["signature"] = json!("int(const int*,int)");
        let report = serde_json::to_string(&report).expect("serializes");
        let (_, _, siblings) =
            from_report_json_with_siblings(&report).expect("signature sibling reads");
        assert_eq!(siblings[0].siblings[0].basis, SiblingBasis::Signature);
        assert_eq!(
            siblings[0].siblings[0].signature.as_deref(),
            Some("int(const int*,int)")
        );
    }

    #[test]
    fn rich_adapter_rejects_an_unknown_sibling_owner() {
        let mut report: Value = serde_json::from_str(&report_with_siblings()).expect("parses");
        report["siblings"][0]["group_fingerprint"] = json!("missing");
        let report = serde_json::to_string(&report).expect("serializes");
        let error = from_report_json_with_siblings(&report).expect_err("owner must exist");
        assert!(matches!(error, Error::InvalidSibling { .. }));
    }

    #[test]
    fn rich_adapter_rejects_a_sibling_that_is_already_a_primary_member() {
        let mut report: Value = serde_json::from_str(&report_with_siblings()).expect("parses");
        report["siblings"][0]["siblings"][0]["member"]["file"] = json!("a.rs");
        report["siblings"][0]["siblings"][0]["member"]["start_line"] = json!(10);
        report["siblings"][0]["siblings"][0]["member"]["end_line"] = json!(24);
        let report = serde_json::to_string(&report).expect("serializes");
        let error = from_report_json_with_siblings(&report).expect_err("overlap must reject");
        assert!(matches!(error, Error::InvalidSibling { .. }));
    }

    #[test]
    fn a_report_is_read_as_the_findings_it_puts_forward() {
        let (result, lines) = from_report_json(REPORT).expect("report reads");
        assert_eq!(lines, 240);
        assert_eq!(result.language, "rust");
        // The suppressed group is not among them: it was withheld.
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.id, "abc");
        assert_eq!(finding.clone_type, CloneType::Type2);
        assert!((finding.score - 0.62).abs() < 1e-9);
        assert_eq!(finding.size_tokens, 120);
        assert_eq!(finding.band.as_deref(), Some("high"));
        assert_eq!(
            finding.fragments,
            vec![
                Fragment {
                    file: "a.rs".to_string(),
                    start_line: 10,
                    end_line: 24,
                    tokens: 12,
                },
                Fragment {
                    file: "b.rs".to_string(),
                    start_line: 5,
                    end_line: 19,
                    tokens: 14,
                },
            ]
        );
    }

    #[test]
    fn a_finding_the_detector_never_scored_carries_no_band() {
        // Split pairs and fragment runs reach the report with a null similarity
        // breakdown. Reading them as an absent band rather than as a failure
        // is what lets the band table account for every judged finding.
        let unscored = REPORT.replace(
            r#""similarity": {
            "lexical": null,
            "structural": null,
            "control_flow": null,
            "api": null,
            "composite": 0.91,
            "confidence_band": "high"
          },"#,
            r#""similarity": null,"#,
        );
        let (result, _lines) = from_report_json(&unscored).expect("report reads");
        assert_eq!(result.findings[0].band, None);
    }

    #[test]
    fn a_report_of_another_version_is_refused_rather_than_guessed_at() {
        // The failure this rejects is the one that costs the most: a report
        // whose shape moved on, read as though it had not, quietly scoring
        // whatever still happened to parse.
        let moved_on = REPORT.replace("\"schema_version\": 1", "\"schema_version\": 2");
        let error = from_report_json(&moved_on).expect_err("a later version is refused");
        assert!(matches!(error, Error::Version { found: 2 }));
    }

    #[test]
    fn a_document_that_is_not_a_report_is_a_parse_error() {
        let error = from_report_json("{\"schema_version\": 1}").expect_err("no summary");
        assert!(matches!(error, Error::MissingField { .. }));
    }

    #[test]
    fn a_v1_report_missing_a_current_contract_field_is_refused() {
        let stale = REPORT.replacen("\"width_family\": false,", "", 1);
        let error = from_report_json(&stale).expect_err("missing v1 field is refused");
        assert!(matches!(
            error,
            Error::MissingField { ref path } if path == "groups[0].width_family"
        ));
    }

    #[test]
    fn a_v1_report_missing_the_sibling_section_is_refused() {
        let stale = REPORT.replace(",\n      \"siblings\": []", "");
        let error = from_report_json(&stale).expect_err("missing siblings must be refused");
        assert!(matches!(
            error,
            Error::MissingField { ref path } if path == "report.siblings"
        ));
    }

    #[test]
    fn a_group_the_report_files_below_the_rest_is_read_as_one() {
        let filed = REPORT.replacen("\"ranked_down\": false", "\"ranked_down\": true", 1);
        let (result, _lines) = from_report_json(&filed).expect("report reads");
        assert!(!result.findings[0].actionable);

        // Without this, the assertion above would pass on a reader that
        // always answered no.
        let (result, _lines) = from_report_json(REPORT).expect("report reads");
        assert!(result.findings[0].actionable);
    }

    /// The fold this module reads is the explicit decision the report drew.
    #[test]
    fn the_fold_this_reads_is_where_the_report_put_it() {
        let ordered = REPORT.replacen(
            "\"ranked_down\": true,\n          \"suppressed\": {\"kind\": \"rule\", \"detail\": \"path\"},",
            "\"ranked_down\": true,\n          \"suppressed\": null,",
            1,
        );
        let (result, _lines) = from_report_json(&ordered).expect("report reads");
        let fold = result
            .findings
            .iter()
            .position(|finding| !finding.actionable)
            .unwrap_or(result.findings.len());
        assert!(
            result.findings[fold..].iter().all(|f| !f.actionable),
            "the report put a finding forward below one it filed away, so the \
             policy read here is not the policy it applied"
        );
        assert_eq!(fold, 1, "the fixture is meant to have a fold to find");
    }

    #[test]
    fn a_corpus_of_more_than_one_language_says_so() {
        let mixed = REPORT.replace("\"c\": 0", "\"c\": 3");
        let (result, _) = from_report_json(&mixed).expect("report reads");
        assert_eq!(result.language, "mixed");
    }
}
