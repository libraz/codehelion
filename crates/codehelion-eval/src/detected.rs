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

use std::fmt;

use serde::Deserialize;

use crate::schema::{Axes, CloneType, DetectionResult, Finding, Fragment};

/// Report schema version this adapter reads.
///
/// The report's version covers its shape, not its content: findings move with
/// every detector change, and that is what the harness exists to measure. Only
/// a change to the document's structure lands here.
pub const SUPPORTED_REPORT_SCHEMA: u32 = 2;

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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Version { .. } => None,
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
    /// Present when the group was hidden from the report by a suppression
    /// rule. Its shape does not matter here, only whether there is one.
    #[serde(default)]
    suppressed: Option<serde_json::Value>,
    /// Absent for a group whose similarity was never scored.
    #[serde(default)]
    similarity: Option<Similarity>,
    /// The three report fields the default policy ranks a group down for. See
    /// [`put_forward`].
    #[serde(default)]
    split_pair: bool,
    #[serde(default)]
    test_code: bool,
    #[serde(default)]
    boilerplate: Option<String>,
    /// Whether the detector read the group as one routine written once per
    /// integer width.
    #[serde(default)]
    width_family: bool,
    /// Registered-rule evidence for a restricted-semantic group.
    #[serde(default)]
    semantic: Option<SemanticEvidence>,
    members: Vec<Member>,
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

/// Boilerplate category the default policy ranks down rather than hides.
const RANKED_DOWN_BOILERPLATE: &str = "macro-repetition";

/// Whether the report puts a group forward or files it below the findings
/// that carry behaviour.
///
/// The report sorts by this and does not state it, so it is read back from the
/// three fields the decision is made of. That leaves the default policy
/// written down twice, which is why the answer is checked against the order
/// the report actually emitted — everything it puts forward comes first, so a
/// policy change that moves the fold moves the order with it and the
/// disagreement is the signal.
///
/// A configured run can rank other things down, and this will not know. The
/// harness scans with the defaults, which is the run the figure describes.
fn put_forward(group: &Group) -> bool {
    !(group.split_pair
        || group.test_code
        || group.boilerplate.as_deref() == Some(RANKED_DOWN_BOILERPLATE))
}

#[derive(Debug, Deserialize)]
struct Similarity {
    #[serde(default)]
    confidence_band: Option<String>,
    #[serde(default)]
    lexical: Option<f64>,
    #[serde(default)]
    structural: Option<f64>,
    #[serde(default)]
    control_flow: Option<f64>,
    #[serde(default)]
    api: Option<f64>,
    #[serde(default)]
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
    start_line: u32,
    end_line: u32,
    #[serde(default)]
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
    members: Vec<Member>,
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
pub fn from_report_json(json: &str) -> Result<(DetectionResult, u32), Error> {
    let report: ScanReport = serde_json::from_str(json)?;
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

    Ok((
        DetectionResult {
            schema_version: crate::schema::SCHEMA_VERSION,
            language: language_of(&report.summary.files),
            findings: strip(findings),
            withheld: strip(withheld),
        },
        report.summary.lines,
    ))
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
                    tokens: member.tokens,
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
      "schema_version": 2,
      "run": {"id": 1},
      "summary": {
        "files": {"total": 2, "rust": 2, "c": 0, "cpp": 0},
        "lines": 240,
        "groups": {"total": 2}
      },
      "groups": [
        {
          "fingerprint": "abc",
          "clone_type": "type-2",
          "scope": "unit",
          "priority": {"value": 0.62, "inputs": {"largest_member_tokens": 120}},
          "similarity": {"composite": 0.91, "confidence_band": "high"},
          "suppressed": null,
          "members": [
            {"finding_id": "m1", "file": "a.rs", "start_line": 10, "end_line": 24},
            {"finding_id": "m2", "file": "b.rs", "start_line": 5, "end_line": 19}
          ]
        },
        {
          "fingerprint": "def",
          "clone_type": "type-1",
          "scope": "unit",
          "priority": {"value": 0.41, "inputs": {"largest_member_tokens": 90}},
          "suppressed": {"kind": "rule", "detail": "path"},
          "members": [
            {"finding_id": "m3", "file": "c.rs", "start_line": 1, "end_line": 4}
          ]
        }
      ]
    }"#;

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
                    tokens: 0,
                },
                Fragment {
                    file: "b.rs".to_string(),
                    start_line: 5,
                    end_line: 19,
                    tokens: 0,
                },
            ]
        );
    }

    #[test]
    fn a_finding_the_detector_never_scored_carries_no_band() {
        // Split pairs and fragment runs reach the report without a similarity
        // breakdown. Reading them as an absent band rather than as a failure
        // is what lets the band table account for every judged finding.
        let unscored = REPORT.replace(
            r#""similarity": {"composite": 0.91, "confidence_band": "high"},"#,
            "",
        );
        let (result, _lines) = from_report_json(&unscored).expect("report reads");
        assert_eq!(result.findings[0].band, None);
    }

    #[test]
    fn a_report_of_another_version_is_refused_rather_than_guessed_at() {
        // The failure this rejects is the one that costs the most: a report
        // whose shape moved on, read as though it had not, quietly scoring
        // whatever still happened to parse.
        let moved_on = REPORT.replace("\"schema_version\": 2", "\"schema_version\": 3");
        let error = from_report_json(&moved_on).expect_err("a later version is refused");
        assert!(matches!(error, Error::Version { found: 3 }));
    }

    #[test]
    fn a_document_that_is_not_a_report_is_a_parse_error() {
        let error = from_report_json("{\"schema_version\": 2}").expect_err("no summary");
        assert!(matches!(error, Error::Parse(_)));
    }

    #[test]
    fn a_group_the_report_files_below_the_rest_is_read_as_one() {
        for (field, value) in [
            ("\"suppressed\": null,", "\"split_pair\": true,"),
            ("\"suppressed\": null,", "\"test_code\": true,"),
            (
                "\"suppressed\": null,",
                "\"boilerplate\": \"macro-repetition\",",
            ),
        ] {
            let filed = REPORT.replacen(field, value, 1);
            let (result, _lines) = from_report_json(&filed).expect("report reads");
            assert!(
                !result.findings[0].actionable,
                "a group carrying {value} was read as one the report puts forward"
            );
        }
        // And a group carrying none of the three is put forward. Without this
        // the three above would pass on a reader that always answered no.
        let (result, _lines) = from_report_json(REPORT).expect("report reads");
        assert!(result.findings[0].actionable);
    }

    /// The fold this module reads is the one the report drew.
    ///
    /// [`put_forward`] restates the default policy, so it can disagree with
    /// the report that applied it. The report cannot be asked where its fold
    /// is, but it sorts by it — everything it puts forward comes first — so a
    /// disagreement shows up as a finding read as filed-below sitting above
    /// one read as put-forward.
    #[test]
    fn the_fold_this_reads_is_where_the_report_put_it() {
        let ordered = REPORT.replacen(
            "\"suppressed\": {\"kind\": \"rule\", \"detail\": \"path\"},",
            "\"suppressed\": null, \"split_pair\": true,",
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
