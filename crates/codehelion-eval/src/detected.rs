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

use crate::schema::{CloneType, DetectionResult, Finding, Fragment};

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
    members: Vec<Member>,
}

#[derive(Debug, Deserialize)]
struct Similarity {
    #[serde(default)]
    confidence_band: Option<String>,
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

    let findings = report
        .groups
        .iter()
        // A suppressed group is not something the report puts in front of
        // anyone, so scoring it would credit or blame the tool for a finding
        // it withheld.
        .filter(|group| group.suppressed.is_none())
        .map(|group| Finding {
            id: group.fingerprint.clone(),
            clone_type: group.clone_type,
            // The ranking the tool would show, which is what precision@k is a
            // statement about. The metrics read it for order alone.
            score: group.priority.value,
            size_tokens: group.priority.inputs.largest_member_tokens,
            band: group
                .similarity
                .as_ref()
                .and_then(|similarity| similarity.confidence_band.clone()),
            fragments: group
                .members
                .iter()
                .map(|member| Fragment {
                    file: member.file.clone(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                })
                .collect(),
        })
        .collect();

    Ok((
        DetectionResult {
            schema_version: crate::schema::SCHEMA_VERSION,
            language: language_of(&report.summary.files),
            findings,
        },
        report.summary.lines,
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
                },
                Fragment {
                    file: "b.rs".to_string(),
                    start_line: 5,
                    end_line: 19,
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
    fn a_corpus_of_more_than_one_language_says_so() {
        let mixed = REPORT.replace("\"c\": 0", "\"c\": 3");
        let (result, _) = from_report_json(&mixed).expect("report reads");
        assert_eq!(result.language, "mixed");
    }
}
