//! Detection-result contract shared by every clone-detection prototype.
//!
//! A prototype emits a [`DetectionResult`] as JSON; the harness parses it with
//! serde and scores it against corpus labels. Keeping this contract stable lets
//! prototypes evolve independently while remaining comparable.

use serde::{Deserialize, Serialize};

/// Schema version of the [`DetectionResult`] documents this crate produces.
pub const SCHEMA_VERSION: u32 = 0;

/// An inclusive source line range within a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    /// Source file path, relative to the corpus label file's directory.
    pub file: String,
    /// First line of the range (inclusive, 1-based).
    pub start_line: u32,
    /// Last line of the range (inclusive, 1-based).
    pub end_line: u32,
}

impl Fragment {
    /// Number of lines the fragment spans.
    ///
    /// Returns `0` for a malformed range where `end_line < start_line` rather
    /// than underflowing.
    #[must_use]
    pub const fn line_count(&self) -> u32 {
        if self.end_line >= self.start_line {
            self.end_line - self.start_line + 1
        } else {
            0
        }
    }

    /// Jaccard similarity of the two inclusive line sets, or `0.0` when the
    /// fragments refer to different files.
    ///
    /// Computed as `|A ∩ B| / |A ∪ B|` over line numbers using range
    /// arithmetic, without materializing the line sets. A malformed range
    /// (empty [`line_count`](Self::line_count)) yields `0.0`.
    #[must_use]
    pub fn overlap(&self, other: &Self) -> f64 {
        if self.file != other.file {
            return 0.0;
        }
        let a = f64::from(self.line_count());
        let b = f64::from(other.line_count());
        if a == 0.0 || b == 0.0 {
            return 0.0;
        }
        let inter_start = self.start_line.max(other.start_line);
        let inter_end = self.end_line.min(other.end_line);
        let intersection = if inter_end >= inter_start {
            f64::from(inter_end - inter_start + 1)
        } else {
            0.0
        };
        let union = a + b - intersection;
        if union == 0.0 {
            0.0
        } else {
            intersection / union
        }
    }
}

/// Clone category, following the standard Type-1..3 taxonomy plus a restricted
/// notion of semantic clones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloneType {
    /// Identical up to whitespace and comments.
    #[serde(rename = "type-1")]
    Type1,
    /// Identical up to renamed identifiers and changed literals.
    #[serde(rename = "type-2")]
    Type2,
    /// Type-2 plus small statement-level additions or deletions.
    #[serde(rename = "type-3")]
    Type3,
    /// Behaviourally equivalent within a deliberately limited scope.
    RestrictedSemantic,
}

impl CloneType {
    /// Kebab-case label matching the JSON representation, for display.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Type1 => "type-1",
            Self::Type2 => "type-2",
            Self::Type3 => "type-3",
            Self::RestrictedSemantic => "restricted-semantic",
        }
    }
}

/// A single reported clone: a set of fragments the detector considers mutually
/// cloned, with a confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Detector-assigned identifier. May differ across runs, so it is never
    /// used as a stable identity key.
    pub id: String,
    /// Reported clone category.
    pub clone_type: CloneType,
    /// Detector confidence in `[0.0, 1.0]`; higher is more confident.
    pub score: f64,
    /// Size of the largest fragment, in tokens.
    ///
    /// Carried so a scoring run can compare the detector's own ranking against
    /// the obvious alternative — sort by size — without going back to the
    /// report for it. Zero when the source of the result did not state one.
    #[serde(default)]
    pub size_tokens: u64,
    /// Confidence band the detector put the finding in, when it stated one.
    ///
    /// Carried so a scoring run can say what a band is worth against the
    /// verdicts, which is a different question from what the band measures.
    /// Absent for a finding whose similarity was never scored — a split pair
    /// or a fragment run.
    #[serde(default)]
    pub band: Option<String>,
    /// The fragments this finding relates as clones.
    pub fragments: Vec<Fragment>,
}

/// The full output of one detection run over a set of source files.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Schema version of this document, so the harness can reject or migrate
    /// incompatible inputs.
    pub schema_version: u32,
    /// Source language of the analysed files (`rust` | `c` | `cpp`).
    pub language: String,
    /// Every clone the detector reported.
    pub findings: Vec<Finding>,
}

impl DetectionResult {
    /// Parse a [`DetectionResult`] from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns the underlying serde error if `json` is not a valid
    /// [`DetectionResult`] document.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    /// Serialize this [`DetectionResult`] to a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns the underlying serde error if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "schema_version": 0,
      "language": "rust",
      "findings": [
        { "id": "f-001", "clone_type": "type-2", "score": 0.95,
          "fragments": [
            {"file": "a.rs", "start_line": 10, "end_line": 24},
            {"file": "b.rs", "start_line": 5, "end_line": 19} ] }
      ]
    }"#;

    #[test]
    fn json_round_trip_is_stable() {
        let parsed = DetectionResult::from_json(EXAMPLE).expect("example parses");
        let reserialized = parsed.to_json().expect("serializes");
        let reparsed = DetectionResult::from_json(&reserialized).expect("re-parses");
        assert_eq!(parsed, reparsed);

        assert_eq!(parsed.schema_version, 0);
        assert_eq!(parsed.language, "rust");
        assert_eq!(parsed.findings.len(), 1);
        let finding = &parsed.findings[0];
        assert_eq!(finding.id, "f-001");
        assert_eq!(finding.clone_type, CloneType::Type2);
        assert!((finding.score - 0.95).abs() < 1e-9);
        assert_eq!(finding.fragments.len(), 2);
    }

    #[test]
    fn clone_type_serializes_as_kebab_case() {
        let cases = [
            (CloneType::Type1, "\"type-1\""),
            (CloneType::Type2, "\"type-2\""),
            (CloneType::Type3, "\"type-3\""),
            (CloneType::RestrictedSemantic, "\"restricted-semantic\""),
        ];
        for (value, json) in cases {
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            let back: CloneType = serde_json::from_str(json).unwrap();
            assert_eq!(back, value);
        }
    }

    #[test]
    fn overlap_identical_is_one() {
        let a = Fragment {
            file: "a.rs".to_string(),
            start_line: 10,
            end_line: 20,
        };
        assert!((a.overlap(&a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn overlap_disjoint_is_zero() {
        let a = Fragment {
            file: "a.rs".to_string(),
            start_line: 10,
            end_line: 20,
        };
        let b = Fragment {
            file: "a.rs".to_string(),
            start_line: 30,
            end_line: 40,
        };
        assert!(a.overlap(&b).abs() < 1e-9);
    }

    #[test]
    fn overlap_half_is_known_value() {
        // A = 1..=10 (10 lines), B = 6..=15 (10 lines).
        // Intersection 6..=10 = 5 lines, union = 10 + 10 - 5 = 15. 5/15 = 1/3.
        let a = Fragment {
            file: "a.rs".to_string(),
            start_line: 1,
            end_line: 10,
        };
        let b = Fragment {
            file: "a.rs".to_string(),
            start_line: 6,
            end_line: 15,
        };
        assert!((a.overlap(&b) - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn overlap_different_file_is_zero() {
        let a = Fragment {
            file: "a.rs".to_string(),
            start_line: 10,
            end_line: 20,
        };
        let b = Fragment {
            file: "b.rs".to_string(),
            start_line: 10,
            end_line: 20,
        };
        assert!(a.overlap(&b).abs() < 1e-9);
    }

    #[test]
    fn line_count_guards_malformed_range() {
        let f = Fragment {
            file: "a.rs".to_string(),
            start_line: 20,
            end_line: 10,
        };
        assert_eq!(f.line_count(), 0);
    }
}
