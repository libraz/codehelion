//! Corpus ground-truth format.
//!
//! A [`LabelSet`] describes, for a group of source files, both the clone pairs
//! that a detector *should* report (driving recall) and the deliberate
//! non-clones that it *must not* report (driving precision). It is stored as
//! JSON so it can be validated by a script rather than kept as prose tables.
//!
//! Line ranges are evaluation input only. Stable identity in `codehelion` is
//! fingerprint-based, never line- or position-based, so ranges here never feed
//! into any stable ID.

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::schema::{CloneType, Fragment, SiblingBasis};

/// Schema version of [`LabelSet`] documents this crate accepts.
pub const LABEL_SCHEMA_VERSION: u32 = 1;

/// Accepted `non_clones.reason` values.
///
/// These names are a measurement dimension, not free-form annotations: a
/// typo would otherwise silently create a new row in [`crate::metrics::ReasonSplit`].
/// Add a value here and document it in `corpus/README.md` in the same change.
pub const NON_CLONE_REASONS: &[&str] = &[
    "assertion-run",
    "const-overload-pair",
    "declaration-run",
    "different-computation-skeleton",
    "dispatch-table-entry",
    "exhaustive-match-table",
    "field-mapping-boilerplate",
    "forwarding-wrapper",
    "getter-boilerplate",
    "guarded-forwarding",
    "lifecycle-teardown",
    "list-walk-idiom",
    "member-call-run",
    "mirrored-operation",
    "nested-inside-copy",
    "parameterised-dispatch",
    "parse-error-boilerplate",
    "semantic-rule-boundary",
    "single-expression-return",
    "trivial-accessor-pair",
    "trivial-factory",
    "type-dispatch-accessor",
    "type-specialised-variant",
    "unrolled-repetition",
    "validated-setter",
];

/// A positive example: fragments that should be reported as clones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelPair {
    /// Stable label identifier within the corpus (e.g. `cp-001`).
    pub id: String,
    /// Expected clone category for this pair.
    #[serde(rename = "type")]
    pub clone_type: CloneType,
    /// Registered semantic rule expected to produce this pair, when the
    /// label measures a restricted-semantic rule in isolation.
    ///
    /// Ordinary Type-1 through Type-3 labels leave this absent. It remains a
    /// label-side assertion rather than a detector identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The two fragments that form the labelled clone relation.
    #[serde(deserialize_with = "pair_fragments")]
    pub fragments: Vec<Fragment>,
}

/// A negative example: fragments that must not be reported as clones, such as
/// getter/setter boilerplate or trait-impl scaffolding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonClone {
    /// Stable label identifier within the corpus (e.g. `nc-001`).
    pub id: String,
    /// Why these fragments look similar yet must not count as a clone.
    #[serde(deserialize_with = "non_clone_reason")]
    pub reason: String,
    /// Registered semantic rule this deliberate lookalike is intended to
    /// challenge, when it is part of a per-rule measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The two fragments that must not be reported together.
    #[serde(deserialize_with = "pair_fragments")]
    pub fragments: Vec<Fragment>,
}

/// A known incomplete mirror used to measure the supplemental sibling channel.
///
/// The two primary fragments identify the ordinary clone group that owns the
/// mirror.  The sibling fragment is deliberately kept outside that pair: a
/// detector earns this label only when it reports both primary members in one
/// group and separately attaches the sibling occurrence to that group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownSibling {
    /// Stable label identifier within the corpus (e.g. `ks-001`).
    pub id: String,
    /// Candidate channel expected to recover the mirror.
    pub basis: SiblingBasis,
    /// The two primary fragments that establish the owning clone group.
    pub primary_fragments: [Fragment; 2],
    /// The incomplete mirror occurrence expected as a supplemental sibling.
    pub sibling: Fragment,
}

/// Deserialize a controlled-vocabulary negative-label reason.
fn non_clone_reason<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let reason = String::deserialize(deserializer)?;
    if NON_CLONE_REASONS.contains(&reason.as_str()) {
        Ok(reason)
    } else {
        Err(D::Error::custom(format!(
            "unsupported non_clone reason `{reason}`"
        )))
    }
}

/// Ground truth for a set of source files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelSet {
    /// Schema version of this label document.
    pub schema_version: u32,
    /// Source language of the labelled files (`rust` | `c` | `cpp`).
    pub language: String,
    /// Source files this label set refers to, relative to the label file.
    pub files: Vec<String>,
    /// Fragment pairs that should be reported as clones.
    pub clone_pairs: Vec<LabelPair>,
    /// Fragments that must not be reported as clones.
    #[serde(default)]
    pub non_clones: Vec<NonClone>,
    /// Incomplete mirrors whose primary group and sibling are known by the
    /// corpus author. These are scored separately from primary findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_siblings: Vec<KnownSibling>,
}

impl LabelSet {
    /// Parse a [`LabelSet`] from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns the underlying serde error if `json` is not a valid
    /// [`LabelSet`] document or its schema version is unsupported.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        let labels: Self = serde_json::from_str(json)?;
        if labels.schema_version != LABEL_SCHEMA_VERSION {
            return Err(serde_json::Error::custom(format!(
                "unsupported label schema_version {} (expected {LABEL_SCHEMA_VERSION})",
                labels.schema_version
            )));
        }
        Ok(labels)
    }
}

/// Deserialize the fragments of a binary label relation.
///
/// Labels score one relation at a time. Keeping that relation binary makes a
/// partial group finding match precisely the pair it contains instead of
/// relying on an ambiguous all-members convention.
fn pair_fragments<'de, D>(deserializer: D) -> Result<Vec<Fragment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let fragments = Vec::deserialize(deserializer)?;
    if fragments.len() != 2 {
        return Err(D::Error::custom(
            "a label must contain exactly two fragments",
        ));
    }
    Ok(fragments)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "schema_version": 1,
      "language": "rust",
      "files": ["seed.rs", "type2.rs"],
      "clone_pairs": [
        {"id":"cp-001","type":"type-2","fragments":[{"file":"seed.rs","start_line":1,"end_line":12},{"file":"type2.rs","start_line":1,"end_line":12}]}
      ],
          "non_clones": [
            {"id":"nc-001","reason":"getter-boilerplate","fragments":[{"file":"seed.rs","start_line":20,"end_line":22},{"file":"type2.rs","start_line":25,"end_line":27}]}
      ],
      "known_siblings": []
    }"#;

    #[test]
    fn parses_full_example() {
        let labels = LabelSet::from_json(EXAMPLE).expect("example parses");
        assert_eq!(labels.schema_version, 1);
        assert_eq!(labels.language, "rust");
        assert_eq!(labels.files, vec!["seed.rs", "type2.rs"]);
        assert_eq!(labels.clone_pairs.len(), 1);
        assert_eq!(labels.clone_pairs[0].clone_type, CloneType::Type2);
        assert_eq!(labels.non_clones.len(), 1);
        assert_eq!(labels.non_clones[0].reason, "getter-boilerplate");
        assert!(labels.known_siblings.is_empty());
    }

    #[test]
    fn non_clones_default_to_empty_when_absent() {
        let json = r#"{
          "schema_version": 1,
          "language": "rust",
          "files": ["seed.rs"],
          "clone_pairs": []
        }"#;
        let labels = LabelSet::from_json(json).expect("parses without non_clones");
        assert!(labels.non_clones.is_empty());
        assert!(labels.known_siblings.is_empty());
    }

    #[test]
    fn unknown_non_clone_reason_is_rejected_at_import() {
        let json = EXAMPLE.replace("getter-boilerplate", "not-a-controlled-reason");
        let error = LabelSet::from_json(&json).expect_err("unknown reason must not parse");
        assert!(
            error
                .to_string()
                .contains("unsupported non_clone reason `not-a-controlled-reason`")
        );
    }

    #[test]
    fn parse_error_boilerplate_is_a_registered_reason() {
        let json = EXAMPLE.replace("getter-boilerplate", "parse-error-boilerplate");
        let labels = LabelSet::from_json(&json).expect("registered reason parses");
        assert_eq!(labels.non_clones[0].reason, "parse-error-boilerplate");
    }

    #[test]
    fn every_registered_reason_is_documented_in_the_corpus_guide() {
        let guide = include_str!("../../../corpus/README.md");
        for reason in NON_CLONE_REASONS {
            assert!(
                guide.contains(&format!("| `{reason}` |")),
                "{reason} is accepted but absent from corpus/README.md"
            );
        }
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let json = EXAMPLE.replace("\"schema_version\": 1", "\"schema_version\": 2");
        let error = LabelSet::from_json(&json).expect_err("later schema must not parse");
        assert!(
            error
                .to_string()
                .contains("unsupported label schema_version 2")
        );
    }

    #[test]
    fn known_siblings_require_two_primary_fragments_and_a_controlled_basis() {
        let json = r#"{
          "schema_version": 1,
          "language": "cpp",
          "files": ["seed.cpp", "mirror.cpp"],
          "clone_pairs": [],
          "known_siblings": [{
            "id": "ks-001",
            "basis": "signature",
            "primary_fragments": [
              {"file":"seed.cpp","start_line":1,"end_line":2},
              {"file":"seed.cpp","start_line":3,"end_line":4}
            ],
            "sibling": {"file":"mirror.cpp","start_line":1,"end_line":4}
          }]
        }"#;
        let labels = LabelSet::from_json(json).expect("known sibling parses");
        assert_eq!(labels.known_siblings[0].basis, SiblingBasis::Signature);
        assert_eq!(labels.known_siblings[0].primary_fragments.len(), 2);
    }

    #[test]
    fn unknown_known_sibling_basis_is_rejected_at_import() {
        let json = r#"{
          "schema_version": 1,
          "language": "cpp",
          "files": ["seed.cpp"],
          "clone_pairs": [],
          "known_siblings": [{
            "id": "ks-001",
            "basis": "not-a-channel",
            "primary_fragments": [
              {"file":"seed.cpp","start_line":1,"end_line":2},
              {"file":"seed.cpp","start_line":3,"end_line":4}
            ],
            "sibling": {"file":"seed.cpp","start_line":5,"end_line":8}
          }]
        }"#;
        let error = LabelSet::from_json(json).expect_err("unknown basis must not parse");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn a_restricted_semantic_label_can_name_its_registered_rule() {
        let json = r#"{
          "schema_version": 1,
          "language": "mixed",
          "files": ["a.rs", "b.cpp"],
          "clone_pairs": [{
            "id": "cp-001",
            "type": "restricted-semantic",
            "rule_id": "cross-language-sequence-pipeline-v1",
            "fragments": [
              {"file":"a.rs","start_line":1,"end_line":2},
              {"file":"b.cpp","start_line":1,"end_line":2}
            ]
          }]
        }"#;
        let labels = LabelSet::from_json(json).expect("rule-labelled semantic case parses");
        assert_eq!(
            labels.clone_pairs[0].rule_id.as_deref(),
            Some("cross-language-sequence-pipeline-v1")
        );
    }

    #[test]
    fn labels_with_other_than_two_fragments_are_rejected_at_import() {
        let json = r#"{
          "schema_version": 1,
          "language": "rust",
          "files": ["seed.rs"],
          "clone_pairs": [{"id":"cp-001","type":"type-1","fragments":[]}]
        }"#;
        let error = LabelSet::from_json(json).expect_err("empty clone label is invalid");
        assert!(error.to_string().contains("exactly two fragments"));

        let json = r#"{
          "schema_version": 1,
          "language": "rust",
          "files": ["seed.rs", "type2.rs", "type3.rs"],
          "non_clones": [{
            "id":"nc-001",
            "reason":"getter-boilerplate",
            "fragments":[
              {"file":"seed.rs","start_line":1,"end_line":2},
              {"file":"type2.rs","start_line":1,"end_line":2},
              {"file":"type3.rs","start_line":1,"end_line":2}
            ]
          }]
        }"#;
        let error =
            LabelSet::from_json(json).expect_err("three-fragment negative label is invalid");
        assert!(error.to_string().contains("exactly two fragments"));
    }
}
