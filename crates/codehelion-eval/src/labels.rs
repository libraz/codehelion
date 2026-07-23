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

use serde::{Deserialize, Serialize};

use crate::schema::{CloneType, Fragment};

/// A positive example: fragments that should be reported as clones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelPair {
    /// Stable label identifier within the corpus (e.g. `cp-001`).
    pub id: String,
    /// Expected clone category for this pair.
    #[serde(rename = "type")]
    pub clone_type: CloneType,
    /// The fragments that form the labelled clone (exactly two).
    pub fragments: Vec<Fragment>,
}

/// A negative example: fragments that must not be reported as clones, such as
/// getter/setter boilerplate or trait-impl scaffolding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonClone {
    /// Stable label identifier within the corpus (e.g. `nc-001`).
    pub id: String,
    /// Why these fragments look similar yet must not count as a clone.
    pub reason: String,
    /// The fragments that must not be reported together (exactly two).
    pub fragments: Vec<Fragment>,
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
}

impl LabelSet {
    /// Parse a [`LabelSet`] from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns the underlying serde error if `json` is not a valid
    /// [`LabelSet`] document.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "schema_version": 0,
      "language": "rust",
      "files": ["seed.rs", "type2.rs"],
      "clone_pairs": [
        {"id":"cp-001","type":"type-2","fragments":[{"file":"seed.rs","start_line":1,"end_line":12},{"file":"type2.rs","start_line":1,"end_line":12}]}
      ],
      "non_clones": [
        {"id":"nc-001","reason":"getter-boilerplate","fragments":[{"file":"seed.rs","start_line":20,"end_line":22},{"file":"type2.rs","start_line":25,"end_line":27}]}
      ]
    }"#;

    #[test]
    fn parses_full_example() {
        let labels = LabelSet::from_json(EXAMPLE).expect("example parses");
        assert_eq!(labels.schema_version, 0);
        assert_eq!(labels.language, "rust");
        assert_eq!(labels.files, vec!["seed.rs", "type2.rs"]);
        assert_eq!(labels.clone_pairs.len(), 1);
        assert_eq!(labels.clone_pairs[0].clone_type, CloneType::Type2);
        assert_eq!(labels.non_clones.len(), 1);
        assert_eq!(labels.non_clones[0].reason, "getter-boilerplate");
    }

    #[test]
    fn non_clones_default_to_empty_when_absent() {
        let json = r#"{
          "schema_version": 0,
          "language": "rust",
          "files": ["seed.rs"],
          "clone_pairs": []
        }"#;
        let labels = LabelSet::from_json(json).expect("parses without non_clones");
        assert!(labels.non_clones.is_empty());
    }
}
