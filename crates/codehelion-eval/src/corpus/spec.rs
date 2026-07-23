//! Declarative mutation-spec format.
//!
//! A [`MutationSpec`] describes, in JSON, how to derive every variant file of
//! a synthetic corpus from one seed source file. The generator reads the spec,
//! applies the declared mutations, and emits both the variant sources and a
//! label document whose line ranges are computed from the edits actually
//! performed.
//!
//! See [`MutationSpec`] for the full document layout and an example.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::schema::CloneType;

/// Top-level mutation-spec document.
///
/// # Format
///
/// ```json
/// {
///   "schema_version": 0,
///   "language": "rust",
///   "seed": "seed.rs",
///   "variants": [
///     {
///       "file": "type2.rs",
///       "type": "type-2",
///       "header_comment": "Type-2 variant of seed.rs.",
///       "items": [
///         {
///           "item": "fn sum_even",
///           "labelled": true,
///           "rename": { "values": "items" },
///           "literals": { "0": "1" }
///         }
///       ]
///     }
///   ],
///   "non_clones": [
///     { "reason": "getter-boilerplate", "function": "fn value", "variant": "type2.rs" }
///   ]
/// }
/// ```
///
/// - `seed` is resolved relative to the spec file's directory.
/// - Each variant lists, in output order, the seed items it carries; the
///   generator emits the variant's `header_comment`, a generated-file marker
///   comment, and then each item separated by one blank line.
/// - Item keys are the scanner's keys: the item keyword plus its name, e.g.
///   `fn sum_even`, `struct Counter`, `impl Counter`. C/C++ functions use the
///   same `fn <name>` scheme, and C++ classes are keyed `class <Name>` (see
///   [`scan`](crate::corpus::scan)).
/// - Every item marked `labelled` produces one `clone_pair` linking the
///   item's range in the seed to its computed range in the variant.
/// - `non_clones` are carried into the label document with recomputed ranges;
///   `function` may name a nested function (a method inside an `impl` block).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationSpec {
    /// Schema version of this spec document.
    pub schema_version: u32,
    /// Source language of the seed (`rust` | `c` | `cpp`), copied into the
    /// generated label document.
    pub language: String,
    /// Seed source file, relative to the spec file's directory.
    pub seed: String,
    /// The variant files to derive, in output order.
    pub variants: Vec<VariantSpec>,
    /// Deliberate non-clones to carry into the label document.
    #[serde(default)]
    pub non_clones: Vec<NonCloneSpec>,
}

impl MutationSpec {
    /// Parse a [`MutationSpec`] from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns the underlying serde error if `json` is not a valid
    /// [`MutationSpec`] document.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// One derived variant file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariantSpec {
    /// Output file name, relative to the output directory.
    pub file: String,
    /// Default clone type of this variant's labelled items. Individual items
    /// may override it with [`ItemSpec::clone_type`]. Must be `type-1`,
    /// `type-2` or `type-3`.
    #[serde(rename = "type")]
    pub clone_type: CloneType,
    /// Comment text emitted as the variant's first line (without `// `).
    pub header_comment: String,
    /// Seed items to carry into this variant, in output order.
    pub items: Vec<ItemSpec>,
}

/// One seed item carried into a variant, with its mutations.
///
/// The allowed mutations depend on the item's effective clone type:
///
/// - **type-1** — whitespace/comment edits only ([`EditOp::CommentBefore`],
///   [`EditOp::CommentAfter`], [`EditOp::BlankAfter`],
///   [`EditOp::RemoveBlankAfter`], [`EditOp::Reindent`]); the token stream is
///   unchanged. `rename` and `literals` must be empty.
/// - **type-2** — additionally `rename` (whole-identifier substitution) and
///   `literals` (whole-literal substitution). Line structure is preserved, so
///   ranges map line-for-line.
/// - **type-3** — additionally statement-level [`EditOp::InsertAfter`],
///   [`EditOp::InsertBefore`] and [`EditOp::Delete`], plus fragment
///   [`transplants`](Self::transplants), with an optional
///   [`target_change_rate`](Self::target_change_rate) that the generator
///   compares against the achieved rate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSpec {
    /// Key of the top-level seed item to carry, e.g. `fn sum_even`.
    pub item: String,
    /// Whether this item produces a labelled `clone_pair`.
    #[serde(default)]
    pub labelled: bool,
    /// Clone type override for this item; defaults to the variant's type.
    /// Useful for an unmutated item copied into a variant, which is a
    /// `type-1` clone regardless of the variant's default.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub clone_type: Option<CloneType>,
    /// Whole-identifier substitution map (old identifier to new identifier).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
    /// Whole-literal substitution map (old literal token to new literal
    /// token). Keys match the literal's exact source text, e.g. `0` or
    /// `"text"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub literals: BTreeMap<String, String>,
    /// Fragments transplanted from donor seed items into this item, applied
    /// in order after `rename`/`literals` and before `edits`. Inserting a
    /// fragment is a statement-level change, so any transplant requires the
    /// item's effective clone type to be type-3.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transplants: Vec<TransplantSpec>,
    /// Line edits, applied in order after `rename`/`literals` and
    /// `transplants`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edits: Vec<EditOp>,
    /// Declared target statement-change rate for a type-3 item. The generator
    /// reports the achieved rate (statements inserted or deleted, divided by
    /// the seed item's statement count) alongside this target; it never
    /// fabricates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_change_rate: Option<f64>,
}

/// One declarative line edit within an item.
///
/// `anchor` fields match a line of the item by exact comparison against the
/// line's whitespace-trimmed text, and must match exactly one line at the time
/// the edit is applied (edits run in spec order over the already-edited item).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EditOp {
    /// Insert `// {text}` immediately before the item's header line.
    CommentBefore {
        /// Comment text without the leading `// `.
        text: String,
    },
    /// Insert `// {text}` after the anchor line, at the anchor's indentation.
    CommentAfter {
        /// Trimmed text of the line to insert after.
        anchor: String,
        /// Comment text without the leading `// `.
        text: String,
    },
    /// Insert one blank line after the anchor line.
    BlankAfter {
        /// Trimmed text of the line to insert after.
        anchor: String,
    },
    /// Remove the blank line directly after the anchor line.
    RemoveBlankAfter {
        /// Trimmed text of the line whose following blank line is removed.
        anchor: String,
    },
    /// Re-indent every line of the item, replacing each 4-space indentation
    /// level with `unit` spaces.
    Reindent {
        /// Spaces per indentation level in the output.
        unit: u8,
    },
    /// Insert the given lines (verbatim, including their indentation) after
    /// the anchor line.
    InsertAfter {
        /// Trimmed text of the line to insert after.
        anchor: String,
        /// Lines to insert, written exactly as they should appear.
        lines: Vec<String>,
    },
    /// Insert the given lines (verbatim, including their indentation) before
    /// the anchor line.
    InsertBefore {
        /// Trimmed text of the line to insert before.
        anchor: String,
        /// Lines to insert, written exactly as they should appear.
        lines: Vec<String>,
    },
    /// Delete the anchor line.
    Delete {
        /// Trimmed text of the line to delete.
        anchor: String,
    },
}

/// One fragment transplanted from a donor seed item into the host item.
///
/// A transplant copies a contiguous run of a *donor* seed item's lines and
/// inserts it into the item that declares the transplant (the *host*), making
/// the fragment — not the whole item — the cloned region. The generator then
/// emits a fragment-level label pairing the donor fragment's range in the
/// seed with the transplanted fragment's range in the variant.
///
/// # Format
///
/// ```json
/// {
///   "donor": "fn tally_input",
///   "from": "let value = match line.parse::<i64>() {",
///   "to": "};",
///   "after": "for line in rows {",
///   "labelled": true,
///   "type": "type-2",
///   "rename": { "sum": "kept" }
/// }
/// ```
///
/// - `from` and `to` anchor the first and last donor line of the fragment.
///   Like edit anchors, each matches a line by exact comparison against the
///   line's whitespace-trimmed text and must match exactly one line — here
///   within the donor item's seed lines, before any mutation. The fragment
///   must be brace-balanced.
/// - `after` anchors the host line to insert the fragment after, matched
///   against the host item's lines at the time the transplant is applied
///   (after the host's `rename`/`literals` and any earlier transplants).
/// - The donor lines are inserted verbatim, keeping their seed indentation,
///   after `rename`/`literals` — the transplant's own maps, independent of
///   the host's — are applied. A verbatim fragment is a type-1 partial clone;
///   a substituted one is type-2.
/// - `labelled` emits a `clone_pair` whose type is `type` (defaulting to the
///   variant's type, like [`ItemSpec::clone_type`]); a labelled transplant
///   must be type-1 or type-2, and type-1 forbids `rename`/`literals`.
/// - `non_clone` instead emits a `non_clone` with the given reason, for a
///   recurring boilerplate idiom that must not be reported as a clone. It is
///   mutually exclusive with `labelled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransplantSpec {
    /// Key of the seed item the fragment is taken from, e.g. `fn tally_input`.
    pub donor: String,
    /// Trimmed text of the fragment's first line within the donor item.
    pub from: String,
    /// Trimmed text of the fragment's last line within the donor item.
    pub to: String,
    /// Trimmed text of the host line to insert the fragment after.
    pub after: String,
    /// Whether this transplant produces a labelled `clone_pair`.
    #[serde(default)]
    pub labelled: bool,
    /// Clone type of the emitted `clone_pair`; defaults to the variant's
    /// type. Must be `type-1` or `type-2` when `labelled` is set.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub clone_type: Option<CloneType>,
    /// Whole-identifier substitution applied to the donor lines only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
    /// Whole-literal substitution applied to the donor lines only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub literals: BTreeMap<String, String>,
    /// When set, emit a `non_clone` with this reason instead of a
    /// `clone_pair`: the fragments look similar yet must not count as a
    /// clone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_clone: Option<String>,
}

/// A deliberate non-clone carried into the label document.
///
/// The generator emits one `non_clone` entry whose fragments are the named
/// seed function's range and that function's computed range in the named
/// variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonCloneSpec {
    /// Why the fragments look similar yet must not count as a clone.
    pub reason: String,
    /// Seed function key, e.g. `fn value`; nested functions are allowed.
    pub function: String,
    /// Variant file that carries the counterpart fragment.
    pub variant: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "schema_version": 0,
      "language": "rust",
      "seed": "seed.rs",
      "variants": [
        {
          "file": "type2.rs",
          "type": "type-2",
          "header_comment": "Type-2 variant.",
          "items": [
            {
              "item": "fn sum_even",
              "labelled": true,
              "rename": { "values": "items" },
              "literals": { "0": "1" },
              "edits": [ { "op": "comment_before", "text": "Renamed copy." } ]
            },
            { "item": "fn max_run", "type": "type-1" }
          ]
        }
      ],
      "non_clones": [
        { "reason": "getter-boilerplate", "function": "fn value", "variant": "type2.rs" }
      ]
    }"#;

    #[test]
    fn parses_full_example() {
        let spec = MutationSpec::from_json(EXAMPLE).expect("example parses");
        assert_eq!(spec.schema_version, 0);
        assert_eq!(spec.seed, "seed.rs");
        assert_eq!(spec.variants.len(), 1);
        let variant = &spec.variants[0];
        assert_eq!(variant.clone_type, CloneType::Type2);
        assert_eq!(variant.items.len(), 2);
        assert!(variant.items[0].labelled);
        assert_eq!(variant.items[0].rename["values"], "items");
        assert_eq!(variant.items[0].literals["0"], "1");
        assert_eq!(
            variant.items[0].edits[0],
            EditOp::CommentBefore {
                text: "Renamed copy.".to_string()
            }
        );
        assert_eq!(variant.items[1].clone_type, Some(CloneType::Type1));
        assert_eq!(spec.non_clones.len(), 1);
    }

    #[test]
    fn parses_transplants() {
        let json = r#"{
          "schema_version": 0,
          "language": "rust",
          "seed": "seed.rs",
          "variants": [
            {
              "file": "partial.rs",
              "type": "type-3",
              "header_comment": "Partial-clone variant.",
              "items": [
                {
                  "item": "fn host",
                  "transplants": [
                    {
                      "donor": "fn donor",
                      "from": "let mut total = 0;",
                      "to": "total",
                      "after": "let mut count = 0;",
                      "labelled": true,
                      "type": "type-2",
                      "rename": { "total": "sum" },
                      "literals": { "0": "1" }
                    },
                    {
                      "donor": "fn idiom",
                      "from": "buffer.clear();",
                      "to": "state = 0;",
                      "after": "count",
                      "non_clone": "cleanup-boilerplate"
                    }
                  ]
                }
              ]
            }
          ]
        }"#;
        let spec = MutationSpec::from_json(json).expect("transplant spec parses");
        let transplants = &spec.variants[0].items[0].transplants;
        assert_eq!(transplants.len(), 2);
        assert!(transplants[0].labelled);
        assert_eq!(transplants[0].clone_type, Some(CloneType::Type2));
        assert_eq!(transplants[0].rename["total"], "sum");
        assert_eq!(transplants[0].literals["0"], "1");
        assert!(transplants[0].non_clone.is_none());
        assert!(!transplants[1].labelled);
        assert_eq!(
            transplants[1].non_clone.as_deref(),
            Some("cleanup-boilerplate")
        );
        // Round trip: serializing and re-parsing preserves the spec.
        let json = serde_json::to_string(&spec).unwrap();
        let back = MutationSpec::from_json(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{
          "schema_version": 0,
          "language": "rust",
          "seed": "seed.rs",
          "variants": [],
          "surprise": true
        }"#;
        assert!(MutationSpec::from_json(json).is_err());
    }

    #[test]
    fn edit_ops_round_trip() {
        let ops = vec![
            EditOp::CommentBefore {
                text: "a".to_string(),
            },
            EditOp::CommentAfter {
                anchor: "x;".to_string(),
                text: "b".to_string(),
            },
            EditOp::BlankAfter {
                anchor: "x;".to_string(),
            },
            EditOp::RemoveBlankAfter {
                anchor: "x;".to_string(),
            },
            EditOp::Reindent { unit: 2 },
            EditOp::InsertAfter {
                anchor: "x;".to_string(),
                lines: vec!["    y;".to_string()],
            },
            EditOp::InsertBefore {
                anchor: "x;".to_string(),
                lines: vec!["    y;".to_string()],
            },
            EditOp::Delete {
                anchor: "x;".to_string(),
            },
        ];
        let json = serde_json::to_string(&ops).unwrap();
        let back: Vec<EditOp> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ops);
    }
}
