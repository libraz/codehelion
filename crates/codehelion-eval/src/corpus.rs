//! Deterministic synthetic-corpus mutation generator.
//!
//! Derives Type-1/2/3 clone variant source files, and their exact ground-truth
//! labels, from a seed source file plus a declarative mutation spec
//! ([`spec::MutationSpec`]). Besides whole-item clones, a variant can
//! transplant a fragment of one seed item into a different host item
//! ([`spec::TransplantSpec`]), producing fragment-level partial-clone labels.
//! Label line ranges are computed from the edits the
//! generator actually performs, so the emitted
//! [`LabelSet`](crate::labels::LabelSet) can never drift from the
//! variant files. This is a development and CI tool compiled only under the
//! `corpus-gen` feature; it is not part of the shipped `codehelion` CLI.
//!
//! The pieces are:
//!
//! - [`spec`] — the declarative JSON mutation-spec format.
//! - [`lexer`] — a minimal line lexer used for whole-token identifier and
//!   literal substitution.
//! - [`scan`] — a brace-depth scanner that locates function, struct and impl
//!   items in the seed.
//! - [`generate`] — variant emission, provenance-based range computation and
//!   label assembly.
//!
//! Determinism is a hard requirement: no randomness, no time, no hash-order
//! iteration. Running the generator twice over the same inputs produces
//! byte-identical output.

pub mod generate;
pub mod lexer;
pub mod scan;
pub mod spec;

use std::fmt;

/// Schema version of the mutation-spec documents this generator accepts.
pub const SPEC_SCHEMA_VERSION: u32 = 0;

/// Schema version written into generated label documents. Tracks the current
/// [`LabelSet`](crate::labels::LabelSet) format.
pub const LABEL_SCHEMA_VERSION: u32 = 0;

/// File name of the generated label document.
pub const LABELS_FILE: &str = "labels.json";

/// Errors produced while generating a corpus from a mutation spec.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The spec declares a schema version this generator does not understand.
    UnsupportedSchemaVersion(u32),
    /// The spec declares a language the scanner has no header syntax for.
    UnsupportedLanguage {
        /// The spec's `language` value.
        language: String,
    },
    /// The scanner found two seed items with the same key, so references to
    /// that key would be ambiguous.
    DuplicateItem {
        /// The colliding item key.
        key: String,
    },
    /// Two outputs (variant files or the label document) share a file name.
    DuplicateFile {
        /// The colliding output file name.
        file: String,
    },
    /// A variant references a seed item that the scanner did not find at the
    /// top level.
    UnknownItem {
        /// Variant file being generated.
        variant: String,
        /// The unresolved item key.
        item: String,
    },
    /// The variant declares a clone type the generator cannot produce.
    UnsupportedCloneType {
        /// Variant file being generated.
        variant: String,
    },
    /// An edit or substitution is not allowed for the item's clone type, or
    /// cannot be applied to the item's current lines.
    DisallowedEdit {
        /// Variant file being generated.
        variant: String,
        /// Item being mutated.
        item: String,
        /// Why the edit is rejected.
        reason: String,
    },
    /// An edit anchor matched no line of the item being mutated.
    AnchorNotFound {
        /// Variant file being generated.
        variant: String,
        /// Item being mutated.
        item: String,
        /// The anchor text that did not match.
        anchor: String,
    },
    /// An edit anchor matched more than one line of the item being mutated.
    AmbiguousAnchor {
        /// Variant file being generated.
        variant: String,
        /// Item being mutated.
        item: String,
        /// The anchor text that matched several lines.
        anchor: String,
    },
    /// A non-clone label references an unknown variant file or seed function.
    UnknownNonCloneRef {
        /// The unresolved reference (variant file or function key).
        reference: String,
    },
    /// A labelled region has no surviving lines in the variant, so no range
    /// can be computed for it.
    EmptyRange {
        /// Variant file being generated.
        variant: String,
        /// The region whose mapping is empty.
        item: String,
    },
    /// Serializing the generated label document failed.
    Serialize(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    f,
                    "unsupported spec schema_version {version} (expected {SPEC_SCHEMA_VERSION})"
                )
            }
            Self::UnsupportedLanguage { language } => {
                write!(
                    f,
                    "unsupported language `{language}` (expected rust, c or cpp)"
                )
            }
            Self::DuplicateItem { key } => write!(f, "duplicate seed item key `{key}`"),
            Self::DuplicateFile { file } => write!(f, "duplicate output file name `{file}`"),
            Self::UnknownItem { variant, item } => {
                write!(f, "{variant}: unknown top-level seed item `{item}`")
            }
            Self::UnsupportedCloneType { variant } => {
                write!(f, "{variant}: clone type must be type-1, type-2 or type-3")
            }
            Self::DisallowedEdit {
                variant,
                item,
                reason,
            } => write!(f, "{variant}: `{item}`: {reason}"),
            Self::AnchorNotFound {
                variant,
                item,
                anchor,
            } => write!(f, "{variant}: `{item}`: anchor `{anchor}` matched no line"),
            Self::AmbiguousAnchor {
                variant,
                item,
                anchor,
            } => write!(
                f,
                "{variant}: `{item}`: anchor `{anchor}` matched more than one line"
            ),
            Self::UnknownNonCloneRef { reference } => {
                write!(f, "non-clone label references unknown `{reference}`")
            }
            Self::EmptyRange { variant, item } => {
                write!(
                    f,
                    "{variant}: `{item}` has no surviving lines in the variant"
                )
            }
            Self::Serialize(source) => write!(f, "serializing labels failed: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialize(source) => Some(source),
            _ => None,
        }
    }
}
