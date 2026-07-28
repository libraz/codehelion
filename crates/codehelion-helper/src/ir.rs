//! What a compiler knows, in the shape both sides agree on.
//!
//! This is the payload the whole process boundary exists to carry: resolved
//! symbols and types, a control-flow graph, what each call actually calls, and
//! where a generic body was instantiated from. A helper produces it with one
//! compiler; the analysis crates consume it without knowing which.
//!
//! # Anchoring, and why expansion is the side that anchors
//!
//! Every node carries an [`Anchor`] rather than a single range, because code
//! that came from a macro or a template has two places and they answer
//! different questions. The *expansion* site is where the code physically sits
//! in the file someone reads, which is the only place a syntax fragment can be
//! cut from — so that is what a node anchors to. The *definition* site is where
//! the text was actually written, and it is kept because it is what tells
//! repetition apart from duplication.
//!
//! The distinction is not academic. A macro invoked twenty times produces
//! twenty identical bodies, and a detector that anchors only at the expansion
//! site reports twenty clones of something nobody wrote twice and nobody can
//! remove — the labelled corpora call that shape something other than
//! duplication, consistently. Keeping the definition site lets a group say "one
//! definition, twenty expansions" instead.
//!
//! # What is declared but not yet filled
//!
//! [`EffectSummary`] and [`DataFlowSummary`] are in the schema and empty in
//! practice. They are here now so that filling them later is an additive change
//! to a version this schema already names, rather than a shape change to one it
//! does not.

use serde::{Deserialize, Serialize};

/// The revision of the compiler-IR shape.
///
/// Recorded beside every stored result: a stored IR whose schema this build
/// cannot read must be recognised as such rather than read as if it were
/// current.
pub const COMPILER_IR_SCHEMA_VERSION: &str = "compiler-ir-v0";

/// A half-open byte range in one file, with the line its start falls on.
///
/// Byte offsets rather than lines alone: a line number cannot say where inside
/// a line something begins, and clone fragments regularly do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    /// Path as the project spells it, relative to the scan root.
    pub file: String,
    /// First byte covered.
    pub start_byte: u64,
    /// One past the last byte covered.
    pub end_byte: u64,
    /// Line the first byte falls on, counting from one.
    pub start_line: u32,
}

/// Where a node is, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Where the code sits in the file being read. Syntax fragments are cut
    /// from here, so this is what a node anchors to.
    pub expansion: SourceRange,
    /// Where the code was written, when that is somewhere else — inside a
    /// macro body, or in the template this instantiation came from.
    ///
    /// `None` for code that is where it was written.
    pub definition: Option<SourceRange>,
}

impl Anchor {
    /// An anchor for code that is where it was written.
    #[must_use]
    pub const fn written_here(range: SourceRange) -> Self {
        Self {
            expansion: range,
            definition: None,
        }
    }

    /// Whether this node was produced somewhere other than where it reads.
    #[must_use]
    pub const fn is_expanded(&self) -> bool {
        self.definition.is_some()
    }
}

/// The normalized kind of a type.
///
/// Deliberately coarse. Two languages do not agree on what a type *is*, and a
/// similarity measure that compares spelled type names compares vocabularies
/// rather than programs. What survives translation is the shape: whether a
/// value is a number, a sequence, a handle to something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeCategory {
    /// Any integer width or signedness.
    Integer,
    /// Any floating-point width.
    Float,
    /// A boolean.
    Boolean,
    /// A character or code point.
    Character,
    /// A string or string slice.
    Text,
    /// A raw pointer or a reference.
    Handle,
    /// A contiguous sequence: array, slice, vector.
    Sequence,
    /// An associative container.
    Mapping,
    /// A fixed heterogeneous group: tuple, pair.
    Tuple,
    /// A record with named fields.
    Record,
    /// A closed set of alternatives.
    Enumeration,
    /// An interface: trait, abstract base, concept.
    Interface,
    /// Something callable: function, method, closure.
    Callable,
    /// A type parameter not yet substituted.
    Parameter,
    /// The absence of a value: unit, void.
    Nothing,
    /// A type the helper could not resolve.
    Unresolved,
}

/// A name the compiler resolved to a definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSymbol {
    /// Stable identity of the definition within this build, as the compiler
    /// spells it — a path, a mangled name, a USR.
    pub id: String,
    /// The name a reader would use.
    pub name: String,
    /// What kind of thing it is.
    pub kind: SymbolKind,
    /// Where the use is, and where the definition was written.
    pub anchor: Anchor,
    /// Its type, as an index into [`CompilerIr::types`].
    pub type_index: Option<u32>,
    /// Whether the definition is outside the code being scanned.
    ///
    /// The difference matters to normalization: a call into a library names an
    /// interface two fragments genuinely share, while a call to a local
    /// function names something one of them happens to have called.
    pub external: bool,
}

/// What kind of definition a symbol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A function, method, or closure.
    Function,
    /// A type definition.
    Type,
    /// A field or member.
    Field,
    /// A variant of an enumeration.
    Variant,
    /// A local binding or parameter.
    Binding,
    /// A constant or static.
    Constant,
    /// A module, namespace, or crate.
    Namespace,
    /// Something this build has no name for.
    #[serde(other)]
    Other,
}

/// A type as the compiler resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedType {
    /// The type as the compiler spells it, for display.
    pub display: String,
    /// Its normalized category.
    pub category: TypeCategory,
    /// Types it is built from: element, key and value, parameters.
    pub arguments: Vec<u32>,
    /// The symbol defining it, when it has one.
    pub definition: Option<String>,
}

/// One call, and what it was found to call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSite {
    /// Where the call is.
    pub anchor: Anchor,
    /// What it calls.
    pub target: CallTarget,
}

/// What a call resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum CallTarget {
    /// Exactly one definition.
    Static {
        /// The symbol called.
        symbol: String,
    },
    /// One of several, chosen at run time.
    ///
    /// Kept as the candidate set rather than collapsed to "dynamic": two calls
    /// that dispatch over the same small set of implementations are doing the
    /// same thing, and that is invisible once the set is thrown away.
    Dynamic {
        /// Every definition the compiler admits as possible.
        candidates: Vec<String>,
    },
    /// The compiler could not say.
    Unresolved,
}

/// A control-flow graph, as the compiler built it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Blocks, in the order the compiler numbered them.
    pub blocks: Vec<BasicBlock>,
    /// Edges between blocks, by index into `blocks`.
    pub edges: Vec<Edge>,
}

/// One straight-line run of a control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Where the block's code sits.
    pub anchor: Anchor,
    /// How many statements or instructions it holds.
    pub length: u32,
}

/// A transfer of control between two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// Index of the block control leaves.
    pub from: u32,
    /// Index of the block control reaches.
    pub to: u32,
    /// Why control moves.
    pub kind: EdgeKind,
}

/// Why control moves along an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Control falls through or jumps unconditionally.
    Flow,
    /// A condition held.
    Taken,
    /// A condition did not hold.
    NotTaken,
    /// Control left by unwinding or an exception.
    Unwind,
    /// Control returned to the caller.
    Return,
}

/// Where an instantiated body came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instantiation {
    /// Where the instantiated code sits.
    pub anchor: Anchor,
    /// The generic or template it was instantiated from.
    pub definition: String,
    /// What groups every instantiation of that definition together.
    ///
    /// Two bodies with the same key are the same source text with different
    /// substitutions — one thing written once, not two things that agree.
    pub instantiation_key: String,
    /// The type arguments substituted, as indices into [`CompilerIr::types`].
    pub arguments: Vec<u32>,
}

/// What a unit does beyond computing a value.
///
/// Declared and empty. Semantic clone detection wants to know whether two
/// bodies that compute the same thing also *do* the same things — write the
/// same state, perform the same I/O — and that analysis is not in this phase.
/// The shape is fixed now so that filling it is an addition rather than a
/// change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSummary {
    /// Whether the helper attempted this analysis at all.
    ///
    /// Distinguishes "computed, and there are no effects" from "not computed",
    /// which are the same empty summary and very different claims.
    pub computed: bool,
    /// Symbols whose state the unit writes.
    #[serde(default)]
    pub writes: Vec<String>,
    /// Kinds of external interaction the unit performs.
    #[serde(default)]
    pub interactions: Vec<String>,
}

/// How values move through a unit.
///
/// Declared and empty, for the same reason as [`EffectSummary`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowSummary {
    /// Whether the helper attempted this analysis at all.
    pub computed: bool,
    /// Pairs of symbol ids where the first flows into the second.
    #[serde(default)]
    pub flows: Vec<(String, String)>,
}

/// Which piece of a project an analysis is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnitRef {
    /// The translation unit or crate, as the build system names it.
    pub unit: String,
    /// The file being analyzed within it.
    ///
    /// A header analyzed from two translation units is two analyses of one
    /// file, which is why the unit is part of the identity and the file alone
    /// is not.
    pub file: String,
    /// The build variant this analysis belongs to.
    pub variant: String,
}

/// Everything one helper found in one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerIr {
    /// The schema this was written against.
    pub schema_version: String,
    /// What it is about.
    pub unit: UnitRef,
    /// Names resolved to definitions.
    pub symbols: Vec<ResolvedSymbol>,
    /// Types, referred to by index from everything else.
    pub types: Vec<ResolvedType>,
    /// Calls and what they call.
    pub calls: Vec<CallSite>,
    /// Control flow, when the helper offers it.
    pub cfg: Option<ControlFlowGraph>,
    /// Generic and template instantiations.
    pub instantiations: Vec<Instantiation>,
    /// What the unit does. Declared, not yet computed.
    pub effects: EffectSummary,
    /// How values move. Declared, not yet computed.
    pub data_flow: DataFlowSummary,
}

impl CompilerIr {
    /// An empty result for `unit`, written against this build's schema.
    #[must_use]
    pub fn empty(unit: UnitRef) -> Self {
        Self {
            schema_version: COMPILER_IR_SCHEMA_VERSION.to_owned(),
            unit,
            symbols: Vec::new(),
            types: Vec::new(),
            calls: Vec::new(),
            cfg: None,
            instantiations: Vec::new(),
            effects: EffectSummary::default(),
            data_flow: DataFlowSummary::default(),
        }
    }

    /// Whether this was written against a schema this build reads.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.schema_version == COMPILER_IR_SCHEMA_VERSION
    }
}

/// Why a unit has no compiler IR.
///
/// A first-class outcome rather than an error: a scan of a real project will
/// have units nobody can analyze — a crate whose build script would have to run,
/// a file no compile command mentions — and reporting less about those is the
/// correct result, not a failed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailability {
    /// Analyzing it would mean running code from the project.
    RequiresExecution,
    /// Nothing says how the file is compiled.
    NoBuildInformation,
    /// The helper was built for a different toolchain than the project uses.
    ToolchainMismatch,
    /// The helper took too long and was given up on.
    HelperTimedOut,
    /// The helper stopped before answering.
    HelperDied,
    /// The helper answered, but not in a schema this build reads.
    UnreadableSchema,
    /// The helper does not analyze this kind of input.
    NotSupported,
}

impl Unavailability {
    /// Whether trying the same unit again could plausibly go differently.
    ///
    /// A helper that died might have died on this input in particular, and
    /// retrying costs one more crash to find out. A helper that says the input
    /// needs execution will say so every time, and retrying is only slower.
    #[must_use]
    pub const fn worth_retrying(self) -> bool {
        matches!(self, Self::HelperTimedOut | Self::HelperDied)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn range(file: &str) -> SourceRange {
        SourceRange {
            file: file.into(),
            start_byte: 10,
            end_byte: 40,
            start_line: 2,
        }
    }

    #[test]
    fn code_written_where_it_reads_has_no_second_place() {
        let anchor = Anchor::written_here(range("src/lib.rs"));
        assert!(!anchor.is_expanded());
    }

    #[test]
    fn expanded_code_keeps_both_places() {
        let anchor = Anchor {
            expansion: range("src/uses.rs"),
            definition: Some(range("src/macros.rs")),
        };
        assert!(anchor.is_expanded());
        // The expansion site is what a fragment can be cut from, so it is the
        // one a node anchors to.
        assert_eq!(anchor.expansion.file, "src/uses.rs");
    }

    #[test]
    fn an_empty_result_still_says_which_schema_it_is() {
        let ir = CompilerIr::empty(UnitRef {
            unit: "crate".into(),
            file: "src/lib.rs".into(),
            variant: "v1".into(),
        });
        assert!(ir.is_readable());
        assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
    }

    #[test]
    fn a_result_from_another_schema_is_not_read_as_if_it_were_current() {
        let mut ir = CompilerIr::empty(UnitRef {
            unit: "crate".into(),
            file: "src/lib.rs".into(),
            variant: "v1".into(),
        });
        ir.schema_version = "compiler-ir-v99".into();
        assert!(!ir.is_readable());
    }

    #[test]
    fn an_empty_summary_says_whether_anyone_looked() {
        let summary = EffectSummary::default();
        assert!(!summary.computed);
        assert!(summary.writes.is_empty());
        // "Nothing was found" and "nothing was attempted" are the same empty
        // list and must not read the same.
        let looked = EffectSummary {
            computed: true,
            ..EffectSummary::default()
        };
        assert_ne!(summary, looked);
    }

    #[test]
    fn only_a_helper_that_broke_is_worth_asking_twice() {
        assert!(Unavailability::HelperDied.worth_retrying());
        assert!(Unavailability::HelperTimedOut.worth_retrying());
        for settled in [
            Unavailability::RequiresExecution,
            Unavailability::NoBuildInformation,
            Unavailability::ToolchainMismatch,
            Unavailability::UnreadableSchema,
            Unavailability::NotSupported,
        ] {
            assert!(!settled.worth_retrying(), "{settled:?}");
        }
    }

    #[test]
    fn a_dynamic_call_keeps_the_candidates_rather_than_the_word_dynamic() {
        let target = CallTarget::Dynamic {
            candidates: vec!["a::run".into(), "b::run".into()],
        };
        let text = serde_json::to_string(&target).unwrap();
        let back: CallTarget = serde_json::from_str(&text).unwrap();
        assert_eq!(back, target);
        assert!(text.contains("a::run") && text.contains("b::run"));
    }

    #[test]
    fn a_symbol_kind_from_a_newer_helper_still_parses() {
        let kind: SymbolKind = serde_json::from_str("\"something_new\"").unwrap();
        assert_eq!(kind, SymbolKind::Other);
    }
}
