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
//! # Auxiliary semantic evidence
//!
//! [`EffectSummary`] reports only closed, compiler-confirmed resource
//! interactions. Its empty list is never a purity claim. [`DataFlowSummary`]
//! records only bounded compiler-confirmed operation flows; absent evidence
//! never changes which semantic findings exist.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The compiler-IR schema identifier.
///
/// The product has not been released, so the complete current shape is the
/// only supported wire contract.
pub const COMPILER_IR_SCHEMA_VERSION: &str = "compiler-ir-v1";

/// A half-open byte range in one file, with the line its start falls on.
///
/// Byte offsets rather than lines alone: a line number cannot say where inside
/// a line something begins, and clone fragments regularly do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    /// Path as the analysis spells it — see [`CompilerIr::anchored_at`] for
    /// what it is spelled against.
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

impl TypeCategory {
    /// Stable lowercase identifier, the same spelling this serializes as.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Character => "character",
            Self::Text => "text",
            Self::Handle => "handle",
            Self::Sequence => "sequence",
            Self::Mapping => "mapping",
            Self::Tuple => "tuple",
            Self::Record => "record",
            Self::Enumeration => "enumeration",
            Self::Interface => "interface",
            Self::Callable => "callable",
            Self::Parameter => "parameter",
            Self::Nothing => "nothing",
            Self::Unresolved => "unresolved",
        }
    }
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
    /// A compiler fact that has no more specific symbol category.
    Other,
}

impl SymbolKind {
    /// Stable lowercase identifier, the same spelling this serializes as.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Type => "type",
            Self::Field => "field",
            Self::Variant => "variant",
            Self::Binding => "binding",
            Self::Constant => "constant",
            Self::Namespace => "namespace",
            Self::Other => "other",
        }
    }
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
    /// A compiler-confirmed standard-library API name, when the helper can
    /// establish it without deriving it from the stable target identifier.
    ///
    /// `None` for calls outside the deliberately small API vocabulary used by
    /// restricted semantic rules.
    pub api_name: Option<String>,
}

/// One compiler-confirmed construct that a restricted semantic rule may
/// normalize without reconstructing syntax in the analysis process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticConstruct {
    /// Where the construct occurs, preserving macro expansion provenance.
    pub anchor: Anchor,
    /// The closed meaning the helper established for this construct.
    pub kind: SemanticConstructKind,
    /// The standard fallible container the compiler resolved, when this
    /// construct operates on one.
    ///
    /// `None` when the construct does not operate on a fallible container.
    pub fallible_kind: Option<FallibleKind>,
    /// A closed form that makes this propagation directly comparable to a
    /// different spelling without general equivalence reasoning.
    pub direct_propagation: Option<DirectPropagation>,
    /// Closed resource category for a compiler-confirmed acquire or release.
    /// It is absent for every other construct.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<String>,
}

/// A standard library fallible container established by the compiler.
///
/// This is deliberately narrower than a general algebraic-data-type category:
/// registered rules must not treat a project enum with similarly named arms as
/// a `Result` or `Option`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallibleKind {
    /// `core::option::Option` or its standard-library re-export.
    Option,
    /// `core::result::Result` or its standard-library re-export.
    Result,
}

impl FallibleKind {
    /// Stable storage spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Option => "option",
            Self::Result => "result",
        }
    }

    /// Parse the stable storage spelling.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "option" => Some(Self::Option),
            "result" => Some(Self::Result),
            _ => None,
        }
    }
}

/// A compiler-confirmed direct spelling of a fallible propagation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectPropagation {
    /// `Ok(value?)` or an identity `Result` match.
    ResultAdapter,
    /// `Some(value?)` or an identity `Option` match.
    OptionAdapter,
}

impl DirectPropagation {
    /// Stable storage spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ResultAdapter => "result_adapter",
            Self::OptionAdapter => "option_adapter",
        }
    }

    /// Parse the stable storage spelling.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "result_adapter" => Some(Self::ResultAdapter),
            "option_adapter" => Some(Self::OptionAdapter),
            _ => None,
        }
    }
}

/// Closed semantic constructs that compiler helpers may report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConstructKind {
    /// A compiler-verified sequence consumed by a restricted explicit loop.
    Source,
    /// A compiler-verified explicit loop materialized one element per iteration.
    Collect,
    /// A compiler-verified explicit loop accumulated every sequence element.
    Reduce,
    /// Rust `?` propagated an error-like value to the surrounding caller.
    PropagateError,
    /// Rust selected a branch after checking a fallible or optional value.
    Validate,
    /// A compiler-confirmed standard operation acquired a tracked resource.
    AcquireResource,
    /// A lexical scope ended and released a tracked resource.
    ReleaseResource,
}

impl SemanticConstructKind {
    /// Stable storage spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Collect => "collect",
            Self::Reduce => "reduce",
            Self::PropagateError => "propagate_error",
            Self::Validate => "validate",
            Self::AcquireResource => "acquire_resource",
            Self::ReleaseResource => "release_resource",
        }
    }

    /// Parse the stable storage spelling.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "source" => Some(Self::Source),
            "collect" => Some(Self::Collect),
            "reduce" => Some(Self::Reduce),
            "propagate_error" => Some(Self::PropagateError),
            "validate" => Some(Self::Validate),
            "acquire_resource" => Some(Self::AcquireResource),
            "release_resource" => Some(Self::ReleaseResource),
            _ => None,
        }
    }
}

/// The type the compiler resolved for an expression with no physical source
/// token of its own, such as the body a declarative macro generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedExpression {
    /// Where the expression is observable and where it was written.
    pub anchor: Anchor,
    /// Its entry in [`CompilerIr::types`].
    pub type_index: u32,
}

/// A macro invocation the helper deliberately did not expand.
///
/// This is coverage information, not a failed unit. A procedural macro can
/// leave the surrounding crate meaningful while its generated declarations
/// remain unavailable; recording the invocation prevents that thin answer
/// from reading as a complete one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnexpandedMacro {
    /// The invocation written in the analysed source.
    pub invocation: SourceRange,
    /// Why its expansion is absent.
    pub reason: UnexpandedMacroReason,
}

/// Why an individual macro invocation was not expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnexpandedMacroReason {
    /// Expanding the invocation would execute a procedural macro.
    RequiresExecution,
    /// The analysis engine could not resolve the invocation to a macro.
    Unresolved,
    /// A declarative macro was known but its expansion was unavailable.
    ExpansionUnavailable,
}

impl UnexpandedMacroReason {
    /// Stable spelling for storage and reporting.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RequiresExecution => "requires_execution",
            Self::Unresolved => "unresolved",
            Self::ExpansionUnavailable => "expansion_unavailable",
        }
    }

    /// Parse the stable storage spelling.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "requires_execution" => Some(Self::RequiresExecution),
            "unresolved" => Some(Self::Unresolved),
            "expansion_unavailable" => Some(Self::ExpansionUnavailable),
            _ => None,
        }
    }
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

impl EdgeKind {
    /// Stable lowercase identifier, the same spelling this serializes as.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Taken => "taken",
            Self::NotTaken => "not_taken",
            Self::Unwind => "unwind",
            Self::Return => "return",
        }
    }
}

/// Where an instantiated body came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instantiation {
    /// Where the instantiated code sits.
    pub anchor: Anchor,
    /// The generic or template it was instantiated from.
    pub definition: String,
    /// One-based final line of the generic or template definition when the
    /// compiler reported a complete source range.
    ///
    /// This is a source anchor used to contain nested members of a class
    /// template during artifact correlation. It is not an identity.
    pub definition_end_line: Option<u32>,
    /// Optional compiler-produced spelling used only to correlate a source
    /// specialization with a demangled artifact symbol.
    ///
    /// This is comparison evidence, not a stable identity or a replacement
    /// for [`Self::definition`] or [`Self::instantiation_key`].
    pub artifact_match_key: Option<String>,
    /// What groups every instantiation of that definition together.
    ///
    /// Two bodies with the same key are the same source text with different
    /// substitutions — one thing written once, not two things that agree.
    pub instantiation_key: String,
    /// The type arguments substituted, as indices into [`CompilerIr::types`].
    pub arguments: Vec<u32>,
}

/// What a unit does beyond computing a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSummary {
    /// Whether the helper attempted this analysis at all.
    ///
    /// Distinguishes "computed, and there are no effects" from "not computed",
    /// which are the same empty summary and very different claims.
    pub computed: bool,
    /// Symbols whose state the unit writes.
    pub writes: Vec<String>,
    /// Closed external interactions observed in the unit.
    ///
    /// An empty list is not a proof that the unit is pure; helpers report only
    /// interactions they can establish from their deliberately narrow
    /// vocabulary.
    pub interactions: Vec<String>,
}

/// How values move through a unit.
///
/// The deliberately small initial vocabulary records only direct, resolved
/// `filter`/`map` receiver chains.  Each endpoint is a helper-local operation
/// reference in the form `start_byte:end_byte:resolved_api_name`; it is not a
/// stable identifier and is meaningful only beside this unit's source and
/// schema version.  This is evidence that one operation's output is the next
/// operation's receiver, not a general data-flow result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowSummary {
    /// Whether the helper attempted this analysis at all.
    pub computed: bool,
    /// Pairs of operation references where the first directly feeds the
    /// second. The references are intentionally local to this compiler IR.
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
    /// The directory the file paths in this analysis are spelled against.
    ///
    /// A helper reports paths the way the project spells them, which is
    /// relative to the root it read the project from — not to whatever
    /// directory a scan was started in. Saying which root that was is what lets
    /// a reader turn a file it knows about into the name this analysis filed it
    /// under. Without it the two spellings can only be compared by hoping they
    /// agree, and comparing on a shared suffix instead would let one file's
    /// answers be counted for another's, since two files can end the same way.
    ///
    /// `None` when the paths stand on their own, which is what an analysis
    /// with no project root to speak of reports.
    ///
    pub anchored_at: Option<String>,
    /// Names resolved to definitions.
    pub symbols: Vec<ResolvedSymbol>,
    /// Types, referred to by index from everything else.
    pub types: Vec<ResolvedType>,
    /// Calls and what they call.
    pub calls: Vec<CallSite>,
    /// Compiler-confirmed constructs available to restricted semantic rules.
    pub semantic_constructs: Vec<SemanticConstruct>,
    /// Expression types whose anchor may cover an invocation rather than one
    /// source token.
    pub expressions: Vec<ResolvedExpression>,
    /// Macro invocations that were not expanded, and why.
    pub unexpanded_macros: Vec<UnexpandedMacro>,
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
            anchored_at: None,
            symbols: Vec::new(),
            types: Vec::new(),
            calls: Vec::new(),
            semantic_constructs: Vec::new(),
            expressions: Vec::new(),
            unexpanded_macros: Vec::new(),
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

    /// How this analysis spells `absolute`, so a caller holding a file can
    /// look up what was said about it.
    #[must_use]
    pub fn spelling(&self, absolute: &Path) -> String {
        spell(self.anchored_at.as_ref().map(Path::new), absolute)
    }
}

/// How a path is spelled against `root`.
///
/// One function for both sides of the wire. A helper writes its anchors with
/// it and a reader looks them up with it, so the two spellings agree because
/// they are the same rule rather than because they were written to match.
///
/// A path outside `root` keeps its own name: made relative it would climb out
/// of the project with `..`, which says less than the path it started as.
///
/// Components are separated by `/` whatever the platform separates them with.
/// This spelling is a value on the wire, in the audit database and in every
/// exported report, so a file has to have one name rather than one per
/// operating system — and Windows opens a path spelled this way as readily as
/// its own.
#[must_use]
pub fn spell(root: Option<&Path>, path: &Path) -> String {
    let relative = root
        .and_then(|root| relative_to(root, path))
        .unwrap_or(path);
    separated_by(&relative.display().to_string(), std::path::MAIN_SEPARATOR)
}

/// Where `path` sits under `root`, if it sits under it at all.
///
/// The two sides of this question are resolved by two different programs, and
/// on Windows resolving a path can produce the *verbatim* form — the `\\?\`
/// spelling that exists so paths the ordinary rules cannot express are still
/// reachable. One side arriving in that form and the other not is a difference
/// in how the two were written down, not in which directory they name, so the
/// prefix is read past on both sides before they are compared.
fn relative_to<'a>(root: &Path, path: &'a Path) -> Option<&'a Path> {
    ordinary(path).strip_prefix(ordinary(root)).ok()
}

/// A Windows verbatim path read as the path it stands for, and anything else
/// unchanged.
fn ordinary(path: &Path) -> &Path {
    path.to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .map_or(path, Path::new)
}

/// Restate a path that was written with `separator` so its components are
/// separated by `/`.
///
/// Takes the separator rather than reading it, so that the rewrite Windows
/// needs can be exercised on any machine. A rule only one operating system can
/// run is a rule only that operating system can find a mistake in.
fn separated_by(displayed: &str, separator: char) -> String {
    if separator == '/' {
        return displayed.to_owned();
    }
    displayed.replace(separator, "/")
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
    /// Cargo cannot resolve dependencies without network access or a lockfile change.
    MetadataUnavailable,
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
    /// The helper produced an IR response over the protocol frame ceiling.
    ResponseTooLarge,
    /// Consecutive helper crashes exhausted the restart budget for this run.
    RestartBudgetExhausted,
    /// The helper does not analyze this kind of input.
    NotSupported,
}

impl Unavailability {
    /// Stable lowercase identifier, the same spelling this serializes as.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RequiresExecution => "requires_execution",
            Self::MetadataUnavailable => "metadata_unavailable",
            Self::NoBuildInformation => "no_build_information",
            Self::ToolchainMismatch => "toolchain_mismatch",
            Self::HelperTimedOut => "helper_timed_out",
            Self::HelperDied => "helper_died",
            Self::UnreadableSchema => "unreadable_schema",
            Self::ResponseTooLarge => "response_too_large",
            Self::RestartBudgetExhausted => "restart_budget_exhausted",
            Self::NotSupported => "not_supported",
        }
    }

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
        ir.schema_version = "compiler-ir-unsupported".into();
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
            Unavailability::MetadataUnavailable,
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
    fn an_unknown_symbol_kind_is_rejected() {
        assert!(serde_json::from_str::<SymbolKind>("\"something_new\"").is_err());
    }

    /// Built the way the platform builds one, so that on Windows the parts are
    /// joined by the separator this rule has to answer for.
    fn native(parts: &[&str]) -> std::path::PathBuf {
        parts.iter().collect()
    }

    /// A file inside the project is named by where it sits in the project,
    /// with the separator every reader of this value expects — and it is the
    /// same string wherever the file was read, because the value travels on
    /// the wire, into the audit database and out into every report.
    #[test]
    fn a_file_under_the_root_is_named_relative_to_it() {
        let root = native(&["home", "project"]);
        let nested = native(&["home", "project", "src", "inner", "mod.rs"]);
        assert_eq!(spell(Some(&root), &nested), "src/inner/mod.rs");
    }

    /// The rewrite Windows depends on, run here whatever this machine is.
    #[test]
    fn a_path_written_with_backslashes_is_named_with_slashes() {
        assert_eq!(separated_by(r"src\inner\mod.rs", '\\'), "src/inner/mod.rs");
        assert_eq!(separated_by(r"C:\home\project", '\\'), "C:/home/project");
        // Already spelled that way, from a caller that wrote it by hand.
        assert_eq!(separated_by("src/lib.rs", '\\'), "src/lib.rs");
        // On a platform whose separator is already the one wanted, a name
        // containing a backslash is a name, not a separator.
        assert_eq!(separated_by(r"src/odd\name.rs", '/'), r"src/odd\name.rs");
    }

    /// The same path written the way Windows writes one it had to reach past
    /// the ordinary rules for. Built from a native path so that the rule can be
    /// exercised on any machine: what is under test is reading past the prefix,
    /// and a prefix nothing here can produce is still a prefix that arrives.
    fn verbatim(path: &Path) -> std::path::PathBuf {
        std::path::PathBuf::from(format!(r"\\?\{}", path.display()))
    }

    /// Two programs resolved these paths, and only one of them need have come
    /// back in the verbatim form for the file to look like it sits somewhere
    /// else entirely.
    #[test]
    fn a_root_and_a_file_written_in_different_forms_still_meet() {
        let root = native(&["home", "project"]);
        let file = native(&["home", "project", "src", "lib.rs"]);
        let expected = native(&["src", "lib.rs"]);
        for (root, file) in [
            (root.clone(), verbatim(&file)),
            (verbatim(&root), file.clone()),
            (verbatim(&root), verbatim(&file)),
            (root.clone(), file.clone()),
        ] {
            assert_eq!(
                relative_to(&root, &file),
                Some(expected.as_path()),
                "{} under {}",
                file.display(),
                root.display()
            );
        }
    }

    /// Reading past the prefix is for comparing, not for deciding a file is
    /// somewhere it is not.
    #[test]
    fn reading_past_the_prefix_does_not_put_a_file_under_the_wrong_root() {
        let root = verbatim(&native(&["home", "project"]));
        for elsewhere in [
            native(&["home", "other", "x.rs"]),
            verbatim(&native(&["home", "other", "x.rs"])),
        ] {
            assert_eq!(
                relative_to(&root, &elsewhere),
                None,
                "{}",
                elsewhere.display()
            );
        }
    }

    /// Outside the root there is nothing to be relative to, so the path keeps
    /// its own name rather than climbing out of the project to reach it.
    #[test]
    fn a_file_outside_the_root_keeps_its_own_name() {
        let root = native(&["home", "project"]);
        let elsewhere = native(&["home", "elsewhere", "vendor.rs"]);
        assert_eq!(spell(Some(&root), &elsewhere), "home/elsewhere/vendor.rs");
        assert_eq!(
            spell(None, &elsewhere),
            spell(Some(&root), &elsewhere),
            "an unrooted analysis names the file the same way"
        );
    }

    /// What a caller holding an absolute path looks up, written by the same
    /// rule the helper wrote the anchor with.
    #[test]
    fn a_reader_looks_a_file_up_the_way_the_helper_wrote_it() {
        let root = native(&["home", "project"]);
        let mut ir = CompilerIr::empty(UnitRef {
            unit: "crate".into(),
            file: "src/lib.rs".into(),
            variant: "v1".into(),
        });
        ir.anchored_at = Some(root.display().to_string());
        assert_eq!(
            ir.spelling(&native(&["home", "project", "src", "lib.rs"])),
            "src/lib.rs"
        );
    }
}
