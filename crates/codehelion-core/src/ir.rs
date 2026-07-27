//! The Syntax IR: a language-neutral structural view of one source file.
//!
//! Structural mode compares code by shape, not just by token content. Each
//! frontend parses a file with its real parser and maps the resulting tree
//! onto this IR: a token stream (the same [`Token`] representation Fast mode
//! uses) plus a tree of [`IrNode`]s whose [`Shape`]s come from a small
//! cross-language vocabulary. Nodes that have no cross-language equivalent
//! keep their native grammar kind instead of being forced into the nearest
//! common shape — a C++ `template_declaration` stays distinguishable from a
//! Rust generic function.
//!
//! Error tolerance follows the frontend contract: a malformed region becomes
//! an [`Shape::Error`] node covering its source range and parsing continues.
//! Consumers that segment the tree into units must search recursively and
//! judge each found node by its own subtree, never by the mere presence of an
//! error ancestor: real parsers wrap large healthy regions in error nodes
//! whose ranges are the union of individually intact children.
//!
//! Macros and templates are not expanded in Fast or Structural mode. The IR
//! records definition sites ([`Shape::MacroDef`]) and invocation sites
//! ([`Shape::MacroCall`]) as ordinary nodes so later phases can attach
//! expansion information without changing this schema.
//!
//! Byte ranges are the only positions stored on nodes; line/column rendering
//! is a reporting concern served by the token stream. No position feeds any
//! stable identifier.
//!
//! # Schema versioning
//!
//! [`IR_SCHEMA_VERSION`] is a fingerprint input. Any change that can alter a
//! comparison result — adding or removing a [`Shape`], changing a shape tag,
//! changing how frontends map native kinds — must bump it, and fingerprints
//! built from different IR schema versions are never considered equal.

use crate::discovery::Language;
use crate::frontend::{Diagnostic, Lexeme, Token};

/// Version of the Syntax IR schema, recorded per file and hashed into every
/// structural fingerprint.
pub const IR_SCHEMA_VERSION: u32 = 1;

/// A half-open byte range into the source text.
///
/// Ordering is by start then end, which is source order: it exists so ranges
/// can be sorted into a deterministic reporting order, and carries no meaning
/// beyond that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteRange {
    /// Byte offset of the range start.
    pub start: usize,
    /// Byte offset one past the range end.
    pub end: usize,
}

impl ByteRange {
    /// Length of the range in bytes; `0` for a malformed range.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `other` lies entirely within this range.
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// The cross-language shape vocabulary.
///
/// Every variant except [`Shape::Native`] means the same thing in all three
/// languages, so structural comparison across files (and, in later phases,
/// across languages) can work on shapes alone. A frontend maps its grammar
/// onto these; whatever does not fit is carried as [`Shape::Native`] with the
/// grammar's own kind name preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// A free function definition.
    Function,
    /// A method definition (function inside an `impl`/class/struct body).
    Method,
    /// A closure or lambda.
    Closure,
    /// A record definition: `struct`, `class`, `union` or `enum`.
    Record,
    /// An implementation or member-definition container (`impl`, class body).
    Impl,
    /// A braced statement block.
    Block,
    /// A loop of any flavour (`for`, `while`, `loop`, do-while).
    Loop,
    /// A two-way conditional (`if`/`else` chain member).
    Branch,
    /// A multi-way conditional (`match`, `switch`).
    Match,
    /// One arm of a multi-way conditional.
    MatchArm,
    /// A function, method or macro-like call expression.
    Call,
    /// An assignment or compound assignment.
    Assign,
    /// A local variable declaration (`let`, C/C++ declaration statement).
    VarDecl,
    /// A `return` (or expression-position tail return).
    Return,
    /// An early loop exit (`break`).
    Break,
    /// A loop continuation (`continue`).
    Continue,
    /// Error propagation or handling (`?` operator, `try`/`catch`).
    Try,
    /// An expression used as a statement, not covered by a finer shape.
    ExprStmt,
    /// A macro or preprocessor definition site.
    MacroDef,
    /// A macro invocation site (not expanded).
    MacroCall,
    /// A region the parser could not interpret. Children may still be intact.
    Error,
    /// A node kept under its native grammar kind because no common shape
    /// applies. The kind name takes part in structural comparison, so two
    /// native nodes match only when their grammars call them the same thing.
    Native(Lexeme),
}

impl Shape {
    /// A stable one-byte tag for this shape, for use as fingerprint input.
    ///
    /// For [`Shape::Native`] the tag alone is not sufficient input: the
    /// native kind name must be hashed alongside it, or all native nodes
    /// would collapse into one shape.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Function => 1,
            Self::Method => 2,
            Self::Closure => 3,
            Self::Record => 4,
            Self::Impl => 5,
            Self::Block => 6,
            Self::Loop => 7,
            Self::Branch => 8,
            Self::Match => 9,
            Self::MatchArm => 10,
            Self::Call => 11,
            Self::Assign => 12,
            Self::VarDecl => 13,
            Self::Return => 14,
            Self::Break => 15,
            Self::Continue => 16,
            Self::Try => 17,
            Self::ExprStmt => 18,
            Self::MacroDef => 19,
            Self::MacroCall => 20,
            Self::Error => 21,
            Self::Native(_) => 22,
        }
    }

    /// Whether this shape opens a lexical scope for alpha renaming.
    ///
    /// This is the structural basis normalization uses to rename identifiers
    /// consistently within — and only within — one scope. The judgement is
    /// syntactic and shared by all three languages: bodies bind, containers
    /// and single statements do not.
    #[must_use]
    pub const fn introduces_scope(&self) -> bool {
        matches!(
            self,
            Self::Function
                | Self::Method
                | Self::Closure
                | Self::Block
                | Self::Loop
                | Self::Branch
                | Self::Match
                | Self::MatchArm
                | Self::Try
        )
    }

    /// Whether nodes of this shape are statements for the purposes of
    /// statement sequences and statement-window fragments.
    #[must_use]
    pub const fn is_statement(&self) -> bool {
        matches!(
            self,
            Self::Loop
                | Self::Branch
                | Self::Match
                | Self::Assign
                | Self::VarDecl
                | Self::Return
                | Self::Break
                | Self::Continue
                | Self::Try
                | Self::ExprStmt
                | Self::MacroCall
        )
    }
}

/// One node of the Syntax IR tree.
///
/// A node covers a contiguous token range (`token_start..token_end` indices
/// into [`SyntaxIrFile::tokens`]) and a contiguous byte range of the source.
/// Children are in source order and lie within their parent's ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrNode {
    /// The node's shape.
    pub shape: Shape,
    /// The declared name, when the frontend can recover one (functions,
    /// methods, records, macro definitions).
    pub name: Option<Lexeme>,
    /// Index of the node's first token in the file's token stream.
    pub token_start: usize,
    /// Index one past the node's last token.
    pub token_end: usize,
    /// Source bytes the node covers.
    pub range: ByteRange,
    /// Child nodes in source order.
    pub children: Vec<Self>,
}

impl IrNode {
    /// Number of tokens the node covers; `0` for a malformed range.
    #[must_use]
    pub const fn token_len(&self) -> usize {
        self.token_end.saturating_sub(self.token_start)
    }

    /// Depth-first pre-order traversal over this node and its descendants.
    pub fn walk(&self, visit: &mut impl FnMut(&Self)) {
        visit(self);
        for child in &self.children {
            child.walk(visit);
        }
    }

    /// The sequence of statement children, summarised.
    ///
    /// This is the per-block statement sequence view of the IR: direct
    /// children whose shapes are statements, in source order, each reduced
    /// to its [`StatementSummary`]. Non-statement children (nested items,
    /// blocks acting as expressions) are skipped, matching how statement
    /// windows are cut.
    ///
    /// [`Shape::Native`] children are included: a native node that is a
    /// direct child of the node being summarised sits in statement position
    /// by construction (C `goto`, a preprocessor conditional inside a
    /// function body), and dropping it would silently shorten the sequence.
    #[must_use]
    pub fn statement_summaries(&self, tokens: &[Token]) -> Vec<StatementSummary> {
        self.children
            .iter()
            .filter(|child| child.shape.is_statement() || matches!(child.shape, Shape::Native(_)))
            .map(|child| StatementSummary::of(child, tokens))
            .collect()
    }
}

/// How many leading tokens a [`StatementSummary`] keeps.
pub const SUMMARY_HEAD_TOKENS: usize = 4;

/// A statement reduced to its shape and the span of its tokens.
///
/// The shape carries the rename-invariant signal that aligns two statement
/// sequences; the span is how the text itself is recovered, for the lexical
/// comparison that decides whether aligned statements are actually copies.
///
/// The span is kept rather than the token texts because a compound statement
/// covers its whole body: cloning the texts would cost a copy of the token
/// stream once per level of nesting, while an index pair costs the same
/// whatever the statement contains. It is a position into one file's stream
/// and nothing more — identity in this tool is content-derived, and no
/// fingerprint reads this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementSummary {
    /// Shape tag of the statement (see [`Shape::tag`]).
    pub shape_tag: u8,
    /// Native kind name when the statement is a [`Shape::Native`] node.
    pub native_kind: Option<Lexeme>,
    /// Index of the statement's first token in its file's stream.
    pub token_start: usize,
    /// Index one past the statement's last token in its file's stream.
    pub token_end: usize,
}

impl StatementSummary {
    /// Summarise one node against its file's token stream.
    #[must_use]
    pub fn of(node: &IrNode, tokens: &[Token]) -> Self {
        let native_kind = match &node.shape {
            Shape::Native(kind) => Some(kind.clone()),
            _ => None,
        };
        let token_end = node.token_end.min(tokens.len());
        Self {
            shape_tag: node.shape.tag(),
            native_kind,
            token_start: node.token_start.min(token_end),
            token_end,
        }
    }

    /// The statement's tokens, resolved against the stream it was summarised
    /// from. Empty for any other stream, since the span would not be its own.
    #[must_use]
    pub fn tokens<'a>(&self, tokens: &'a [Token]) -> &'a [Token] {
        tokens.get(self.token_start..self.token_end).unwrap_or(&[])
    }
}

/// The Syntax IR of one source file.
#[derive(Debug, Clone)]
pub struct SyntaxIrFile {
    /// Language the file was parsed as.
    pub language: Language,
    /// Version tag of the structural frontend that produced this IR; a
    /// fingerprint input alongside [`IR_SCHEMA_VERSION`].
    pub frontend_version: &'static str,
    /// IR schema version this file conforms to.
    pub ir_schema_version: u32,
    /// Tokens in source order, comments and whitespace removed. Same
    /// representation as Fast mode, so token-level normalization is shared.
    pub tokens: Vec<Token>,
    /// Top-level IR nodes in source order.
    pub roots: Vec<IrNode>,
    /// Recoverable lexical problems, as in Fast mode.
    pub diagnostics: Vec<Diagnostic>,
    /// Source regions the parser marked as errors. Overlapping nodes are
    /// still emitted; these ranges only lower confidence downstream.
    pub error_ranges: Vec<ByteRange>,
    /// Whether the file is the body of a module its tree declares test-only.
    ///
    /// Not something a parse can answer: the declaration carrying the marker
    /// is in another file, so this is settled once the whole set is known and
    /// left here for the walk that reads a unit's markers to start from. A
    /// frontend leaves it false. See
    /// [`declared_test_modules`](crate::test_code::declared_test_modules).
    pub test_module: bool,
}

impl SyntaxIrFile {
    /// Depth-first pre-order traversal over every node in the file.
    pub fn walk(&self, visit: &mut impl FnMut(&IrNode)) {
        for root in &self.roots {
            root.walk(visit);
        }
    }

    /// Total number of nodes in the file.
    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut count = 0;
        self.walk(&mut |_| count += 1);
        count
    }

    /// Tokens the parser could not attach to any structure: those inside a
    /// [`Shape::Error`] node that none of its children recovered.
    ///
    /// This is the honest measure of what a parse lost, and
    /// [`error_ranges`](Self::error_ranges) is not. An error-tolerant parser
    /// recovering from one bad construct routinely wraps everything around it
    /// in a single error node: a header whose include guard encloses the file
    /// gets one error region covering every byte of it, with the whole file's
    /// declarations intact inside. Measured over one project's C++ sources,
    /// the error regions covered 13.3% of the bytes while the tokens that
    /// actually failed to parse were 1.82% — the difference is entirely code
    /// the parser did read, sitting inside a region it had to open.
    ///
    /// Nesting is not double-counted: an error node inside another is covered
    /// by its parent's children, so the parent contributes only the gaps
    /// around it and the child contributes its own.
    #[must_use]
    pub fn unaccounted_tokens(&self) -> usize {
        let mut lost = 0;
        self.walk(&mut |node| {
            if matches!(node.shape, Shape::Error) {
                let recovered: usize = node.children.iter().map(IrNode::token_len).sum();
                lost += node.token_len().saturating_sub(recovered);
            }
        });
        lost
    }
}

/// A Structural-mode parser for one language.
///
/// Like the Fast [`Frontend`](crate::frontend::Frontend), a structural
/// frontend never executes, expands or resolves anything in the target code:
/// it parses text and maps the tree. Malformed input degrades to
/// [`Shape::Error`] nodes plus [`SyntaxIrFile::error_ranges`]; it never
/// aborts the file.
pub trait StructuralFrontend {
    /// The language this frontend parses.
    fn language(&self) -> Language;

    /// The frontend's version tag, used as a fingerprint input.
    fn frontend_version(&self) -> &'static str;

    /// Parse `source` into a Syntax IR file.
    fn parse(&self, source: &str) -> SyntaxIrFile;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{SourceSpan, TokenKind};

    fn token(text: &str, start_byte: usize) -> Token {
        Token {
            kind: TokenKind::Identifier,
            text: Lexeme::from(text),
            span: SourceSpan {
                start_byte,
                end_byte: start_byte + text.len(),
                start_line: 1,
                start_column: 1,
            },
        }
    }

    fn node(shape: Shape, token_start: usize, token_end: usize) -> IrNode {
        IrNode {
            shape,
            name: None,
            token_start,
            token_end,
            range: ByteRange {
                start: token_start,
                end: token_end,
            },
            children: Vec::new(),
        }
    }

    #[test]
    fn shape_tags_are_distinct_and_stable() {
        let shapes = [
            Shape::Function,
            Shape::Method,
            Shape::Closure,
            Shape::Record,
            Shape::Impl,
            Shape::Block,
            Shape::Loop,
            Shape::Branch,
            Shape::Match,
            Shape::MatchArm,
            Shape::Call,
            Shape::Assign,
            Shape::VarDecl,
            Shape::Return,
            Shape::Break,
            Shape::Continue,
            Shape::Try,
            Shape::ExprStmt,
            Shape::MacroDef,
            Shape::MacroCall,
            Shape::Error,
            Shape::Native(Lexeme::from("preproc_ifdef")),
        ];
        let mut tags: Vec<u8> = shapes.iter().map(Shape::tag).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), shapes.len(), "shape tags must be distinct");
        // Tag values are part of the fingerprint schema: spot-pin endpoints.
        assert_eq!(Shape::Function.tag(), 1);
        assert_eq!(Shape::Native(Lexeme::from("x")).tag(), 22);
    }

    #[test]
    fn native_nodes_share_a_tag_but_keep_their_kind() {
        let a = Shape::Native(Lexeme::from("preproc_ifdef"));
        let b = Shape::Native(Lexeme::from("using_declaration"));
        assert_eq!(a.tag(), b.tag());
        assert_ne!(a, b, "the kind name still distinguishes native shapes");
    }

    #[test]
    fn scope_and_statement_tables_are_consistent() {
        assert!(Shape::Function.introduces_scope());
        assert!(Shape::Block.introduces_scope());
        assert!(!Shape::Call.introduces_scope());
        assert!(!Shape::Record.introduces_scope());

        assert!(Shape::Return.is_statement());
        assert!(Shape::MacroCall.is_statement());
        assert!(!Shape::Function.is_statement(), "items are not statements");
        assert!(!Shape::Block.is_statement());
    }

    #[test]
    fn byte_range_arithmetic_guards_malformed_input() {
        let range = ByteRange { start: 10, end: 20 };
        assert_eq!(range.len(), 10);
        assert!(!range.is_empty());
        assert!(range.contains(&ByteRange { start: 12, end: 18 }));
        assert!(!range.contains(&ByteRange { start: 5, end: 18 }));

        let malformed = ByteRange { start: 20, end: 10 };
        assert_eq!(malformed.len(), 0);
        assert!(malformed.is_empty());
    }

    #[test]
    fn statement_summaries_take_statement_children_in_order() {
        let tokens: Vec<Token> = ["let", "x", "=", "f", "(", ")", "return", "x"]
            .iter()
            .enumerate()
            .map(|(i, text)| token(text, i * 8))
            .collect();

        let mut block = node(Shape::Block, 0, 8);
        block.children = vec![
            node(Shape::VarDecl, 0, 6),
            node(Shape::Function, 0, 0), // nested item: not a statement
            node(Shape::Return, 6, 8),
        ];

        let summaries = block.statement_summaries(&tokens);
        assert_eq!(summaries.len(), 2);
        assert!(
            summaries.iter().all(|s| s.native_kind.is_none()),
            "no native statements in this block"
        );
        assert_eq!(summaries[0].shape_tag, Shape::VarDecl.tag());
        let text = |summary: &StatementSummary| -> Vec<String> {
            summary
                .tokens(&tokens)
                .iter()
                .map(|token| token.text.as_str().to_string())
                .collect()
        };
        assert_eq!(
            text(&summaries[0]),
            vec!["let", "x", "=", "f", "(", ")"],
            "the span covers the whole statement, not just its head"
        );
        assert_eq!(summaries[1].shape_tag, Shape::Return.tag());
        assert_eq!(text(&summaries[1]), vec!["return", "x"]);
    }

    #[test]
    fn native_children_count_as_statements_in_position() {
        let tokens = vec![token("goto", 0), token("fail", 8)];
        let mut block = node(Shape::Block, 0, 2);
        block.children = vec![IrNode {
            shape: Shape::Native(Lexeme::from("goto_statement")),
            name: None,
            token_start: 0,
            token_end: 2,
            range: ByteRange { start: 0, end: 12 },
            children: Vec::new(),
        }];

        let summaries = block.statement_summaries(&tokens);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].native_kind,
            Some(Lexeme::from("goto_statement"))
        );
    }

    #[test]
    fn summary_of_out_of_bounds_token_range_is_empty_not_panicking() {
        let tokens = vec![token("x", 0)];
        let stray = node(Shape::ExprStmt, 5, 9);
        let summary = StatementSummary::of(&stray, &tokens);
        assert!(summary.tokens(&tokens).is_empty());
    }

    #[test]
    fn walk_visits_every_node_pre_order() {
        let mut root = node(Shape::Function, 0, 10);
        let mut block = node(Shape::Block, 1, 9);
        block.children = vec![node(Shape::Return, 2, 4)];
        root.children = vec![block];

        let file = SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test-v0",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: Vec::new(),
            roots: vec![root],
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            test_module: false,
        };

        let mut seen = Vec::new();
        file.walk(&mut |n| seen.push(n.shape.tag()));
        assert_eq!(
            seen,
            vec![
                Shape::Function.tag(),
                Shape::Block.tag(),
                Shape::Return.tag()
            ]
        );
        assert_eq!(file.node_count(), 3);
    }

    /// A file whose roots are `roots`, for the traversal tests.
    fn file_of(roots: Vec<IrNode>) -> SyntaxIrFile {
        SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test-v0",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: Vec::new(),
            roots,
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            test_module: false,
        }
    }

    #[test]
    fn code_recovered_inside_an_error_node_is_not_counted_as_lost() {
        // The shape an error-tolerant parser actually produces: one error
        // node opened by a construct it could not read, holding everything
        // that followed and parsed cleanly. Counting the node's own extent
        // would call the whole file unreadable.
        let mut wrapper = node(Shape::Error, 0, 100);
        wrapper.children = vec![node(Shape::Function, 3, 60), node(Shape::Function, 60, 100)];
        assert_eq!(
            file_of(vec![wrapper]).unaccounted_tokens(),
            3,
            "only the tokens no child accounts for"
        );
    }

    #[test]
    fn an_error_node_that_recovered_nothing_loses_all_of_it() {
        assert_eq!(
            file_of(vec![node(Shape::Error, 0, 40)]).unaccounted_tokens(),
            40
        );
    }

    #[test]
    fn a_file_the_parser_followed_loses_nothing() {
        let mut function = node(Shape::Function, 0, 20);
        function.children = vec![node(Shape::Block, 4, 20)];
        assert_eq!(file_of(vec![function]).unaccounted_tokens(), 0);
    }

    #[test]
    fn nested_error_nodes_count_their_own_gaps_once() {
        // The inner error is one of the outer's children, so the outer counts
        // only what surrounds it and the inner counts what it failed to
        // recover. Adding both extents would report more than the file holds.
        let mut inner = node(Shape::Error, 40, 60);
        inner.children = vec![node(Shape::Return, 45, 55)];
        let mut outer = node(Shape::Error, 0, 100);
        outer.children = vec![node(Shape::Function, 0, 40), inner];
        assert_eq!(
            file_of(vec![outer]).unaccounted_tokens(),
            40 + 10,
            "the outer's trailing gap plus the inner's own"
        );
    }
}
