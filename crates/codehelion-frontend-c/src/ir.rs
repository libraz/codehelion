//! Structural-mode C frontend and the shared C-family CST walking machinery.
//!
//! The file is parsed with the tree-sitter C grammar and the resulting
//! error-tolerant concrete syntax tree is mapped onto the language-neutral
//! [`SyntaxIrFile`]: a comment-free token stream plus a tree of [`IrNode`]s
//! built from structurally meaningful grammar nodes only. Interior expression
//! detail (member accesses, casts, non-assignment binary operators,
//! parentheses) stays token-only under the nearest ancestor node. Statement
//! wrappers add no node of their own when their inner expression already maps
//! to a shape: `f();` is one [`Shape::Call`] node, not an `ExprStmt(Call)`
//! pair.
//!
//! The walking machinery is language-parameterized through [`IrMapping`] and
//! shared with the C++ structural frontend, which layers its own mapping
//! table on top of the C one (`cpp → c → core` is the fixed dependency
//! direction, so the shared code lives here).
//!
//! # Granularity decisions specific to C
//!
//! - `declaration` maps to [`Shape::VarDecl`] uniformly — locals, file-scope
//!   variables and function prototypes alike. C declarations have no lexical
//!   marker separating those roles, and prototype-vs-variable disambiguation
//!   is a semantic judgement Structural mode does not make.
//! - Macro invocations are structurally indistinguishable from
//!   `call_expression` (the grammar has no separate node for them), so they
//!   surface as [`Shape::Call`]; [`Shape::MacroCall`] is never produced.
//! - Preprocessor conditionals (`preproc_if`, `preproc_ifdef`, ...) become
//!   [`Shape::Native`] nodes and both branches stay in the IR unexpanded.
//!   `#include` and other non-defining directives produce tokens only.
//! - Macro replacement text is a single opaque `preproc_arg` leaf in the
//!   grammar; it becomes one [`TokenKind::Unknown`] token.
//!
//! # Degradation
//!
//! Malformed regions become [`Shape::Error`] nodes plus byte ranges in
//! [`SyntaxIrFile::error_ranges`], and parsing never aborts the file. If the
//! parser itself cannot be set up (grammar version mismatch) or returns no
//! tree, the file degrades to an empty token stream and node tree with one
//! error range spanning the whole file.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{
    Lexeme, LexemeInterner, LiteralKind, SourceSpan, Token, TokenKind,
};
use codehelion_core::ir::{
    ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, StructuralFrontend, SyntaxIrFile,
};
use tree_sitter::{Node, Parser};

/// Version tag of this structural frontend, used as a fingerprint input. Bump
/// it whenever a change alters the token stream or the IR tree for unchanged
/// input.
pub const STRUCTURAL_FRONTEND_VERSION: &str = "c-ir-v1";

/// Grammar kinds lexed as one atomic token: the walker emits a single token
/// for the whole node and never descends into its children (escape sequences,
/// raw-string delimiters). `raw_string_literal` is C++-only; listing it here
/// is harmless for C, whose grammar never produces that kind.
const ATOMIC_TOKEN_KINDS: &[&str] = &[
    "string_literal",
    "char_literal",
    "system_lib_string",
    "raw_string_literal",
];

/// Grammar kind of comment nodes, dropped from the token stream entirely.
const COMMENT_KIND: &str = "comment";

/// How one CST node maps onto the IR.
#[derive(Debug, Clone)]
pub enum Mapping {
    /// Emit a node with this shape and recurse into children.
    Emit(Shape),
    /// Emit a [`Shape::Native`] node under this grammar kind name.
    Native(&'static str),
    /// A statement wrapper: unwrap when the inner expression emits a node.
    ExprStmt,
    /// A parser error region: emit [`Shape::Error`] and record its range.
    Error,
    /// No node of its own; children are still visited.
    Transparent,
}

/// The per-language part of a C-family structural frontend.
///
/// The shared walker owns tokenisation, error recovery and IR assembly; an
/// implementation of this trait supplies the language's node-mapping table.
/// The provided methods cover the whole C family — the C++-only grammar kinds
/// they mention never occur in C trees — so implementations rarely override
/// them.
pub trait IrMapping {
    /// Decide how one CST node maps onto the IR. This table is the
    /// granularity contract of a frontend; changing it changes fingerprint
    /// input and requires a frontend-version bump.
    fn classify(&self, node: &Node<'_>) -> Mapping;

    /// Recover the declared name of a node that emits a named shape.
    fn node_name<'s>(&self, node: &Node<'_>, source: &'s str) -> Option<&'s str> {
        c_family_node_name(node, source)
    }

    /// Map one CST leaf onto the shared [`TokenKind`] vocabulary.
    fn token_kind(&self, kind: &str, is_named: bool, text: &str) -> TokenKind {
        classify_token(kind, is_named, text)
    }
}

/// The C node-mapping table, also the fallthrough table of the C++ frontend.
///
/// Everything not listed — type plumbing, patterns and interior expression
/// detail — is transparent: no node, children visited.
#[must_use]
pub fn classify_c(node: &Node<'_>) -> Mapping {
    match node.kind() {
        "function_definition" => Mapping::Emit(Shape::Function),
        "compound_statement" => Mapping::Emit(Shape::Block),
        "for_statement" | "while_statement" | "do_statement" => Mapping::Emit(Shape::Loop),
        // Each `else if` is its own `if_statement` inside the transparent
        // `else_clause`, so a chain nests as Branch nodes without special
        // handling.
        "if_statement" => Mapping::Emit(Shape::Branch),
        "switch_statement" => Mapping::Emit(Shape::Match),
        // `case_statement` covers `case X:` and `default:` alike.
        "case_statement" => Mapping::Emit(Shape::MatchArm),
        "call_expression" => Mapping::Emit(Shape::Call),
        // The grammar folds compound assignment into `assignment_expression`.
        "assignment_expression" => Mapping::Emit(Shape::Assign),
        "declaration" => Mapping::Emit(Shape::VarDecl),
        "return_statement" => Mapping::Emit(Shape::Return),
        "break_statement" => Mapping::Emit(Shape::Break),
        "continue_statement" => Mapping::Emit(Shape::Continue),
        "expression_statement" => Mapping::ExprStmt,
        "preproc_def" | "preproc_function_def" => Mapping::Emit(Shape::MacroDef),
        // `goto` has no cross-language shape; `labeled_statement` stays
        // transparent so the labelled statement itself is still mapped.
        "goto_statement" => Mapping::Native("goto_statement"),
        // Conditional compilation is kept unexpanded: both branches stay in
        // the IR under native nodes.
        "preproc_if" | "preproc_ifdef" | "preproc_else" | "preproc_elif" | "preproc_elifdef" => {
            Mapping::Native(node.kind())
        }
        "struct_specifier" | "union_specifier" | "enum_specifier" => record_mapping(node),
        "ERROR" => Mapping::Error,
        _ => Mapping::Transparent,
    }
}

/// [`Shape::Record`] when a record specifier carries a body; transparent in
/// type-reference position (`struct foo x;` names a type, it defines
/// nothing).
#[must_use]
pub fn record_mapping(node: &Node<'_>) -> Mapping {
    if node.child_by_field_name("body").is_some() {
        Mapping::Emit(Shape::Record)
    } else {
        Mapping::Transparent
    }
}

/// The shared C-family token classification.
///
/// Grammar kind names drive the mapping; anonymous (non-named) tokens are
/// keywords when their kind is purely alphabetic and punctuation otherwise
/// (operators, delimiters, and directive introducers like `#include`). Named
/// leaves outside the known kinds — notably the opaque `preproc_arg`
/// replacement text — classify as [`TokenKind::Unknown`].
#[must_use]
pub fn classify_token(kind: &str, is_named: bool, text: &str) -> TokenKind {
    match kind {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "statement_identifier"
        | "namespace_identifier" => TokenKind::Identifier,
        // Type-naming leaves (`int`, `unsigned long`) and the C++ keyword
        // leaves the grammar exposes as named nodes (`auto`, `this`) are
        // lexically keywords, matching the Fast lexer's classification.
        "primitive_type" | "sized_type_specifier" | "auto" | "this" => TokenKind::Keyword,
        // `null` covers both spellings: `nullptr` is a keyword while `NULL`
        // is a macro identifier, matching the Fast lexer.
        "null" => {
            if text == "nullptr" {
                TokenKind::Keyword
            } else {
                TokenKind::Identifier
            }
        }
        "number_literal" => TokenKind::Literal(number_literal_kind(text)),
        "string_literal" | "system_lib_string" | "raw_string_literal" => {
            TokenKind::Literal(LiteralKind::String)
        }
        "char_literal" => TokenKind::Literal(LiteralKind::Char),
        "true" | "false" => TokenKind::Literal(LiteralKind::Bool),
        _ if !is_named => {
            if !kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
                TokenKind::Keyword
            } else {
                TokenKind::Punctuation
            }
        }
        _ => TokenKind::Unknown,
    }
}

/// Float/integer split for a `number_literal`, mirroring the Fast lexer's
/// rule: a decimal point, a decimal (`e`) or hexadecimal (`p`) exponent, or a
/// float suffix makes it a float.
fn number_literal_kind(text: &str) -> LiteralKind {
    let hex = text.starts_with("0x") || text.starts_with("0X");
    let float = text.contains('.')
        || if hex {
            text.contains(['p', 'P'])
        } else {
            text.contains(['e', 'E']) || text.ends_with(['f', 'F'])
        };
    if float {
        LiteralKind::Float
    } else {
        LiteralKind::Integer
    }
}

/// Recover a declared name where the C-family grammars provide one: the
/// `name` field of record specifiers and macro definitions, or the identifier
/// buried in a function definition's declarator chain.
#[must_use]
pub fn c_family_node_name<'s>(node: &Node<'_>, source: &'s str) -> Option<&'s str> {
    match node.kind() {
        "function_definition" => {
            declarator_identifier(node.child_by_field_name("declarator")?, source)
        }
        "struct_specifier"
        | "union_specifier"
        | "enum_specifier"
        | "class_specifier"
        | "preproc_def"
        | "preproc_function_def" => node_text(&node.child_by_field_name("name")?, source),
        _ => None,
    }
}

/// Strip a declarator down to the declared identifier: through pointer,
/// function, parenthesized and reference declarators, and through the `name`
/// field of C++ qualified identifiers. `None` when no identifier is
/// recoverable.
fn declarator_identifier<'s>(declarator: Node<'_>, source: &'s str) -> Option<&'s str> {
    let mut current = declarator;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "type_identifier" | "operator_name"
            | "destructor_name" => return node_text(&current, source),
            "qualified_identifier" => current = current.child_by_field_name("name")?,
            "pointer_declarator"
            | "function_declarator"
            | "parenthesized_declarator"
            | "reference_declarator" => {
                current = current
                    .child_by_field_name("declarator")
                    .or_else(|| current.named_child(0))?;
            }
            _ => return None,
        }
    }
}

/// The source text a node covers; empty for a malformed range.
fn node_text<'s>(node: &Node<'_>, source: &'s str) -> Option<&'s str> {
    source.get(node.start_byte()..node.end_byte())
}

/// The byte range a CST node covers.
fn node_range(node: &Node<'_>) -> ByteRange {
    ByteRange {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

/// Parse `source` with `grammar` and map the tree onto the IR under
/// `mapping`. This is the shared entry point of the C-family structural
/// frontends.
///
/// When the parser cannot be set up or returns no tree, the result degrades
/// to an empty token stream and node tree with one error range spanning the
/// whole file — the file is never lost, only marked unreadable.
#[must_use]
pub fn parse_to_ir(
    source: &str,
    grammar: &tree_sitter::Language,
    mapping: &dyn IrMapping,
    language: Language,
    frontend_version: &'static str,
) -> SyntaxIrFile {
    let mut parser = Parser::new();
    let tree = if parser.set_language(grammar).is_ok() {
        parser.parse(source, None)
    } else {
        None
    };
    let Some(tree) = tree else {
        return SyntaxIrFile {
            language,
            frontend_version,
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: Vec::new(),
            roots: Vec::new(),
            diagnostics: Vec::new(),
            error_ranges: vec![ByteRange {
                start: 0,
                end: source.len(),
            }],
            test_module: false,
        };
    };

    let root = tree.root_node();
    let mut builder = IrBuilder::new(source, mapping);
    builder.collect_tokens(root);

    let mut roots = Vec::new();
    // The root (`translation_unit`) classifies as transparent, so visiting it
    // fills `roots` with the file's top-level nodes.
    builder.visit(root, &mut roots);

    builder
        .error_ranges
        .sort_unstable_by_key(|range| (range.start, range.end));
    builder.error_ranges.dedup();

    SyntaxIrFile {
        language,
        frontend_version,
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens: builder.tokens,
        roots,
        // Lexical diagnostics are a Fast-lexer concept; the structural
        // frontend reports problems through `error_ranges` only.
        diagnostics: Vec::new(),
        error_ranges: builder.error_ranges,
        test_module: false,
    }
}

/// Accumulates the token stream and IR tree for one file.
struct IrBuilder<'s, 'm> {
    source: &'s str,
    mapping: &'m dyn IrMapping,
    interner: LexemeInterner,
    tokens: Vec<Token>,
    /// Byte start of each emitted token, for mapping node byte ranges onto
    /// token index ranges by binary search.
    token_starts: Vec<usize>,
    /// Byte offset of the start of each source line.
    line_starts: Vec<usize>,
    error_ranges: Vec<ByteRange>,
}

impl<'s, 'm> IrBuilder<'s, 'm> {
    fn new(source: &'s str, mapping: &'m dyn IrMapping) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }
        Self {
            source,
            mapping,
            interner: LexemeInterner::new(),
            tokens: Vec::new(),
            token_starts: Vec::new(),
            line_starts,
            error_ranges: Vec::new(),
        }
    }

    /// Walk every CST leaf in source order, dropping comments, emitting
    /// atomic literal nodes as single tokens, and recording zero-width
    /// `missing` leaves (the parser's recovery insertions) as error ranges.
    fn collect_tokens(&mut self, root: Node<'_>) {
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            let kind = node.kind();
            let descend = kind != COMMENT_KIND
                && !ATOMIC_TOKEN_KINDS.contains(&kind)
                && node.child_count() > 0;
            if descend && cursor.goto_first_child() {
                continue;
            }
            if !descend && kind != COMMENT_KIND {
                if node.is_missing() {
                    self.error_ranges.push(node_range(&node));
                } else if node.end_byte() > node.start_byte() {
                    self.emit_token(&node);
                }
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    fn emit_token(&mut self, node: &Node<'_>) {
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        let text = node_text(node, self.source).unwrap_or("");
        let kind = self.mapping.token_kind(node.kind(), node.is_named(), text);
        let (start_line, start_column) = self.line_column(start_byte);
        let text = self.interner.intern(text);
        self.token_starts.push(start_byte);
        self.tokens.push(Token {
            kind,
            text,
            span: SourceSpan {
                start_byte,
                end_byte,
                start_line,
                start_column,
            },
        });
    }

    /// 1-based line and character column of a byte offset.
    fn line_column(&self, byte: usize) -> (u32, u32) {
        let line_index = self
            .line_starts
            .partition_point(|&start| start <= byte)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        let column_chars = self
            .source
            .get(line_start..byte)
            .map_or(0, |prefix| prefix.chars().count());
        (
            u32::try_from(line_index + 1).unwrap_or(u32::MAX),
            u32::try_from(column_chars + 1).unwrap_or(u32::MAX),
        )
    }

    /// Map one CST node onto the IR, appending zero or more nodes to `out`.
    fn visit(&mut self, cst: Node<'_>, out: &mut Vec<IrNode>) {
        match self.mapping.classify(&cst) {
            Mapping::Emit(shape) => {
                let name = self
                    .mapping
                    .node_name(&cst, self.source)
                    .map(|text| self.interner.intern(text));
                let node = self.build_node(shape, name, cst);
                out.push(node);
            }
            Mapping::Native(kind) => {
                let shape = Shape::Native(self.interner.intern(kind));
                let node = self.build_node(shape, None, cst);
                out.push(node);
            }
            Mapping::ExprStmt => {
                if self.inner_expression_emits(cst) {
                    // The inner expression's own node is the statement.
                    self.visit_children(cst, out);
                } else {
                    let node = self.build_node(Shape::ExprStmt, None, cst);
                    out.push(node);
                }
            }
            Mapping::Error => {
                self.error_ranges.push(node_range(&cst));
                // Recurse anyway: tree-sitter wraps intact regions in error
                // nodes, and those descendants must still be recovered.
                let node = self.build_node(Shape::Error, None, cst);
                out.push(node);
            }
            Mapping::Transparent => self.visit_children(cst, out),
        }
    }

    fn visit_children(&mut self, cst: Node<'_>, out: &mut Vec<IrNode>) {
        let mut cursor = cst.walk();
        let children: Vec<Node<'_>> = cst.named_children(&mut cursor).collect();
        for child in children {
            self.visit(child, out);
        }
    }

    /// Build an [`IrNode`] for `cst`, visiting its children first.
    fn build_node(&mut self, shape: Shape, name: Option<Lexeme>, cst: Node<'_>) -> IrNode {
        let mut children = Vec::new();
        self.visit_children(cst, &mut children);
        let range = node_range(&cst);
        IrNode {
            shape,
            name,
            token_start: self.token_index_at(range.start),
            token_end: self.token_index_at(range.end),
            range,
            children,
        }
    }

    /// Index of the first emitted token starting at or after `byte`.
    fn token_index_at(&self, byte: usize) -> usize {
        self.token_starts.partition_point(|&start| start < byte)
    }

    /// Whether a statement's inner expression maps to a shape of its own,
    /// making the `expression_statement` wrapper redundant.
    fn inner_expression_emits(&self, stmt: Node<'_>) -> bool {
        let mut cursor = stmt.walk();
        stmt.named_children(&mut cursor)
            .find(|child| child.kind() != COMMENT_KIND)
            .is_some_and(|inner| {
                matches!(
                    self.mapping.classify(&inner),
                    Mapping::Emit(_) | Mapping::Native(_) | Mapping::Error
                )
            })
    }
}

/// The C node-mapping table as an [`IrMapping`].
#[derive(Debug, Clone, Copy, Default)]
pub struct CMapping;

impl IrMapping for CMapping {
    fn classify(&self, node: &Node<'_>) -> Mapping {
        classify_c(node)
    }
}

/// The C Structural-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CStructuralFrontend;

impl StructuralFrontend for CStructuralFrontend {
    fn language(&self) -> Language {
        Language::C
    }

    fn frontend_version(&self) -> &'static str {
        STRUCTURAL_FRONTEND_VERSION
    }

    fn parse(&self, source: &str) -> SyntaxIrFile {
        let grammar = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
        parse_to_ir(
            source,
            &grammar,
            &CMapping,
            Language::C,
            STRUCTURAL_FRONTEND_VERSION,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(source: &str) -> SyntaxIrFile {
        CStructuralFrontend.parse(source)
    }

    fn shape_label(shape: &Shape) -> String {
        match shape {
            Shape::Function => "function".to_owned(),
            Shape::Method => "method".to_owned(),
            Shape::Closure => "closure".to_owned(),
            Shape::Record => "record".to_owned(),
            Shape::Impl => "impl".to_owned(),
            Shape::Block => "block".to_owned(),
            Shape::Loop => "loop".to_owned(),
            Shape::Branch => "branch".to_owned(),
            Shape::Match => "match".to_owned(),
            Shape::MatchArm => "match-arm".to_owned(),
            Shape::Call => "call".to_owned(),
            Shape::Assign => "assign".to_owned(),
            Shape::VarDecl => "var-decl".to_owned(),
            Shape::Return => "return".to_owned(),
            Shape::Break => "break".to_owned(),
            Shape::Continue => "continue".to_owned(),
            Shape::Try => "try".to_owned(),
            Shape::ExprStmt => "expr-stmt".to_owned(),
            Shape::MacroDef => "macro-def".to_owned(),
            Shape::MacroCall => "macro-call".to_owned(),
            Shape::Error => "error".to_owned(),
            Shape::Native(kind) => format!("native:{kind}"),
        }
    }

    fn render_node(node: &IrNode, depth: usize, out: &mut String) {
        for _ in 0..depth {
            out.push_str("  ");
        }
        out.push_str(&shape_label(&node.shape));
        if let Some(name) = &node.name {
            out.push(' ');
            out.push_str(name);
        }
        out.push('\n');
        for child in &node.children {
            render_node(child, depth + 1, out);
        }
    }

    /// Render the IR tree as one indented line per node: shape label plus
    /// the recovered name, when present.
    fn render(file: &SyntaxIrFile) -> String {
        let mut out = String::new();
        for root in &file.roots {
            render_node(root, 0, &mut out);
        }
        out
    }

    fn shapes_of(children: &[IrNode]) -> Vec<Shape> {
        children.iter().map(|child| child.shape.clone()).collect()
    }

    const GOLDEN_SOURCE: &str = r"
#define LIMIT 8
#define TWICE(x) ((x) + (x))

struct point {
    int x;
    int y;
};

enum op {
    OP_ADD,
    OP_SUB,
};

typedef struct pair {
    int a;
    int b;
} pair_t;

int classify_value(int v);

int compute(int kind, int acc) {
    struct point p;
    p.x = 0;
    for (int i = 0; i < LIMIT; i++) {
        if (i == 2) {
            continue;
        }
        acc += classify_value(i);
    }
    while (acc > 10) {
        acc -= 1;
    }
    do {
        acc = acc - 1;
    } while (acc > 8);
    if (acc == 0) {
        return 0;
    } else if (acc < 0) {
        goto fail;
    } else {
        acc = TWICE(acc);
    }
    switch (kind) {
        case 0:
            acc += 1;
            break;
        default:
            break;
    }
#ifdef VERBOSE
    log_value(acc);
#endif
fail:
    return acc;
}
";

    #[test]
    fn golden_tree_pins_the_mapping_contract() {
        let file = parse(GOLDEN_SOURCE);
        assert!(
            file.error_ranges.is_empty(),
            "the golden source must parse cleanly: {:?}",
            file.error_ranges
        );
        let expected = "\
macro-def LIMIT
macro-def TWICE
record point
record op
record pair
var-decl
function compute
  block
    var-decl
    assign
    loop
      var-decl
      block
        branch
          block
            continue
        assign
          call
    loop
      block
        assign
    loop
      block
        assign
    branch
      block
        return
      branch
        block
          native:goto_statement
        block
          assign
            call
    match
      block
        match-arm
          assign
          break
        match-arm
          break
    native:preproc_ifdef
      call
    return
";
        assert_eq!(render(&file), expected);
    }

    #[test]
    fn record_requires_a_body() {
        let file = parse("struct point { int x; };\nvoid f(void) { struct point p; p.x = 1; }\n");
        let mut records = Vec::new();
        file.walk(&mut |node| {
            if node.shape == Shape::Record {
                records.push(node.name.as_ref().map(ToString::to_string));
            }
        });
        assert_eq!(
            records,
            vec![Some("point".to_owned())],
            "only the definition emits a Record; the type reference does not"
        );
    }

    #[test]
    fn expr_stmt_unwraps_to_the_inner_shape() {
        let file = parse("void f(void) { g(); a + b; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Call, Shape::ExprStmt],
            "a call statement is the Call node itself; an unmapped expression keeps ExprStmt"
        );
        assert!(
            body.children[1].children.is_empty(),
            "plain operands produce no nodes under the ExprStmt"
        );
    }

    #[test]
    fn assignment_operators_map_to_assign_and_comparisons_do_not() {
        let file = parse("void f(void) { x = 1; x += 1; x == 1; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Assign, Shape::Assign, Shape::ExprStmt],
            "`=` and `+=` are assignments; `==` is interior expression detail"
        );
    }

    #[test]
    fn goto_is_native_and_counts_in_statement_summaries() {
        let file = parse("int f(int v) { goto out; v += 1;\nout:\n    return v; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![
                Shape::Native(Lexeme::from("goto_statement")),
                Shape::Assign,
                Shape::Return,
            ]
        );

        let summaries = body.statement_summaries(&file.tokens);
        assert_eq!(summaries.len(), 3, "the native goto stays in the sequence");
        assert_eq!(
            summaries[0].native_kind,
            Some(Lexeme::from("goto_statement"))
        );
        let head: Vec<&str> = summaries[0]
            .tokens(&file.tokens)
            .iter()
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(head, vec!["goto", "out", ";"]);
    }

    #[test]
    fn preproc_conditionals_keep_both_branches() {
        let file =
            parse("int f(void) {\n#ifdef FAST\n    return 1;\n#else\n    return 2;\n#endif\n}\n");
        let body = &file.roots[0].children[0];
        let ifdef = &body.children[0];
        assert_eq!(ifdef.shape, Shape::Native(Lexeme::from("preproc_ifdef")));
        assert_eq!(
            shapes_of(&ifdef.children),
            vec![Shape::Return, Shape::Native(Lexeme::from("preproc_else"))],
            "the taken branch and the else branch both stay in the IR"
        );
        assert_eq!(shapes_of(&ifdef.children[1].children), vec![Shape::Return]);
    }

    #[test]
    fn function_name_survives_pointer_declarators() {
        let file = parse("static int *find(int v) { return 0; }");
        assert_eq!(file.roots[0].shape, Shape::Function);
        assert_eq!(file.roots[0].name.as_deref(), Some("find"));
    }

    #[test]
    fn broken_function_between_intact_functions_keeps_both_neighbours() {
        let file = parse(
            "int first(void) { return 1; }\nint broken( { ;\nint second(void) { return 2; }\n",
        );
        let mut function_names = Vec::new();
        file.walk(&mut |node| {
            if node.shape == Shape::Function {
                function_names.push(node.name.as_ref().map(ToString::to_string));
            }
        });
        assert!(function_names.contains(&Some("first".to_owned())));
        assert!(function_names.contains(&Some("second".to_owned())));
        assert!(!file.error_ranges.is_empty());
    }

    // Observed worst-case truncation behaviour: tree-sitter recovers the
    // unclosed function by inserting a zero-width missing `}` at EOF, so the
    // unit survives with its parsed statements and the missing brace shows up
    // as a (possibly zero-width) error range. The assertions pin what the
    // parser actually does, not an idealised recovery.
    #[test]
    fn truncation_at_eof_keeps_the_function_with_error_ranges() {
        let file = parse("int tail(void) { int x = 1;");
        assert_eq!(file.roots.len(), 1);
        let function = &file.roots[0];
        assert_eq!(function.shape, Shape::Function);
        assert_eq!(function.name.as_deref(), Some("tail"));
        assert_eq!(shapes_of(&function.children), vec![Shape::Block]);
        assert_eq!(
            shapes_of(&function.children[0].children),
            vec![Shape::VarDecl]
        );
        assert!(!file.error_ranges.is_empty());
    }

    #[test]
    fn token_stream_classification_and_spans() {
        let source = "#include <stdio.h>\nint main(void) {\n    /* é */ double d = 1.5;\n    char c = 'x';\n    const char *s = \"a\\nb\";\n    unsigned long n = 0xFF;\n    bool ok = true;\n    return 0;\n}\n";
        let file = parse(source);

        // `None` marks a token that is missing from the stream entirely.
        let kind_of = |text: &str| -> Option<TokenKind> {
            file.tokens
                .iter()
                .find(|token| token.text == text)
                .map(|token| token.kind)
        };
        assert_eq!(kind_of("#include"), Some(TokenKind::Punctuation));
        assert_eq!(
            kind_of("<stdio.h>"),
            Some(TokenKind::Literal(LiteralKind::String))
        );
        assert_eq!(kind_of("int"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("double"), Some(TokenKind::Keyword));
        // `unsigned long` is a `sized_type_specifier` whose modifiers are
        // anonymous child tokens, so it lexes as two keyword tokens.
        assert_eq!(kind_of("unsigned"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("long"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("const"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("return"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("main"), Some(TokenKind::Identifier));
        assert_eq!(kind_of("1.5"), Some(TokenKind::Literal(LiteralKind::Float)));
        assert_eq!(kind_of("0"), Some(TokenKind::Literal(LiteralKind::Integer)));
        assert_eq!(
            kind_of("0xFF"),
            Some(TokenKind::Literal(LiteralKind::Integer))
        );
        assert_eq!(kind_of("'x'"), Some(TokenKind::Literal(LiteralKind::Char)));
        assert_eq!(
            kind_of("\"a\\nb\""),
            Some(TokenKind::Literal(LiteralKind::String)),
            "the string is one atomic token, escape sequence included"
        );
        assert_eq!(kind_of("true"), Some(TokenKind::Literal(LiteralKind::Bool)));
        assert_eq!(kind_of("{"), Some(TokenKind::Punctuation));
        assert_eq!(kind_of("="), Some(TokenKind::Punctuation));

        assert!(
            file.tokens
                .iter()
                .all(|token| !token.text.contains('é') && !token.text.trim().is_empty()),
            "comments and whitespace must not appear in the stream"
        );

        // Spans are byte-accurate and positions are 1-based; the column is
        // counted in characters, so `double` sits one byte further right than
        // its column suggests (the `é` in the comment before it is two bytes).
        let double = file
            .tokens
            .iter()
            .find(|token| token.text == "double")
            .unwrap();
        assert_eq!(double.span.start_byte, source.find("double").unwrap());
        assert_eq!(double.span.end_byte, double.span.start_byte + 6);
        assert_eq!(double.span.start_line, 3);
        assert_eq!(double.span.start_column, 13);
    }

    #[test]
    fn empty_source_yields_an_empty_file() {
        let file = parse("");
        assert!(file.tokens.is_empty());
        assert!(file.roots.is_empty());
        assert!(file.error_ranges.is_empty());
    }

    #[test]
    fn parsing_twice_is_deterministic() {
        let first = parse(GOLDEN_SOURCE);
        let second = parse(GOLDEN_SOURCE);
        assert_eq!(first.tokens, second.tokens);
        assert_eq!(first.roots, second.roots);
        assert_eq!(first.error_ranges, second.error_ranges);
    }

    #[test]
    fn file_carries_language_and_versions() {
        let frontend = CStructuralFrontend;
        assert_eq!(frontend.language(), Language::C);
        assert_eq!(frontend.frontend_version(), "c-ir-v1");

        let file = parse("int a;");
        assert_eq!(file.language, Language::C);
        assert_eq!(file.frontend_version, STRUCTURAL_FRONTEND_VERSION);
        assert_eq!(file.ir_schema_version, IR_SCHEMA_VERSION);
        assert!(file.diagnostics.is_empty());
    }
}
