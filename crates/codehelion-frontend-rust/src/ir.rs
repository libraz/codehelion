//! Structural-mode Rust frontend: real-parser CST to Syntax-IR conversion.
//!
//! The file is parsed with `ra_ap_syntax` (rust-analyzer's error-tolerant
//! parser) and the resulting lossless CST is mapped onto the language-neutral
//! [`SyntaxIrFile`]: a comment- and whitespace-free token stream plus a tree
//! of [`IrNode`]s built from structurally meaningful grammar nodes only.
//! Interior expression detail (paths, literals, parentheses, non-assignment
//! binary operators, field accesses) stays token-only under the nearest
//! ancestor node, keeping the tree at the granularity structural comparison
//! works on. Statement wrappers add no node of their own when their inner
//! expression already maps to a shape: `f();` is one [`Shape::Call`] node,
//! not an `ExprStmt(Call)` pair.
//!
//! Nothing is executed or expanded: macro definitions and invocations are
//! recorded as nodes over their raw token trees. Malformed regions become
//! [`Shape::Error`] nodes plus byte ranges in [`SyntaxIrFile::error_ranges`],
//! and parsing never aborts the file.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{
    Lexeme, LexemeInterner, LiteralKind, SourceSpan, Token, TokenKind,
};
use codehelion_core::ir::{
    ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, StructuralFrontend, SyntaxIrFile,
};
use ra_ap_syntax::{Edition, SourceFile, SyntaxKind, SyntaxNode};

/// Version tag of this structural frontend, used as a fingerprint input. Bump
/// it whenever a change alters the token stream or the IR tree for unchanged
/// input.
pub const STRUCTURAL_FRONTEND_VERSION: &str = "rust-ir-v1";

/// Edition the parser assumes. Parsing is edition-tolerant enough for audit
/// purposes; a wrong guess degrades to error ranges, never to a lost file.
const PARSE_EDITION: Edition = Edition::CURRENT;

/// Binary operator tokens that make a `BIN_EXPR` an assignment.
const ASSIGN_OPS: &[SyntaxKind] = &[
    SyntaxKind::EQ,
    SyntaxKind::PLUSEQ,
    SyntaxKind::MINUSEQ,
    SyntaxKind::STAREQ,
    SyntaxKind::SLASHEQ,
    SyntaxKind::PERCENTEQ,
    SyntaxKind::AMPEQ,
    SyntaxKind::PIPEEQ,
    SyntaxKind::CARETEQ,
    SyntaxKind::SHLEQ,
    SyntaxKind::SHREQ,
];

/// The Rust Structural-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustStructuralFrontend;

impl StructuralFrontend for RustStructuralFrontend {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn frontend_version(&self) -> &'static str {
        STRUCTURAL_FRONTEND_VERSION
    }

    fn parse(&self, source: &str) -> SyntaxIrFile {
        let parse = SourceFile::parse(source, PARSE_EDITION);
        let root = parse.syntax_node();

        let mut builder = IrBuilder::new(source);
        builder.collect_tokens(&root);

        let mut roots = Vec::new();
        for child in root.children() {
            builder.visit(&child, &mut roots);
        }

        for error in parse.errors() {
            let range = error.range();
            builder.error_ranges.push(ByteRange {
                start: usize::from(range.start()),
                end: usize::from(range.end()),
            });
        }
        builder
            .error_ranges
            .sort_unstable_by_key(|range| (range.start, range.end));
        builder.error_ranges.dedup();

        SyntaxIrFile {
            language: Language::Rust,
            frontend_version: STRUCTURAL_FRONTEND_VERSION,
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
}

/// How one CST node maps onto the IR.
enum Mapping {
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

/// Decide how `node` maps onto the IR. This table is the granularity
/// contract of the Rust structural frontend; changing it changes fingerprint
/// input and requires a [`STRUCTURAL_FRONTEND_VERSION`] bump.
fn classify(node: &SyntaxNode) -> Mapping {
    match node.kind() {
        SyntaxKind::FN => Mapping::Emit(fn_shape(node)),
        SyntaxKind::CLOSURE_EXPR => Mapping::Emit(Shape::Closure),
        SyntaxKind::STRUCT | SyntaxKind::ENUM | SyntaxKind::UNION => Mapping::Emit(Shape::Record),
        SyntaxKind::IMPL => Mapping::Emit(Shape::Impl),
        SyntaxKind::TRAIT => Mapping::Native("trait"),
        // `BLOCK_EXPR` and the `STMT_LIST` inside it collapse into one Block:
        // the block emits, the statement list stays transparent.
        SyntaxKind::BLOCK_EXPR => Mapping::Emit(Shape::Block),
        SyntaxKind::LOOP_EXPR | SyntaxKind::WHILE_EXPR | SyntaxKind::FOR_EXPR => {
            Mapping::Emit(Shape::Loop)
        }
        // Each `else if` is its own `IF_EXPR` child, so a chain nests as
        // Branch nodes without special handling.
        SyntaxKind::IF_EXPR => Mapping::Emit(Shape::Branch),
        SyntaxKind::MATCH_EXPR => Mapping::Emit(Shape::Match),
        SyntaxKind::MATCH_ARM => Mapping::Emit(Shape::MatchArm),
        SyntaxKind::CALL_EXPR | SyntaxKind::METHOD_CALL_EXPR => Mapping::Emit(Shape::Call),
        SyntaxKind::AWAIT_EXPR => Mapping::Native("await_expr"),
        SyntaxKind::BIN_EXPR if is_assignment(node) => Mapping::Emit(Shape::Assign),
        SyntaxKind::LET_STMT => Mapping::Emit(Shape::VarDecl),
        SyntaxKind::RETURN_EXPR => Mapping::Emit(Shape::Return),
        SyntaxKind::BREAK_EXPR => Mapping::Emit(Shape::Break),
        SyntaxKind::CONTINUE_EXPR => Mapping::Emit(Shape::Continue),
        SyntaxKind::TRY_EXPR => Mapping::Emit(Shape::Try),
        SyntaxKind::EXPR_STMT => Mapping::ExprStmt,
        SyntaxKind::MACRO_RULES | SyntaxKind::MACRO_DEF => Mapping::Emit(Shape::MacroDef),
        SyntaxKind::MACRO_CALL => Mapping::Emit(Shape::MacroCall),
        SyntaxKind::MODULE => Mapping::Native("module"),
        SyntaxKind::EXTERN_BLOCK => Mapping::Native("extern_block"),
        SyntaxKind::CONST => Mapping::Native("const"),
        SyntaxKind::STATIC => Mapping::Native("static"),
        SyntaxKind::ERROR => Mapping::Error,
        // Everything else — item plumbing, patterns, types and interior
        // expression detail — is transparent: no node, children visited.
        _ => Mapping::Transparent,
    }
}

/// An `fn` directly inside an `impl` or `trait` body is a method; anywhere
/// else (file root, module, nested in another body) it is a free function.
fn fn_shape(node: &SyntaxNode) -> Shape {
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == SyntaxKind::ASSOC_ITEM_LIST)
    {
        Shape::Method
    } else {
        Shape::Function
    }
}

/// Whether a `BIN_EXPR`'s operator token is `=` or a compound assignment.
/// Operands are child nodes, so the only child tokens besides trivia are the
/// operator itself.
fn is_assignment(node: &SyntaxNode) -> bool {
    node.children_with_tokens()
        .filter_map(ra_ap_syntax::SyntaxElement::into_token)
        .any(|token| ASSIGN_OPS.contains(&token.kind()))
}

/// Whether a statement's inner expression maps to a shape of its own, making
/// the `EXPR_STMT` wrapper redundant. Expression-position macro calls sit
/// inside a `MACRO_EXPR` wrapper, which is looked through.
fn inner_expression_emits(stmt: &SyntaxNode) -> bool {
    let mut expr = stmt.children().next();
    while let Some(node) = expr {
        match classify(&node) {
            Mapping::Emit(_) | Mapping::Native(_) | Mapping::Error => return true,
            Mapping::Transparent if node.kind() == SyntaxKind::MACRO_EXPR => {
                expr = node.children().next();
            }
            _ => return false,
        }
    }
    false
}

/// Map one CST token kind onto the shared [`TokenKind`] vocabulary.
fn map_token_kind(kind: SyntaxKind) -> TokenKind {
    match kind {
        SyntaxKind::IDENT => TokenKind::Identifier,
        SyntaxKind::TRUE_KW | SyntaxKind::FALSE_KW => TokenKind::Literal(LiteralKind::Bool),
        SyntaxKind::INT_NUMBER => TokenKind::Literal(LiteralKind::Integer),
        SyntaxKind::FLOAT_NUMBER => TokenKind::Literal(LiteralKind::Float),
        // Raw strings have no kind of their own: the parser reports `r"..."`
        // as STRING, `br"..."` as BYTE_STRING and `cr"..."` as C_STRING, so
        // the three of them are already covered here.
        SyntaxKind::STRING | SyntaxKind::BYTE_STRING | SyntaxKind::C_STRING => {
            TokenKind::Literal(LiteralKind::String)
        }
        SyntaxKind::CHAR | SyntaxKind::BYTE => TokenKind::Literal(LiteralKind::Char),
        SyntaxKind::LIFETIME_IDENT => TokenKind::Lifetime,
        kind if kind.is_keyword(PARSE_EDITION) => TokenKind::Keyword,
        kind if kind.is_punct() => TokenKind::Punctuation,
        _ => TokenKind::Unknown,
    }
}

/// Accumulates the token stream and IR tree for one file.
struct IrBuilder<'s> {
    source: &'s str,
    interner: LexemeInterner,
    tokens: Vec<Token>,
    /// Byte start of each emitted token, for mapping node byte ranges onto
    /// token index ranges by binary search.
    token_starts: Vec<usize>,
    /// Byte offset of the start of each source line.
    line_starts: Vec<usize>,
    error_ranges: Vec<ByteRange>,
}

impl<'s> IrBuilder<'s> {
    fn new(source: &'s str) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }
        Self {
            source,
            interner: LexemeInterner::new(),
            tokens: Vec::new(),
            token_starts: Vec::new(),
            line_starts,
            error_ranges: Vec::new(),
        }
    }

    /// Walk every CST token in source order, dropping trivia. The CST is
    /// lossless, so this yields the complete token stream of the file.
    fn collect_tokens(&mut self, root: &SyntaxNode) {
        for element in root.descendants_with_tokens() {
            let Some(token) = element.into_token() else {
                continue;
            };
            let kind = token.kind();
            if matches!(kind, SyntaxKind::WHITESPACE | SyntaxKind::COMMENT) {
                continue;
            }
            let range = token.text_range();
            let start_byte = usize::from(range.start());
            let end_byte = usize::from(range.end());
            let (start_line, start_column) = self.line_column(start_byte);
            let text = self.interner.intern(token.text());
            self.token_starts.push(start_byte);
            self.tokens.push(Token {
                kind: map_token_kind(kind),
                text,
                span: SourceSpan {
                    start_byte,
                    end_byte,
                    start_line,
                    start_column,
                },
            });
        }
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
    fn visit(&mut self, cst: &SyntaxNode, out: &mut Vec<IrNode>) {
        match classify(cst) {
            Mapping::Emit(shape) => {
                let name = self.node_name(cst);
                let node = self.build_node(shape, name, cst);
                out.push(node);
            }
            Mapping::Native(kind) => {
                let shape = Shape::Native(self.interner.intern(kind));
                let node = self.build_node(shape, None, cst);
                out.push(node);
            }
            Mapping::ExprStmt => {
                if inner_expression_emits(cst) {
                    // The inner expression's own node is the statement.
                    for child in cst.children() {
                        self.visit(&child, out);
                    }
                } else {
                    let node = self.build_node(Shape::ExprStmt, None, cst);
                    out.push(node);
                }
            }
            Mapping::Error => {
                self.error_ranges.push(byte_range(cst));
                // Recurse anyway: real parsers wrap intact regions in error
                // nodes, and those descendants must still be recovered.
                let node = self.build_node(Shape::Error, None, cst);
                out.push(node);
            }
            Mapping::Transparent => {
                for child in cst.children() {
                    self.visit(&child, out);
                }
            }
        }
    }

    /// Build an [`IrNode`] for `cst`, visiting its children first.
    fn build_node(&mut self, shape: Shape, name: Option<Lexeme>, cst: &SyntaxNode) -> IrNode {
        let mut children = Vec::new();
        for child in cst.children() {
            self.visit(&child, &mut children);
        }
        let range = byte_range(cst);
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

    /// Recover a declared name where the grammar provides one: the `NAME`
    /// child of definitions, or the invoked path of a macro call.
    fn node_name(&mut self, cst: &SyntaxNode) -> Option<Lexeme> {
        let name_kind = match cst.kind() {
            SyntaxKind::FN
            | SyntaxKind::STRUCT
            | SyntaxKind::ENUM
            | SyntaxKind::UNION
            | SyntaxKind::MACRO_RULES
            | SyntaxKind::MACRO_DEF => SyntaxKind::NAME,
            SyntaxKind::MACRO_CALL => SyntaxKind::PATH,
            _ => return None,
        };
        cst.children()
            .find(|child| child.kind() == name_kind)
            .map(|child| self.interner.intern(&child.text().to_string()))
    }
}

/// The byte range a CST node covers.
fn byte_range(node: &SyntaxNode) -> ByteRange {
    let range = node.text_range();
    ByteRange {
        start: usize::from(range.start()),
        end: usize::from(range.end()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(source: &str) -> SyntaxIrFile {
        RustStructuralFrontend.parse(source)
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

    const GOLDEN_SOURCE: &str = r#"
mod app {
    pub struct Point {
        x: i32,
        y: i32,
    }

    pub enum Op {
        Add,
        Sub,
    }

    impl Point {
        fn shift(&mut self, dx: i32) -> i32 {
            self.x += dx;
            self.x
        }
    }

    macro_rules! trace {
        ($e:expr) => {
            $e
        };
    }

    fn compute(op: Op, mut acc: i32) -> Result<i32, String> {
        let step = |v: i32| v + 1;
        for i in 0..3 {
            acc = step(acc + i);
        }
        while acc > 10 {
            acc -= 1;
        }
        loop {
            if acc == 0 {
                break;
            } else if acc < 0 {
                continue;
            } else {
                acc = acc.checked_sub(1).ok_or("underflow")?;
            }
        }
        match op {
            Op::Add => acc += 1,
            Op::Sub => acc -= 1,
        }
        fn helper(v: i32) -> i32 {
            v
        }
        println!("{}", helper(acc));
        return Ok(acc);
    }
}
"#;

    #[test]
    fn golden_tree_pins_the_mapping_contract() {
        let file = parse(GOLDEN_SOURCE);
        assert!(
            file.error_ranges.is_empty(),
            "the golden source must parse cleanly"
        );
        let expected = "\
native:module
  record Point
  record Op
  impl
    method shift
      block
        assign
  macro-def trace
  function compute
    block
      var-decl
        closure
      loop
        block
          assign
            call
      loop
        block
          assign
      loop
        block
          branch
            block
              break
            branch
              block
                continue
              block
                assign
                  try
                    call
                      call
      match
        match-arm
          assign
        match-arm
          assign
      function helper
        block
      macro-call println
      return
        call
";
        assert_eq!(render(&file), expected);
    }

    #[test]
    fn fn_position_separates_methods_from_functions() {
        let source = "\
fn free() {}
struct S;
impl S {
    fn on_impl(&self) {}
}
trait T {
    fn on_trait(&self);
}
";
        let file = parse(source);
        let mut found = Vec::new();
        file.walk(&mut |node| {
            if matches!(node.shape, Shape::Function | Shape::Method) {
                let name = node.name.as_ref().map(ToString::to_string);
                found.push((node.shape.clone(), name));
            }
        });
        assert_eq!(
            found,
            vec![
                (Shape::Function, Some("free".to_owned())),
                (Shape::Method, Some("on_impl".to_owned())),
                (Shape::Method, Some("on_trait".to_owned())),
            ]
        );
    }

    #[test]
    fn fn_body_collapses_to_one_block_of_statements() {
        let file = parse("fn f() { let a = 1; a = 2; g(); return; }");
        let function = &file.roots[0];
        assert_eq!(function.shape, Shape::Function);
        assert_eq!(
            function.children.len(),
            1,
            "the body must be exactly one Block node"
        );
        let body = &function.children[0];
        assert_eq!(body.shape, Shape::Block);
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::VarDecl, Shape::Assign, Shape::Call, Shape::Return]
        );

        let summaries = body.statement_summaries(&file.tokens);
        let tags: Vec<u8> = summaries.iter().map(|summary| summary.shape_tag).collect();
        assert_eq!(
            tags,
            vec![
                Shape::VarDecl.tag(),
                Shape::Assign.tag(),
                Shape::Return.tag()
            ],
            "a bare call statement is a Call node, which is not a statement shape"
        );
        let text: Vec<&str> = summaries[0]
            .tokens(&file.tokens)
            .iter()
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(text, vec!["let", "a", "=", "1", ";"]);
    }

    #[test]
    fn expr_stmt_unwraps_to_the_inner_shape() {
        let file = parse("fn f() { g(); a + b; }");
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
        let file = parse("fn f() { x = 1; x += 1; x == 1; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Assign, Shape::Assign, Shape::ExprStmt],
            "`=` and `+=` are assignments; `==` is interior expression detail"
        );
    }

    #[test]
    fn broken_fn_between_intact_fns_keeps_both_neighbours() {
        let file = parse("fn first() {}\nfn broken() { let = ; }\nfn second() {}\n");
        let mut function_names = Vec::new();
        let mut error_nodes = 0;
        file.walk(&mut |node| {
            if node.shape == Shape::Function {
                function_names.push(node.name.as_ref().map(ToString::to_string));
            }
            if node.shape == Shape::Error {
                error_nodes += 1;
            }
        });
        assert!(function_names.contains(&Some("first".to_owned())));
        assert!(function_names.contains(&Some("second".to_owned())));
        assert!(
            error_nodes >= 1,
            "the malformed region yields an Error node"
        );
        assert!(!file.error_ranges.is_empty());
    }

    #[test]
    fn truncation_at_eof_still_yields_the_function() {
        let file = parse("fn tail() { let x = 1;");
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
        let source = "fn f<'a>(x: &'a str) -> u32 {\n    // gone\n    let é = 1.5; g(2, 'z', \"s\", true)\n}\n";
        let file = parse(source);

        // `None` marks a token that is missing from the stream entirely.
        let kind_of = |text: &str| -> Option<TokenKind> {
            file.tokens
                .iter()
                .find(|token| token.text == text)
                .map(|token| token.kind)
        };
        assert_eq!(kind_of("fn"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("let"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("f"), Some(TokenKind::Identifier));
        assert_eq!(kind_of("é"), Some(TokenKind::Identifier));
        assert_eq!(kind_of("'a"), Some(TokenKind::Lifetime));
        assert_eq!(kind_of("1.5"), Some(TokenKind::Literal(LiteralKind::Float)));
        assert_eq!(kind_of("2"), Some(TokenKind::Literal(LiteralKind::Integer)));
        assert_eq!(kind_of("'z'"), Some(TokenKind::Literal(LiteralKind::Char)));
        assert_eq!(
            kind_of("\"s\""),
            Some(TokenKind::Literal(LiteralKind::String))
        );
        assert_eq!(kind_of("true"), Some(TokenKind::Literal(LiteralKind::Bool)));
        assert_eq!(kind_of("->"), Some(TokenKind::Punctuation));
        assert_eq!(kind_of("("), Some(TokenKind::Punctuation));

        assert!(
            file.tokens
                .iter()
                .all(|token| !token.text.contains("gone") && !token.text.trim().is_empty()),
            "comments and whitespace must not appear in the stream"
        );

        // Spans are byte-accurate and positions are 1-based; the column is
        // counted in characters, so `1.5` sits one byte further right than
        // its column suggests (the `é` before it is two bytes).
        let e_acute = file.tokens.iter().find(|token| token.text == "é").unwrap();
        assert_eq!(e_acute.span.start_byte, source.find('é').unwrap());
        assert_eq!(
            e_acute.span.end_byte,
            e_acute.span.start_byte + 'é'.len_utf8()
        );
        assert_eq!(e_acute.span.start_line, 3);
        assert_eq!(e_acute.span.start_column, 9);

        let float = file
            .tokens
            .iter()
            .find(|token| token.text == "1.5")
            .unwrap();
        assert_eq!(float.span.start_byte, source.find("1.5").unwrap());
        assert_eq!(float.span.end_byte, float.span.start_byte + 3);
        assert_eq!(float.span.start_line, 3);
        assert_eq!(float.span.start_column, 13);
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
        let frontend = RustStructuralFrontend;
        assert_eq!(frontend.language(), Language::Rust);
        assert_eq!(frontend.frontend_version(), "rust-ir-v1");

        let file = parse("fn a() {}");
        assert_eq!(file.language, Language::Rust);
        assert_eq!(file.frontend_version, STRUCTURAL_FRONTEND_VERSION);
        assert_eq!(file.ir_schema_version, IR_SCHEMA_VERSION);
        assert!(file.diagnostics.is_empty());
    }
}
