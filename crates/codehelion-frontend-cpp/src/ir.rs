//! Structural-mode C++ frontend: tree-sitter CST to Syntax-IR conversion.
//!
//! Built on the shared C-family walking machinery from
//! [`codehelion_frontend_c::ir`]: the same tokenisation, error recovery and
//! IR assembly, driven by a C++ mapping table that layers the C++-only grammar
//! kinds (lambdas, classes, templates, namespaces, exceptions, range-`for`)
//! over the shared C table.
//!
//! # Granularity decisions specific to C++
//!
//! - A `function_definition` written inside a class body (lexically inside a
//!   `field_declaration_list`) is a [`Shape::Method`]; an out-of-class member
//!   definition (`int A::f() { ... }`) stays [`Shape::Function`], because the
//!   in-class/out-of-class distinction is lexical, not semantic, and
//!   Structural mode does not resolve scopes.
//! - `field_declaration` maps to [`Shape::VarDecl`] uniformly — member
//!   variables and member-function declarations alike, matching the C
//!   frontend's uniform treatment of `declaration`.
//! - `template_declaration` and `namespace_definition` have no cross-language
//!   shape and become [`Shape::Native`] nodes; their contents stay in the IR
//!   unexpanded and uninstantiated.
//! - `try` maps to [`Shape::Try`]; each `catch_clause` is transparent, so its
//!   handler surfaces as a plain [`Shape::Block`] child of the `Try` node.
//!   `throw` has no cross-language shape and stays native.

use codehelion_core::discovery::Language;
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_frontend_c::ir::{IrMapping, Mapping, classify_c, parse_to_ir, record_mapping};
use tree_sitter::Node;

/// Version tag of this structural frontend, used as a fingerprint input. Bump
/// it whenever a change alters the token stream or the IR tree for unchanged
/// input.
pub const STRUCTURAL_FRONTEND_VERSION: &str = "cpp-ir-v0";

/// The C++ node-mapping table: C++-only kinds first, then the shared C table.
#[derive(Debug, Clone, Copy, Default)]
pub struct CppMapping;

impl IrMapping for CppMapping {
    fn classify(&self, node: &Node<'_>) -> Mapping {
        match node.kind() {
            "function_definition" => Mapping::Emit(function_shape(node)),
            "lambda_expression" => Mapping::Emit(Shape::Closure),
            "class_specifier" => record_mapping(node),
            "template_declaration" => Mapping::Native("template_declaration"),
            "namespace_definition" => Mapping::Native("namespace"),
            "try_statement" => Mapping::Emit(Shape::Try),
            "throw_statement" => Mapping::Native("throw_statement"),
            "for_range_loop" => Mapping::Emit(Shape::Loop),
            "field_declaration" => Mapping::Emit(Shape::VarDecl),
            // Everything else — including `catch_clause`, `new_expression`
            // and `delete_expression`, which are transparent interior detail —
            // falls through to the shared C-family table.
            _ => classify_c(node),
        }
    }
}

/// [`Shape::Method`] for an in-class definition (lexically inside a
/// `field_declaration_list`, looking through member templates);
/// [`Shape::Function`] anywhere else, out-of-class member definitions
/// included.
fn function_shape(node: &Node<'_>) -> Shape {
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        match ancestor.kind() {
            "field_declaration_list" => return Shape::Method,
            "template_declaration" => parent = ancestor.parent(),
            _ => return Shape::Function,
        }
    }
    Shape::Function
}

/// The C++ Structural-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CppStructuralFrontend;

impl StructuralFrontend for CppStructuralFrontend {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn frontend_version(&self) -> &'static str {
        STRUCTURAL_FRONTEND_VERSION
    }

    fn parse(&self, source: &str) -> SyntaxIrFile {
        let grammar = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
        parse_to_ir(
            source,
            &grammar,
            &CppMapping,
            Language::Cpp,
            STRUCTURAL_FRONTEND_VERSION,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use codehelion_core::frontend::{Lexeme, LiteralKind, TokenKind};
    use codehelion_core::ir::{IR_SCHEMA_VERSION, IrNode};

    fn parse(source: &str) -> SyntaxIrFile {
        CppStructuralFrontend.parse(source)
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
namespace app {

template <typename T>
T twice(T value) {
    return value + value;
}

class Counter {
public:
    int bump(int by) {
        total_ += by;
        return total_;
    }
    int reset();

private:
    int total_ = 0;
};

int Counter::reset() {
    int old_total = total_;
    total_ = 0;
    return old_total;
}

int run(const int *xs, int n) {
    auto add = [](int a, int b) { return a + b; };
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc = add(acc, xs[i]);
    }
    for (int v : xs) {
        acc += v;
    }
    try {
        if (acc < 0) {
            throw make_error(acc);
        }
    } catch (const error &e) {
        acc = 0;
    }
    return acc;
}

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
native:namespace
  native:template_declaration
    function twice
      block
        return
  record Counter
    method bump
      block
        assign
        return
    var-decl
    var-decl
  function reset
    block
      var-decl
      assign
      return
  function run
    block
      var-decl
        closure
          block
            return
      var-decl
      loop
        var-decl
        block
          assign
            call
      loop
        block
          assign
      try
        block
          branch
            block
              native:throw_statement
                call
        block
          assign
      return
";
        assert_eq!(render(&file), expected);
    }

    #[test]
    fn function_position_separates_methods_from_functions() {
        let source = "\
int free_fn() { return 0; }
struct S {
    int in_class() { return 1; }
    template <typename T> T member_template(T v) { return v; }
};
int S::out_of_class() { return 2; }
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
                (Shape::Function, Some("free_fn".to_owned())),
                (Shape::Method, Some("in_class".to_owned())),
                (Shape::Method, Some("member_template".to_owned())),
                (Shape::Function, Some("out_of_class".to_owned())),
            ]
        );
    }

    #[test]
    fn record_requires_a_body_and_covers_classes() {
        let file = parse("class Fwd;\nclass Def { int a_; };\nvoid f() { Def d; }\n");
        let mut records = Vec::new();
        file.walk(&mut |node| {
            if node.shape == Shape::Record {
                records.push(node.name.as_ref().map(ToString::to_string));
            }
        });
        assert_eq!(
            records,
            vec![Some("Def".to_owned())],
            "the forward declaration and the type reference emit no Record"
        );
    }

    #[test]
    fn expr_stmt_unwraps_to_the_inner_shape() {
        let file = parse("void f() { g(); a + b; }");
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
        let file = parse("void f() { x = 1; x += 1; x == 1; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Assign, Shape::Assign, Shape::ExprStmt],
            "`=` and `+=` are assignments; `==` is interior expression detail"
        );
    }

    #[test]
    fn throw_is_native_and_counts_in_statement_summaries() {
        let file = parse("int f(int v) { throw v; v += 1; return v; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![
                Shape::Native(Lexeme::from("throw_statement")),
                Shape::Assign,
                Shape::Return,
            ]
        );

        let summaries = body.statement_summaries(&file.tokens);
        assert_eq!(summaries.len(), 3, "the native throw stays in the sequence");
        assert_eq!(
            summaries[0].native_kind,
            Some(Lexeme::from("throw_statement"))
        );
        let head: Vec<&str> = summaries[0]
            .tokens(&file.tokens)
            .iter()
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(head, vec!["throw", "v", ";"]);
    }

    #[test]
    fn try_catch_yields_try_with_plain_block_handlers() {
        let file = parse("void f() { try { g(); } catch (const E &e) { h(); } catch (...) { } }");
        let body = &file.roots[0].children[0];
        let try_node = &body.children[0];
        assert_eq!(try_node.shape, Shape::Try);
        assert_eq!(
            shapes_of(&try_node.children),
            vec![Shape::Block, Shape::Block, Shape::Block],
            "the try block and each transparent catch clause's handler block"
        );
    }

    #[test]
    fn broken_function_between_intact_functions_keeps_both_neighbours() {
        let file =
            parse("int first() { return 1; }\nint broken( { ;\nint second() { return 2; }\n");
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
        let file = parse("int tail() { int x = 1;");
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
        let source = "namespace ns {\nint f(int n) {\n    /* é */ double d = 1.5;\n    auto s = R\"(raw \"text\")\";\n    bool ok = true;\n    auto *self = this;\n    void *none = nullptr;\n    return ns::g(n, 'x', \"lit\");\n}\n}\n";
        let file = parse(source);

        // `None` marks a token that is missing from the stream entirely.
        let kind_of = |text: &str| -> Option<TokenKind> {
            file.tokens
                .iter()
                .find(|token| token.text == text)
                .map(|token| token.kind)
        };
        assert_eq!(kind_of("namespace"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("ns"), Some(TokenKind::Identifier));
        // `auto`, `this` and `nullptr` are named leaves in the grammar but
        // lexically keywords.
        assert_eq!(kind_of("auto"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("this"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("nullptr"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("1.5"), Some(TokenKind::Literal(LiteralKind::Float)));
        assert_eq!(
            kind_of("R\"(raw \"text\")\""),
            Some(TokenKind::Literal(LiteralKind::String)),
            "the raw string is one atomic token, delimiters included"
        );
        assert_eq!(kind_of("true"), Some(TokenKind::Literal(LiteralKind::Bool)));
        assert_eq!(kind_of("'x'"), Some(TokenKind::Literal(LiteralKind::Char)));
        assert_eq!(
            kind_of("\"lit\""),
            Some(TokenKind::Literal(LiteralKind::String))
        );
        assert_eq!(kind_of("::"), Some(TokenKind::Punctuation));
        assert_eq!(kind_of("{"), Some(TokenKind::Punctuation));

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
    fn parsing_twice_is_deterministic() {
        let first = parse(GOLDEN_SOURCE);
        let second = parse(GOLDEN_SOURCE);
        assert_eq!(first.tokens, second.tokens);
        assert_eq!(first.roots, second.roots);
        assert_eq!(first.error_ranges, second.error_ranges);
    }

    #[test]
    fn file_carries_language_and_versions() {
        let frontend = CppStructuralFrontend;
        assert_eq!(frontend.language(), Language::Cpp);
        assert_eq!(frontend.frontend_version(), "cpp-ir-v0");

        let file = parse("int a;");
        assert_eq!(file.language, Language::Cpp);
        assert_eq!(file.frontend_version, STRUCTURAL_FRONTEND_VERSION);
        assert_eq!(file.ir_schema_version, IR_SCHEMA_VERSION);
        assert!(file.diagnostics.is_empty());
    }
}
