use super::*;

fn parse(source: &str) -> SyntaxIrFile {
    CStructuralFrontend.parse(source)
}

#[test]
fn signatures_are_sorted_exact_and_ignore_parameter_names() {
    let source = "const int *first(const char *left, int values[4]) { return 0; }\nconst int *second(const char *right, int items[4]) { return 0; }";
    let file = parse(source);
    assert!(
        file.error_ranges.is_empty(),
        "unexpected parse errors: {:?}",
        file.error_ranges
    );
    assert_eq!(file.signatures.len(), 2);
    assert!(file.signatures.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let first = file.signature_for_range(file.signatures[0].0).unwrap();
    let second = file.signature_for_range(file.signatures[1].0).unwrap();
    assert_eq!(first.normalized, second.normalized);
    assert_eq!(first.key, second.key);
    assert!(first.normalized.contains("t3:int"));
    assert!(first.normalized.contains("t5:const"));
    assert!(first.normalized.contains("t4:char"));
    assert!(first.normalized.contains("t1:4"));
}

#[test]
fn signatures_distinguish_return_type_changes() {
    let int_file = parse("int first(int value) { return value; }");
    let long_file = parse("long first(int value) { return value; }");
    assert_eq!(int_file.signatures.len(), 1);
    assert_eq!(long_file.signatures.len(), 1);
    assert_ne!(int_file.signatures[0].1.key, long_file.signatures[0].1.key);
}

#[test]
fn signatures_alpha_normalize_vla_parameter_references() {
    let first = parse("int first(int count, int values[count]) { return count; }");
    let second = parse("int second(int renamed, int items[renamed]) { return renamed; }");
    assert!(first.error_ranges.is_empty(), "{:?}", first.error_ranges);
    assert!(second.error_ranges.is_empty(), "{:?}", second.error_ranges);
    assert_eq!(first.signatures.len(), 1);
    assert_eq!(second.signatures.len(), 1);
    assert_eq!(first.signatures[0].1, second.signatures[0].1);
    assert!(
        first.signatures[0]
            .1
            .normalized
            .contains("t3:intt1:[p0;t1:]")
    );

    let non_parameter_type = parse(
        "int first(int count, int values[limit]) { return count; }\nint second(int renamed, int items[other_limit]) { return renamed; }",
    );
    assert!(non_parameter_type.error_ranges.is_empty());
    assert_eq!(non_parameter_type.signatures.len(), 2);
    assert_ne!(
        non_parameter_type.signatures[0].1.key,
        non_parameter_type.signatures[1].1.key
    );
}

#[test]
fn signatures_respect_parameter_declaration_order_in_vla_bounds() {
    let external = parse(
        "enum { N = 4 }; enum { M = 5 }; int first(int values[N], int N) { return N; }\nint second(int values[M], int M) { return M; }",
    );
    assert!(
        external.error_ranges.is_empty(),
        "{:?}",
        external.error_ranges
    );
    assert_eq!(external.signatures.len(), 2);
    assert_ne!(external.signatures[0].1.key, external.signatures[1].1.key);

    let renamed = parse(
        "enum { N = 4 }; int first(int values[N], int N) { return N; }\nint second(int items[N], int M) { return M; }",
    );
    assert!(
        renamed.error_ranges.is_empty(),
        "{:?}",
        renamed.error_ranges
    );
    assert_eq!(renamed.signatures.len(), 2);
    assert_eq!(renamed.signatures[0].1.key, renamed.signatures[1].1.key);
}

#[test]
fn signatures_preserve_c_token_boundaries() {
    let file = parse(
        "typedef int unsignedlong; unsigned long first(int value) { return 0; }\nunsignedlong second(int value) { return 0; }",
    );
    assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
    assert_eq!(file.signatures.len(), 2);
    assert_ne!(file.signatures[0].1.key, file.signatures[1].1.key);
    assert!(
        file.signatures[0]
            .1
            .normalized
            .contains("t8:unsignedt4:long")
    );
}

#[test]
fn signatures_skip_parameter_list_comments() {
    let comments = parse(
        "int first(int left /* parameter */, /* between */ int right) { return 0; }\nint second(int left, int right) { return 0; }",
    );
    assert!(
        comments.error_ranges.is_empty(),
        "{:?}",
        comments.error_ranges
    );
    assert_eq!(comments.signatures.len(), 2);
    assert_eq!(comments.signatures[0].1, comments.signatures[1].1);
}

#[test]
fn signatures_reject_c_attributes_and_calling_convention_extensions() {
    let attributes = parse(
        "int first(int value) __attribute__((nonnull)) { return value; }\nint second(int value) __attribute__((nothrow)) { return value; }",
    );
    assert!(attributes.signatures.is_empty());

    let declspec = parse(
        "__declspec(noinline) int first(int value) { return value; }\n__declspec(nothrow) int second(int value) { return value; }",
    );
    assert!(declspec.signatures.is_empty());

    let calling_convention = parse(
        "int __cdecl first(int value) { return value; }\nint __stdcall second(int value) { return value; }",
    );
    assert!(calling_convention.signatures.is_empty());
}

#[test]
fn signatures_reject_variadic_and_function_pointer_parameters() {
    for source in [
        "int variadic(int first, ...) { return first; }",
        "int callback(int (*handler)(int)) { return 0; }",
        "int broken(int value { return value; }",
    ] {
        let file = parse(source);
        assert!(
            file.signatures.is_empty(),
            "unsupported signature must not be guessed: {source:?}"
        );
    }
}

#[test]
fn signatures_keep_healthy_units_when_another_header_is_broken() {
    let source = "int healthy(int value) { MACRO_BODY(value); return value; }\nint broken(int value { return value; }";
    let file = parse(source);
    assert!(!file.error_ranges.is_empty());
    assert_eq!(file.signatures.len(), 1);
    let (range, signature) = &file.signatures[0];
    assert!(source[range.start..range.end].contains("healthy"));
    assert!(signature.normalized.contains("receiver=free"));
}

#[test]
fn signatures_keep_a_healthy_header_when_its_body_has_an_error() {
    let source =
        "int healthy(int value) { @@@ return value; }\nint broken(int value { return value; }";
    let file = parse(source);
    assert!(!file.error_ranges.is_empty());
    assert_eq!(file.signatures.len(), 1);
    let (range, _) = &file.signatures[0];
    assert!(source[range.start..range.end].contains("healthy"));
}

#[test]
fn macro_built_function_declarations_are_not_signatures() {
    for source in [
        "API(int) first(int value) { return value; }",
        "API(foo)(int value) { return value; }",
        "TEST(Suite, Case) { return 0; }",
    ] {
        let file = parse(source);
        assert!(
            file.signatures.is_empty(),
            "macro-built declaration must be unsupported: {source:?}"
        );
    }
    let body_macro = parse("int body_macro(int value) { API(value); return value; }");
    assert_eq!(body_macro.signatures.len(), 1);
}

fn assert_bounded_depth_truncation(file: &SyntaxIrFile, source_len: usize) {
    assert!(
        file.depth_truncated,
        "a depth-limited parse must be distinguished from ordinary recovery"
    );
    let mut deepest = 0;
    let mut error_leaves = Vec::new();
    let mut pending: Vec<(&IrNode, usize)> = file.roots.iter().map(|root| (root, 1)).collect();
    while let Some((node, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        if node.shape == Shape::Error && node.children.is_empty() {
            error_leaves.push(node.range);
        }
        pending.extend(node.children.iter().rev().map(|child| (child, depth + 1)));
    }

    assert!(
        deepest <= MAX_IR_DEPTH,
        "IR depth {deepest} exceeds the frontend limit {MAX_IR_DEPTH}"
    );
    assert!(
        error_leaves.iter().any(|range| {
            !range.is_empty() && range.end <= source_len && file.error_ranges.contains(range)
        }),
        "depth truncation must be represented by an Error leaf and error range"
    );

    let mut visited = 0;
    file.walk(&mut |_| visited += 1);
    assert_eq!(visited, file.node_count());
}

#[test]
fn deeply_nested_c_is_truncated_without_unbounded_ir() {
    let control = parse("int control(void) { return 0; }");
    assert!(control.error_ranges.is_empty());
    assert!(
        control.roots.iter().all(|node| node.shape != Shape::Error),
        "normal input remains unchanged"
    );

    let depth = 10_000;
    let mut source = String::from("int deeply_nested(void) ");
    source.push_str(&"{".repeat(depth));
    source.push(';');
    source.push_str(&"}".repeat(depth));

    let file = parse(&source);
    assert_bounded_depth_truncation(&file, source.len());
    drop(file);
    drop(control);
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
    let file =
        parse("int first(void) { return 1; }\nint broken( { ;\nint second(void) { return 2; }\n");
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
    // A reserved word, exactly as the Fast lexer reads it.
    assert_eq!(kind_of("true"), Some(TokenKind::Keyword));
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

/// The [`TokenKind`] both modes give the first occurrence of `word` in
/// `source`, or `None` where a mode did not produce that lexeme at all.
fn token_kinds_of(source: &str, word: &str) -> (Option<TokenKind>, Option<TokenKind>) {
    let structural = parse(source);
    let (fast, _) = crate::lexer::lex(source, &crate::dialect::C);
    let structural_kind = structural
        .tokens
        .iter()
        .find(|token| token.text == word)
        .map(|token| token.kind);
    let fast_kind = fast
        .iter()
        .find(|token| token.text == word)
        .map(|token| token.kind);
    (fast_kind, structural_kind)
}

#[test]
fn both_modes_read_a_boolean_constant_as_the_same_token() {
    // A pair of units differing only in a boolean constant must be told apart
    // the same way whichever mode read them, so the two frontends have to
    // agree on what kind of token the constant is.
    let source = "int f(void) { return g(true) + h(false); }";
    for word in ["true", "false"] {
        let (fast, structural) = token_kinds_of(source, word);
        assert_eq!(structural, Some(TokenKind::Keyword), "{word}");
        assert_eq!(fast, structural, "{word} in both modes");
    }
}

#[test]
fn both_modes_read_every_reserved_word_as_a_keyword() {
    // Spellings the structural grammar does not model surface as identifier
    // leaves. Read as identifiers they would enter the API-call profile as
    // callees and would alpha-normalize against user type names, so both
    // modes must agree that a reserved word is a keyword — for the whole
    // dialect vocabulary, not for the words that happened to expose it.
    for word in crate::dialect::C.keywords {
        // A declaration context every spelling can stand in without the
        // grammar rewriting the lexeme itself.
        let source = format!("int probe(void) {{ {word} ; }}");
        let (fast, structural) = token_kinds_of(&source, word);
        assert_eq!(fast, Some(TokenKind::Keyword), "{word} in fast mode");
        assert_eq!(structural, fast, "{word} in both modes");
    }
}

#[test]
fn the_keyword_set_is_what_lifts_an_identifier_leaf_to_a_keyword() {
    // Without the dialect's vocabulary the grammar's own view stands, and a
    // spelling it does not model reads as an identifier. This is the step that
    // keeps the structural stream in line with the Fast lexer, so it is
    // asserted directly rather than only through its effect.
    for word in ["_Bool", "typeof", "static_assert"] {
        assert_eq!(
            classify_token("identifier", true, word, &[]),
            TokenKind::Identifier,
            "{word}"
        );
        assert_eq!(
            classify_token("identifier", true, word, crate::dialect::C.keywords),
            TokenKind::Keyword,
            "{word}"
        );
    }
    // A declared name that is not reserved keeps its own kind.
    assert_eq!(
        classify_token(
            "identifier",
            true,
            "typeof_helper",
            crate::dialect::C.keywords
        ),
        TokenKind::Identifier
    );
}

#[test]
fn both_modes_agree_on_reserved_words_the_grammar_leaves_as_identifiers() {
    let source = "\
_Static_assert(1, \"ok\");\n\
static_assert(1, \"ok\");\n\
_Thread_local int counter;\n\
int classify(int n) {\n\
    _Bool flag = 0;\n\
    typeof(n) copy = n;\n\
    switch (n) { default: break; }\n\
    return flag + copy;\n\
}\n";
    for word in [
        "_Bool",
        "_Static_assert",
        "static_assert",
        "typeof",
        "_Thread_local",
        "default",
    ] {
        let (fast, structural) = token_kinds_of(source, word);
        assert_eq!(fast, Some(TokenKind::Keyword), "{word} in fast mode");
        assert_eq!(structural, fast, "{word} in both modes");
    }
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
