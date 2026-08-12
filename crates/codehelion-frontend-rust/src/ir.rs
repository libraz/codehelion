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
//! recorded as nodes over their raw token trees. Malformed regions and
//! CST-depth truncation become [`Shape::Error`] nodes plus byte ranges in
//! [`SyntaxIrFile::error_ranges`].
//! Delimiter nesting is checked with the nonrecursive lexer before the Rust
//! parser constructs its CST, so excessive nesting also becomes explicit
//! truncation data.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{
    Lexeme, LexemeInterner, LiteralKind, SourceSpan, Token, TokenKind,
};
use codehelion_core::ir::{
    ByteRange, IR_SCHEMA_VERSION, IrNode, MAX_IR_DEPTH, Shape, Signature, StructuralFrontend,
    SyntaxIrFile, canonicalize_signatures,
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

/// Return the source range that must not enter the recursive Rust CST parser.
///
/// The Rust lexer is nonrecursive and already treats comments and literals as
/// atomic tokens, so delimiter text inside either cannot be mistaken for
/// syntax here. The parser is only entered while this same nesting budget can
/// still bound the structural IR it would produce.
fn delimiter_nesting_overflow(tokens: &[Token], source_len: usize) -> Option<ByteRange> {
    let mut expected_closers = Vec::new();
    for token in tokens {
        match token.text.as_str() {
            "{" => expected_closers.push("}"),
            "(" => expected_closers.push(")"),
            "[" => expected_closers.push("]"),
            "}" | ")" | "]" if expected_closers.last() == Some(&token.text.as_str()) => {
                expected_closers.pop();
            }
            _ => continue,
        }

        if expected_closers.len() > MAX_IR_DEPTH {
            return Some(ByteRange {
                start: token.span.start_byte,
                end: source_len,
            });
        }
    }
    None
}

/// Build the explicit partial result returned when preflight blocks CST
/// construction for excessive delimiter nesting.
fn depth_error_file(source: &str, tokens: Vec<Token>, range: ByteRange) -> SyntaxIrFile {
    // The delimiter preflight tells us where recursive parsing must stop, but
    // it does not make the source before that point unusable. Parse that
    // prefix independently so healthy functions remain available even when a
    // later generated expression exceeds the depth budget.
    let prefix_end = safe_depth_prefix_end(&tokens, range);
    let omitted_range = ByteRange {
        start: prefix_end,
        end: range.end,
    };
    let prefix = source.get(..prefix_end).unwrap_or("");
    let parse = SourceFile::parse(prefix, PARSE_EDITION);
    let root = parse.syntax_node();
    let mut builder = IrBuilder::new(prefix);
    builder.collect_tokens(&root);
    let mut roots = Vec::new();
    for child in root.children() {
        builder.visit(&child, &mut roots, 1);
    }
    for error in parse.errors() {
        let error_range = error.range();
        builder.error_ranges.push(ByteRange {
            start: usize::from(error_range.start()),
            end: usize::from(error_range.end()),
        });
    }
    builder.error_ranges.push(omitted_range);
    builder
        .error_ranges
        .sort_unstable_by_key(|error_range| (error_range.start, error_range.end));
    builder.error_ranges.dedup();

    let token_start = tokens.partition_point(|token| token.span.start_byte < omitted_range.start);
    let token_end = tokens.partition_point(|token| token.span.start_byte < omitted_range.end);
    roots.push(IrNode {
        shape: Shape::Error,
        name: None,
        token_start,
        token_end,
        range: omitted_range,
        children: Vec::new(),
    });
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: STRUCTURAL_FRONTEND_VERSION,
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens,
        signatures: canonicalize_signatures(builder.signatures),
        roots,
        diagnostics: Vec::new(),
        error_ranges: builder.error_ranges,
        depth_truncated: true,
        test_module: false,
    }
}

/// Keep the recovery parse shallow enough that the parser itself cannot
/// overflow its native call stack while still retaining top-level units that
/// precede a pathological nesting run. The omitted range is represented as
/// one explicit Error leaf below.
fn safe_depth_prefix_end(tokens: &[Token], overflow: ByteRange) -> usize {
    let safe_limit = (MAX_IR_DEPTH / 8).max(1);
    let mut expected_closers = Vec::new();
    for token in tokens {
        if token.span.start_byte >= overflow.start {
            break;
        }
        match token.text.as_str() {
            "{" => expected_closers.push("}"),
            "(" => expected_closers.push(")"),
            "[" => expected_closers.push("]"),
            "}" | ")" | "]" if expected_closers.last() == Some(&token.text.as_str()) => {
                expected_closers.pop();
            }
            _ => continue,
        }
        if expected_closers.len() >= safe_limit {
            return token.span.start_byte;
        }
    }
    overflow.start
}

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
        let (preflight_tokens, _) = crate::lexer::lex(source);
        if let Some(range) = delimiter_nesting_overflow(&preflight_tokens, source.len()) {
            return depth_error_file(source, preflight_tokens, range);
        }

        let parse = SourceFile::parse(source, PARSE_EDITION);
        let root = parse.syntax_node();

        let mut builder = IrBuilder::new(source);
        builder.collect_tokens(&root);

        let mut roots = Vec::new();
        for child in root.children() {
            builder.visit(&child, &mut roots, 1);
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

        let signatures = canonicalize_signatures(builder.signatures);

        SyntaxIrFile {
            language: Language::Rust,
            frontend_version: STRUCTURAL_FRONTEND_VERSION,
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: builder.tokens,
            signatures,
            roots,
            // Lexical diagnostics are a Fast-lexer concept; the structural
            // frontend reports problems through `error_ranges` only.
            diagnostics: Vec::new(),
            error_ranges: builder.error_ranges,
            depth_truncated: builder.depth_truncated,
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
/// input, which invalidates every result recorded under the old table. Before
/// the first release that is settled by rescanning rather than by raising
/// [`STRUCTURAL_FRONTEND_VERSION`], which stays at v1.
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
        SyntaxKind::BIN_EXPR => binary_operator(node).map_or(Mapping::Transparent, Mapping::Native),
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

/// Build the conservative signature side-table entry for one Rust function.
///
/// The CST gives us the type nodes directly, so the function name and every
/// parameter pattern can be left out without guessing where an identifier is
/// part of a type. A function whose parameter type is itself a function
/// pointer, a macro or an incomplete/error node is deliberately unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GenericBinding {
    name: String,
    role: &'static str,
    index: usize,
}

fn rust_signature(node: &SyntaxNode) -> Option<Signature> {
    let parameter_list = rust_signature_parameter_list(node)?;
    let generic_lists = rust_generic_parameter_lists(node);
    let generic_bindings = rust_generic_bindings(&generic_lists)?;
    let ancestor_where_clauses = rust_generic_where_clauses(node);
    if rust_has_nested_generic_binder(node, &ancestor_where_clauses) {
        return None;
    }
    let body_start: usize = node
        .children()
        .find(|child| child.kind() == SyntaxKind::BLOCK_EXPR)
        .map_or_else(
            || usize::from(parameter_list.text_range().start()),
            |body| usize::from(body.text_range().start()),
        );
    if node
        .children()
        .filter(|child| usize::from(child.text_range().start()) < body_start)
        .any(|child| {
            child.kind() != SyntaxKind::ATTR
                && child.descendants().any(|descendant| {
                    matches!(
                        descendant.kind(),
                        SyntaxKind::ERROR | SyntaxKind::MACRO_CALL
                    )
                })
        })
    {
        return None;
    }
    let receiver = rust_receiver_kind(node, &parameter_list);
    let mut normalized = String::from("rust|receiver=");
    normalized.push_str(receiver);
    normalized.push_str("|qual=");
    let mut generic = String::new();
    let mut qualifiers = String::new();
    for element in node.children_with_tokens() {
        match element {
            ra_ap_syntax::NodeOrToken::Node(child) => match child.kind() {
                SyntaxKind::VISIBILITY
                | SyntaxKind::ATTR
                | SyntaxKind::NAME
                | SyntaxKind::PARAM_LIST
                | SyntaxKind::RET_TYPE
                | SyntaxKind::BLOCK_EXPR
                | SyntaxKind::GENERIC_PARAM_LIST => {}
                _ => push_signature_chunk(
                    &mut qualifiers,
                    &compact_element_with_generics(&child, &generic_bindings),
                ),
            },
            ra_ap_syntax::NodeOrToken::Token(token) => {
                let text = token.text();
                if !matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT)
                    && !matches!(text, "fn" | ";")
                {
                    push_signature_token(&mut qualifiers, text);
                }
            }
        }
    }
    for where_clause in &ancestor_where_clauses {
        push_signature_chunk(
            &mut qualifiers,
            &compact_node_with_generics(where_clause, &generic_bindings),
        );
    }
    for list in &generic_lists {
        push_signature_chunk(
            &mut generic,
            &compact_node_with_generics(list, &generic_bindings),
        );
    }
    normalized.push_str(&qualifiers);
    normalized.push_str("|generic=");
    normalized.push_str(&generic);
    normalized.push_str("|params=");
    for parameter in parameter_list.children() {
        let parameter_text = match parameter.kind() {
            SyntaxKind::SELF_PARAM => compact_node_with_generics(&parameter, &generic_bindings),
            SyntaxKind::PARAM => rust_parameter_signature(&parameter, &generic_bindings)?,
            _ => return None,
        };
        normalized.push('[');
        normalized.push_str(&parameter_text);
        normalized.push(']');
    }
    normalized.push_str("|return=");
    if let Some(return_type) = node
        .children()
        .find(|child| child.kind() == SyntaxKind::RET_TYPE)
    {
        normalized.push_str(&rust_return_signature(&return_type, &generic_bindings)?);
    } else {
        normalized.push_str("()");
    }

    Some(Signature::new(Language::Rust, normalized))
}

fn rust_generic_parameter_lists(node: &SyntaxNode) -> Vec<SyntaxNode> {
    let mut lists: Vec<SyntaxNode> = node
        .ancestors()
        .skip(1)
        .filter(|ancestor| matches!(ancestor.kind(), SyntaxKind::IMPL | SyntaxKind::TRAIT))
        .filter_map(|ancestor| {
            ancestor
                .children()
                .find(|child| child.kind() == SyntaxKind::GENERIC_PARAM_LIST)
        })
        .collect();
    lists.reverse();
    if let Some(function_list) = node
        .children()
        .find(|child| child.kind() == SyntaxKind::GENERIC_PARAM_LIST)
    {
        lists.push(function_list);
    }
    lists
}

fn rust_generic_where_clauses(node: &SyntaxNode) -> Vec<SyntaxNode> {
    let mut clauses: Vec<SyntaxNode> = node
        .ancestors()
        .skip(1)
        .filter(|ancestor| matches!(ancestor.kind(), SyntaxKind::IMPL | SyntaxKind::TRAIT))
        .filter_map(|ancestor| {
            ancestor
                .children()
                .find(|child| child.kind() == SyntaxKind::WHERE_CLAUSE)
        })
        .collect();
    clauses.reverse();
    clauses
}

fn rust_has_nested_generic_binder(
    node: &SyntaxNode,
    ancestor_where_clauses: &[SyntaxNode],
) -> bool {
    node.children()
        .filter(|child| child.kind() != SyntaxKind::BLOCK_EXPR)
        .any(|child| {
            child.kind() == SyntaxKind::FOR_BINDER
                || child
                    .descendants()
                    .any(|descendant| descendant.kind() == SyntaxKind::FOR_BINDER)
        })
        || ancestor_where_clauses.iter().any(|clause| {
            clause
                .descendants()
                .any(|descendant| descendant.kind() == SyntaxKind::FOR_BINDER)
        })
}

fn rust_generic_bindings(lists: &[SyntaxNode]) -> Option<Vec<GenericBinding>> {
    let mut bindings = Vec::new();
    for list in lists {
        for parameter in list.children() {
            let (role, name) = match parameter.kind() {
                SyntaxKind::TYPE_PARAM => ("type", rust_generic_name(&parameter)?),
                SyntaxKind::LIFETIME_PARAM => ("lifetime", rust_generic_name(&parameter)?),
                SyntaxKind::CONST_PARAM => ("const", rust_generic_name(&parameter)?),
                _ => return None,
            };
            if bindings
                .iter()
                .any(|binding: &GenericBinding| binding.name == name)
            {
                return None;
            }
            let index = bindings
                .iter()
                .filter(|binding| binding.role == role)
                .count();
            bindings.push(GenericBinding { name, role, index });
        }
    }
    Some(bindings)
}

fn rust_generic_name(parameter: &SyntaxNode) -> Option<String> {
    if parameter.kind() == SyntaxKind::LIFETIME_PARAM {
        return parameter
            .descendants_with_tokens()
            .filter_map(ra_ap_syntax::NodeOrToken::into_token)
            .find(|token| token.kind() == SyntaxKind::LIFETIME_IDENT)
            .map(|token| token.text().to_owned());
    }
    parameter
        .children()
        .find(|child| child.kind() == SyntaxKind::NAME)
        .map(|name| name.text().to_string())
}

fn rust_signature_parameter_list(node: &SyntaxNode) -> Option<SyntaxNode> {
    // A foreign item inherits its ABI from the surrounding `extern` block.
    // The local function node does not carry that ancestor in the same shape
    // as an `extern "C" fn` item, so retaining it here would risk colliding
    // distinct foreign ABIs. Until inherited ABI is modelled, reject it.
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == SyntaxKind::EXTERN_BLOCK {
            return None;
        }
        ancestor = current.parent();
    }
    if !node
        .children()
        .any(|child| child.kind() == SyntaxKind::BLOCK_EXPR)
    {
        // Bodyless declarations are valid required trait items, but the
        // grammar also recovers invalid top-level and impl `fn f();` items.
        let mut context = node.parent();
        let in_trait = loop {
            let Some(current) = context else {
                break false;
            };
            if current.kind() == SyntaxKind::TRAIT {
                break true;
            }
            context = current.parent();
        };
        if !in_trait {
            return None;
        }
    }
    node.children()
        .find(|child| child.kind() == SyntaxKind::PARAM_LIST)
}

fn rust_return_signature(
    return_type: &SyntaxNode,
    generic_bindings: &[GenericBinding],
) -> Option<String> {
    if return_type.descendants().any(|child| {
        matches!(
            child.kind(),
            SyntaxKind::ERROR | SyntaxKind::MACRO_CALL | SyntaxKind::FN_PTR_TYPE
        )
    }) {
        return None;
    }
    let type_node = return_type
        .children()
        .find(|child| format!("{:?}", child.kind()).ends_with("_TYPE"))?;
    Some(compact_node_with_generics(&type_node, generic_bindings))
}

/// Classify the declaration context without including the associated type or
/// function name. Receiver presence is a semantic part of a Rust method's
/// callable shape, while a self-less associated function is distinct from a
/// free function even when all type fields match.
fn rust_receiver_kind<'a>(node: &SyntaxNode, parameters: &SyntaxNode) -> &'a str {
    if node
        .parent()
        .is_none_or(|parent| parent.kind() != SyntaxKind::ASSOC_ITEM_LIST)
    {
        return "free";
    }
    if parameters.children().any(|parameter| {
        parameter.kind() == SyntaxKind::SELF_PARAM
            || (parameter.kind() == SyntaxKind::PARAM
                && rust_parameter_has_self_pattern(&parameter))
    }) {
        "instance"
    } else {
        "associated"
    }
}

fn rust_parameter_has_self_pattern(parameter: &SyntaxNode) -> bool {
    parameter
        .children()
        .find(|child| format!("{:?}", child.kind()).ends_with("_PAT"))
        .is_some_and(|pattern| {
            let tokens: Vec<String> = pattern
                .descendants_with_tokens()
                .filter_map(ra_ap_syntax::NodeOrToken::into_token)
                .filter(|token| {
                    !matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT)
                })
                .map(|token| token.text().to_owned())
                .collect();
            tokens == ["self"] || tokens == ["mut", "self"]
        })
}

/// Extract one Rust parameter's type while omitting its pattern/name.
fn rust_parameter_signature(
    parameter: &SyntaxNode,
    generic_bindings: &[GenericBinding],
) -> Option<String> {
    if parameter.descendants().any(|child| {
        matches!(
            child.kind(),
            SyntaxKind::ERROR | SyntaxKind::MACRO_CALL | SyntaxKind::FN_PTR_TYPE
        )
    }) {
        return None;
    }
    let children: Vec<SyntaxNode> = parameter.children().collect();
    let type_node = children.iter().rev().find(|child| {
        let kind = format!("{:?}", child.kind());
        kind.ends_with("_TYPE")
    })?;
    let mut normalized = compact_node_with_generics(type_node, generic_bindings);
    let self_pattern = rust_parameter_has_self_pattern(parameter);
    if self_pattern {
        normalized.insert_str(0, "self:");
    }
    if parameter.children_with_tokens().any(|element| {
        matches!(
            element,
            ra_ap_syntax::NodeOrToken::Token(token) if token.text() == "const"
        )
    }) {
        normalized.insert_str(0, "const");
    }
    Some(normalized)
}

fn compact_node_with_generics(node: &SyntaxNode, generic_bindings: &[GenericBinding]) -> String {
    let mut out = String::new();
    for token in node
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| {
            !token
                .parent_ancestors()
                .any(|ancestor| ancestor.kind() == SyntaxKind::ATTR)
        })
        .filter(|token| !matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT))
    {
        if let Some(binding) = rust_generic_binding_for_token(&token, generic_bindings) {
            push_signature_generic(&mut out, binding);
        } else {
            push_signature_token(&mut out, token.text());
        }
    }
    out
}

fn compact_element_with_generics(node: &SyntaxNode, generic_bindings: &[GenericBinding]) -> String {
    compact_node_with_generics(node, generic_bindings)
}

fn rust_generic_binding_for_token<'a>(
    token: &ra_ap_syntax::SyntaxToken,
    generic_bindings: &'a [GenericBinding],
) -> Option<&'a GenericBinding> {
    let binding = generic_bindings
        .iter()
        .find(|binding| binding.name == token.text())?;
    if token
        .prev_token()
        .is_some_and(|previous| previous.kind() == SyntaxKind::COLON2)
    {
        return None;
    }
    if rust_is_associated_type_label(token) {
        return None;
    }
    if rust_is_field_expr_member(token) {
        return None;
    }
    Some(binding)
}

fn rust_is_associated_type_label(token: &ra_ap_syntax::SyntaxToken) -> bool {
    let Some(associated) = token
        .parent_ancestors()
        .find(|ancestor| ancestor.kind() == SyntaxKind::ASSOC_TYPE_ARG)
    else {
        return false;
    };
    let first = associated
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .find(|candidate| {
            !matches!(
                candidate.kind(),
                SyntaxKind::WHITESPACE | SyntaxKind::COMMENT
            )
        });
    first.is_some_and(|first| first.text_range() == token.text_range())
}

fn rust_is_field_expr_member(token: &ra_ap_syntax::SyntaxToken) -> bool {
    if !token.parent_ancestors().any(|ancestor| {
        matches!(
            ancestor.kind(),
            SyntaxKind::FIELD_EXPR | SyntaxKind::METHOD_CALL_EXPR
        )
    }) {
        return false;
    }
    let mut previous = token.prev_token();
    while previous
        .as_ref()
        .is_some_and(|token| matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT))
    {
        previous = previous.and_then(|token| token.prev_token());
    }
    previous.is_some_and(|token| token.kind() == SyntaxKind::DOT)
}

/// Keep every non-trivia Rust token boundary explicit. Literal tokens are
/// emitted atomically, so whitespace inside a string or raw string remains
/// payload rather than becoming a separator.
fn push_signature_token(output: &mut String, token: &str) {
    use core::fmt::Write as _;

    let _ = write!(output, "t{}:{}", token.len(), token);
}

fn push_signature_generic(output: &mut String, binding: &GenericBinding) {
    use core::fmt::Write as _;

    let _ = write!(output, "g{}{};", binding.role, binding.index);
}

fn push_signature_chunk(output: &mut String, chunk: &str) {
    if chunk.is_empty() {
        return;
    }
    output.push_str(chunk);
}

/// Whether a `BIN_EXPR`'s operator token is `=` or a compound assignment.
/// Operands are child nodes, so the only child tokens besides trivia are the
/// operator itself.
fn is_assignment(node: &SyntaxNode) -> bool {
    node.children_with_tokens()
        .filter_map(ra_ap_syntax::SyntaxElement::into_token)
        .any(|token| ASSIGN_OPS.contains(&token.kind()))
}

/// Stable native shape for a non-assignment binary operation.
fn binary_operator(node: &SyntaxNode) -> Option<&'static str> {
    node.children_with_tokens()
        .filter_map(ra_ap_syntax::SyntaxElement::into_token)
        .map(|token| token.kind())
        .find_map(|operator| match operator {
            SyntaxKind::PLUS => Some("binary-add"),
            SyntaxKind::MINUS => Some("binary-sub"),
            SyntaxKind::STAR => Some("binary-mul"),
            SyntaxKind::SLASH => Some("binary-div"),
            SyntaxKind::PERCENT => Some("binary-rem"),
            SyntaxKind::SHL => Some("binary-shl"),
            SyntaxKind::SHR => Some("binary-shr"),
            SyntaxKind::AMP => Some("binary-bit-and"),
            SyntaxKind::PIPE => Some("binary-bit-or"),
            SyntaxKind::CARET => Some("binary-bit-xor"),
            SyntaxKind::AMP2 => Some("binary-and"),
            SyntaxKind::PIPE2 => Some("binary-or"),
            SyntaxKind::EQ2 => Some("binary-eq"),
            SyntaxKind::NEQ => Some("binary-ne"),
            SyntaxKind::L_ANGLE => Some("binary-lt"),
            SyntaxKind::R_ANGLE => Some("binary-gt"),
            SyntaxKind::LTEQ => Some("binary-le"),
            SyntaxKind::GTEQ => Some("binary-ge"),
            _ => None,
        })
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
    signatures: Vec<(ByteRange, Signature)>,
    depth_truncated: bool,
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
            signatures: Vec::new(),
            depth_truncated: false,
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
    fn visit(&mut self, cst: &SyntaxNode, out: &mut Vec<IrNode>, depth: usize) {
        if depth >= MAX_IR_DEPTH {
            self.emit_depth_error(cst, out);
            return;
        }

        match classify(cst) {
            Mapping::Emit(shape) => {
                let name = self.node_name(cst);
                if matches!(shape, Shape::Function | Shape::Method)
                    && cst.kind() == SyntaxKind::FN
                    && let Some(signature) = rust_signature(cst)
                {
                    self.signatures.push((byte_range(cst), signature));
                }
                let node = self.build_node(shape, name, cst, depth);
                out.push(node);
            }
            Mapping::Native(kind) => {
                let shape = Shape::Native(self.interner.intern(kind));
                let node = self.build_node(shape, None, cst, depth);
                out.push(node);
            }
            Mapping::ExprStmt => {
                if inner_expression_emits(cst) {
                    // The inner expression's own node is the statement.
                    for child in cst.children() {
                        self.visit(&child, out, depth + 1);
                    }
                } else {
                    let node = self.build_node(Shape::ExprStmt, None, cst, depth);
                    out.push(node);
                }
            }
            Mapping::Error => {
                self.error_ranges.push(byte_range(cst));
                // Recurse anyway: real parsers wrap intact regions in error
                // nodes, and those descendants must still be recovered.
                let node = self.build_node(Shape::Error, None, cst, depth);
                out.push(node);
            }
            Mapping::Transparent => {
                for child in cst.children() {
                    self.visit(&child, out, depth + 1);
                }
            }
        }
    }

    /// Build an [`IrNode`] for `cst`, visiting its children first.
    fn build_node(
        &mut self,
        shape: Shape,
        name: Option<Lexeme>,
        cst: &SyntaxNode,
        depth: usize,
    ) -> IrNode {
        let mut children = Vec::new();
        for child in cst.children() {
            self.visit(&child, &mut children, depth + 1);
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

    /// Preserve an unvisited CST subtree as recoverable truncation data.
    fn emit_depth_error(&mut self, cst: &SyntaxNode, out: &mut Vec<IrNode>) {
        let range = byte_range(cst);
        self.depth_truncated = true;
        self.error_ranges.push(range);
        out.push(IrNode {
            shape: Shape::Error,
            name: None,
            token_start: self.token_index_at(range.start),
            token_end: self.token_index_at(range.end),
            range,
            children: Vec::new(),
        });
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
    use codehelion_core::ir::MAX_IR_DEPTH;

    fn parse(source: &str) -> SyntaxIrFile {
        RustStructuralFrontend.parse(source)
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
    fn deeply_nested_rust_is_truncated_without_unbounded_ir() {
        let depth = 10_000;
        let ignored_braces = "{".repeat(depth);
        let control_source =
            format!("fn control() {{ /* {ignored_braces} */ let text = \"{ignored_braces}\"; }}");
        let control = parse(&control_source);
        assert!(control.error_ranges.is_empty());
        assert!(
            control.roots.iter().all(|node| node.shape != Shape::Error),
            "delimiters in comments and literals must not consume nesting budget"
        );

        let mut builder_guard_source = String::from("fn builder_guard() ");
        builder_guard_source.push_str(&"{".repeat(MAX_IR_DEPTH));
        builder_guard_source.push_str("()");
        builder_guard_source.push_str(&"}".repeat(MAX_IR_DEPTH));
        let builder_guard_file = parse(&builder_guard_source);
        assert_bounded_depth_truncation(&builder_guard_file, builder_guard_source.len());

        let mut source = String::from("fn deeply_nested() ");
        source.push_str(&"{".repeat(depth));
        source.push_str("()");
        source.push_str(&"}".repeat(depth));

        let file = parse(&source);
        assert_bounded_depth_truncation(&file, source.len());
        drop(file);
        drop(builder_guard_file);
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
          native:binary-add
      loop
        block
          assign
            call
              native:binary-add
      loop
        native:binary-gt
        block
          assign
      loop
        block
          branch
            native:binary-eq
            block
              break
            branch
              native:binary-lt
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
            vec![Shape::Call, Shape::Native("binary-add".into())],
            "a call statement and a binary expression retain their own shapes"
        );
    }

    #[test]
    fn assignment_operators_map_to_assign_and_comparisons_do_not() {
        let file = parse("fn f() { x = 1; x += 1; x == 1; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![
                Shape::Assign,
                Shape::Assign,
                Shape::Native("binary-eq".into())
            ],
            "assignments and comparisons retain distinct structural shapes"
        );
    }

    #[test]
    fn non_assignment_binary_operators_are_distinct_structural_nodes() {
        let file = parse("fn f(a: u64, b: u64) { a + b; a / b; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![
                Shape::Native("binary-add".into()),
                Shape::Native("binary-div".into())
            ]
        );
        assert_eq!(body.children[0].shape, Shape::Native("binary-add".into()));
        assert_eq!(body.children[1].shape, Shape::Native("binary-div".into()));
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

    #[test]
    fn signatures_are_sorted_exact_and_ignore_parameter_names() {
        let source = "fn first(left: &str, values: [u8; 4]) -> Option<u8> { None }\nfn second(right: &str, items: [u8; 4]) -> Option<u8> { None }";
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
        assert!(first.normalized.contains("t1:&t3:str"));
        assert!(first.normalized.contains("t1:[t2:u8t1:;t1:4t1:]"));
    }

    #[test]
    fn signatures_keep_self_form_and_return_type_distinctions() {
        let borrowed = parse("impl Item { fn value(&self, input: i32) -> i32 { input } }");
        let mutable = parse("impl Item { fn value(&mut self, input: i32) -> i32 { input } }");
        let returned = parse("impl Item { fn value(&self, input: i32) -> i64 { input as i64 } }");
        let typed_self =
            parse("impl Item { fn value(self: Box<Self>, input: i32) -> i32 { input } }");
        assert_ne!(borrowed.signatures[0].1.key, mutable.signatures[0].1.key);
        assert_ne!(borrowed.signatures[0].1.key, returned.signatures[0].1.key);
        assert!(
            typed_self.signatures[0]
                .1
                .normalized
                .contains("t4:selft1::t3:Boxt1:<t4:Selft1:>")
        );
        assert!(
            borrowed.signatures[0]
                .1
                .normalized
                .contains("return=t3:i32")
        );
        assert!(!borrowed.signatures[0].1.normalized.contains("return=->"));
    }

    #[test]
    fn signatures_distinguish_free_associated_and_instance_receivers() {
        let free = parse("fn free(value: i32) -> i32 { value }");
        let associated = parse("impl Item { fn associated(value: i32) -> i32 { value } }");
        let instance = parse("impl Item { fn instance(&self, value: i32) -> i32 { value } }");
        assert!(free.signatures[0].1.normalized.contains("receiver=free"));
        assert!(
            associated.signatures[0]
                .1
                .normalized
                .contains("receiver=associated")
        );
        assert!(
            instance.signatures[0]
                .1
                .normalized
                .contains("receiver=instance")
        );
        assert_ne!(free.signatures[0].1.key, associated.signatures[0].1.key);
        assert_ne!(associated.signatures[0].1.key, instance.signatures[0].1.key);

        let same_kind = parse(
            "impl Item { fn first(value: i32) -> i32 { value } fn second(other: i32) -> i32 { other } }",
        );
        assert_eq!(same_kind.signatures[0].1, same_kind.signatures[1].1);
    }

    #[test]
    fn function_body_macros_do_not_remove_a_valid_signature() {
        let plain = parse("fn value(input: i32) -> i32 { input }");
        let macro_body = parse("fn value(input: i32) -> i32 { todo!() }");
        let malformed_body = parse("fn value(input: i32) -> i32 { let = ; }");
        assert_eq!(plain.signatures[0].1, macro_body.signatures[0].1);
        assert!(!malformed_body.error_ranges.is_empty());
        assert_eq!(plain.signatures[0].1, malformed_body.signatures[0].1);
    }

    #[test]
    fn signatures_keep_healthy_units_when_another_header_is_broken() {
        let source = "fn healthy(value: i32) { todo!(); }\nfn broken(value: ) { return; }";
        let file = parse(source);
        assert!(!file.error_ranges.is_empty());
        assert_eq!(file.signatures.len(), 1);
        let (range, signature) = &file.signatures[0];
        assert!(source[range.start..range.end].contains("healthy"));
        assert!(signature.normalized.contains("receiver=free"));
    }

    #[test]
    fn depth_truncation_keeps_a_signature_before_the_omitted_region() {
        let mut source = String::from("fn healthy(value: i32) -> i32 { value }\nfn deep() ");
        source.push_str(&"{".repeat(MAX_IR_DEPTH + 10));
        source.push(';');
        source.push_str(&"}".repeat(MAX_IR_DEPTH + 10));
        let file = parse(&source);
        assert!(file.depth_truncated);
        assert!(
            file.signatures
                .iter()
                .any(|(range, _)| source[range.start..range.end].contains("healthy"))
        );
    }

    #[test]
    fn signatures_reject_variadic_macro_and_function_pointer_parameters() {
        for source in [
            "fn callback(handler: fn(i32) -> i32) { let _ = handler; }",
            "fn macro_type(value: some_type!()) { let _ = value; }",
            "fn broken(value: ) { let _ = value; }",
        ] {
            let file = parse(source);
            assert!(
                file.signatures.is_empty(),
                "unsupported signature must not be guessed: {source:?}"
            );
        }
    }

    #[test]
    fn signatures_ignore_function_attributes_and_reject_function_pointer_returns() {
        let attributed = parse(
            "#[inline] fn first(value: i32) -> i32 { value }\n#[cold] fn second(other: i32) -> i32 { other }",
        );
        assert_eq!(attributed.signatures.len(), 2);
        assert_eq!(attributed.signatures[0].1, attributed.signatures[1].1);
        assert!(!attributed.signatures[0].1.normalized.contains("inline"));
        assert!(!attributed.signatures[1].1.normalized.contains("cold"));

        for source in [
            "fn callback() -> fn(i32) -> i32 { todo!() }",
            "fn macro_return() -> return_type!() { todo!() }",
            "fn broken() -> { todo!() }",
        ] {
            let file = parse(source);
            assert!(
                file.signatures.is_empty(),
                "unsupported return type must not be guessed: {source:?}"
            );
        }
    }

    #[test]
    fn signatures_keep_abi_and_where_constraints_and_skip_bodyless_semicolons() {
        let abi = parse(
            "extern \"C\" fn first(value: i32) -> i32 { value }\nfn second(other: i32) -> i32 { other }",
        );
        assert_eq!(abi.signatures.len(), 2);
        assert_ne!(abi.signatures[0].1.key, abi.signatures[1].1.key);

        let where_clauses = parse(
            "fn first<T>(value: T) -> T where T: Copy { value }\nfn second<T>(other: T) -> T where T: Copy { other }\nfn third<T>(item: T) -> T where T: Clone { item }",
        );
        assert_eq!(where_clauses.signatures.len(), 3);
        assert_eq!(where_clauses.signatures[0].1, where_clauses.signatures[1].1);
        assert_ne!(
            where_clauses.signatures[0].1.key,
            where_clauses.signatures[2].1.key
        );

        let foreign = parse(
            "extern \"C\" { fn first(value: i32); }\nextern \"system\" { fn second(value: i32); }",
        );
        assert!(foreign.signatures.is_empty());

        let recovered_invalid =
            parse("fn first(value: i32);\nimpl Item { fn second(value: i32); }");
        assert!(recovered_invalid.error_ranges.is_empty());
        assert!(recovered_invalid.signatures.is_empty());

        let bodyless = parse("trait Item { fn first(value: i32); fn second(other: i32) {} }");
        assert!(
            bodyless.error_ranges.is_empty(),
            "{:#?}",
            bodyless.error_ranges
        );
        assert_eq!(bodyless.signatures.len(), 2);
        assert_eq!(bodyless.signatures[0].1, bodyless.signatures[1].1);
        assert!(!bodyless.signatures[0].1.normalized.contains("t1:;"));
    }

    #[test]
    fn signatures_alpha_normalize_ancestor_generics_and_keep_ancestor_where_clauses() {
        let same = parse(
            "impl<T> Thing<T> where T: Copy { fn f<U>(x: T, y: U) -> T where U: Copy { x } }\nimpl<X> Thing<X> where X: Copy { fn f<V>(x: X, y: V) -> X where V: Copy { x } }",
        );
        assert!(same.error_ranges.is_empty(), "{:?}", same.error_ranges);
        assert_eq!(same.signatures.len(), 2);
        assert_eq!(same.signatures[0].1, same.signatures[1].1);

        let different = parse(
            "impl<T> Thing<T> where T: Copy { fn f<U>(x: T, y: U) -> T where U: Copy { x } }\nimpl<X> Thing<X> where X: Clone { fn f<V>(x: X, y: V) -> X where V: Copy { x } }",
        );
        assert!(
            different.error_ranges.is_empty(),
            "{:?}",
            different.error_ranges
        );
        assert_eq!(different.signatures.len(), 2);
        assert_ne!(different.signatures[0].1.key, different.signatures[1].1.key);
        assert!(different.signatures[0].1.normalized.contains("gtype0;"));
    }

    #[test]
    fn signatures_reject_nested_higher_ranked_generic_binders() {
        let file = parse(
            "fn first<T>(value: T) -> impl for<'a> Fn(&'a T) { todo!() }\nfn second<T>(value: T) where T: for<'a> Trait<&'a T> { todo!() }",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert!(file.signatures.is_empty());
    }

    #[test]
    fn signatures_ignore_higher_ranked_binders_inside_function_bodies() {
        let file = parse(
            "fn first<T>(value: T) -> T { let _: for<'a> fn(&'a str) = todo!(); value }\nfn second<U>(renamed: U) -> U { renamed }",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert_eq!(file.signatures.len(), 2);
        assert_eq!(file.signatures[0].1, file.signatures[1].1);
    }

    #[test]
    fn signatures_keep_associated_type_labels_raw_while_alpha_normalizing_type_params() {
        let file = parse(
            "fn first<Item: Iterator<Item = u8>>(value: Item) -> Item { value }\nfn second<T: Iterator<Item = u8>>(value: T) -> T { value }",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert_eq!(file.signatures.len(), 2);
        assert_eq!(file.signatures[0].1, file.signatures[1].1);
        assert!(file.signatures[0].1.normalized.contains("t4:Item"));
    }

    #[test]
    fn signatures_keep_const_field_members_raw_while_alpha_normalizing_const_params() {
        let file = parse(
            "fn first<const N: usize>(value: [u8; { value.N }]) {}\nfn second<const M: usize>(value: [u8; { value.M }]) {}",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert_eq!(file.signatures.len(), 2);
        assert_ne!(file.signatures[0].1.key, file.signatures[1].1.key);
        assert!(file.signatures[0].1.normalized.contains("t1:N"));
        assert!(file.signatures[1].1.normalized.contains("t1:M"));

        let associated_const = parse(
            "fn first<const N: usize>() -> Trait<N = N> { todo!() }\nfn second<const M: usize>() -> Trait<N = M> { todo!() }",
        );
        assert!(
            associated_const.error_ranges.is_empty(),
            "{:?}",
            associated_const.error_ranges
        );
        assert_eq!(associated_const.signatures.len(), 2);
        assert_eq!(
            associated_const.signatures[0].1,
            associated_const.signatures[1].1
        );
        assert!(associated_const.signatures[0].1.normalized.contains("t1:N"));
    }

    #[test]
    fn signatures_keep_method_members_raw_while_alpha_normalizing_const_params() {
        let renamed = parse(
            "fn first<const N: usize>(value: [u8; { value.N() }]) {}\nfn second<const M: usize>(value: [u8; { value.N() }]) {}",
        );
        assert!(
            renamed.error_ranges.is_empty(),
            "{:?}",
            renamed.error_ranges
        );
        assert_eq!(renamed.signatures.len(), 2);
        assert_eq!(renamed.signatures[0].1, renamed.signatures[1].1);

        let changed_method = parse(
            "fn first<const N: usize>(value: [u8; { value.N() }]) {}\nfn second<const N: usize>(value: [u8; { value.M() }]) {}",
        );
        assert!(
            changed_method.error_ranges.is_empty(),
            "{:?}",
            changed_method.error_ranges
        );
        assert_eq!(changed_method.signatures.len(), 2);
        assert_ne!(
            changed_method.signatures[0].1.key,
            changed_method.signatures[1].1.key
        );
    }

    #[test]
    fn signatures_preserve_rust_token_boundaries_and_literal_payload() {
        let boundaries = parse(
            "fn first(value: dyn Fn()) -> i32 { value(); 0 }\nfn second(value: dynFn()) -> i32 { value(); 0 }",
        );
        assert_eq!(boundaries.signatures.len(), 2);
        assert_ne!(
            boundaries.signatures[0].1.key,
            boundaries.signatures[1].1.key
        );

        let literals = parse(
            "fn first(value: [u8; 4]) -> &str { value }\nfn second(value: [u8; 5]) -> &str { value }",
        );
        assert_eq!(literals.signatures.len(), 2);
        assert_ne!(literals.signatures[0].1.key, literals.signatures[1].1.key);
        assert!(literals.signatures[0].1.normalized.contains("t1:4"));
    }
}
