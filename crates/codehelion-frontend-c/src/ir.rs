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
//! Malformed regions and CST-depth truncation become [`Shape::Error`] nodes
//! plus byte ranges in [`SyntaxIrFile::error_ranges`]. If the parser itself
//! cannot be set up (grammar version mismatch) or returns no tree, the file
//! degrades to an empty token stream and node tree with one error range
//! spanning the whole file.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{IrAssembly, Lexeme, LiteralKind, TokenKind};
use codehelion_core::ir::{
    ByteRange, IR_SCHEMA_VERSION, IrNode, MAX_IR_DEPTH, Shape, Signature, StructuralFrontend,
    SyntaxIrFile, canonicalize_signatures,
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
    /// input, which invalidates every result recorded under the old table.
    /// Such a change is settled by rescanning the recorded results, not by
    /// raising the frontend version, which stays at v1.
    fn classify(&self, node: &Node<'_>) -> Mapping;

    /// Recover the declared name of a node that emits a named shape.
    fn node_name<'s>(&self, node: &Node<'_>, source: &'s str) -> Option<&'s str> {
        c_family_node_name(node, source)
    }

    /// Map one CST leaf onto the shared [`TokenKind`] vocabulary.
    fn token_kind(&self, kind: &str, is_named: bool, text: &str) -> TokenKind {
        classify_token(kind, is_named, text)
    }

    /// Build the function/method signature side-table entry for this node.
    fn signature(&self, node: &Node<'_>, source: &str, language: Language) -> Option<Signature> {
        c_family_signature(node, source, language)
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
        // the IR under native nodes. Each kind names itself rather than being
        // read back off the node, because a node's kind borrows from the tree
        // while a native node's name outlives it.
        "preproc_if" => Mapping::Native("preproc_if"),
        "preproc_ifdef" => Mapping::Native("preproc_ifdef"),
        "preproc_else" => Mapping::Native("preproc_else"),
        "preproc_elif" => Mapping::Native("preproc_elif"),
        "preproc_elifdef" => Mapping::Native("preproc_elifdef"),
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
        //
        // `true` and `false` belong here for the same reason: they are
        // reserved words of both dialects and the Fast lexer reads them off
        // the same keyword set. Calling them boolean literals instead would
        // hand the shared literal normalization a difference it is meant to
        // erase, so two units disagreeing only in a boolean constant would
        // normalize alike in Structural mode while Fast mode kept them apart.
        "primitive_type" | "sized_type_specifier" | "auto" | "this" | "true" | "false" => {
            TokenKind::Keyword
        }
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

/// Build a conservative signature for a C-family function definition.
#[allow(clippy::too_many_lines)]
fn c_family_signature(node: &Node<'_>, source: &str, language: Language) -> Option<Signature> {
    if node.kind() != "function_definition" {
        return None;
    }
    // Constructors, destructors and conversion operators have no declared
    // return type. They are intentionally outside this return-bearing
    // signature contract.
    let return_type = node.child_by_field_name("type")?;
    let declarator = node.child_by_field_name("declarator")?;
    let function_declarator = find_function_declarator(declarator)?;
    let parameters = function_declarator.child_by_field_name("parameters")?;
    let parameter_nodes = real_parameter_nodes(parameters);
    if parameter_nodes.iter().any(|parameter| {
        !matches!(
            parameter.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        )
    }) {
        return None;
    }
    let parameter_names = parameter_names(&parameter_nodes, source)?;
    let template_context = c_family_template_context(*node, source)?;
    if parameter_names.iter().any(|(name, _)| {
        template_context
            .bindings
            .iter()
            .any(|binding| binding.name.as_deref() == Some(name.as_str()))
    }) {
        return None;
    }
    if !c_family_header_is_supported(*node, return_type, declarator, function_declarator) {
        return None;
    }

    let mut normalized = String::from("c-family|receiver=");
    normalized.push_str(c_family_receiver_kind(node, declarator, source, language));
    normalized.push('|');
    if template_context.templates.is_empty() {
        normalized.push_str("template=|template_requires=|");
    } else {
        normalized.push_str("template=");
        for template in &template_context.templates {
            let parameters = template.child_by_field_name("parameters")?;
            normalized.push_str(&compact_template_parameters(
                parameters,
                source,
                &template_context.bindings,
            ));
        }
        normalized.push('|');
        normalized.push_str("template_requires=");
        for requires in &template_context.requires {
            normalized.push_str(&compact_node_with_generics(
                *requires,
                source,
                &template_context.bindings,
            ));
        }
        normalized.push('|');
    }
    normalized.push_str("template_args=");
    let function_name = function_declarator
        .child_by_field_name("declarator")
        .unwrap_or(declarator);
    normalized.push_str(&template_arguments(
        function_name,
        source,
        &template_context.bindings,
    ));
    normalized.push('|');
    normalized.push_str("return=");
    let trailing_return = {
        let mut cursor = function_declarator.walk();
        function_declarator
            .named_children(&mut cursor)
            .find(|child| child.kind() == "trailing_return_type")
    };
    if let Some(trailing_return) = trailing_return {
        let actual_type = trailing_return.child_by_field_name("type").or_else(|| {
            let mut cursor = trailing_return.walk();
            trailing_return
                .named_children(&mut cursor)
                .find(|child| child.kind() == "type_descriptor")
        })?;
        normalized.push_str(&compact_node_with_parameter_refs(
            actual_type,
            source,
            &[],
            None,
            &parameter_names,
            &template_context.bindings,
        )?);
    } else {
        normalized.push_str(&return_type_signature(
            *node,
            return_type,
            declarator,
            function_declarator,
            source,
            &template_context.bindings,
        ));
    }
    normalized.push_str("|params=");
    if contains_variadic_marker(parameters) {
        return None;
    }
    for (position, parameter) in parameter_nodes.iter().enumerate() {
        let in_scope: Vec<(String, usize)> = parameter_names
            .iter()
            .filter(|(_, index)| *index < position)
            .cloned()
            .collect();
        let value =
            c_parameter_signature(*parameter, source, &in_scope, &template_context.bindings)?;
        normalized.push('[');
        normalized.push_str(&value);
        normalized.push(']');
    }
    normalized.push_str("|qual=");
    let parameter_end = parameters.end_byte();
    let excluded = trailing_return.map(|trailing_return| node_range(&trailing_return));
    let excluded_ranges: &[ByteRange] = excluded.as_slice();
    let qualifier = compact_node_between_with_parameter_refs(
        function_declarator,
        source,
        parameter_end,
        excluded_ranges,
        &parameter_names,
        &template_context.bindings,
    )?;
    normalized.push_str(&qualifier);

    Some(Signature::new(language, normalized))
}

fn c_family_header_is_supported(
    node: Node<'_>,
    return_type: Node<'_>,
    declarator: Node<'_>,
    function_declarator: Node<'_>,
) -> bool {
    if has_unsupported_header(&return_type)
        || has_unsupported_header(&declarator)
        || contains_nested_function_declarator(function_declarator)
        || contains_requires_parameter_binding(function_declarator)
        || contains_header_kind(function_declarator, "lambda_expression")
        || (return_type.kind() == "type_identifier"
            && contains_kind(declarator, "parenthesized_declarator"))
        || has_unsupported_declaration_attribute(node)
        || containing_template(node).is_some_and(|parameters| has_unsupported_header(&parameters))
        || containing_template_requires(node).is_some_and(|requires| {
            has_unsupported_header(&requires) || contains_requires_parameter_binding(requires)
        })
        || containing_template(node)
            .is_some_and(|parameters| has_unsupported_declaration_attribute(parameters))
    {
        return false;
    }
    true
}

/// Return a parameter's type and declarator modifiers, excluding its name and
/// any default value. K&R identifiers and nested function-pointer parameters
/// never reach this path because they have no parameter declaration node or
/// are rejected by the header-only unsupported checks.
fn c_parameter_signature(
    parameter: Node<'_>,
    source: &str,
    parameters: &[(String, usize)],
    generic_bindings: &[GenericBinding],
) -> Option<String> {
    if parameter.has_error()
        || has_unsupported_parameter_descendant(parameter)
        || contains_kind(parameter, "function_declarator")
        || contains_variadic_marker(parameter)
    {
        return None;
    }
    let type_node = parameter.child_by_field_name("type")?;
    let end = parameter
        .child_by_field_name("declarator")
        .map_or_else(|| type_node.end_byte(), |declarator| declarator.end_byte());
    let name = parameter
        .child_by_field_name("declarator")
        .and_then(declarator_leaf);
    let excluded = name.map(|node| ByteRange {
        start: node.start_byte(),
        end: node.end_byte(),
    });
    let excluded_ranges: &[ByteRange] = excluded.as_slice();
    compact_node_with_parameter_refs(
        parameter,
        source,
        excluded_ranges,
        Some(end),
        parameters,
        generic_bindings,
    )
}

fn contains_kind(node: Node<'_>, wanted: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == wanted {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

fn contains_header_kind(node: Node<'_>, wanted: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "default_value" {
            continue;
        }
        if current.kind() == wanted {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

fn contains_variadic_marker(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "default_value" {
            continue;
        }
        if current.kind() == "variadic_parameter_declaration" {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| !is_default_value_child(current, *child)),
        );
        let mut children = current.walk();
        if current.children(&mut children).any(|child| {
            !is_default_value_child(current, child) && !child.is_named() && child.kind() == "..."
        }) {
            return true;
        }
    }
    false
}

/// Find the function declarator in the outer declarator chain.
fn find_function_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "function_declarator" {
            return Some(node);
        }
        node = node
            .child_by_field_name("declarator")
            .or_else(|| node.named_child(0))?;
    }
}

/// Return the terminal identifier in a declarator, used only to remove a
/// parameter name from its otherwise lossless type/declarator text.
fn declarator_leaf(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "field_identifier" | "type_identifier" | "operator_name"
            | "destructor_name" => return Some(node),
            "qualified_identifier" => node = node.child_by_field_name("name")?,
            "pointer_declarator"
            | "pointer_type_declarator"
            | "reference_declarator"
            | "reference_type_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "function_declarator" => {
                node = node
                    .child_by_field_name("declarator")
                    .or_else(|| node.named_child(0))?;
            }
            _ => return None,
        }
    }
}

/// Return the real parameter declarations, excluding comment trivia that the
/// parser exposes as named children of a parameter list.
fn real_parameter_nodes(parameters: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| parameter.kind() != COMMENT_KIND)
        .collect()
}

/// Return parameter declaration names with their stable positional indexes.
/// Duplicate names make a later qualifier reference ambiguous, so the whole
/// signature is conservatively unsupported.
fn parameter_names(parameters: &[Node<'_>], source: &str) -> Option<Vec<(String, usize)>> {
    let mut names = Vec::new();
    for (index, parameter) in parameters.iter().enumerate() {
        let Some(declarator) = parameter.child_by_field_name("declarator") else {
            continue;
        };
        let Some(name) = declarator_leaf(declarator) else {
            continue;
        };
        if name.kind() != "identifier" {
            continue;
        }
        let name = node_text(&name, source)?.to_owned();
        if names.iter().any(|(existing, _)| existing == &name) {
            return None;
        }
        names.push((name, index));
    }
    Some(names)
}

fn containing_template(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "template_declaration" {
            return parent.child_by_field_name("parameters");
        }
        node = parent;
    }
    None
}

#[derive(Debug, Clone)]
struct GenericBinding {
    name: Option<String>,
    role: &'static str,
    index: usize,
    owner_start: usize,
    owner_end: usize,
    declaration_start: usize,
    declaration_end: usize,
    parameter_start: usize,
    parameter_end: usize,
}

#[derive(Debug, Default)]
struct GenericContext<'tree> {
    templates: Vec<Node<'tree>>,
    requires: Vec<Node<'tree>>,
    bindings: Vec<GenericBinding>,
}

fn c_family_template_context<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<GenericContext<'tree>> {
    let mut templates = Vec::new();
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "template_declaration" {
            templates.push(current);
        }
        ancestor = current.parent();
    }
    templates.reverse();

    let mut bindings: Vec<GenericBinding> = Vec::new();
    let mut role_counts = std::collections::HashMap::<&'static str, usize>::new();
    for template in &templates {
        let parameters = template.child_by_field_name("parameters")?;
        let mut cursor = parameters.walk();
        for parameter in parameters
            .named_children(&mut cursor)
            .filter(|parameter| parameter.kind() != COMMENT_KIND)
        {
            let (role, name_node) = match parameter.kind() {
                "type_parameter_declaration" | "optional_type_parameter_declaration" => {
                    ("type", template_parameter_name(parameter))
                }
                "variadic_type_parameter_declaration" => {
                    ("type_pack", template_parameter_name(parameter))
                }
                "parameter_declaration" | "optional_parameter_declaration" => {
                    ("value", template_parameter_name(parameter))
                }
                "variadic_parameter_declaration" => {
                    ("value_pack", template_parameter_name(parameter))
                }
                _ => return None,
            };
            let name =
                name_node.and_then(|name_node| node_text(&name_node, source).map(str::to_owned));
            if name.as_ref().is_some_and(|name| {
                bindings
                    .iter()
                    .any(|binding| binding.name.as_deref() == Some(name.as_str()))
            }) {
                return None;
            }
            let index = *role_counts.entry(role).or_insert(0);
            *role_counts.get_mut(role)? += 1;
            let (declaration_start, declaration_end) = name_node.map_or_else(
                || (parameter.start_byte(), parameter.start_byte()),
                |name_node| (name_node.start_byte(), name_node.end_byte()),
            );
            bindings.push(GenericBinding {
                name,
                role,
                index,
                owner_start: template.start_byte(),
                owner_end: template.end_byte(),
                declaration_start,
                declaration_end,
                parameter_start: parameter.start_byte(),
                parameter_end: parameter.end_byte(),
            });
        }
    }

    let mut requires = Vec::new();
    for template in &templates {
        let mut cursor = template.walk();
        requires.extend(
            template
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "requires_clause"),
        );
    }
    Some(GenericContext {
        templates,
        requires,
        bindings,
    })
}

fn template_parameter_name(parameter: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) = parameter.child_by_field_name("name") {
        return Some(name);
    }
    if let Some(declarator) = parameter.child_by_field_name("declarator") {
        return declarator_leaf(declarator);
    }
    let mut cursor = parameter.walk();
    let mut last_name = None;
    for child in parameter.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "type_identifier") {
            last_name = Some(child);
        }
    }
    last_name
}

fn containing_template_requires(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "template_declaration" {
            let mut cursor = parent.walk();
            return parent
                .named_children(&mut cursor)
                .find(|child| child.kind() == "requires_clause");
        }
        node = parent;
    }
    None
}

fn template_arguments(node: Node<'_>, source: &str, generic_bindings: &[GenericBinding]) -> String {
    let mut lists = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "template_argument_list" {
            lists.push(current);
            continue;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    lists.sort_unstable_by_key(Node::start_byte);
    lists
        .into_iter()
        .map(|list| compact_node_with_generics(list, source, generic_bindings))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_default_value_child(parent: Node<'_>, child: Node<'_>) -> bool {
    parent
        .child_by_field_name("default_value")
        .is_some_and(|default| {
            default.start_byte() == child.start_byte() && default.end_byte() == child.end_byte()
        })
}

/// Header-only unsupported grammar check. Function bodies are intentionally
/// not traversed: a body macro or recoverable body error must not erase a
/// valid declaration signature. Default argument expressions are similarly
/// outside the signature contract and are skipped.
fn has_unsupported_header(node: &Node<'_>) -> bool {
    let mut pending = vec![*node];
    while let Some(current) = pending.pop() {
        let kind = current.kind();
        if kind == "default_value" {
            continue;
        }
        if kind.starts_with("preproc_")
            || kind.contains("macro")
            || kind == "ERROR"
            || current.is_missing()
        {
            return true;
        }
        let mut children = current.walk();
        pending.extend(
            current
                .children(&mut children)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

/// Attributes and Microsoft calling-convention extensions can affect ABI,
/// diagnostics or overload resolution in ways that this structural frontend
/// cannot classify safely. Reject them in the declaration header, while
/// deliberately ignoring attributes inside the function body. This is shared
/// by C and C++ because both grammars expose these extensions.
fn has_unsupported_declaration_attribute(node: Node<'_>) -> bool {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte());
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if body_start.is_some_and(|start| current.start_byte() >= start) {
            continue;
        }
        if matches!(
            current.kind(),
            "attribute_declaration"
                | "attribute_specifier"
                | "ms_declspec_modifier"
                | "ms_call_modifier"
        ) {
            return true;
        }
        let mut children = current.walk();
        pending.extend(
            current
                .children(&mut children)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

/// Build a return shape from the declared type and only the outer declarator
/// modifiers. Function specifiers such as `inline` and `constexpr` live on
/// the definition itself and are intentionally excluded; pointer/reference
/// modifiers on the outer declarator remain callable return type information.
fn return_type_signature(
    node: Node<'_>,
    return_type: Node<'_>,
    declarator: Node<'_>,
    function_declarator: Node<'_>,
    source: &str,
    generic_bindings: &[GenericBinding],
) -> String {
    let mut out = String::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= function_declarator.start_byte() {
            continue;
        }
        if child.kind() == "type_qualifier" {
            let raw_qualifier = node_text(&child, source).map(str::trim).unwrap_or_default();
            if matches!(raw_qualifier, "const" | "volatile" | "restrict") {
                push_signature_chunk(
                    &mut out,
                    &compact_node_with_generics(child, source, generic_bindings),
                );
            }
        }
    }
    push_signature_chunk(
        &mut out,
        &compact_node_with_generics(return_type, source, generic_bindings),
    );
    push_signature_chunk(
        &mut out,
        &compact_node_with_generics_before(
            declarator,
            source,
            Some(function_declarator.start_byte()),
            generic_bindings,
        ),
    );
    out
}

fn has_unsupported_parameter_descendant(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        let kind = current.kind();
        if kind == "default_value" {
            continue;
        }
        if kind.starts_with("preproc_")
            || kind.contains("macro")
            || kind == "ERROR"
            || current.is_missing()
        {
            return true;
        }
        let mut children = current.walk();
        pending.extend(
            current
                .children(&mut children)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

fn contains_nested_function_declarator(function_declarator: Node<'_>) -> bool {
    let mut pending = Vec::new();
    let mut cursor = function_declarator.walk();
    pending.extend(
        function_declarator
            .named_children(&mut cursor)
            .filter(|child| !is_default_value_child(function_declarator, *child)),
    );
    while let Some(current) = pending.pop() {
        if current.kind() == "function_declarator" {
            return true;
        }
        let mut children = current.walk();
        pending.extend(
            current
                .named_children(&mut children)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

/// Requires-expressions introduce a second parameter scope. Resolving those
/// bindings would need a full C++ name lookup pass; rejecting the declaration
/// keeps an outer function-parameter map from accidentally renaming an inner
/// binding or vice versa.
fn contains_requires_parameter_binding(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "requires_expression"
            && (current.child_by_field_name("parameters").is_some()
                || contains_kind(current, "parameter_declaration"))
        {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| !is_default_value_child(current, *child)),
        );
    }
    false
}

fn c_family_receiver_kind<'a>(
    node: &Node<'_>,
    declarator: Node<'_>,
    source: &str,
    language: Language,
) -> &'a str {
    if language != Language::Cpp {
        return "free";
    }
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        match ancestor.kind() {
            "field_declaration_list" => {
                if has_direct_storage_class(node, source, "static") {
                    return "in-class-static";
                }
                return "in-class";
            }
            "template_declaration" => parent = ancestor.parent(),
            _ => break,
        }
    }
    if function_name_is_qualified(declarator) {
        "qualified"
    } else {
        "free"
    }
}

fn has_direct_storage_class(node: &Node<'_>, source: &str, wanted: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        child.kind() == "storage_class_specifier"
            && child
                .utf8_text(source.as_bytes())
                .is_ok_and(|text| text == wanted)
    })
}

fn function_name_is_qualified(mut declarator: Node<'_>) -> bool {
    loop {
        if declarator.kind() == "function_declarator" {
            let Some(name) = declarator
                .child_by_field_name("declarator")
                .or_else(|| declarator.named_child(0))
            else {
                return false;
            };
            return name.kind() == "qualified_identifier";
        }
        let Some(next) = declarator
            .child_by_field_name("declarator")
            .or_else(|| declarator.named_child(0))
        else {
            return false;
        };
        declarator = next;
    }
}

fn compact_node_with_generics(
    node: Node<'_>,
    source: &str,
    generic_bindings: &[GenericBinding],
) -> String {
    let mut out = String::new();
    let mut cursor = node.walk();
    loop {
        let current = cursor.node();
        let kind = current.kind();
        let descend = kind != COMMENT_KIND
            && !ATOMIC_TOKEN_KINDS.contains(&kind)
            && current.child_count() > 0;
        if descend && cursor.goto_first_child() {
            continue;
        }
        if !descend && kind != COMMENT_KIND {
            let start = current.start_byte();
            let finish = current.end_byte();
            if finish > start
                && let Some(binding) = generic_binding_for_token(current, source, generic_bindings)
            {
                push_signature_generic(&mut out, binding);
            } else if finish > start
                && let Some(text) = source.get(start..finish)
            {
                push_signature_token(&mut out, text);
            }
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}

fn compact_template_parameters(
    parameters: Node<'_>,
    source: &str,
    generic_bindings: &[GenericBinding],
) -> String {
    let mut out = String::new();
    let mut cursor = parameters.walk();
    for parameter in parameters
        .named_children(&mut cursor)
        .filter(|parameter| parameter.kind() != COMMENT_KIND)
    {
        let value = compact_template_parameter(parameter, source, generic_bindings);
        out.push_str(&value);
    }
    out
}

fn compact_template_parameter(
    parameter: Node<'_>,
    source: &str,
    generic_bindings: &[GenericBinding],
) -> String {
    let Some(binding) = generic_bindings.iter().find(|binding| {
        binding.parameter_start == parameter.start_byte()
            && binding.parameter_end == parameter.end_byte()
    }) else {
        return compact_node_with_generics(parameter, source, generic_bindings);
    };
    let name = template_parameter_name(parameter);
    let insertion_end = name.map_or_else(
        || unnamed_template_marker_end(parameter, source),
        |name| name.start_byte(),
    );
    let marker = format!("g{}{};", binding.role, binding.index);
    let mut out = String::new();
    let mut inserted = false;
    let mut cursor = parameter.walk();
    loop {
        let current = cursor.node();
        let kind = current.kind();
        let descend = kind != COMMENT_KIND
            && !ATOMIC_TOKEN_KINDS.contains(&kind)
            && current.child_count() > 0;
        if descend && cursor.goto_first_child() {
            continue;
        }
        if !descend && kind != COMMENT_KIND {
            let start = current.start_byte();
            let finish = current.end_byte();
            if finish > start {
                let is_declared_name = name
                    .is_some_and(|name| name.start_byte() == start && name.end_byte() == finish);
                if is_declared_name {
                    out.push_str(&marker);
                    inserted = true;
                } else if let Some(generic) =
                    generic_binding_for_token(current, source, generic_bindings)
                {
                    push_signature_generic(&mut out, generic);
                } else if let Some(text) = source.get(start..finish)
                    && !matches!(text, "class" | "typename")
                {
                    push_signature_token(&mut out, text);
                }
                if !inserted && finish == insertion_end {
                    out.push_str(&marker);
                    inserted = true;
                }
            }
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                if !inserted {
                    out.push_str(&marker);
                }
                return out;
            }
        }
    }
}

fn unnamed_template_marker_end(parameter: Node<'_>, source: &str) -> usize {
    let mut leaves = Vec::new();
    let mut cursor = parameter.walk();
    loop {
        let current = cursor.node();
        let kind = current.kind();
        let descend = kind != COMMENT_KIND
            && !ATOMIC_TOKEN_KINDS.contains(&kind)
            && current.child_count() > 0;
        if descend && cursor.goto_first_child() {
            continue;
        }
        if !descend && kind != COMMENT_KIND {
            let start = current.start_byte();
            let finish = current.end_byte();
            if finish > start {
                leaves.push((start, finish, source.get(start..finish).unwrap_or("")));
            }
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return leaves
                    .iter()
                    .find(|(_, _, text)| *text == "...")
                    .map_or_else(
                        || {
                            leaves
                                .iter()
                                .find(|(_, _, text)| matches!(*text, "class" | "typename"))
                                .map_or_else(
                                    || {
                                        parameter.child_by_field_name("type").map_or_else(
                                            || parameter.start_byte(),
                                            |node| node.end_byte(),
                                        )
                                    },
                                    |(_, end, _)| *end,
                                )
                        },
                        |(_, end, _)| *end,
                    );
            }
        }
    }
}

fn compact_node_with_generics_before(
    node: Node<'_>,
    source: &str,
    end: Option<usize>,
    generic_bindings: &[GenericBinding],
) -> String {
    let mut out = String::new();
    let mut cursor = node.walk();
    loop {
        let current = cursor.node();
        let kind = current.kind();
        let descend = kind != COMMENT_KIND
            && !ATOMIC_TOKEN_KINDS.contains(&kind)
            && current.child_count() > 0;
        if descend && cursor.goto_first_child() {
            continue;
        }
        if !descend && kind != COMMENT_KIND {
            let start = current.start_byte();
            let finish = current.end_byte();
            if end.is_none_or(|limit| finish <= limit) && finish > start {
                if let Some(binding) = generic_binding_for_token(current, source, generic_bindings)
                {
                    push_signature_generic(&mut out, binding);
                } else if let Some(text) = source.get(start..finish) {
                    push_signature_token(&mut out, text);
                }
            }
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}

fn generic_binding_for_token<'a>(
    node: Node<'_>,
    source: &str,
    bindings: &'a [GenericBinding],
) -> Option<&'a GenericBinding> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "namespace_identifier"
    ) {
        return None;
    }
    if node
        .prev_sibling()
        .is_some_and(|previous| previous.kind() == "::")
    {
        return None;
    }
    if let Some(parent) = node.parent() {
        let name_field = parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("field"));
        if matches!(
            parent.kind(),
            "field_expression"
                | "qualified_identifier"
                | "template_type"
                | "template_method"
                | "template_function"
        ) && name_field.is_some_and(|name| node_contains(name, node))
        {
            return None;
        }
    }
    let mut ancestor = node.parent();
    let mut inside_template_arguments = false;
    while let Some(current) = ancestor {
        inside_template_arguments |= current.kind() == "template_argument_list";
        if current.kind() == "function_declarator"
            && current
                .child_by_field_name("declarator")
                .is_some_and(|declarator| node_contains(declarator, node))
            && !inside_template_arguments
        {
            return None;
        }
        if matches!(current.kind(), "class_specifier" | "struct_specifier")
            && current
                .child_by_field_name("name")
                .is_some_and(|name| node_contains(name, node))
        {
            return None;
        }
        ancestor = current.parent();
    }
    let text = node_text(&node, source)?;
    bindings
        .iter()
        .filter(|binding| {
            binding.name.as_deref() == Some(text)
                && binding.owner_start <= node.start_byte()
                && node.end_byte() <= binding.owner_end
                && (node.start_byte() >= binding.declaration_end
                    || (node.start_byte() == binding.declaration_start
                        && node.end_byte() == binding.declaration_end))
        })
        .max_by_key(|binding| binding.owner_start)
}

fn push_signature_generic(output: &mut String, binding: &GenericBinding) {
    use core::fmt::Write as _;

    let _ = write!(output, "g{}{};", binding.role, binding.index);
}

/// Compact a function declarator's post-parameter qualifiers while replacing
/// only identifier leaves that are expression references to declared
/// parameters. Declaration names, call callees, type/template names, member
/// fields and qualified names remain source text.
fn compact_node_between_with_parameter_refs(
    node: Node<'_>,
    source: &str,
    start: usize,
    excluded: &[ByteRange],
    parameters: &[(String, usize)],
    generic_bindings: &[GenericBinding],
) -> Option<String> {
    let mut compact = compact_node_with_parameter_refs(
        node,
        source,
        excluded,
        Some(node.end_byte()),
        parameters,
        generic_bindings,
    )?;
    let prefix = compact_node_with_parameter_refs(
        node,
        source,
        excluded,
        Some(start),
        parameters,
        generic_bindings,
    )?;
    if !compact.starts_with(&prefix) {
        return None;
    }
    compact.drain(..prefix.len());
    Some(compact.trim_start().to_owned())
}

fn compact_node_with_parameter_refs(
    node: Node<'_>,
    source: &str,
    excluded: &[ByteRange],
    end: Option<usize>,
    parameters: &[(String, usize)],
    generic_bindings: &[GenericBinding],
) -> Option<String> {
    let mut out = String::new();
    let mut cursor = node.walk();
    loop {
        let current = cursor.node();
        let kind = current.kind();
        let descend = kind != COMMENT_KIND
            && !ATOMIC_TOKEN_KINDS.contains(&kind)
            && current.child_count() > 0;
        if descend && cursor.goto_first_child() {
            continue;
        }
        if !descend && kind != COMMENT_KIND {
            let start = current.start_byte();
            let finish = current.end_byte();
            let within_end = end.is_none_or(|limit| finish <= limit);
            let range = ByteRange { start, end: finish };
            if finish > start
                && within_end
                && !excluded
                    .iter()
                    .any(|excluded_range| excluded_range.contains(&range))
            {
                match parameter_reference_index(current, source, parameters) {
                    Ok(Some(index)) => {
                        push_signature_parameter(&mut out, index);
                    }
                    Ok(None) => {
                        if let Some(binding) =
                            generic_binding_for_token(current, source, generic_bindings)
                        {
                            push_signature_generic(&mut out, binding);
                        } else {
                            push_signature_token(&mut out, source.get(start..finish)?);
                        }
                    }
                    Err(()) => return None,
                }
            }
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Some(out);
            }
        }
    }
}

/// Keep every CST token boundary explicit while preserving the exact text of
/// atomic literals. A separator between every emitted token is deliberate:
/// token adjacency is otherwise lossy (`+ +x` versus `++x`, or `dyn Fn`
/// versus `dynFn`).
fn push_signature_token(output: &mut String, token: &str) {
    use core::fmt::Write as _;

    let _ = write!(output, "t{}:{}", token.len(), token);
}

fn push_signature_chunk(output: &mut String, chunk: &str) {
    if chunk.is_empty() {
        return;
    }
    output.push_str(chunk);
}

fn push_signature_parameter(output: &mut String, index: usize) {
    use core::fmt::Write as _;

    let _ = write!(output, "p{index};");
}

fn parameter_reference_index(
    node: Node<'_>,
    source: &str,
    parameters: &[(String, usize)],
) -> Result<Option<usize>, ()> {
    if node.kind() != "identifier" {
        return Ok(None);
    }
    let text = node_text(&node, source).ok_or(())?;
    let Some((_, index)) = parameters.iter().find(|(name, _)| name == text) else {
        return Ok(None);
    };
    if is_shadowed_by_requires_binding(node, text, source)? {
        return Err(());
    }
    if is_call_callee(node) && !is_direct_parameter_callee(node) {
        return Ok(None);
    }

    let mut expression_context = false;
    let mut type_wrapper_context = false;
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        let kind = current.kind();
        if matches!(
            kind,
            "parameter_declaration"
                | "optional_parameter_declaration"
                | "variadic_parameter_declaration"
        ) {
            if !expression_context {
                return Ok(None);
            }
            break;
        }
        if kind == "qualified_identifier"
            && current
                .child_by_field_name("name")
                .is_some_and(|name| node_contains(name, node))
        {
            return Ok(None);
        }
        if kind == "template_argument_list" && !expression_context {
            return Err(());
        }
        if kind.ends_with("_type") && kind != "trailing_return_type" && !expression_context {
            return Err(());
        }
        type_wrapper_context |= matches!(kind, "type_descriptor" | "trailing_return_type");
        if kind == "array_declarator"
            && current
                .child_by_field_name("size")
                .is_some_and(|size| node_contains(size, node))
        {
            expression_context = true;
        }
        expression_context |= kind == "argument_list"
            || kind == "noexcept"
            || kind == "requires_clause"
            || kind == "requires_expression"
            || kind == "fold_expression"
            || kind == "decltype"
            || kind.ends_with("_expression");
        ancestor = current.parent();
    }
    if expression_context {
        Ok(Some(*index))
    } else if type_wrapper_context {
        Err(())
    } else {
        Ok(None)
    }
}

fn is_call_callee(node: Node<'_>) -> bool {
    let Some(function) = nearest_call_function(node) else {
        return false;
    };
    if !node_contains(function, node) {
        return false;
    }
    // A parameter reference nested inside `decltype(...)` is an expression
    // operand even when the enclosing expression is itself the qualified call
    // spelling (`decltype(value)::ready()`) or a template function's argument
    // (`check<typename decltype(value)::type>()`).  The outer call's function
    // subtree must not reclassify that inner operand as a callee name.
    if path_contains_kind_until(node, function, "decltype") {
        return false;
    }
    if function.kind() == "qualified_identifier"
        && function
            .child_by_field_name("scope")
            .is_some_and(|scope| node_contains(scope, node))
    {
        return false;
    }
    if function.kind() == "field_expression" {
        return function
            .child_by_field_name("field")
            .is_some_and(|field| node_contains(field, node));
    }
    true
}

fn path_contains_kind_until(node: Node<'_>, ancestor: Node<'_>, wanted: &str) -> bool {
    let mut current = node;
    loop {
        if current.kind() == wanted {
            return true;
        }
        if current.start_byte() == ancestor.start_byte()
            && current.end_byte() == ancestor.end_byte()
        {
            return false;
        }
        let Some(parent) = current.parent() else {
            return false;
        };
        current = parent;
    }
}

fn is_direct_parameter_callee(node: Node<'_>) -> bool {
    let Some(function) = nearest_call_function(node) else {
        return false;
    };
    if !node_contains(function, node) {
        return false;
    }

    // A parameter can be the callable expression through transparent
    // wrappers (`(callback)(x)`, `(*callback)(x)`) or a subscripted callable
    // (`callbacks[index](x)`). Member fields and qualified names are the
    // exception: their identifier leaves are names of the member/namespace,
    // not references to the parameter.
    let mut path = node;
    while path.start_byte() != function.start_byte() || path.end_byte() != function.end_byte() {
        let Some(parent) = path.parent() else {
            return false;
        };
        if !node_contains(function, parent) {
            return false;
        }
        if parent.kind() == "qualified_identifier"
            || (parent.kind() == "field_expression"
                && parent
                    .child_by_field_name("field")
                    .is_some_and(|field| node_contains(field, path)))
        {
            return false;
        }
        path = parent;
    }
    true
}

fn nearest_call_function(node: Node<'_>) -> Option<Node<'_>> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "call_expression" {
            let function = current.child_by_field_name("function")?;
            // Once the nearest call sees this identifier in its argument
            // list, an enclosing call may contain that whole call as its
            // callee (`factory(callback)(value)`). The identifier is still
            // an argument, never the outer callable, so stop here.
            return node_contains(function, node).then_some(function);
        }
        ancestor = current.parent();
    }
    None
}

/// Return whether a matching parameter spelling is shadowed by a local
/// requires-expression binding. A shadowed reference cannot be alpha-
/// normalized with the outer function parameter map without resolving C++
/// lexical scopes, so the containing signature is rejected conservatively.
fn is_shadowed_by_requires_binding(node: Node<'_>, name: &str, source: &str) -> Result<bool, ()> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "requires_expression" {
            let Some(parameters) = current.child_by_field_name("parameters") else {
                if contains_kind(current, "parameter_declaration") {
                    return Err(());
                }
                ancestor = current.parent();
                continue;
            };
            for parameter in real_parameter_nodes(parameters) {
                if parameter.has_error() {
                    return Err(());
                }
                let Some(declarator) = parameter.child_by_field_name("declarator") else {
                    continue;
                };
                let Some(binding) = declarator_leaf(declarator) else {
                    if contains_identifier_named(parameter, name, source) {
                        return Err(());
                    }
                    continue;
                };
                if binding.kind() == "identifier"
                    && node_text(&binding, source).is_some_and(|text| text == name)
                {
                    return Ok(true);
                }
            }
        }
        ancestor = current.parent();
    }
    Ok(false)
}

fn contains_identifier_named(node: Node<'_>, wanted: &str, source: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "identifier" && node_text(&current, source) == Some(wanted) {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    false
}

fn node_contains(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
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
/// whole file. CST-depth exhaustion instead emits an `Error` leaf over the
/// unvisited subtree, so the recovered IR stays bounded.
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
            signatures: Vec::new(),
            roots: Vec::new(),
            diagnostics: Vec::new(),
            error_ranges: vec![ByteRange {
                start: 0,
                end: source.len(),
            }],
            depth_truncated: false,
            test_module: false,
        };
    };

    let root = tree.root_node();
    let mut builder = IrBuilder::new(source, mapping, language);
    builder.collect_tokens(root);

    let mut roots = Vec::new();
    // The root (`translation_unit`) classifies as transparent, so visiting it
    // fills `roots` with the file's top-level nodes.
    builder.visit(root, &mut roots, 0);

    let signatures = canonicalize_signatures(builder.signatures);
    let assembled = builder.assembly.finish();

    SyntaxIrFile {
        language,
        frontend_version,
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens: assembled.tokens,
        signatures,
        roots,
        // Lexical diagnostics are a Fast-lexer concept; the structural
        // frontend reports problems through `error_ranges` only.
        diagnostics: Vec::new(),
        error_ranges: assembled.error_ranges,
        depth_truncated: assembled.depth_truncated,
        test_module: false,
    }
}

/// Accumulates the token stream and IR tree for one file.
///
/// Everything that does not read the tree-sitter CST — interning, line
/// mapping, byte-to-token lookup, depth-budget recovery — is delegated to the
/// shared [`IrAssembly`], so those behaviours cannot drift from the other
/// languages.
struct IrBuilder<'s, 'm> {
    assembly: IrAssembly<'s>,
    mapping: &'m dyn IrMapping,
    language: Language,
    signatures: Vec<(ByteRange, Signature)>,
}

impl<'s, 'm> IrBuilder<'s, 'm> {
    fn new(source: &'s str, mapping: &'m dyn IrMapping, language: Language) -> Self {
        Self {
            assembly: IrAssembly::new(source),
            mapping,
            language,
            signatures: Vec::new(),
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
                    self.assembly.record_error_range(node_range(&node));
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
        let text = node_text(node, self.assembly.source()).unwrap_or("");
        let kind = self.mapping.token_kind(node.kind(), node.is_named(), text);
        self.assembly
            .push_token(kind, text, node.start_byte(), node.end_byte());
    }

    /// Map one CST node onto the IR, appending zero or more nodes to `out`.
    fn visit(&mut self, cst: Node<'_>, out: &mut Vec<IrNode>, depth: usize) {
        if depth >= MAX_IR_DEPTH {
            self.emit_depth_error(cst, out);
            return;
        }

        match self.mapping.classify(&cst) {
            Mapping::Emit(shape) => {
                let source = self.assembly.source();
                let name = self
                    .mapping
                    .node_name(&cst, source)
                    .map(|text| self.assembly.intern(text));
                if matches!(shape, Shape::Function | Shape::Method)
                    && cst.kind() == "function_definition"
                    && let Some(signature) = self.mapping.signature(&cst, source, self.language)
                {
                    self.signatures.push((node_range(&cst), signature));
                }
                let node = self.build_node(shape, name, cst, depth);
                out.push(node);
            }
            Mapping::Native(kind) => {
                let shape = Shape::Native(self.assembly.intern(kind));
                let node = self.build_node(shape, None, cst, depth);
                out.push(node);
            }
            Mapping::ExprStmt => {
                if self.inner_expression_emits(cst) {
                    // The inner expression's own node is the statement.
                    self.visit_children(cst, out, depth);
                } else {
                    let node = self.build_node(Shape::ExprStmt, None, cst, depth);
                    out.push(node);
                }
            }
            Mapping::Error => {
                self.assembly.record_error_range(node_range(&cst));
                // Recurse anyway: tree-sitter wraps intact regions in error
                // nodes, and those descendants must still be recovered.
                let node = self.build_node(Shape::Error, None, cst, depth);
                out.push(node);
            }
            Mapping::Transparent => self.visit_children(cst, out, depth),
        }
    }

    fn visit_children(&mut self, cst: Node<'_>, out: &mut Vec<IrNode>, depth: usize) {
        let mut cursor = cst.walk();
        let children: Vec<Node<'_>> = cst.named_children(&mut cursor).collect();
        for child in children {
            self.visit(child, out, depth + 1);
        }
    }

    /// Build an [`IrNode`] for `cst`, visiting its children first.
    fn build_node(
        &mut self,
        shape: Shape,
        name: Option<Lexeme>,
        cst: Node<'_>,
        depth: usize,
    ) -> IrNode {
        let mut children = Vec::new();
        self.visit_children(cst, &mut children, depth);
        let range = node_range(&cst);
        let (token_start, token_end) = self.assembly.token_bounds(range);
        IrNode {
            shape,
            name,
            token_start,
            token_end,
            range,
            children,
        }
    }

    /// Preserve an unvisited CST subtree as recoverable truncation data.
    fn emit_depth_error(&mut self, cst: Node<'_>, out: &mut Vec<IrNode>) {
        let node = self.assembly.truncate_at_depth(node_range(&cst));
        out.push(node);
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
mod tests;
