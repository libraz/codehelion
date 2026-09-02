//! The function-signature contract of the C-family structural frontends.
//!
//! [`c_family_signature`] builds the normalized signature recorded for a
//! function definition, together with the header-only checks that decide when
//! a declaration is outside the contract and gets no signature at all.

use codehelion_core::discovery::Language;
use codehelion_core::ir::{ByteRange, Signature};
use tree_sitter::Node;

use super::COMMENT_KIND;
use super::emit::{
    compact_node_between_with_parameter_refs, compact_node_with_parameter_refs,
    push_signature_chunk,
};
use super::generics::{
    GenericBinding, c_family_template_context, compact_node_with_generics,
    compact_node_with_generics_before, compact_template_parameters, containing_template,
    containing_template_requires, is_default_value_child, template_arguments,
};
use super::navigate::{
    contains_header_kind, contains_kind, contains_variadic_marker, declarator_leaf,
    find_function_declarator, node_range, node_text,
};

/// Build a conservative signature for a C-family function definition.
#[allow(clippy::too_many_lines)]
pub(super) fn c_family_signature(
    node: &Node<'_>,
    source: &str,
    language: Language,
) -> Option<Signature> {
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

/// Return the real parameter declarations, excluding comment trivia that the
/// parser exposes as named children of a parameter list.
pub(super) fn real_parameter_nodes(parameters: Node<'_>) -> Vec<Node<'_>> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
