//! CST traversal predicates shared by the rest of the frontend.
//!
//! Every helper here answers a question about the tree-sitter tree alone:
//! whether a subtree contains a grammar kind, where a declarator's identifier
//! is, whether an identifier stands in callee position, and what text or byte
//! range a node covers.

use codehelion_core::ir::ByteRange;
use tree_sitter::Node;

use super::generics::is_default_value_child;
use super::signature::real_parameter_nodes;

pub(super) fn contains_kind(node: Node<'_>, wanted: &str) -> bool {
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

pub(super) fn contains_header_kind(node: Node<'_>, wanted: &str) -> bool {
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

pub(super) fn contains_variadic_marker(node: Node<'_>) -> bool {
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
pub(super) fn find_function_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
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
pub(super) fn declarator_leaf(mut node: Node<'_>) -> Option<Node<'_>> {
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

pub(super) fn is_call_callee(node: Node<'_>) -> bool {
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

pub(super) fn is_direct_parameter_callee(node: Node<'_>) -> bool {
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
pub(super) fn is_shadowed_by_requires_binding(
    node: Node<'_>,
    name: &str,
    source: &str,
) -> Result<bool, ()> {
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

pub(super) fn node_contains(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

/// Strip a declarator down to the declared identifier: through pointer,
/// function, parenthesized and reference declarators, and through the `name`
/// field of C++ qualified identifiers. `None` when no identifier is
/// recoverable.
pub(super) fn declarator_identifier<'s>(declarator: Node<'_>, source: &'s str) -> Option<&'s str> {
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
pub(super) fn node_text<'s>(node: &Node<'_>, source: &'s str) -> Option<&'s str> {
    source.get(node.start_byte()..node.end_byte())
}

/// The byte range a CST node covers.
pub(super) fn node_range(node: &Node<'_>) -> ByteRange {
    ByteRange {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}
