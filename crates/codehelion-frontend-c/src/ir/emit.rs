//! The signature encoding: how compacted CST text is written out.
//!
//! Every emitted lexeme is length-prefixed so that token adjacency stays
//! recoverable, and identifier leaves that reference a declared parameter are
//! replaced by that parameter's position.

use codehelion_core::ir::ByteRange;
use tree_sitter::Node;

use super::generics::{GenericBinding, generic_binding_for_token};
use super::navigate::{
    is_call_callee, is_direct_parameter_callee, is_shadowed_by_requires_binding, node_contains,
    node_text,
};
use super::{ATOMIC_TOKEN_KINDS, COMMENT_KIND};

pub(super) fn push_signature_generic(output: &mut String, binding: &GenericBinding) {
    use core::fmt::Write as _;

    let _ = write!(output, "g{}{};", binding.role, binding.index);
}

/// Compact a function declarator's post-parameter qualifiers while replacing
/// only identifier leaves that are expression references to declared
/// parameters. Declaration names, call callees, type/template names, member
/// fields and qualified names remain source text.
pub(super) fn compact_node_between_with_parameter_refs(
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

pub(super) fn compact_node_with_parameter_refs(
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
pub(super) fn push_signature_token(output: &mut String, token: &str) {
    use core::fmt::Write as _;

    let _ = write!(output, "t{}:{}", token.len(), token);
}

pub(super) fn push_signature_chunk(output: &mut String, chunk: &str) {
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
