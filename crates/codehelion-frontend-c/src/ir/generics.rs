//! Template parameters and their alpha-normalized references.
//!
//! A C++ template introduces names that a signature must compare structurally
//! rather than by spelling. [`c_family_template_context`] collects the
//! enclosing template declarations into [`GenericBinding`]s, and the compact
//! walkers here replace every reference to one with its role and index.

use tree_sitter::Node;

use super::emit::{push_signature_generic, push_signature_token};
use super::navigate::{declarator_leaf, node_contains, node_text};
use super::{ATOMIC_TOKEN_KINDS, COMMENT_KIND};

pub(super) fn containing_template(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "template_declaration" {
            return parent.child_by_field_name("parameters");
        }
        node = parent;
    }
    None
}

#[derive(Debug, Clone)]
pub(super) struct GenericBinding {
    pub(super) name: Option<String>,
    pub(super) role: &'static str,
    pub(super) index: usize,
    owner_start: usize,
    owner_end: usize,
    declaration_start: usize,
    declaration_end: usize,
    parameter_start: usize,
    parameter_end: usize,
}

#[derive(Debug, Default)]
pub(super) struct GenericContext<'tree> {
    pub(super) templates: Vec<Node<'tree>>,
    pub(super) requires: Vec<Node<'tree>>,
    pub(super) bindings: Vec<GenericBinding>,
}

pub(super) fn c_family_template_context<'tree>(
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

pub(super) fn containing_template_requires(mut node: Node<'_>) -> Option<Node<'_>> {
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

pub(super) fn template_arguments(
    node: Node<'_>,
    source: &str,
    generic_bindings: &[GenericBinding],
) -> String {
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

pub(super) fn is_default_value_child(parent: Node<'_>, child: Node<'_>) -> bool {
    parent
        .child_by_field_name("default_value")
        .is_some_and(|default| {
            default.start_byte() == child.start_byte() && default.end_byte() == child.end_byte()
        })
}

pub(super) fn compact_node_with_generics(
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

pub(super) fn compact_template_parameters(
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

pub(super) fn compact_node_with_generics_before(
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

pub(super) fn generic_binding_for_token<'a>(
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
