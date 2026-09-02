//! Conservative signature extraction for Rust functions.
//!
//! The CST gives the type nodes directly, so a function's callable shape is
//! read out of them without guessing where an identifier is part of a type.
//! Anything the rules cannot state exactly — inherited ABIs, function pointers,
//! macros, higher-ranked binders, malformed headers — yields no signature at
//! all rather than an approximate one.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::TokenKind;
use codehelion_core::ir::Signature;
use ra_ap_syntax::{SyntaxKind, SyntaxNode};

use super::emit::{
    compact_element_with_generics, compact_node_with_generics, push_signature_chunk,
    push_signature_token,
};
use super::map_token_kind;

/// The tokens of an `impl` header: everything the node covers before its body.
///
/// The header is handed to the shared naming rule as a flat token sequence,
/// which is the same shape Fast mode gives it, so both modes name an `impl`
/// after the same identifier.
pub(super) fn impl_header(cst: &SyntaxNode) -> Vec<(TokenKind, String)> {
    let body_start = cst
        .children()
        .find(|child| child.kind() == SyntaxKind::ASSOC_ITEM_LIST)
        .map(|body| body.text_range().start());
    cst.descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| !matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT))
        .take_while(|token| body_start.is_none_or(|start| token.text_range().start() < start))
        .map(|token| (map_token_kind(token.kind()), token.text().to_owned()))
        .collect()
}

/// Build the conservative signature side-table entry for one Rust function.
///
/// The CST gives us the type nodes directly, so the function name and every
/// parameter pattern can be left out without guessing where an identifier is
/// part of a type. A function whose parameter type is itself a function
/// pointer, a macro or an incomplete/error node is deliberately unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GenericBinding {
    pub(super) name: String,
    pub(super) role: &'static str,
    pub(super) index: usize,
}

pub(super) fn rust_signature(node: &SyntaxNode) -> Option<Signature> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ir::test_support::parse;
    use codehelion_core::ir::MAX_IR_DEPTH;

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
}
