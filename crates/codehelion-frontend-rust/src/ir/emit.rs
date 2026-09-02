//! Rendering of CST fragments into the normalized signature encoding.
//!
//! Every non-trivia token keeps an explicit boundary, and a token that names a
//! generic parameter in scope is replaced by its alpha-normalized binding.
//! Identifiers that only look like a parameter name — path segments after
//! `::`, associated-type labels and field or method members — stay raw.

use ra_ap_syntax::{SyntaxKind, SyntaxNode};

use super::signature::GenericBinding;

pub(super) fn compact_node_with_generics(
    node: &SyntaxNode,
    generic_bindings: &[GenericBinding],
) -> String {
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

pub(super) fn compact_element_with_generics(
    node: &SyntaxNode,
    generic_bindings: &[GenericBinding],
) -> String {
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
pub(super) fn push_signature_token(output: &mut String, token: &str) {
    use core::fmt::Write as _;

    let _ = write!(output, "t{}:{}", token.len(), token);
}

fn push_signature_generic(output: &mut String, binding: &GenericBinding) {
    use core::fmt::Write as _;

    let _ = write!(output, "g{}{};", binding.role, binding.index);
}

pub(super) fn push_signature_chunk(output: &mut String, chunk: &str) {
    if chunk.is_empty() {
        return;
    }
    output.push_str(chunk);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ir::test_support::parse;

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
