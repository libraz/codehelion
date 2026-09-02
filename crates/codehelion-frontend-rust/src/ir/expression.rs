//! Expression-level classification rules.
//!
//! Interior expression detail stays token-only, so only the distinctions the
//! structural comparison works on are read out of a `BIN_EXPR` here, and a
//! statement wrapper is dropped whenever its inner expression already maps to
//! a shape of its own.

use ra_ap_syntax::{SyntaxKind, SyntaxNode};

use super::{Mapping, classify};

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

/// Whether a `BIN_EXPR`'s operator token is `=` or a compound assignment.
/// Operands are child nodes, so the only child tokens besides trivia are the
/// operator itself.
pub(super) fn is_assignment(node: &SyntaxNode) -> bool {
    node.children_with_tokens()
        .filter_map(ra_ap_syntax::SyntaxElement::into_token)
        .any(|token| ASSIGN_OPS.contains(&token.kind()))
}

/// Stable native shape for a non-assignment binary operation.
pub(super) fn binary_operator(node: &SyntaxNode) -> Option<&'static str> {
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
pub(super) fn inner_expression_emits(stmt: &SyntaxNode) -> bool {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ir::test_support::{parse, shapes_of};
    use codehelion_core::ir::Shape;

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
}
