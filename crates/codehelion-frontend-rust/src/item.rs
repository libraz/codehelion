//! The item rules both Rust analysis modes answer with.
//!
//! Fast mode walks a token stream and Structural mode walks a parsed tree, but
//! some questions have one answer that must not depend on which walk asked
//! them: what kind of item a construct is, which of those kinds are reportable
//! units, and which identifier names an `impl`. Each mode finds the construct
//! with its own machinery and then comes here for the answer, so a rule stated
//! once cannot reach one mode and miss the other.

#![allow(clippy::redundant_pub_crate)] // internal rules reached from both modes

use codehelion_core::frontend::{TokenKind, UnitKind};
use codehelion_core::ir::Shape;

/// Keywords that introduce a record definition.
///
/// `union` is a contextual keyword: the Fast lexer reads it as an identifier,
/// and a caller matching on this table has to allow for that. Structural mode
/// reaches the same set through the grammar's own `STRUCT`/`ENUM`/`UNION`
/// nodes.
pub(crate) const RECORD_KEYWORDS: &[&str] = &["struct", "enum", "union"];

/// Whether `text` spells a record-introducing keyword.
pub(crate) fn is_record_keyword(text: &str) -> bool {
    RECORD_KEYWORDS.contains(&text)
}

/// A Rust item as both modes classify it, however it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemKind {
    /// A function that is not an associated item.
    Function,
    /// A function directly inside an `impl` or `trait` body.
    Method,
    /// An `impl` block.
    Impl,
    /// A `struct`, `enum` or `union` definition.
    Record,
    /// A closure with a block body.
    Closure,
    /// A `macro_rules!` or `macro` definition.
    MacroDef,
}

impl ItemKind {
    /// The kind of a function, given whether it sits directly in the body of an
    /// `impl` or a `trait`.
    ///
    /// Directly is the whole rule: a function nested in another function's body
    /// is a free function even when that outer function is a method, and one
    /// written in a trait is a method even when it is only a default body.
    pub(crate) const fn of_fn(directly_in_assoc_body: bool) -> Self {
        if directly_in_assoc_body {
            Self::Method
        } else {
            Self::Function
        }
    }

    /// The unit kind Fast mode reports this item as, or `None` for an item
    /// that anchors no unit.
    pub(crate) const fn unit_kind(self) -> Option<UnitKind> {
        match self {
            Self::Function => Some(UnitKind::Function),
            Self::Method => Some(UnitKind::Method),
            Self::Impl => Some(UnitKind::Impl),
            Self::Record => Some(UnitKind::Record),
            Self::Closure => Some(UnitKind::Closure),
            // A macro definition is a template, not code that runs: its body is
            // opaque in both modes and anchors nothing.
            Self::MacroDef => None,
        }
    }

    /// The IR shape Structural mode emits for this item.
    pub(crate) const fn shape(self) -> Shape {
        match self {
            Self::Function => Shape::Function,
            Self::Method => Shape::Method,
            Self::Impl => Shape::Impl,
            Self::Record => Shape::Record,
            Self::Closure => Shape::Closure,
            Self::MacroDef => Shape::MacroDef,
        }
    }
}

/// One header token as the shared naming rule sees it: what kind it is and how
/// it is spelled. Each mode builds these from its own token representation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderToken<'a> {
    /// The token's kind.
    pub kind: TokenKind,
    /// The token's text.
    pub text: &'a str,
}

/// The identifier naming the type an `impl` header implements for, given the
/// header tokens between the `impl` keyword and the body.
///
/// Taking the first identifier would name the generic parameter of
/// `impl<T> Foo<T>` and the trait of `impl Trait for Foo`, neither of which
/// says which type the block belongs to. The rule is the last identifier
/// written at the header's own bracket depth, restarted at a `for` and stopped
/// by a `where` clause: everything inside `<...>`, `(...)` or `[...]` is a
/// parameter list or an argument to the type, and the last segment of a path is
/// the type itself, so `impl Trait for std::vec::Vec<T>` is named `Vec`.
///
/// `None` where no identifier is written at that depth, as for a tuple or an
/// array type, rather than a name taken from inside the type.
pub(crate) fn impl_self_type_name<'a>(
    header: impl IntoIterator<Item = HeaderToken<'a>>,
) -> Option<&'a str> {
    let mut depth = 0usize;
    let mut name = None;
    for token in header {
        match token.kind {
            TokenKind::Punctuation => match token.text {
                "<" | "(" | "[" => depth += 1,
                ">" | ")" | "]" => depth = depth.saturating_sub(1),
                // The lexer glues a closing run, so one token can open or give
                // back both of the levels it stands for.
                "<<" => depth += 2,
                ">>" => depth = depth.saturating_sub(2),
                "{" | ";" => break,
                _ => {}
            },
            TokenKind::Keyword if depth == 0 => match token.text {
                "for" => name = None,
                "where" => break,
                _ => {}
            },
            TokenKind::Identifier if depth == 0 => name = Some(token.text),
            _ => {}
        }
    }
    name
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn header(tokens: &[(TokenKind, &'static str)]) -> Vec<HeaderToken<'static>> {
        tokens
            .iter()
            .map(|&(kind, text)| HeaderToken { kind, text })
            .collect()
    }

    #[test]
    fn a_function_is_a_method_only_directly_inside_an_associated_body() {
        assert_eq!(ItemKind::of_fn(true), ItemKind::Method);
        assert_eq!(ItemKind::of_fn(false), ItemKind::Function);
    }

    #[test]
    fn every_item_kind_reports_one_unit_kind_and_one_shape() {
        for (item, unit, shape) in [
            (
                ItemKind::Function,
                Some(UnitKind::Function),
                Shape::Function,
            ),
            (ItemKind::Method, Some(UnitKind::Method), Shape::Method),
            (ItemKind::Impl, Some(UnitKind::Impl), Shape::Impl),
            (ItemKind::Record, Some(UnitKind::Record), Shape::Record),
            (ItemKind::Closure, Some(UnitKind::Closure), Shape::Closure),
            (ItemKind::MacroDef, None, Shape::MacroDef),
        ] {
            assert_eq!(item.unit_kind(), unit, "{item:?}");
            assert_eq!(item.shape(), shape, "{item:?}");
        }
    }

    #[test]
    fn a_generic_parameter_never_names_an_impl() {
        // `impl<T> Foo<T>`
        let tokens = header(&[
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">"),
            (TokenKind::Identifier, "Foo"),
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">"),
        ]);
        assert_eq!(impl_self_type_name(tokens), Some("Foo"));
    }

    #[test]
    fn a_trait_never_names_an_impl() {
        // `impl Display for Foo`
        let tokens = header(&[
            (TokenKind::Identifier, "Display"),
            (TokenKind::Keyword, "for"),
            (TokenKind::Identifier, "Foo"),
        ]);
        assert_eq!(impl_self_type_name(tokens), Some("Foo"));
    }

    #[test]
    fn a_path_type_is_named_by_its_last_segment() {
        // `impl Trait for std::vec::Vec<T>`
        let tokens = header(&[
            (TokenKind::Identifier, "Trait"),
            (TokenKind::Keyword, "for"),
            (TokenKind::Identifier, "std"),
            (TokenKind::Punctuation, "::"),
            (TokenKind::Identifier, "vec"),
            (TokenKind::Punctuation, "::"),
            (TokenKind::Identifier, "Vec"),
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">"),
        ]);
        assert_eq!(impl_self_type_name(tokens), Some("Vec"));
    }

    #[test]
    fn a_where_clause_does_not_rename_an_impl() {
        // `impl<T> Foo<T> where T: Clone`
        let tokens = header(&[
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">"),
            (TokenKind::Identifier, "Foo"),
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">"),
            (TokenKind::Keyword, "where"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ":"),
            (TokenKind::Identifier, "Clone"),
        ]);
        assert_eq!(impl_self_type_name(tokens), Some("Foo"));
    }

    #[test]
    fn a_glued_closing_run_gives_back_both_levels() {
        // `impl Trait for Foo<Bar<T>>`
        let tokens = header(&[
            (TokenKind::Identifier, "Trait"),
            (TokenKind::Keyword, "for"),
            (TokenKind::Identifier, "Foo"),
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "Bar"),
            (TokenKind::Punctuation, "<"),
            (TokenKind::Identifier, "T"),
            (TokenKind::Punctuation, ">>"),
        ]);
        assert_eq!(impl_self_type_name(tokens), Some("Foo"));
    }

    #[test]
    fn a_type_with_no_identifier_of_its_own_is_unnamed() {
        // `impl Trait for [u8; 4]`
        let tokens = header(&[
            (TokenKind::Identifier, "Trait"),
            (TokenKind::Keyword, "for"),
            (TokenKind::Punctuation, "["),
            (TokenKind::Identifier, "u8"),
            (TokenKind::Punctuation, ";"),
            (
                TokenKind::Literal(codehelion_core::frontend::LiteralKind::Integer),
                "4",
            ),
            (TokenKind::Punctuation, "]"),
        ]);
        assert_eq!(impl_self_type_name(tokens), None);
    }

    #[test]
    fn the_record_keywords_are_one_table() {
        for keyword in ["struct", "enum", "union"] {
            assert!(is_record_keyword(keyword), "{keyword}");
        }
        assert!(!is_record_keyword("trait"));
        assert!(!is_record_keyword("impl"));
    }
}
