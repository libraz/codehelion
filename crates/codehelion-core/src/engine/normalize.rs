//! Scope-local token normalization for Type-2 clone matching.
//!
//! Type-2 clones differ from their siblings only by consistently renamed
//! identifiers and changed literal values. Matching them requires a normal
//! form in which those differences disappear while everything that identifies
//! what the code *does* — keywords, operators, called APIs, paths, field
//! names — is preserved.
//!
//! Normalization is scoped: identifier numbering restarts for every slice
//! passed to [`normalize`], so a fragment's normal form depends only on the
//! fragment's own content, never on what precedes it in the enclosing
//! function. Scope-local first-occurrence numbering also makes the identifier
//! bijection of a Type-2 match consistent by construction: two slices
//! normalize equal exactly when a one-to-one rename maps one onto the other.
//!
//! # Preservation rules
//!
//! An identifier keeps its text (is not renamed) when it looks like an
//! external name rather than a local binding:
//!
//! - it starts with an uppercase letter (types, enum variants, traits),
//! - it is adjacent to `::` (a path segment),
//! - it follows `.` or `->` (a member access: method, field, or a named
//!   return type after Rust's `->`),
//! - it precedes `!` (a macro invocation).
//!
//! These are lexical heuristics; a local binding that happens to match one
//! (say, a closure named like a method) is preserved conservatively, trading
//! a little recall for not conflating different APIs.

use std::collections::BTreeMap;

use crate::frontend::{LiteralKind, Token, TokenKind};

/// Literal-normalization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiteralNorm {
    /// Keep literal values distinct; only identifiers are renamed.
    Preserve,
    /// Collapse literals by category (integer, float, string, char, bool).
    Category,
    /// Collapse every literal to a single placeholder.
    #[default]
    Full,
}

/// The normalized payload of one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormAtom<'a> {
    /// A scope-local name, numbered by first occurrence within the slice.
    Renamed(u32),
    /// Text preserved verbatim (keywords, operators, external names).
    Text(&'a str),
    /// A literal placeholder; the payload is its category class, or a single
    /// shared class under [`LiteralNorm::Full`].
    Literal(u8),
}

/// A normalized token: the lexical kind tag plus the normalized payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NormToken<'a> {
    /// Stable one-byte kind tag (see [`TokenKind::tag`]).
    pub tag: u8,
    /// Normalized payload.
    pub atom: NormAtom<'a>,
}

/// Class byte for a literal under the given strategy.
const fn literal_class(kind: LiteralKind, mode: LiteralNorm) -> u8 {
    match mode {
        // `Preserve` never reaches here; `Full` folds every category together.
        LiteralNorm::Preserve | LiteralNorm::Full => 0,
        LiteralNorm::Category => match kind {
            LiteralKind::Integer => 1,
            LiteralKind::Float => 2,
            LiteralKind::String => 3,
            LiteralKind::Char => 4,
            LiteralKind::Bool => 5,
        },
    }
}

/// The token's text when it is punctuation.
fn punct_text(token: &Token) -> Option<&str> {
    (token.kind == TokenKind::Punctuation).then_some(token.text.as_str())
}

/// Whether the identifier at `i` is preserved rather than renamed.
fn is_preserved(tokens: &[Token], i: usize) -> bool {
    if tokens[i]
        .text
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
    {
        return true;
    }
    let prev = i
        .checked_sub(1)
        .and_then(|p| tokens.get(p))
        .and_then(punct_text);
    let next = tokens.get(i + 1).and_then(punct_text);
    matches!(prev, Some("::" | "." | "->")) || matches!(next, Some("::" | "!"))
}

/// Normalize `tokens` as one scope.
///
/// Neighbour context for the preservation rules is taken from within the
/// slice only, so identical slice content always produces an identical normal
/// form regardless of its surroundings.
#[must_use]
pub fn normalize(tokens: &[Token], literals: LiteralNorm) -> Vec<NormToken<'_>> {
    let mut names: BTreeMap<&str, u32> = BTreeMap::new();
    tokens
        .iter()
        .enumerate()
        .map(|(i, token)| {
            let atom = match token.kind {
                TokenKind::Identifier if is_preserved(tokens, i) => NormAtom::Text(&token.text),
                TokenKind::Identifier | TokenKind::Lifetime => {
                    let next = u32::try_from(names.len()).unwrap_or(u32::MAX);
                    let n = *names.entry(token.text.as_str()).or_insert(next);
                    NormAtom::Renamed(n)
                }
                TokenKind::Literal(kind) => match literals {
                    LiteralNorm::Preserve => NormAtom::Text(&token.text),
                    mode => NormAtom::Literal(literal_class(kind, mode)),
                },
                _ => NormAtom::Text(&token.text),
            };
            NormToken {
                tag: token.kind.tag(),
                atom,
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::frontend::SourceSpan;

    /// Build a token stream from `(kind, text)` pairs with dummy spans.
    fn toks(spec: &[(TokenKind, &str)]) -> Vec<Token> {
        spec.iter()
            .map(|(kind, text)| Token {
                kind: *kind,
                text: (*text).to_string(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: 0,
                    start_line: 1,
                    start_column: 1,
                },
            })
            .collect()
    }

    use TokenKind::{Identifier as Id, Keyword as Kw, Punctuation as Pu};
    const INT: TokenKind = TokenKind::Literal(LiteralKind::Integer);
    const FLT: TokenKind = TokenKind::Literal(LiteralKind::Float);

    #[test]
    fn consistent_renames_normalize_equal() {
        // `let total = a + b ; total` vs `let sum = x + y ; sum`
        let a = toks(&[
            (Kw, "let"),
            (Id, "total"),
            (Pu, "="),
            (Id, "a"),
            (Pu, "+"),
            (Id, "b"),
            (Pu, ";"),
            (Id, "total"),
        ]);
        let b = toks(&[
            (Kw, "let"),
            (Id, "sum"),
            (Pu, "="),
            (Id, "x"),
            (Pu, "+"),
            (Id, "y"),
            (Pu, ";"),
            (Id, "sum"),
        ]);
        assert_eq!(
            normalize(&a, LiteralNorm::Full),
            normalize(&b, LiteralNorm::Full)
        );
    }

    #[test]
    fn inconsistent_renames_do_not_normalize_equal() {
        // `a + a + b` vs `x + y + y`: numbering 0,0,1 vs 0,1,1.
        let a = toks(&[(Id, "a"), (Pu, "+"), (Id, "a"), (Pu, "+"), (Id, "b")]);
        let b = toks(&[(Id, "x"), (Pu, "+"), (Id, "y"), (Pu, "+"), (Id, "y")]);
        assert_ne!(
            normalize(&a, LiteralNorm::Full),
            normalize(&b, LiteralNorm::Full)
        );
    }

    #[test]
    fn literal_modes_control_literal_equality() {
        let a = toks(&[(Id, "x"), (Pu, "+"), (INT, "1")]);
        let b = toks(&[(Id, "y"), (Pu, "+"), (INT, "2")]);
        let c = toks(&[(Id, "z"), (Pu, "+"), (FLT, "2.0")]);
        // Full: any literal matches any literal.
        assert_eq!(
            normalize(&a, LiteralNorm::Full),
            normalize(&b, LiteralNorm::Full)
        );
        assert_eq!(
            normalize(&a, LiteralNorm::Full),
            normalize(&c, LiteralNorm::Full)
        );
        // Category: same category matches, different category does not.
        assert_eq!(
            normalize(&a, LiteralNorm::Category),
            normalize(&b, LiteralNorm::Category)
        );
        assert_ne!(
            normalize(&a, LiteralNorm::Category),
            normalize(&c, LiteralNorm::Category)
        );
        // Preserve: different values do not match.
        assert_ne!(
            normalize(&a, LiteralNorm::Preserve),
            normalize(&b, LiteralNorm::Preserve)
        );
    }

    #[test]
    fn method_and_path_names_are_preserved() {
        // `foo.len()` vs `bar.len()`: receiver renamed, method preserved.
        let len_a = toks(&[(Id, "foo"), (Pu, "."), (Id, "len"), (Pu, "("), (Pu, ")")]);
        let len_b = toks(&[(Id, "bar"), (Pu, "."), (Id, "len"), (Pu, "("), (Pu, ")")]);
        assert_eq!(
            normalize(&len_a, LiteralNorm::Full),
            normalize(&len_b, LiteralNorm::Full)
        );
        // `foo.len()` vs `foo.count()`: different methods must not match.
        let count = toks(&[(Id, "foo"), (Pu, "."), (Id, "count"), (Pu, "("), (Pu, ")")]);
        assert_ne!(
            normalize(&len_a, LiteralNorm::Full),
            normalize(&count, LiteralNorm::Full)
        );
        // `std::mem::swap` vs `std::mem::take`: path tails must not match.
        let swap = toks(&[
            (Id, "std"),
            (Pu, "::"),
            (Id, "mem"),
            (Pu, "::"),
            (Id, "swap"),
        ]);
        let take = toks(&[
            (Id, "std"),
            (Pu, "::"),
            (Id, "mem"),
            (Pu, "::"),
            (Id, "take"),
        ]);
        assert_ne!(
            normalize(&swap, LiteralNorm::Full),
            normalize(&take, LiteralNorm::Full)
        );
    }

    #[test]
    fn arrow_member_names_are_preserved() {
        // `p->next` vs `q->next`: pointer renamed, member preserved.
        let a = toks(&[(Id, "p"), (Pu, "->"), (Id, "next")]);
        let b = toks(&[(Id, "q"), (Pu, "->"), (Id, "next")]);
        assert_eq!(
            normalize(&a, LiteralNorm::Full),
            normalize(&b, LiteralNorm::Full)
        );
        // `p->next` vs `p->prev`: different members must not match.
        let c = toks(&[(Id, "p"), (Pu, "->"), (Id, "prev")]);
        assert_ne!(
            normalize(&a, LiteralNorm::Full),
            normalize(&c, LiteralNorm::Full)
        );
    }

    #[test]
    fn macro_names_and_uppercase_names_are_preserved() {
        let a = toks(&[(Id, "println"), (Pu, "!"), (Pu, "("), (Pu, ")")]);
        let b = toks(&[(Id, "eprintln"), (Pu, "!"), (Pu, "("), (Pu, ")")]);
        assert_ne!(
            normalize(&a, LiteralNorm::Full),
            normalize(&b, LiteralNorm::Full)
        );
        // `Some(x)` vs `Ok(x)`: variants preserved, payload renamed.
        let c = toks(&[(Id, "Some"), (Pu, "("), (Id, "x"), (Pu, ")")]);
        let d = toks(&[(Id, "Ok"), (Pu, "("), (Id, "x"), (Pu, ")")]);
        assert_ne!(
            normalize(&c, LiteralNorm::Full),
            normalize(&d, LiteralNorm::Full)
        );
    }

    #[test]
    fn normal_form_is_context_independent() {
        // The same sub-slice normalizes identically inside different hosts.
        let host_a = toks(&[
            (Id, "extra"),
            (Pu, ";"),
            (Kw, "let"),
            (Id, "v"),
            (Pu, "="),
            (INT, "1"),
            (Pu, ";"),
        ]);
        let host_b = toks(&[
            (Id, "p"),
            (Pu, "+"),
            (Id, "q"),
            (Pu, ";"),
            (Kw, "let"),
            (Id, "v"),
            (Pu, "="),
            (INT, "1"),
            (Pu, ";"),
        ]);
        let a = normalize(&host_a[2..], LiteralNorm::Full);
        let b = normalize(&host_b[4..], LiteralNorm::Full);
        assert_eq!(a, b);
    }

    #[test]
    fn keywords_and_punctuation_pass_through() {
        let a = toks(&[(Kw, "return"), (Pu, ";")]);
        let n = normalize(&a, LiteralNorm::Full);
        assert_eq!(n[0].atom, NormAtom::Text("return"));
        assert_eq!(n[1].atom, NormAtom::Text(";"));
    }
}
