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
//!
//! ## What the member-access rule costs, measured
//!
//! The third rule is the one that gives up the most, and it earns it. Dropping
//! it alone — still preserving types, paths and macro names — was run against
//! the labelled corpora: seventy groups appear that this mode did not report
//! before. Reading them, most are the families the labels already call
//! something other than duplication: exhaustive match tables dispatching to one
//! method per variant, forwarding split by a compile-time flag, option parsers
//! reading one named field per line, and operations mirrored over a start and
//! an end. Those all have one shape and differ only in which member they name,
//! which is exactly what this rule refuses to look past.
//!
//! It does lose real clones. Functions that walk a container by different link
//! fields — first versus last, next versus previous — are labelled clones of
//! each other, and this mode does not report them because `->next` and
//! `->prev` survive normalization as different text. Structural mode reports
//! all of them in one group, because its features read shape and token kinds
//! and never read identifiers at all. That is the division the two modes are
//! for: this one is the cheap screen and pays for its speed in recall.
//!
//! A caution about the figure that measurement produces. The labels rule on
//! about a seventh of what this mode reports, and that seventh is the part
//! Structural also flagged — so it is where the genuine clones concentrate.
//! Judged precision therefore *rises* when the rule is dropped, while what
//! actually arrives is mostly the boilerplate above. The judged share of a
//! biased sample is not this mode's precision.

use std::collections::{BTreeMap, BTreeSet};

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

/// What a compiler resolved the names in a file to, by the byte each name
/// starts at.
///
/// The preservation rules above are lexical guesses at a question a compiler
/// answers outright, and they are wrong in both directions: a local closure
/// named like a method is preserved when it should be renamed, and a
/// lowercase free function from another crate is renamed when it should be
/// preserved. Where a compiler has spoken, its answer replaces the guess —
/// in both directions, because correcting only the misses would leave the
/// over-preservation the guess causes, which is the half that costs recall.
///
/// Byte offsets rather than indices: the resolution is about a file, and a
/// fragment is a slice of one. A token's own start byte survives being sliced
/// out; its position in the slice does not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    external: BTreeSet<usize>,
    local: BTreeSet<usize>,
}

impl Resolution {
    /// Nothing resolved yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the name starting at `start_byte` was resolved, and whether
    /// its definition is outside the code being scanned.
    pub fn insert(&mut self, start_byte: usize, external: bool) {
        if external {
            self.local.remove(&start_byte);
            self.external.insert(start_byte);
        } else {
            self.external.remove(&start_byte);
            self.local.insert(start_byte);
        }
    }

    /// Whether nothing was resolved, in which case normalizing with this is
    /// the same as normalizing without it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.external.is_empty() && self.local.is_empty()
    }

    /// What was resolved about the name starting at `start_byte`, or `None`
    /// when nothing was.
    fn verdict(&self, start_byte: usize) -> Option<bool> {
        if self.external.contains(&start_byte) {
            Some(true)
        } else if self.local.contains(&start_byte) {
            Some(false)
        } else {
            None
        }
    }
}

/// Whether the identifier at `i` is preserved rather than renamed.
///
/// A compiler's answer wins where there is one; the lexical rules are what
/// remains when nothing resolved this name.
fn is_preserved(tokens: &[Token], i: usize, resolved: Option<&Resolution>) -> bool {
    if let Some(verdict) = resolved.and_then(|r| r.verdict(tokens[i].span.start_byte)) {
        return verdict;
    }
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
    let mut out = Vec::new();
    normalize_into(tokens, literals, &mut out);
    out
}

/// [`normalize`] into a caller-owned buffer.
///
/// The buffer is cleared first. Callers normalizing millions of fragments
/// reuse one buffer instead of allocating a vector per fragment.
pub fn normalize_into<'a>(
    tokens: &'a [Token],
    literals: LiteralNorm,
    out: &mut Vec<NormToken<'a>>,
) {
    normalize_resolved_into(tokens, literals, None, out);
}

/// [`normalize_into`] with what a compiler resolved about the names.
///
/// Passing `None` is the modes that run no compiler, and produces exactly
/// what [`normalize_into`] does. Passing a [`Resolution`] produces a different
/// normal form for the same tokens, which is why the analysis mode is part of
/// every fingerprint's context: the two are not comparable and must never
/// merge on an equal hash.
pub fn normalize_resolved_into<'a>(
    tokens: &'a [Token],
    literals: LiteralNorm,
    resolved: Option<&Resolution>,
    out: &mut Vec<NormToken<'a>>,
) {
    out.clear();
    let mut names: BTreeMap<&str, u32> = BTreeMap::new();
    out.extend(tokens.iter().enumerate().map(|(i, token)| {
        let atom = match token.kind {
            TokenKind::Identifier if is_preserved(tokens, i, resolved) => {
                NormAtom::Text(&token.text)
            }
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
    }));
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
                text: (*text).into(),
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

    /// The same tokens, laid out at distinct byte offsets so a resolution can
    /// name one of them.
    fn placed(spec: &[(TokenKind, &str)]) -> Vec<Token> {
        let mut at = 0;
        spec.iter()
            .map(|(kind, text)| {
                let start = at;
                at += text.len() + 1;
                Token {
                    kind: *kind,
                    text: (*text).into(),
                    span: SourceSpan {
                        start_byte: start,
                        end_byte: start + text.len(),
                        start_line: 1,
                        start_column: u32::try_from(start).unwrap() + 1,
                    },
                }
            })
            .collect()
    }

    fn normalized<'a>(tokens: &'a [Token], resolved: Option<&Resolution>) -> Vec<NormToken<'a>> {
        let mut out = Vec::new();
        normalize_resolved_into(tokens, LiteralNorm::Full, resolved, &mut out);
        out
    }

    /// The lexical rules preserve a lowercase name only next to `::`, `.`,
    /// `->` or `!`. A free function imported from another crate is none of
    /// those, and renaming it lets two fragments that call different libraries
    /// normalize equal. A compiler knows better.
    #[test]
    fn a_name_the_rules_would_rename_is_preserved_when_it_is_resolved_external() {
        let tokens = placed(&[(Id, "encode"), (Pu, "("), (Id, "value"), (Pu, ")")]);
        assert_eq!(normalized(&tokens, None)[0].atom, NormAtom::Renamed(0));

        let mut resolution = Resolution::new();
        resolution.insert(tokens[0].span.start_byte, true);
        let resolved = normalized(&tokens, Some(&resolution));
        assert_eq!(resolved[0].atom, NormAtom::Text("encode"));
        // The name beside it was not resolved, so the rules still decide it.
        assert_eq!(resolved[2].atom, NormAtom::Renamed(0));
    }

    /// And the other direction, which is the half that costs recall: the rules
    /// preserve anything capitalised or reached through a member access, so a
    /// local binding shaped like one is never renamed and two fragments that
    /// differ only in that name stop matching.
    #[test]
    fn a_name_the_rules_would_preserve_is_renamed_when_it_is_resolved_local() {
        let tokens = placed(&[(Id, "Buffer"), (Pu, "."), (Id, "len")]);
        let guessed = normalized(&tokens, None);
        assert_eq!(guessed[0].atom, NormAtom::Text("Buffer"));
        assert_eq!(guessed[2].atom, NormAtom::Text("len"));

        let mut resolution = Resolution::new();
        resolution.insert(tokens[0].span.start_byte, false);
        let resolved = normalized(&tokens, Some(&resolution));
        assert_eq!(resolved[0].atom, NormAtom::Renamed(0));
        assert_eq!(resolved[2].atom, NormAtom::Text("len"));
    }

    /// Two fragments a compiler resolved the same way normalize equal even
    /// where the lexical rules keep them apart — which is the point of asking a
    /// compiler at all.
    ///
    /// This is the shape the member-access rule is known to lose: two walks
    /// over one container that differ only in which link field they follow are
    /// copies of each other, and the rules read `.next` and `.prev` as
    /// different code because they cannot tell a field from an API.
    #[test]
    fn two_fragments_resolved_alike_normalize_alike() {
        let a = placed(&[(Id, "node"), (Pu, "."), (Id, "next")]);
        let b = placed(&[(Id, "node"), (Pu, "."), (Id, "prev")]);
        assert_ne!(normalized(&a, None), normalized(&b, None));

        let mut ra = Resolution::new();
        ra.insert(a[2].span.start_byte, false);
        let mut rb = Resolution::new();
        rb.insert(b[2].span.start_byte, false);
        assert_eq!(normalized(&a, Some(&ra)), normalized(&b, Some(&rb)));
    }

    /// A resolution that says nothing changes nothing, so the modes that run no
    /// compiler are unaffected by the path existing.
    #[test]
    fn an_empty_resolution_normalizes_exactly_as_no_resolution_does() {
        let tokens = placed(&[(Id, "Value"), (Pu, "::"), (Id, "from"), (Id, "x")]);
        let empty = Resolution::new();
        assert!(empty.is_empty());
        assert_eq!(normalized(&tokens, Some(&empty)), normalized(&tokens, None));
    }

    /// The last word about one name wins; a resolution cannot hold both
    /// answers about the same place at once.
    #[test]
    fn resolving_one_name_twice_keeps_the_later_answer() {
        let tokens = placed(&[(Id, "encode")]);
        let mut resolution = Resolution::new();
        resolution.insert(tokens[0].span.start_byte, true);
        resolution.insert(tokens[0].span.start_byte, false);
        assert_eq!(
            normalized(&tokens, Some(&resolution))[0].atom,
            NormAtom::Renamed(0)
        );
    }
}
