//! What normalization erased: which name became which.
//!
//! Type-2 detection works by not looking at identifiers, so two occurrences
//! that differ only in their names come out equal. That is the right thing for
//! finding the duplication and the wrong thing for judging it, because the
//! commonest false positive in a typed language is a set of routines the
//! language forced apart — one per integer width, one per float width — and
//! the only thing that says so is the very substitution normalization threw
//! away.
//!
//! This keeps it. A [`Witness`] is the list of name changes that turn one
//! occurrence into the other, with the two questions worth asking of them
//! already answered: whether every change is the same width being swapped for
//! another, and whether any of them changed a literal rather than a name.
//!
//! # What it does not do
//!
//! It aligns by position and gives up when the two token runs are different
//! lengths. A Type-3 pair needs a real alignment, and reading a witness off a
//! rough one would invent substitutions that nobody wrote. Being unable to say
//! is recorded as [`None`], never as an empty witness.

use crate::frontend::{LiteralKind, Token, TokenKind};

/// Version of the witness rules, for recording alongside the other detector
/// versions when something acts on one.
pub const SUBSTITUTION_VERSION: &str = "substitution-v1";

/// The integer widths a type is spelled with.
///
/// Written as digits rather than as type names on purpose. A list of type
/// spellings is a list per language, out of date the moment a project defines
/// `U32`; the widths are the same three-or-so tokens everywhere, and they are
/// what the spellings are built out of — `u32`, `int32_t`, `XXH32_hash_t`.
const WIDTHS: [&str; 5] = ["8", "16", "32", "64", "128"];

/// One name replaced by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The text on the left-hand occurrence.
    pub from: String,
    /// The text on the right-hand occurrence.
    pub to: String,
    /// Whether the token that changed was a literal rather than a name.
    pub literal: bool,
}

/// The substitutions that turn one occurrence into another.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Witness {
    /// Each distinct change, in the order first seen.
    pub changes: Vec<Change>,
}

impl Witness {
    /// The one width swap that explains every change, if there is one.
    ///
    /// `Some(("32", "64"))` says every token that differs does so by having
    /// that width in place of the other, everywhere it occurs: `u32`/`u64`,
    /// `read32`/`read64`, `XXH32_hash_t`/`XXH64_hash_t`. That is what a set of
    /// routines written once per width looks like from the outside, and it is
    /// not what a copied function looks like — a copy renamed by hand changes
    /// names that have nothing to do with each other.
    ///
    /// `None` when the changes are not all one swap, and for a witness with no
    /// changes at all: two occurrences that differ in nothing were not written
    /// one per width, they are the same text.
    #[must_use]
    pub fn one_width_apart(&self) -> Option<(&'static str, &'static str)> {
        if self.changes.is_empty() {
            return None;
        }
        WIDTHS
            .into_iter()
            .flat_map(|from| WIDTHS.into_iter().map(move |to| (from, to)))
            .find(|&(from, to)| {
                from != to
                    && self.changes.iter().all(|change| {
                        change.from.contains(from) && change.from.replace(from, to) == change.to
                    })
            })
    }

    /// Whether any change replaced a literal.
    ///
    /// A changed constant is a changed answer. Two bodies alike but for the
    /// number they compare against are two decisions, however alike they read,
    /// so no rule that sets duplication aside should reach them.
    #[must_use]
    pub fn touches_a_literal(&self) -> bool {
        self.changes.iter().any(|change| change.literal)
    }
}

/// The substitutions turning `left` into `right`, or `None` when the two runs
/// cannot be lined up.
///
/// Alignment is positional, so the runs must be the same length. Tokens whose
/// kind differs are a change like any other; what matters downstream is which
/// text became which, not what the lexer called it.
#[must_use]
pub fn witness(left: &[Token], right: &[Token]) -> Option<Witness> {
    if left.len() != right.len() {
        return None;
    }
    let mut changes: Vec<Change> = Vec::new();
    for (from, to) in left.iter().zip(right) {
        if from.text == to.text {
            continue;
        }
        let change = Change {
            from: from.text.to_string(),
            to: to.text.to_string(),
            literal: is_literal(from.kind) || is_literal(to.kind),
        };
        if !changes.contains(&change) {
            changes.push(change);
        }
    }
    Some(Witness { changes })
}

const fn is_literal(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Literal(
            LiteralKind::Integer
                | LiteralKind::Float
                | LiteralKind::String
                | LiteralKind::Char
                | LiteralKind::Bool
        )
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::frontend::SourceSpan;

    fn tokens(spec: &[(TokenKind, &str)]) -> Vec<Token> {
        spec.iter()
            .map(|&(kind, text)| Token {
                kind,
                text: text.into(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: text.len(),
                    start_line: 1,
                    start_column: 1,
                },
            })
            .collect()
    }

    fn name(text: &str) -> (TokenKind, &str) {
        (TokenKind::Identifier, text)
    }

    fn number(text: &str) -> (TokenKind, &str) {
        (TokenKind::Literal(LiteralKind::Integer), text)
    }

    #[test]
    fn runs_of_different_lengths_have_no_witness() {
        let left = tokens(&[name("a")]);
        let right = tokens(&[name("a"), name("b")]);
        assert_eq!(witness(&left, &right), None);
    }

    #[test]
    fn identical_runs_witness_no_change() {
        let left = tokens(&[name("a"), name("b")]);
        let witness = witness(&left, &left).unwrap();
        assert!(witness.changes.is_empty());
        // No change is not one width apart: they are the same text, which is
        // what a verbatim copy is.
        assert_eq!(witness.one_width_apart(), None);
    }

    #[test]
    fn a_change_is_recorded_once_however_often_it_recurs() {
        let left = tokens(&[name("u32"), name("u32"), name("u32")]);
        let right = tokens(&[name("u64"), name("u64"), name("u64")]);
        let witness = witness(&left, &right).unwrap();
        assert_eq!(witness.changes.len(), 1);
    }

    #[test]
    fn one_width_everywhere_is_recognised() {
        // `U32 read32(...)` against `U64 read64(...)`: the whole difference is
        // the width, in the type and in the names built from it.
        let left = tokens(&[name("U32"), name("XXH_read32"), name("XXH_swap32")]);
        let right = tokens(&[name("U64"), name("XXH_read64"), name("XXH_swap64")]);
        assert_eq!(
            witness(&left, &right).unwrap().one_width_apart(),
            Some(("32", "64"))
        );
    }

    #[test]
    fn a_rename_that_is_not_a_width_is_not_one() {
        // A function copied between two amalgamated libraries: one systematic
        // rename, and nothing to do with a type.
        let left = tokens(&[name("LZ4_isLittleEndian")]);
        let right = tokens(&[name("XXH_isLittleEndian")]);
        assert_eq!(witness(&left, &right).unwrap().one_width_apart(), None);
    }

    #[test]
    fn a_width_beside_a_rename_that_is_not_one_is_not_one_either() {
        // `long`/`short` alongside `m8Index`/`m4Index`: digits change, but not
        // every change is that digit, so the pair was not written per width.
        let left = tokens(&[name("long"), name("m8Index")]);
        let right = tokens(&[name("short"), name("m4Index")]);
        assert_eq!(witness(&left, &right).unwrap().one_width_apart(), None);
    }

    #[test]
    fn a_changed_constant_is_visible_as_one() {
        let left = tokens(&[name("wait"), number("24")]);
        let right = tokens(&[name("wait"), number("1")]);
        assert!(witness(&left, &right).unwrap().touches_a_literal());
    }

    #[test]
    fn a_constant_that_reads_like_a_width_is_still_a_constant() {
        // The digits alone do not say a type was involved. Two bodies that
        // differ in a number are two answers, and a rule that sets width
        // families aside has to be able to tell that apart from a type name.
        let left = tokens(&[number("32")]);
        let right = tokens(&[number("64")]);
        let witness = witness(&left, &right).unwrap();
        assert_eq!(witness.one_width_apart(), Some(("32", "64")));
        assert!(witness.touches_a_literal());
    }
}
