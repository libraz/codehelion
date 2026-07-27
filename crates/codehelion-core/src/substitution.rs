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
//! # How the two occurrences are lined up
//!
//! By the very thing normalization kept. Two tokens may stand in the same place
//! when they are the same kind — [`TokenKind::tag`] decides that, and it is the
//! detector's own answer to what counts as the same token once the spelling is
//! gone. So the alignment is computed over the normalized run and the
//! substitutions are read off the raw one: exactly the two halves of what a
//! Type-2 match is.
//!
//! Where an occurrence has tokens the other does not, those are edits rather
//! than substitutions, and [`Witness::edits`] counts them. Nothing here decides
//! what an edit means; a rule reading a witness does.
//!
//! # What it does not do
//!
//! It gives up on a pair too large to align, because the alignment is quadratic
//! and a bound that is never hit is a bound nobody has tested. Being unable to
//! say is recorded as [`None`], never as an empty witness.

use crate::frontend::{LiteralKind, Token, TokenKind};

/// Version of the witness rules, for recording alongside the other detector
/// versions when something acts on one.
pub const SUBSTITUTION_VERSION: &str = "substitution-v2";

/// Largest product of the two token counts an alignment is computed for.
///
/// The table is one `u32` per cell, so this is four megabytes at the top end,
/// spent on a pair of four-hundred-line bodies. Above it the answer is that
/// nobody looked, which is what [`None`] says.
const ALIGNMENT_LIMIT: usize = 1 << 20;

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
    /// Tokens on either side that had no counterpart in the other.
    ///
    /// A substitution is one token standing where another stood. These are the
    /// rest: the statement one occurrence has and the other does not, the cast
    /// added on one side only. Counted rather than described, because a rule
    /// over a witness cares whether the two bodies do the same work, and that
    /// question is answered by there being none of these.
    pub edits: usize,
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

    /// Whether these two occurrences read as one routine written once per
    /// width.
    ///
    /// The two questions above, asked together, which is the only way either is
    /// worth asking. Kept here rather than at each call site so the rule the
    /// engine acts on and the rule the corpus is measured against cannot drift
    /// apart.
    ///
    /// Nothing is asked about [`Self::edits`]: a routine written for the wider
    /// type does work the narrower one has no need of, and bounding that would
    /// mean choosing a number no measurement over real code has supported.
    #[must_use]
    pub fn written_once_per_width(&self) -> bool {
        self.one_width_apart().is_some() && !self.touches_a_literal()
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

/// The substitutions turning `left` into `right`, or `None` when the pair is
/// too large to align.
///
/// The alignment is the one that pairs off the most tokens, counting an
/// identical token for twice what a merely same-kind one is worth, so a name
/// that did not change is never passed over in favour of one that did. Tokens
/// left unpaired are counted in [`Witness::edits`]; paired tokens whose text
/// differs are the substitutions.
#[must_use]
pub fn witness(left: &[Token], right: &[Token]) -> Option<Witness> {
    let (rows, columns) = (left.len(), right.len());
    if rows.checked_mul(columns)? > ALIGNMENT_LIMIT {
        return None;
    }
    let stride = columns + 1;

    // score[i][j] is the best total over the suffixes starting at i and j.
    // Filled backwards so the traceback can read it forwards.
    let mut score = vec![0u32; (rows + 1) * stride];
    for i in (0..rows).rev() {
        for j in (0..columns).rev() {
            let paired = pairing(&left[i], &right[j]);
            let best = score[(i + 1) * stride + j].max(score[i * stride + j + 1]);
            score[i * stride + j] = if paired > 0 {
                best.max(score[(i + 1) * stride + j + 1] + paired)
            } else {
                best
            };
        }
    }

    let mut changes: Vec<Change> = Vec::new();
    let mut edits = 0usize;
    let (mut i, mut j) = (0usize, 0usize);
    while i < rows && j < columns {
        let paired = pairing(&left[i], &right[j]);
        let here = score[i * stride + j];
        if paired > 0 && here == score[(i + 1) * stride + j + 1] + paired {
            note(&mut changes, &left[i], &right[j]);
            i += 1;
            j += 1;
        } else if here == score[(i + 1) * stride + j] {
            i += 1;
            edits += 1;
        } else {
            j += 1;
            edits += 1;
        }
    }
    // Whatever either run has left over was paired with nothing.
    edits += (rows - i) + (columns - j);
    Some(Witness { changes, edits })
}

/// What pairing these two tokens is worth: nothing unless they are the same
/// kind, and one more when they are also the same text.
///
/// The two numbers are three and two rather than two and one so that the count
/// of pairings decides first and the identical text only breaks a tie: two
/// same-kind pairings are worth four and one identical pairing three, so
/// nothing is ever left unpaired to keep a name intact. That order is the
/// careful one. Reading a differing name as a substitution puts one more
/// change in front of a rule that has to explain every one of them, where
/// reading it as an insertion beside a deletion puts none.
fn pairing(left: &Token, right: &Token) -> u32 {
    if left.kind.tag() != right.kind.tag() {
        0
    } else if left.text == right.text {
        3
    } else {
        2
    }
}

/// Record the change between two paired tokens, unless they are the same text
/// or the change is already known.
fn note(changes: &mut Vec<Change>, from: &Token, to: &Token) {
    if from.text == to.text {
        return;
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
    fn a_token_with_no_counterpart_is_an_edit_and_not_a_change() {
        let left = tokens(&[name("a")]);
        let right = tokens(&[name("a"), name("b")]);
        let witness = witness(&left, &right).unwrap();
        assert!(witness.changes.is_empty(), "nothing was substituted");
        assert_eq!(witness.edits, 1);
    }

    #[test]
    fn a_pair_too_large_to_align_has_no_witness() {
        let long = tokens(&vec![name("a"); 1100]);
        assert_eq!(witness(&long, &long), None);
    }

    #[test]
    fn identical_runs_witness_no_change() {
        let left = tokens(&[name("a"), name("b")]);
        let witness = witness(&left, &left).unwrap();
        assert!(witness.changes.is_empty());
        assert_eq!(witness.edits, 0);
        // No change is not one width apart: they are the same text, which is
        // what a verbatim copy is.
        assert_eq!(witness.one_width_apart(), None);
    }

    #[test]
    fn two_runs_of_one_shape_are_read_as_substitutions_throughout() {
        // Keeping the `b` would mean leaving a token unpaired on each side. The
        // alignment does not: same shape, both names changed, which is the
        // reading a rule over the changes has to answer for.
        let left = tokens(&[name("b"), name("x")]);
        let right = tokens(&[name("y"), name("b")]);
        let witness = witness(&left, &right).unwrap();
        assert_eq!(witness.edits, 0);
        assert_eq!(witness.changes.len(), 2);
    }

    #[test]
    fn an_identical_name_settles_which_of_two_alignments_is_read() {
        // Either `b` or `c` can be dropped to line these up. Dropping `b`
        // leaves `c` against `c`; dropping `c` leaves `b` against `c` and
        // invents a substitution nobody wrote.
        let left = tokens(&[name("a"), name("b"), name("c")]);
        let right = tokens(&[name("a"), name("c")]);
        let witness = witness(&left, &right).unwrap();
        assert!(witness.changes.is_empty());
        assert_eq!(witness.edits, 1);
    }

    #[test]
    fn a_width_swap_survives_an_edit_beside_it() {
        // The 64-bit routine has a step the 32-bit one does not. The names are
        // still one width apart; the extra work is an edit, and what that is
        // worth is not this module's question.
        let left = tokens(&[name("U32"), name("read32")]);
        let right = tokens(&[name("U64"), name("read64"), name("finalize")]);
        let witness = witness(&left, &right).unwrap();
        assert_eq!(witness.one_width_apart(), Some(("32", "64")));
        assert_eq!(witness.edits, 1);
    }

    #[test]
    fn a_kind_that_differs_is_not_paired_off() {
        let left = tokens(&[name("value")]);
        let right = tokens(&[number("7")]);
        let witness = witness(&left, &right).unwrap();
        assert!(witness.changes.is_empty(), "a name did not become a number");
        assert_eq!(witness.edits, 2);
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
