//! Which arm of a preprocessor conditional a unit sits in.
//!
//! C and C++ sources are parsed unexpanded, so both arms of an `#if` are in
//! the IR at once. That is deliberate — the mode resolves no build conditions,
//! and dropping the arm a default configuration would not take would silently
//! hide code. It has a consequence for clone detection: the two arms of
//!
//! ```c
//! #ifdef _WIN32
//! void sleep_ms(int ms) { Sleep(ms); }
//! #else
//! void sleep_ms(int ms) { usleep(ms * 1000); }
//! #endif
//! ```
//!
//! measure as near-identical, and a report that calls them duplicates is
//! telling the reader to remove one. They cannot: exactly one of them exists
//! in any build, and which one is a build condition this mode does not
//! resolve. Reporting the pair would also put two build variants in one
//! finding, which the analysis does not do anywhere else.
//!
//! So the relation is recorded here and the pair is dropped before
//! verification, exactly as a unit nested inside another is: not because the
//! finding would rank badly, but because it is not a statement about any one
//! program.
//!
//! # What this does not claim
//!
//! Only *syntactic* exclusion is recognised: two units under arms of the same
//! conditional. Two units guarded by separate `#if`s that happen to be
//! mutually exclusive — `#ifdef A` here and `#ifndef A` there — are not
//! related by this, because relating them means evaluating the conditions, and
//! the conditions are what this mode does not have.
//!
//! # Only as good as the parse
//!
//! The arms are read off the tree, so a conditional the parser could not
//! follow has no trustworthy arms. That is not hypothetical: a C++ header
//! parsed by the C grammar — which happens whenever a project puts C++ in `.h`
//! and the header policy says C — recovers into a shape where one `#if`
//! swallows the rest of the file and its `#else` holds everything after it.
//! Measured on one such header, that turned ten genuine arm pairs into eight
//! hundred.
//!
//! Dropping a pair hides a finding, so the mistake is not symmetric: a missed
//! exclusion costs a noisy line in a report, an invented one costs a clone
//! nobody will ever see. A conditional is therefore only believed when the
//! parser stumbled nowhere inside it; one that encloses an error region still
//! nests, but relates none of the units under it.
//!
//! The judgement is per conditional rather than per file because error
//! recovery is not local to what broke. A single unparsable construct puts an
//! error region in the file, and a header whose include guard encloses
//! everything gets one spanning the whole of it, which says nothing about the
//! `#if` twenty lines further down. Measured across three C++ projects,
//! believing a whole file only when it is error-free left 69% to 77% of the
//! arms the parser had in fact read cleanly unused.

use crate::ir::{IrNode, Shape};

/// One conditional a unit is inside, and which of its arms.
///
/// Arms are numbered in source order: the `#if` is 0, the first `#elif` is 1,
/// and so on to the `#else`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Arm {
    /// Identifies the conditional, unique across the whole analysed corpus.
    conditional: u32,
    /// Which arm of it, in source order. Stays 0 for every arm of a
    /// conditional the parser stumbled inside, so that none of them is taken
    /// to differ from another.
    index: u32,
    /// Whether the parse of this conditional is worth believing.
    believed: bool,
}

/// The conditionals enclosing a unit, outermost first.
///
/// Empty for the overwhelming majority of units, which sit under no
/// conditional at all, and empty for every Rust unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArmPath {
    arms: Vec<Arm>,
}

impl ArmPath {
    /// The path that applies inside `node`, or `None` when `node` leaves it
    /// unchanged — which is every node but a conditional's own.
    ///
    /// `next` hands out conditional identifiers and must be shared across
    /// every file in a run, so that two files' conditionals never collide.
    ///
    /// Arms nest rather than sit side by side: the grammar puts a `#elif` and
    /// its `#else` inside the arm they follow, so entering one continues the
    /// conditional already open instead of starting another. A conditional the
    /// parser stumbled inside is entered too — it has to be, or a `#else`
    /// under it would advance the arm of the conditional above — but it is
    /// entered unbelieved, and none of its arms is distinguished from another.
    #[must_use]
    pub fn descend(&self, node: &IrNode, next: &mut u32) -> Option<Self> {
        let Shape::Native(kind) = &node.shape else {
            return None;
        };
        let mut arms = self.arms.clone();
        match &**kind {
            "preproc_if" | "preproc_ifdef" => {
                arms.push(Arm {
                    conditional: *next,
                    index: 0,
                    believed: !stumbled_inside(node),
                });
                *next = next.wrapping_add(1);
            }
            "preproc_elif" | "preproc_elifdef" | "preproc_elifndef" | "preproc_else" => {
                // A branch keyword outside any conditional is malformed input
                // the error-tolerant parser still hands over; there is no arm
                // to advance, so the path stays as it was.
                let arm = arms.last_mut()?;
                if !arm.believed {
                    return None;
                }
                arm.index += 1;
            }
            _ => return None,
        }
        Some(Self { arms })
    }

    /// Whether the two units can never both be part of one build.
    ///
    /// True when the paths agree down to some conditional and then take
    /// different arms of it. Diverging on *different* conditionals says
    /// nothing: those are two independent guards, and both can hold. An
    /// unbelieved conditional never separates anything: its arms all carry the
    /// same index, so two units under it agree there and the comparison
    /// continues into whatever nests below.
    #[must_use]
    pub fn excludes(&self, other: &Self) -> bool {
        self.arms
            .iter()
            .zip(&other.arms)
            .find(|(a, b)| a != b)
            .is_some_and(|(a, b)| a.believed && b.believed && a.conditional == b.conditional)
    }
}

/// Whether the parser stumbled anywhere inside `node`.
///
/// Recovered or not: the question here is whether the tree under this
/// conditional is the shape the source has, and a region the parser had to
/// recover from is a region whose arm boundaries it may have placed wrong.
/// That is a different question from how much code a parse lost, which
/// [`SyntaxIrFile::unaccounted_tokens`](crate::ir::SyntaxIrFile::unaccounted_tokens)
/// answers and which error regions measure badly.
fn stumbled_inside(node: &IrNode) -> bool {
    let mut stumbled = false;
    node.walk(&mut |inner| stumbled |= matches!(inner.shape, Shape::Error));
    stumbled
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::frontend::Lexeme;
    use crate::ir::ByteRange;

    fn node(shape: Shape, children: Vec<IrNode>) -> IrNode {
        IrNode {
            shape,
            name: None,
            token_start: 0,
            token_end: 0,
            range: ByteRange { start: 0, end: 0 },
            children,
        }
    }

    /// A conditional the parser read without stumbling.
    fn native(kind: &str) -> IrNode {
        node(Shape::Native(Lexeme::from(kind)), Vec::new())
    }

    /// The same, with an error region somewhere inside it.
    fn broken(kind: &str) -> IrNode {
        node(
            Shape::Native(Lexeme::from(kind)),
            vec![node(Shape::Error, Vec::new())],
        )
    }

    /// Walk a chain of shapes from the file root, returning the path inside
    /// the last one.
    fn path(kinds: &[&str]) -> ArmPath {
        let mut next = 0;
        let mut here = ArmPath::default();
        for kind in kinds {
            if let Some(descended) = here.descend(&native(kind), &mut next) {
                here = descended;
            }
        }
        here
    }

    #[test]
    fn a_shape_that_is_not_a_conditional_changes_nothing() {
        let mut next = 0;
        assert_eq!(
            ArmPath::default().descend(&node(Shape::Function, Vec::new()), &mut next),
            None
        );
        assert_eq!(
            ArmPath::default().descend(&native("goto_statement"), &mut next),
            None
        );
        assert_eq!(next, 0, "no identifier is spent on an ordinary shape");
    }

    #[test]
    fn the_two_arms_of_one_conditional_exclude_each_other() {
        let mut next = 0;
        let root = ArmPath::default();
        let taken = root.descend(&native("preproc_ifdef"), &mut next).unwrap();
        let otherwise = taken.descend(&native("preproc_else"), &mut next).unwrap();
        assert!(taken.excludes(&otherwise));
        assert!(otherwise.excludes(&taken));
    }

    #[test]
    fn every_arm_of_a_chain_excludes_every_other() {
        let mut next = 0;
        let root = ArmPath::default();
        let first = root.descend(&native("preproc_if"), &mut next).unwrap();
        let second = first.descend(&native("preproc_elif"), &mut next).unwrap();
        let third = second.descend(&native("preproc_else"), &mut next).unwrap();
        for (a, b) in [(&first, &second), (&first, &third), (&second, &third)] {
            assert!(a.excludes(b));
            assert!(b.excludes(a));
        }
    }

    #[test]
    fn a_unit_outside_every_conditional_excludes_nothing() {
        let outside = ArmPath::default();
        let guarded = path(&["preproc_ifdef"]);
        assert!(!outside.excludes(&guarded));
        assert!(!guarded.excludes(&outside));
        assert!(!outside.excludes(&ArmPath::default()));
    }

    #[test]
    fn two_separate_conditionals_do_not_exclude_each_other() {
        // `#ifdef A ... #endif` and `#ifdef B ... #endif` side by side. Both
        // can hold, and deciding otherwise means reading the conditions.
        let mut next = 0;
        let root = ArmPath::default();
        let here = root.descend(&native("preproc_ifdef"), &mut next).unwrap();
        let there = root.descend(&native("preproc_ifdef"), &mut next).unwrap();
        assert!(!here.excludes(&there));
        assert!(!there.excludes(&here));
    }

    #[test]
    fn exclusion_survives_further_nesting() {
        // One arm holds a nested conditional; a unit deep inside it is still
        // excluded by anything under the sibling arm.
        let mut next = 0;
        let root = ArmPath::default();
        let taken = root.descend(&native("preproc_if"), &mut next).unwrap();
        let deep = taken.descend(&native("preproc_ifdef"), &mut next).unwrap();
        let otherwise = taken.descend(&native("preproc_else"), &mut next).unwrap();
        assert!(deep.excludes(&otherwise));
        assert!(otherwise.excludes(&deep));
        // But not by something under the same arm as it.
        assert!(!deep.excludes(&taken));
    }

    #[test]
    fn a_branch_keyword_with_no_conditional_open_is_survivable() {
        // The parser is error-tolerant, so a stray `#else` reaches here.
        let mut next = 0;
        assert_eq!(
            ArmPath::default().descend(&native("preproc_else"), &mut next),
            None
        );
    }

    #[test]
    fn a_conditional_the_parser_stumbled_inside_relates_nothing() {
        let mut next = 0;
        let root = ArmPath::default();
        let taken = root.descend(&broken("preproc_if"), &mut next).unwrap();
        let otherwise = taken.descend(&native("preproc_else"), &mut next);
        // The arms are not told apart, so nothing under this conditional is
        // taken to rule anything else out.
        assert_eq!(otherwise, None);
        assert!(!taken.excludes(&root));
        assert!(!root.excludes(&taken));
    }

    #[test]
    fn a_sound_conditional_inside_a_broken_one_still_relates_its_own_arms() {
        // The outer `#if` is unreadable, which says nothing about an inner one
        // the parser followed. Entering the outer one is still necessary: the
        // inner arms must not be mistaken for the outer's.
        let mut next = 0;
        let outer = ArmPath::default()
            .descend(&broken("preproc_if"), &mut next)
            .unwrap();
        let inner = outer.descend(&native("preproc_ifdef"), &mut next).unwrap();
        let otherwise = inner.descend(&native("preproc_else"), &mut next).unwrap();
        assert!(inner.excludes(&otherwise));
        assert!(!inner.excludes(&outer));
    }

    #[test]
    fn an_else_under_a_broken_conditional_leaves_the_sound_one_above_alone() {
        // Without the unbelieved level in between, this `#else` would advance
        // the arm of the conditional above it and invent an exclusion.
        let mut next = 0;
        let outer = ArmPath::default()
            .descend(&native("preproc_if"), &mut next)
            .unwrap();
        let broken_inner = outer.descend(&broken("preproc_if"), &mut next).unwrap();
        assert_eq!(
            broken_inner.descend(&native("preproc_else"), &mut next),
            None
        );
        assert!(!broken_inner.excludes(&outer));
    }

    #[test]
    fn an_error_beside_a_conditional_does_not_touch_it() {
        // Error regions are routine — one bad construct anywhere in a header
        // puts one in the file — so soundness is asked of the conditional
        // itself, not of everything around it.
        let mut next = 0;
        let file = node(
            Shape::Impl,
            vec![node(Shape::Error, Vec::new()), native("preproc_if")],
        );
        let opener = file.children.last().unwrap();
        let taken = ArmPath::default().descend(opener, &mut next).unwrap();
        let otherwise = taken.descend(&native("preproc_else"), &mut next).unwrap();
        assert!(taken.excludes(&otherwise));
    }
}
