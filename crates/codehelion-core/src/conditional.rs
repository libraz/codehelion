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
//! The arms are read off the tree, so a file the parser could not follow has
//! no trustworthy arms. That is not hypothetical: a C++ header parsed by the C
//! grammar — which happens whenever a project puts C++ in `.h` and the header
//! policy says C — recovers into a shape where one `#if` swallows the rest of
//! the file and its `#else` holds everything after it. Measured on one such
//! header, that turned ten genuine arm pairs into eight hundred.
//!
//! Dropping a pair hides a finding, so the mistake is not symmetric: a missed
//! exclusion costs a noisy line in a report, an invented one costs a clone
//! nobody will ever see. [`ArmPath`] is therefore only built for files the
//! parser reported no error regions in; elsewhere every unit gets the empty
//! path and excludes nothing.

use crate::ir::Shape;

/// One conditional a unit is inside, and which of its arms.
///
/// Arms are numbered in source order: the `#if` is 0, the first `#elif` is 1,
/// and so on to the `#else`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Arm {
    /// Identifies the conditional, unique across the whole analysed corpus.
    conditional: u32,
    /// Which arm of it, in source order.
    index: u32,
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
    /// The path that applies inside `shape`, or `None` when `shape` leaves it
    /// unchanged — which is every shape but a conditional's own.
    ///
    /// `next` hands out conditional identifiers and must be shared across
    /// every file in a run, so that two files' conditionals never collide.
    ///
    /// Arms nest rather than sit side by side: the grammar puts a `#elif` and
    /// its `#else` inside the arm they follow, so entering one continues the
    /// conditional already open instead of starting another.
    #[must_use]
    pub fn descend(&self, shape: &Shape, next: &mut u32) -> Option<Self> {
        let Shape::Native(kind) = shape else {
            return None;
        };
        let mut arms = self.arms.clone();
        match &**kind {
            "preproc_if" | "preproc_ifdef" => {
                arms.push(Arm {
                    conditional: *next,
                    index: 0,
                });
                *next = next.wrapping_add(1);
            }
            "preproc_elif" | "preproc_elifdef" | "preproc_elifndef" | "preproc_else" => {
                // A branch keyword outside any conditional is malformed input
                // the error-tolerant parser still hands over; there is no arm
                // to advance, so the path stays as it was.
                arms.last_mut()?.index += 1;
            }
            _ => return None,
        }
        Some(Self { arms })
    }

    /// Whether the two units can never both be part of one build.
    ///
    /// True when the paths agree down to some conditional and then take
    /// different arms of it. Diverging on *different* conditionals says
    /// nothing: those are two independent guards, and both can hold.
    #[must_use]
    pub fn excludes(&self, other: &Self) -> bool {
        self.arms
            .iter()
            .zip(&other.arms)
            .find(|(a, b)| a != b)
            .is_some_and(|(a, b)| a.conditional == b.conditional)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::frontend::Lexeme;

    fn native(kind: &str) -> Shape {
        Shape::Native(Lexeme::from(kind))
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
            ArmPath::default().descend(&Shape::Function, &mut next),
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
}
