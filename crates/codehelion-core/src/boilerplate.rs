//! Boilerplate classification: recognising units whose duplication is
//! expected rather than a finding.
//!
//! Some code is duplicated because the language leaves no other way to write
//! it. A getter, a delegating wrapper and a run of macro invocations are all
//! genuine clones by every similarity measure, and reporting them crowds out
//! the duplication a reader can act on. This module names those shapes so
//! presentation can decide what to do with them.
//!
//! # What this is not
//!
//! Classification is *syntactic and conservative*. It reads the unit's IR
//! subtree and nothing else: no name heuristics, no path guesses, no attempt
//! to infer intent. A unit that carries any control flow is never classified,
//! because branching is where behaviour — and therefore the interesting kind
//! of duplication — lives.
//!
//! The classification is recorded, never acted on here: a classified unit is
//! still analysed, still verified and still grouped. Whether a category is
//! excluded from reports, ranked down or shown as-is is a presentation
//! decision, so a user can always see what was set aside and why.

use crate::ir::{IrNode, Shape};

/// Version of the classification rules.
///
/// Recorded alongside the other detector versions: a change in what counts as
/// boilerplate changes which findings a report shows, so results from two
/// versions are not comparable without saying so.
pub const BOILERPLATE_VERSION: &str = "boilerplate-v1";

/// A recognised boilerplate shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Boilerplate {
    /// No call and no control flow, with at most one statement: getters,
    /// setters and stubs. The body moves a value and does nothing else.
    TrivialBody,
    /// Exactly one call and nothing else: a wrapper that delegates.
    Forwarding,
    /// A body that is nothing but macro invocations, at least two of them.
    /// What the macros expand to is unknown here — the repetition itself is
    /// the observation.
    MacroRepetition,
}

impl Boilerplate {
    /// Stable lowercase identifier used in reports and configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TrivialBody => "trivial-body",
            Self::Forwarding => "forwarding",
            Self::MacroRepetition => "macro-repetition",
        }
    }

    /// Every category, in the order reports and configuration list them.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::TrivialBody, Self::Forwarding, Self::MacroRepetition]
    }

    /// The category with this identifier, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::all().into_iter().find(|kind| kind.name() == name)
    }
}

/// What a unit's body contains, counted over its whole subtree.
///
/// Calls are counted apart from statements because the IR models a call as an
/// expression: `f();` is one call node, not a statement wrapping one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Body {
    /// Branches, loops, multi-way conditionals and error handling.
    control: usize,
    /// Call expressions that are not themselves an argument to a call.
    ///
    /// Nesting is what separates delegation from work. `f(g(x), h(y))` is one
    /// delegation whose arguments happen to be computed by call: counting
    /// three calls there would say a wrapper does three things, when what it
    /// does is call `f`. Sibling calls are counted apart, because two calls in
    /// a row are two things done.
    calls: usize,
    /// Macro invocations.
    macros: usize,
    /// Statements other than macro invocations and control flow.
    statements: usize,
    /// Statements that are not a `return`.
    ///
    /// A `return` around the delegation is punctuation, not work; anything
    /// else in the body is work.
    working_statements: usize,
}

/// Classify a unit by the shape of its body, or return `None` when it does
/// something a reader would want to see duplicated.
///
/// The unit node itself is not counted; only what it contains.
#[must_use]
pub fn classify(unit: &IrNode) -> Option<Boilerplate> {
    let body = count(unit);
    // Anything that branches, loops or handles errors carries behaviour.
    if body.control > 0 {
        return None;
    }
    if body.macros >= 2 && body.calls == 0 && body.statements == 0 {
        return Some(Boilerplate::MacroRepetition);
    }
    if body.macros > 0 {
        return None;
    }
    if body.statements > 1 {
        return None;
    }
    match body.calls {
        0 => Some(Boilerplate::TrivialBody),
        // One delegation, and nothing around it but a `return`.
        1 if body.working_statements == 0 => Some(Boilerplate::Forwarding),
        _ => None,
    }
}

/// Count what a unit's subtree contains, excluding the unit node itself.
fn count(unit: &IrNode) -> Body {
    let mut body = Body::default();
    for child in &unit.children {
        descend(child, false, &mut body);
    }
    body
}

/// Tally `node` and its subtree, remembering whether it sits inside a call.
fn descend(node: &IrNode, in_call: bool, body: &mut Body) {
    tally(node, in_call, body);
    let nested = in_call || node.shape == Shape::Call;
    for child in &node.children {
        descend(child, nested, body);
    }
}

const fn tally(node: &IrNode, in_call: bool, body: &mut Body) {
    match node.shape {
        Shape::Loop
        | Shape::Branch
        | Shape::Match
        | Shape::MatchArm
        | Shape::Try
        | Shape::Break
        | Shape::Continue => body.control += 1,
        Shape::Call => {
            if !in_call {
                body.calls += 1;
            }
        }
        Shape::MacroCall => body.macros += 1,
        Shape::Return => body.statements += 1,
        Shape::Assign | Shape::VarDecl | Shape::ExprStmt => {
            body.statements += 1;
            body.working_statements += 1;
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ir::ByteRange;

    /// Build a unit node whose body holds the given shapes as one flat block.
    fn unit(shapes: &[Shape]) -> IrNode {
        let node = |shape: Shape| IrNode {
            shape,
            name: None,
            token_start: 0,
            token_end: 0,
            range: ByteRange { start: 0, end: 0 },
            children: Vec::new(),
        };
        IrNode {
            children: vec![IrNode {
                children: shapes.iter().cloned().map(node).collect(),
                ..node(Shape::Block)
            }],
            ..node(Shape::Function)
        }
    }

    #[test]
    fn a_body_that_moves_one_value_is_trivial() {
        // A getter: the tail expression is not even a statement.
        assert_eq!(classify(&unit(&[])), Some(Boilerplate::TrivialBody));
        // A setter.
        assert_eq!(
            classify(&unit(&[Shape::Assign])),
            Some(Boilerplate::TrivialBody)
        );
        assert_eq!(
            classify(&unit(&[Shape::Return])),
            Some(Boilerplate::TrivialBody)
        );
        // Two statements are already more than moving one value.
        assert_eq!(classify(&unit(&[Shape::Assign, Shape::Return])), None);
    }

    #[test]
    fn a_single_call_and_nothing_else_is_forwarding() {
        assert_eq!(
            classify(&unit(&[Shape::Call])),
            Some(Boilerplate::Forwarding)
        );
        // A call plus real work is not a wrapper.
        assert_eq!(classify(&unit(&[Shape::Call, Shape::VarDecl])), None);
        assert_eq!(classify(&unit(&[Shape::Call, Shape::Call])), None);
    }

    /// A node of `shape` wrapping `children`, for the nesting cases.
    fn nest(shape: Shape, children: Vec<IrNode>) -> IrNode {
        IrNode {
            shape,
            name: None,
            token_start: 0,
            token_end: 0,
            range: ByteRange { start: 0, end: 0 },
            children,
        }
    }

    fn leaf(shape: Shape) -> IrNode {
        nest(shape, Vec::new())
    }

    /// A unit whose body is the given statements, given as whole subtrees.
    fn unit_of(statements: Vec<IrNode>) -> IrNode {
        nest(Shape::Function, vec![nest(Shape::Block, statements)])
    }

    #[test]
    fn the_arguments_of_a_delegation_are_part_of_it() {
        // `f(g(x))`: one thing done, by way of another. Counting the inner
        // call as a second thing said this was not a wrapper, which is how
        // the commonest wrapper in either language went unrecognised.
        let delegation = nest(Shape::Call, vec![leaf(Shape::Call)]);
        assert_eq!(
            classify(&unit_of(vec![delegation])),
            Some(Boilerplate::Forwarding)
        );

        // `return f(g(x), h(y));` — the `return` is punctuation around the
        // same single delegation.
        let wrapped = nest(
            Shape::Return,
            vec![nest(
                Shape::Call,
                vec![leaf(Shape::Call), leaf(Shape::Call)],
            )],
        );
        assert_eq!(
            classify(&unit_of(vec![wrapped])),
            Some(Boilerplate::Forwarding)
        );
    }

    #[test]
    fn two_calls_side_by_side_are_two_things_done() {
        // Nesting is what makes a call part of a delegation. Siblings are not
        // nested, however deep either of them runs.
        let body = vec![
            nest(Shape::Call, vec![leaf(Shape::Call)]),
            leaf(Shape::Call),
        ];
        assert_eq!(classify(&unit_of(body)), None);
    }

    #[test]
    fn work_beside_a_delegation_still_disqualifies_it() {
        // A `return` is punctuation; an assignment is not.
        let body = vec![
            nest(Shape::Call, vec![leaf(Shape::Call)]),
            leaf(Shape::Assign),
        ];
        assert_eq!(classify(&unit_of(body)), None);
    }

    #[test]
    fn a_run_of_macro_invocations_is_recognised_as_repetition() {
        assert_eq!(
            classify(&unit(&[
                Shape::MacroCall,
                Shape::MacroCall,
                Shape::MacroCall
            ])),
            Some(Boilerplate::MacroRepetition)
        );
        // One macro invocation is not a run, and says nothing about the body.
        assert_eq!(classify(&unit(&[Shape::MacroCall])), None);
        // Macros mixed with other work are not classified: what the macros
        // expand to is unknown, so the body cannot be called trivial.
        assert_eq!(
            classify(&unit(&[Shape::MacroCall, Shape::MacroCall, Shape::Return])),
            None
        );
    }

    #[test]
    fn control_flow_is_never_boilerplate() {
        for shape in [Shape::Branch, Shape::Loop, Shape::Match, Shape::Try] {
            assert_eq!(
                classify(&unit(std::slice::from_ref(&shape))),
                None,
                "{shape:?}"
            );
            // Even alongside a shape that would otherwise classify.
            assert_eq!(classify(&unit(&[Shape::Call, shape])), None);
        }
    }

    #[test]
    fn nested_bodies_count_towards_the_unit() {
        // A closure that branches makes its enclosing unit non-trivial.
        let mut node = unit(&[]);
        node.children[0].children.push(IrNode {
            shape: Shape::Closure,
            name: None,
            token_start: 0,
            token_end: 0,
            range: ByteRange { start: 0, end: 0 },
            children: vec![IrNode {
                shape: Shape::Branch,
                name: None,
                token_start: 0,
                token_end: 0,
                range: ByteRange { start: 0, end: 0 },
                children: Vec::new(),
            }],
        });
        assert_eq!(classify(&node), None);
    }

    #[test]
    fn category_names_round_trip() {
        for category in Boilerplate::all() {
            assert_eq!(Boilerplate::from_name(category.name()), Some(category));
        }
        assert_eq!(Boilerplate::from_name("getter"), None);
    }
}
