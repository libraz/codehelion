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
//! to infer intent. Branching is where behaviour — and therefore the
//! interesting kind of duplication — lives, so a unit that branches is
//! classified only when the branch is a single guard and the body holds
//! nothing else: that unit chooses an answer rather than working one out.
//! Handing an error upwards is not branching at all: it leaves the unit with
//! one path, and the caller with the same one it would have had.
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
pub const BOILERPLATE_VERSION: &str = "boilerplate-v5";

/// A recognised boilerplate shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Boilerplate {
    /// No call and no control flow, with at most one statement: getters,
    /// setters and stubs. The body moves a value and does nothing else.
    TrivialBody,
    /// One call and no work around it: a wrapper that delegates. The locals
    /// it declares and the value it hands back are part of spelling the call,
    /// not of doing something with it.
    Forwarding,
    /// A body that is nothing but macro invocations, at least two of them.
    /// What the macros expand to is unknown here — the repetition itself is
    /// the observation.
    MacroRepetition,
    /// One guard and then an answer on each side of it, with nothing else:
    /// the unit chooses between two results rather than producing one.
    GuardedDispatch,
    /// Several answers with nothing in the code choosing between them: the
    /// build configuration picks one and the rest are never compiled.
    ConfiguredAnswer,
}

impl Boilerplate {
    /// Stable lowercase identifier used in reports and configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TrivialBody => "trivial-body",
            Self::Forwarding => "forwarding",
            Self::MacroRepetition => "macro-repetition",
            Self::GuardedDispatch => "guarded-dispatch",
            Self::ConfiguredAnswer => "configured-answer",
        }
    }

    /// Every category, in the order reports and configuration list them.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::TrivialBody,
            Self::Forwarding,
            Self::MacroRepetition,
            Self::GuardedDispatch,
            Self::ConfiguredAnswer,
        ]
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
    /// Macro invocations that are not themselves an argument to a call.
    ///
    /// Counted the way calls are, and for the same reason. `f(tri!(g(x)))` is
    /// one delegation whose argument happens to be spelled with a macro;
    /// counting the macro would say the body does something besides call `f`,
    /// when handing the argument over is all it does. A macro standing on its
    /// own is still counted: nothing here can see what it expands to, so a
    /// statement that is one is a statement whose contents are unknown.
    macros: usize,
    /// Statements other than macro invocations and control flow.
    statements: usize,
    /// Statements that do more than name a value or hand one back.
    ///
    /// A `return` around a delegation is punctuation. So is a local declared
    /// to receive what the delegation writes: a callee that answers through a
    /// pointer leaves its caller no other way to spell the call. An assignment
    /// or a bare expression statement is work.
    ///
    /// Nothing here can see what an initialiser computes — the IR models a
    /// declaration as one node whether it names a place or fills it with
    /// arithmetic. That is why declarations are punctuation only beside a
    /// delegation, never on their own.
    work: usize,
    /// Two-way conditionals, counted apart from the rest of the control flow.
    ///
    /// One of them is a guard. Several are a decision table, which is
    /// something a reader can act on: two copies of one table differing in
    /// their constants is exactly the duplication worth reporting.
    branches: usize,
    /// Local declarations, counted apart so a body can be required to have
    /// none. See `work` for why an initialiser cannot be inspected.
    declarations: usize,
    /// `return` statements.
    returns: usize,
}

/// Classify a unit by the shape of its body, or return `None` when it does
/// something a reader would want to see duplicated.
///
/// The unit node itself is not counted; only what it contains.
#[must_use]
pub fn classify(unit: &IrNode) -> Option<Boilerplate> {
    let body = count(unit);
    if body.control > 0 {
        return dispatch(&body);
    }
    if body.macros >= 2 && body.calls == 0 && body.statements == 0 {
        return Some(Boilerplate::MacroRepetition);
    }
    if body.macros > 0 {
        return None;
    }
    if configured(&body) {
        return Some(Boilerplate::ConfiguredAnswer);
    }
    match body.calls {
        // Nothing is delegated, so the one statement is the whole body.
        0 if body.statements <= 1 => Some(Boilerplate::TrivialBody),
        // One delegation, with nothing around it but the names it needs.
        1 if body.work == 0 => Some(Boilerplate::Forwarding),
        _ => None,
    }
}

/// Whether the body hands back more than one answer with nothing choosing
/// between them.
///
/// A unit cannot return twice. Where the grammar shows two returns and no
/// branch, loop or guard, something outside the grammar removed the choice:
/// `#if` and `#ifdef` in C and C++, `#[cfg]` in Rust. Only one answer is
/// compiled, and which one is a property of the build rather than of the code.
///
/// That makes two such units alike for a reason no reader can act on. They
/// carry the same platform split, or the same feature flag, and the answer
/// each spells is the one the other could not use. Consolidating them would
/// mean deleting a configuration, not a duplicate.
///
/// The shape is the one [`dispatch`] asks for with the guard taken away, and
/// bounded for the same reason: no local, no assignment, no bare expression,
/// and no more calls than there are answers, so nothing happens here besides
/// producing each answer. Anything more and the arms are doing work, which is
/// work written once per configuration and worth reading.
const fn configured(body: &Body) -> bool {
    body.returns >= 2 && body.work == 0 && body.declarations == 0 && body.calls <= body.returns
}

/// Classify a body that branches, which is only boilerplate in one shape.
///
/// A single guard, with an answer or one delegation on each side of it, is the
/// unit picking between two results rather than producing one: a null check
/// and a field, a capability check and one of two calls, a free guarded
/// against a null pointer. Written once per type or per constant it is the
/// language standing in for a parameter, and every copy says the same thing.
///
/// The shape is bounded because nothing here can read an expression: with no
/// assignment, no bare expression statement, no local, nothing but `return`s
/// and no more calls than there are answers, the body is one condition and
/// what it chooses between. Two branches would be a decision table instead,
/// and two copies of a table differing in their constants is duplication a
/// reader can act on.
///
/// What this cannot separate is a guard whose answer is computed — `if (v >
/// hi) return hi; return v;` reaches here as the same shape as a null check
/// and a field read, because the IR carries no expression to tell them apart.
fn dispatch(body: &Body) -> Option<Boilerplate> {
    let shaped = body.branches == 1
        && body.control == body.branches
        && body.macros == 0
        && body.work == 0
        && body.declarations == 0
        && body.returns >= 2;
    // Each answer is one thing, and the condition may be one more. Beyond that
    // the body is computing something the IR cannot show.
    (shaped && body.calls <= body.returns).then_some(Boilerplate::GuardedDispatch)
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

fn tally(node: &IrNode, in_call: bool, body: &mut Body) {
    match node.shape {
        Shape::Branch => {
            body.control += 1;
            body.branches += 1;
        }
        Shape::Loop | Shape::Match | Shape::MatchArm | Shape::Break | Shape::Continue => {
            body.control += 1;
        }
        Shape::Try => {
            if handles(node) {
                body.control += 1;
            }
        }
        Shape::Call => {
            if !in_call {
                body.calls += 1;
            }
        }
        Shape::MacroCall => {
            if !in_call {
                body.macros += 1;
            }
        }
        Shape::Return => {
            body.statements += 1;
            body.returns += 1;
        }
        Shape::VarDecl => {
            body.statements += 1;
            body.declarations += 1;
        }
        Shape::Assign | Shape::ExprStmt => {
            body.statements += 1;
            body.work += 1;
        }
        _ => {}
    }
}

/// Whether an error-handling node handles the error or only passes it on.
///
/// The two arrive as one shape because they are one concept, but they are not
/// one amount of behaviour. `try`/`catch` writes a second path through the
/// unit and carries that path in a block. Propagation — Rust's `?` — carries
/// only the expression whose error it hands upwards, and leaves the unit with
/// a single path. A block child is what tells them apart, in any language that
/// has both.
fn handles(node: &IrNode) -> bool {
    node.children
        .iter()
        .any(|child| child.shape == Shape::Block)
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
        assert_eq!(classify(&unit(&[Shape::Call, Shape::Assign])), None);
        assert_eq!(classify(&unit(&[Shape::Call, Shape::Call])), None);
    }

    #[test]
    fn a_local_the_delegation_answers_through_is_part_of_the_call() {
        // `U32 val; read(&val, p); return val;` — the local exists because
        // the callee answers through a pointer, and the C caller has no other
        // way to write the call. All three statements are one delegation.
        assert_eq!(
            classify(&unit(&[Shape::VarDecl, Shape::Call, Shape::Return])),
            Some(Boilerplate::Forwarding)
        );
        // Several out-parameters are still one call.
        assert_eq!(
            classify(&unit(&[
                Shape::VarDecl,
                Shape::VarDecl,
                Shape::Call,
                Shape::Return
            ])),
            Some(Boilerplate::Forwarding)
        );
        // Without a delegation there is nothing for the local to be part of,
        // and an initialiser is invisible here: `U32 v = h * 31 + 7; return v;`
        // has the same shape as `U32 v; return v;`, so neither is classified.
        assert_eq!(classify(&unit(&[Shape::VarDecl, Shape::Return])), None);
    }

    #[test]
    fn handing_an_error_upwards_is_not_a_second_path() {
        // Rust's `?`: the node carries the expression whose error it passes
        // on, and the unit still has one path. `Ok(open(p)?)`.
        let propagate = nest(Shape::Call, vec![nest(Shape::Try, vec![leaf(Shape::Call)])]);
        assert_eq!(
            classify(&unit_of(vec![propagate])),
            Some(Boilerplate::Forwarding)
        );

        // `try`/`catch`: the handler is a second path, and it arrives as a
        // block. That is behaviour, whatever the delegation inside it looks
        // like.
        let handle = nest(
            Shape::Try,
            vec![
                nest(Shape::Block, vec![leaf(Shape::Call)]),
                nest(Shape::Block, vec![leaf(Shape::Call)]),
            ],
        );
        assert_eq!(classify(&unit_of(vec![handle])), None);
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
    fn a_macro_inside_a_delegation_is_part_of_it() {
        // `Ok(tri!(self.peek()).unwrap_or(b'\0'))` — a wrapper whose argument
        // is spelled with a macro. Counting the macro as something the body
        // does besides delegate is the same mistake counting the inner call
        // would be, and it was made only for macros.
        let delegation = nest(
            Shape::Call,
            vec![nest(Shape::Call, vec![leaf(Shape::MacroCall)])],
        );
        assert_eq!(
            classify(&unit_of(vec![delegation])),
            Some(Boilerplate::Forwarding)
        );

        // Standing on its own it is still counted: nothing here can see what a
        // macro expands to, so a statement that is one is a statement whose
        // contents are unknown.
        let body = vec![leaf(Shape::Call), leaf(Shape::MacroCall)];
        assert_eq!(classify(&unit_of(body)), None);
    }

    #[test]
    fn a_repetition_of_macros_cannot_hide_inside_a_call() {
        // The repetition rule asks for no calls at all, and a macro counts as
        // nested only under one. So the two rules cannot reach the same body,
        // and relaxing the macro count leaves the repetition rule where it was.
        let body = vec![
            nest(Shape::Call, vec![leaf(Shape::MacroCall)]),
            nest(Shape::Call, vec![leaf(Shape::MacroCall)]),
        ];
        assert_eq!(classify(&unit_of(body)), None);
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
    fn a_guard_and_an_answer_on_each_side_is_a_dispatch() {
        // `if (item == NULL) { return false; } return item->kind == KIND;`
        let guarded = vec![
            nest(Shape::Branch, vec![leaf(Shape::Return)]),
            leaf(Shape::Return),
        ];
        assert_eq!(
            classify(&unit_of(guarded)),
            Some(Boilerplate::GuardedDispatch)
        );

        // A delegation on each side is the same choice: `if (c) return f(x);
        // return g(x);`
        let dispatched = vec![
            nest(
                Shape::Branch,
                vec![nest(Shape::Return, vec![leaf(Shape::Call)])],
            ),
            nest(Shape::Return, vec![leaf(Shape::Call)]),
        ];
        assert_eq!(
            classify(&unit_of(dispatched)),
            Some(Boilerplate::GuardedDispatch)
        );
    }

    #[test]
    fn two_answers_and_no_guard_are_the_build_configuration_choosing() {
        // `#ifdef _WIN32 return f(x); #else return g(x); #endif` — the
        // directive leaves no node, so what reaches here is two returns and
        // nothing between them.
        let configured = vec![
            nest(Shape::Return, vec![leaf(Shape::Call)]),
            nest(Shape::Return, vec![leaf(Shape::Call)]),
        ];
        assert_eq!(
            classify(&unit_of(configured)),
            Some(Boilerplate::ConfiguredAnswer)
        );

        // A third arm, and an answer that calls nothing, are the same shape.
        let three = vec![
            leaf(Shape::Return),
            leaf(Shape::Return),
            leaf(Shape::Return),
        ];
        assert_eq!(
            classify(&unit_of(three)),
            Some(Boilerplate::ConfiguredAnswer)
        );
    }

    #[test]
    fn arms_that_do_something_are_written_once_per_configuration() {
        // A local in one arm is work the other arm does differently, which is
        // what a reader would want to see duplicated.
        let declaring = vec![
            leaf(Shape::VarDecl),
            nest(Shape::Return, vec![leaf(Shape::Call)]),
            nest(Shape::Return, vec![leaf(Shape::Call)]),
        ];
        assert_eq!(classify(&unit_of(declaring)), None);

        let assigning = vec![
            leaf(Shape::Assign),
            leaf(Shape::Return),
            leaf(Shape::Return),
        ];
        assert_eq!(classify(&unit_of(assigning)), None);

        // More calls than answers means an arm is computing one.
        let computing = vec![
            nest(Shape::Return, vec![leaf(Shape::Call)]),
            nest(
                Shape::Return,
                vec![leaf(Shape::Call), leaf(Shape::Call), leaf(Shape::Call)],
            ),
        ];
        assert_eq!(classify(&unit_of(computing)), None);
    }

    #[test]
    fn one_answer_is_not_a_configuration() {
        // A body with a single return is whatever else it is; nothing chose
        // it. `return f(x);` stays a wrapper.
        let single = vec![nest(Shape::Return, vec![leaf(Shape::Call)])];
        assert_eq!(classify(&unit_of(single)), Some(Boilerplate::Forwarding));
    }

    #[test]
    fn more_than_one_guard_is_a_decision_table() {
        // Two copies of a table differing in their constants is duplication
        // worth reporting, so a body that decides is never set aside.
        let table = vec![
            nest(Shape::Branch, vec![leaf(Shape::Return)]),
            nest(Shape::Branch, vec![leaf(Shape::Return)]),
            leaf(Shape::Return),
        ];
        assert_eq!(classify(&unit_of(table)), None);
    }

    #[test]
    fn work_beside_a_guard_is_not_a_choice_between_answers() {
        let assigning = vec![
            nest(Shape::Branch, vec![leaf(Shape::Assign)]),
            leaf(Shape::Return),
        ];
        assert_eq!(classify(&unit_of(assigning)), None);
        // A local is opaque here, so a guard beside one says nothing.
        let declaring = vec![
            leaf(Shape::VarDecl),
            nest(Shape::Branch, vec![leaf(Shape::Return)]),
            leaf(Shape::Return),
        ];
        assert_eq!(classify(&unit_of(declaring)), None);
        // More calls than answers means the body is computing one.
        let computing = vec![
            nest(Shape::Branch, vec![leaf(Shape::Return)]),
            nest(
                Shape::Return,
                vec![leaf(Shape::Call), leaf(Shape::Call), leaf(Shape::Call)],
            ),
        ];
        assert_eq!(classify(&unit_of(computing)), None);
    }

    #[test]
    fn control_flow_other_than_one_guard_is_never_boilerplate() {
        for shape in [Shape::Branch, Shape::Loop, Shape::Match] {
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
