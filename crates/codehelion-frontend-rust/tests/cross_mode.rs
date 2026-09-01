//! Agreement between the Fast and the Structural frontend of one language.
//!
//! The two modes read the same text through different machinery — an
//! error-tolerant lexer against a real Rust parser — and each decides on its
//! own where an item begins, what kind it is and what it is called. Where they
//! disagree the damage is silent: a baseline keyed on the reported kind breaks
//! when the same function is a function in one mode and a method in the other,
//! and a unit boundary one mode invents moves the anchor a clone report names.
//!
//! This file drives both frontends from one table, so a rule that lands in only
//! one of them fails here rather than shipping.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use codehelion_core::frontend::{Frontend, UnitKind};
use codehelion_core::ir::{IrNode, Shape, StructuralFrontend};
use codehelion_frontend_rust::RustFrontend;
use codehelion_frontend_rust::ir::RustStructuralFrontend;

/// One item as both modes report it: the reportable kind, and the name the item
/// is anchored under.
type Item = (&'static str, Option<String>);

/// Sources whose items both modes must describe identically.
///
/// Closures are outside the comparison on purpose: Fast mode anchors only the
/// block-bodied ones, declining anything a lexer cannot tell apart from a
/// bitwise or, and that conservatism is a documented boundary rule rather than
/// a rule one mode lost.
const PROBES: &[&str] = &[
    // A function pointer in every position it can be written in. None of them
    // opens an item, so none may take an anchor away from the function that
    // encloses it.
    "fn dispatch(f: fn(u32) -> u32, v: u32) -> u32 { f(v) }\n",
    "fn dispatch(f: &fn(u32), v: u32) -> u32 { v }\n",
    "fn dispatch(f: (fn(), fn()), v: u32) -> u32 { v }\n",
    "fn dispatch(f: Vec<fn()>, v: u32) -> u32 { v }\n",
    "type Handler = fn(u32) -> u32;\nfn run(h: Handler) -> u32 { h(1) }\n",
    "static HANDLER: fn(u32) -> u32 = double;\nfn run() -> u32 { HANDLER(1) }\n",
    "struct Table { hook: fn(u32) }\n",
    // An opaque type is not an `impl` item either.
    "fn produce() -> impl Iterator<Item = u8> { std::iter::empty() }\n",
    "fn show(value: &impl Display) { print(value) }\n",
    // Every `impl` form, each named after the type it implements for.
    "struct Foo;\nimpl Foo { fn a(&self) -> u8 { 1 } }\n",
    "struct Foo<T> { v: T }\nimpl<T> Foo<T> { fn a(&self) -> u8 { 1 } }\n",
    "struct Foo;\nimpl Display for Foo { fn fmt(&self) -> u8 { 1 } }\n",
    "struct Wrapper<T> { v: T }\nimpl<'a, T: Clone> Trait<'a> for Wrapper<T> { fn a(&self) -> u8 { 1 } }\n",
    "struct Foo<T> { v: T }\nimpl<T> Trait for Foo<T> where T: Clone { fn a(&self) -> u8 { 1 } }\n",
    // A function in a trait body is a method whether or not it has a body, and
    // a helper nested in a method's body is a free function again.
    "trait T { fn f(&self) -> u8 { 1 } }\n",
    "trait T { fn required(&self); fn provided(&self) -> u8 { 1 } }\n",
    "struct Foo;\nimpl Foo { fn a(&self) -> u8 { fn helper() -> u8 { 1 } helper() } }\n",
    // Records, in each of the forms Rust writes them.
    "struct Point { x: i32, y: i32 }\n",
    "struct Handle;\n",
    "struct Pair(u8, u8);\n",
    "struct Wrapper<T> { inner: T }\n",
    "enum Op { Add, Sub }\n",
    "union Bits { raw: u32, parts: [u8; 4] }\n",
    // A macro definition is a template: its body is opaque in both modes.
    "macro_rules! m { ($x:expr) => { fn hidden() { $x } }; }\nfn after() -> u8 { 1 }\n",
    "macro_rules! m { () => { struct Hidden; }; }\nstruct After { v: u8 }\n",
    // Braces written inside a signature belong to the signature, so the unit
    // still covers the body that follows them.
    "fn f(x: Foo<{ 1 + 2 }>) -> u8 { 1 }\n",
    "fn make() -> Matrix<{ 1 + 2 }> { 1 }\n",
    "struct Foo<const N: usize>;\nimpl<const N: usize> Foo<{ N }> { fn len(&self) -> usize { N } }\n",
    "fn digest() -> [u8; 32] { [0; 32] }\n",
    // Items nest, and the outer one is reported before the inner one.
    "mod app {\n    pub struct Point { x: i32 }\n    impl Point { fn shift(&mut self) -> i32 { 1 } }\n}\n",
    // A wide but ordinary signature stays one item in both modes.
    "fn wide(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> u8 { 1 }\n",
];

/// The label a reportable kind is persisted and reported under.
const fn shape_label(shape: &Shape) -> Option<&'static str> {
    match *shape {
        Shape::Function => Some(UnitKind::Function.name()),
        Shape::Method => Some(UnitKind::Method.name()),
        Shape::Impl => Some(UnitKind::Impl.name()),
        Shape::Record => Some(UnitKind::Record.name()),
        _ => None,
    }
}

/// The items Fast mode reports, in source order.
fn fast_items(source: &str) -> Vec<Item> {
    RustFrontend
        .lex(source)
        .units
        .iter()
        .filter(|unit| unit.kind != UnitKind::Closure)
        .map(|unit| (unit.kind.name(), unit.name.clone()))
        .collect()
}

/// Whether a structural item has a body of its own.
///
/// A declaration without one (`fn required(&self);`) anchors nothing in Fast
/// mode, which has no boundary to draw around it.
fn has_body(node: &IrNode) -> bool {
    node.children
        .iter()
        .any(|child| child.shape == Shape::Block)
}

/// The items Structural mode reports, in source order.
fn structural_items(source: &str) -> Vec<Item> {
    let file = RustStructuralFrontend.parse(source);
    let mut items = Vec::new();
    file.walk(&mut |node| {
        let Some(label) = shape_label(&node.shape) else {
            return;
        };
        if matches!(node.shape, Shape::Function | Shape::Method) && !has_body(node) {
            return;
        }
        items.push((label, node.name.as_ref().map(ToString::to_string)));
    });
    items
}

#[test]
fn both_modes_report_the_same_items_for_every_probe() {
    for source in PROBES {
        let fast = fast_items(source);
        assert!(
            !fast.is_empty(),
            "a probe with no item compares nothing: {source:?}"
        );
        assert_eq!(
            fast,
            structural_items(source),
            "the modes disagree on {source:?}"
        );
    }
}

#[test]
fn a_type_position_keyword_never_takes_an_anchor_from_a_function() {
    // The shape the disagreement took: a keyword read in type position opened
    // a nameless unit inside a function whose body it then covered part of, so
    // the report named nothing where it should have named the function.
    for source in PROBES {
        for (label, name) in fast_items(source) {
            assert!(
                label != UnitKind::Function.name() && label != UnitKind::Method.name()
                    || name.is_some(),
                "an unnamed callable unit appeared in {source:?}"
            );
        }
    }
}

#[test]
fn a_unit_covers_the_body_it_anchors() {
    // A signature holding braces of its own must not end the unit early: the
    // last token of the item is the last token of its body.
    for (source, name) in [
        ("fn f(x: Foo<{ 1 + 2 }>) -> u8 { 1 }", "f"),
        ("fn make() -> Matrix<{ 1 + 2 }> { 1 }", "make"),
    ] {
        let lexed = RustFrontend.lex(source);
        let unit = lexed
            .units
            .iter()
            .find(|unit| unit.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("no unit named {name}"));
        assert_eq!(unit.token_end, lexed.tokens.len(), "in {source:?}");
        assert_eq!(unit.span.end_byte, source.len(), "in {source:?}");
    }
}

#[test]
fn a_record_definition_is_reported_under_the_record_kind() {
    // The kind every language's Fast mode gives a record definition, and the
    // spelling the audit ledger stores it under.
    let lexed = RustFrontend.lex("struct Point { x: i32 }\nunion Bits { raw: u32 }\n");
    let records: Vec<_> = lexed
        .units
        .iter()
        .filter(|unit| unit.kind == UnitKind::Record)
        .map(|unit| (unit.kind.name(), unit.name.as_deref()))
        .collect();
    assert_eq!(
        records,
        vec![("record", Some("Point")), ("record", Some("Bits"))]
    );
}

#[test]
fn a_broken_escape_costs_only_its_own_literal() {
    // A malformed character escape is a lexical problem; the items around it
    // are still analysed, and both modes still see the ones that follow.
    let source = "fn broken() -> u8 { let c = '\\u{; 1 }\nfn next() -> u8 { 2 }\n";
    let lexed = RustFrontend.lex(source);
    assert!(!lexed.diagnostics.is_empty(), "the literal is diagnosed");
    let names: Vec<_> = lexed
        .units
        .iter()
        .filter_map(|unit| unit.name.as_deref())
        .collect();
    assert!(names.contains(&"next"), "units: {names:?}");

    let structural = RustStructuralFrontend.parse(source);
    let mut structural_names = Vec::new();
    structural.walk(&mut |node| {
        if matches!(node.shape, Shape::Function | Shape::Method) {
            structural_names.extend(node.name.as_ref().map(ToString::to_string));
        }
    });
    assert!(
        structural_names.iter().any(|name| name == "next"),
        "structural units: {structural_names:?}"
    );
}
