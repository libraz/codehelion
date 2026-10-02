//! Fast-mode unit boundaries for C++ declarator shapes that end in angle
//! brackets or carry C++11 attributes.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::frontend::{Frontend, LexedFile, Unit, UnitKind};
use codehelion_core::ir::{IrNode, Shape, StructuralFrontend};
use codehelion_frontend_cpp::CppFrontend;
use codehelion_frontend_cpp::ir::CppStructuralFrontend;

fn units_of(source: &str) -> Vec<Unit> {
    let file: LexedFile = CppFrontend.lex(source);
    file.units
}

fn count(units: &[Unit], kind: UnitKind) -> usize {
    units.iter().filter(|unit| unit.kind == kind).count()
}

#[test]
fn every_operator_definition_is_a_unit_whatever_its_symbol() {
    let source = "\
struct V {
    bool operator>(const V& o) const { return a > o.a; }
    bool operator<(const V& o) const { return a < o.a; }
    V& operator>>(int n) { a >>= n; return *this; }
    int a;
};
V operator>>(V v, long n) { v.a >>= n; return v; }
bool operator>(V l, V r) { return r < l; }
";
    let units = units_of(source);
    let names: Vec<_> = units
        .iter()
        .filter(|unit| matches!(unit.kind, UnitKind::Function | UnitKind::Method))
        .map(|unit| unit.name.as_deref())
        .collect();
    assert_eq!(
        names,
        vec![
            Some("operator>"),
            Some("operator<"),
            Some("operator>>"),
            Some("operator>>"),
            Some("operator>")
        ],
        "units: {units:?}"
    );
}

#[test]
fn a_template_argument_close_still_resolves_to_its_declarator_name() {
    let units = units_of(
        "template <class T> struct B { B(int x); };\nstruct D : B<int> { D() : B<int>(1) { } };",
    );
    assert_eq!(count(&units, UnitKind::Method), 1, "units: {units:?}");
}

#[test]
fn a_cxx11_attribute_does_not_name_or_end_a_record_header() {
    for (source, name) in [
        ("class [[nodiscard]] Foo { int f() { return 1; } };", "Foo"),
        (
            "struct [[deprecated(\"x\")]] S { int f() { return 1; } };",
            "S",
        ),
        ("struct [[a, b::c(1)]] [[d]] T { };", "T"),
    ] {
        let units = units_of(source);
        let records: Vec<_> = units
            .iter()
            .filter(|unit| unit.kind == UnitKind::Record)
            .collect();
        assert_eq!(records.len(), 1, "in {source}");
        assert_eq!(records[0].name.as_deref(), Some(name), "in {source}");
    }
}

#[test]
fn a_trailing_return_type_with_several_template_arguments_anchors_its_body() {
    let units = units_of(
        "auto f() -> std::pair<int, int> { return {1, 2}; }\n\
         auto g = [](int a) -> std::map<int, std::vector<int>> { return {}; };\n\
         auto h() -> std::map<int, std::vector<int>> { return {}; }\n",
    );
    let functions: Vec<_> = units
        .iter()
        .filter(|unit| unit.kind == UnitKind::Function)
        .map(|unit| unit.name.as_deref())
        .collect();
    assert_eq!(functions, vec![Some("f"), Some("h")], "units: {units:?}");
    assert_eq!(count(&units, UnitKind::Closure), 1, "units: {units:?}");
}

#[test]
fn a_constructor_after_an_access_label_is_a_method() {
    for source in [
        "class Foo { public: Foo() {} };",
        "class Foo { private: Foo(int x) : a(x) {} int a; };",
        "class Foo { protected: ~Foo() {} };",
        "class Foo { signals: void changed() {} };",
        "class Foo { public: Foo() noexcept : a(1), b(2) {} int a, b; };",
        "class Foo { public: Foo() : a(1), b{2} {} int a, b; };",
    ] {
        let units = units_of(source);
        assert_eq!(count(&units, UnitKind::Method), 1, "in {source}: {units:?}");
    }
    let units = units_of("class Foo { public: Foo() : a(1) {} };");
    let methods: Vec<_> = units
        .iter()
        .filter(|unit| unit.kind == UnitKind::Method)
        .map(|unit| unit.name.as_deref())
        .collect();
    assert_eq!(
        methods,
        vec![Some("Foo")],
        "an initialiser entry is not a unit"
    );
}

#[test]
fn a_block_macro_after_a_statement_keyword_is_not_a_function() {
    for source in [
        "void f() { if (x) a(); else list_for_each(it, head) { visit(it); } }",
        "void f() { do list_for_each(it, head) { visit(it); } while (0); }",
        "struct S { void f() { if (x) a(); else list_for_each(it, head) { visit(it); } } };",
    ] {
        let units = units_of(source);
        assert!(
            units
                .iter()
                .all(|unit| unit.name.as_deref() != Some("list_for_each")),
            "in {source}: {units:?}"
        );
    }
}

fn structural_names(source: &str) -> Vec<Option<String>> {
    fn walk(node: &IrNode, out: &mut Vec<Option<String>>) {
        if matches!(node.shape, Shape::Function | Shape::Method) {
            out.push(node.name.as_ref().map(ToString::to_string));
        }
        for child in &node.children {
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    for root in &CppStructuralFrontend.parse(source).roots {
        walk(root, &mut out);
    }
    out
}

#[test]
fn fast_and_structural_name_special_members_alike() {
    for source in [
        "struct V { bool operator==(const V& o) const { return true; } };",
        "struct V { bool operator>(const V& o) const { return true; } };",
        "struct V { V& operator>>(int n) { return *this; } };",
        "struct V { bool operator()(int n) { return true; } };",
        "struct V { bool operator ==(const V& o) const { return true; } };",
        "struct V { ~V() {} };",
        "V::~V() {}",
        "bool V::operator<(const V& o) const { return true; }",
        "struct V { operator bool() const { return true; } };",
        "struct V { operator std::string() const { return {}; } };",
        "template <typename T> void f(T) {}\ntemplate <> void f<int>(int) {}",
        "long operator\"\" _km(unsigned long long v) { return v; }",
    ] {
        let fast: Vec<Option<String>> = units_of(source)
            .iter()
            .filter(|unit| matches!(unit.kind, UnitKind::Function | UnitKind::Method))
            .map(|unit| unit.name.clone())
            .collect();
        assert_eq!(fast, structural_names(source), "in {source}");
    }
}
