//! Structural-mode C++ frontend: tree-sitter CST to Syntax-IR conversion.
//!
//! Built on the shared C-family walking machinery from
//! [`codehelion_frontend_c::ir`]: the same tokenisation, error recovery and
//! IR assembly, driven by a C++ mapping table that layers the C++-only grammar
//! kinds (lambdas, classes, templates, namespaces, exceptions, range-`for`)
//! over the shared C table.
//!
//! # Granularity decisions specific to C++
//!
//! - A `function_definition` written inside a class body (lexically inside a
//!   `field_declaration_list`) is a [`Shape::Method`]; an out-of-class member
//!   definition (`int A::f() { ... }`) stays [`Shape::Function`], because the
//!   in-class/out-of-class distinction is lexical, not semantic, and
//!   Structural mode does not resolve scopes.
//! - `field_declaration` maps to [`Shape::VarDecl`] uniformly — member
//!   variables and member-function declarations alike, matching the C
//!   frontend's uniform treatment of `declaration`.
//! - `template_declaration` and `namespace_definition` have no cross-language
//!   shape and become [`Shape::Native`] nodes; their contents stay in the IR
//!   unexpanded and uninstantiated.
//! - `try` maps to [`Shape::Try`]; each `catch_clause` is transparent, so its
//!   handler surfaces as a plain [`Shape::Block`] child of the `Try` node.
//!   `throw` has no cross-language shape and stays native.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::TokenKind;
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_frontend_c::ir::{
    IrMapping, Mapping, classify_c, classify_token, parse_to_ir, record_mapping,
};
use tree_sitter::Node;

/// Version tag of this structural frontend, used as a fingerprint input. Bump
/// it whenever a change alters the token stream or the IR tree for unchanged
/// input.
pub const STRUCTURAL_FRONTEND_VERSION: &str = "cpp-ir-v1";

/// The C++ node-mapping table: C++-only kinds first, then the shared C table.
#[derive(Debug, Clone, Copy, Default)]
pub struct CppMapping;

impl IrMapping for CppMapping {
    fn classify(&self, node: &Node<'_>) -> Mapping {
        match node.kind() {
            "function_definition" => Mapping::Emit(function_shape(node)),
            "lambda_expression" => Mapping::Emit(Shape::Closure),
            "class_specifier" => record_mapping(node),
            "template_declaration" => Mapping::Native("template_declaration"),
            "namespace_definition" => Mapping::Native("namespace"),
            "try_statement" => Mapping::Emit(Shape::Try),
            "throw_statement" => Mapping::Native("throw_statement"),
            "for_range_loop" => Mapping::Emit(Shape::Loop),
            "field_declaration" => Mapping::Emit(Shape::VarDecl),
            // Everything else — including `catch_clause`, `new_expression`
            // and `delete_expression`, which are transparent interior detail —
            // falls through to the shared C-family table.
            _ => classify_c(node),
        }
    }

    /// The shared table reads a leaf's token kind off its grammar kind, and
    /// the C++ grammar spells several keywords as plain `identifier` leaves:
    /// `static_cast<T>(x)` parses as a call whose callee is the identifier
    /// `static_cast`. Left at that, the structural token stream disagrees with
    /// the Fast lexer, which reads the same word off the C++ keyword set — and
    /// a keyword read as an identifier is then taken for a callee name, so a
    /// cast enters the API-call profile as though the code called something.
    ///
    /// Checking the identifier text against the same keyword set the Fast
    /// lexer uses closes the whole divergence rather than the one word that
    /// exposed it. Nothing legitimate is caught: a keyword cannot also be a
    /// declared name, so an `identifier` leaf spelling one is the grammar's
    /// artefact and not the program's.
    fn token_kind(&self, kind: &str, is_named: bool, text: &str) -> TokenKind {
        match classify_token(kind, is_named, text) {
            TokenKind::Identifier if crate::CPP.keywords.contains(&text) => TokenKind::Keyword,
            other => other,
        }
    }
}

/// [`Shape::Method`] for an in-class definition (lexically inside a
/// `field_declaration_list`, looking through member templates);
/// [`Shape::Function`] anywhere else, out-of-class member definitions
/// included.
fn function_shape(node: &Node<'_>) -> Shape {
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        match ancestor.kind() {
            "field_declaration_list" => return Shape::Method,
            "template_declaration" => parent = ancestor.parent(),
            _ => return Shape::Function,
        }
    }
    Shape::Function
}

/// The C++ Structural-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CppStructuralFrontend;

impl StructuralFrontend for CppStructuralFrontend {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn frontend_version(&self) -> &'static str {
        STRUCTURAL_FRONTEND_VERSION
    }

    fn parse(&self, source: &str) -> SyntaxIrFile {
        let grammar = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
        parse_to_ir(
            source,
            &grammar,
            &CppMapping,
            Language::Cpp,
            STRUCTURAL_FRONTEND_VERSION,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use codehelion_core::frontend::{Lexeme, LiteralKind, TokenKind};
    use codehelion_core::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, MAX_IR_DEPTH};

    fn parse(source: &str) -> SyntaxIrFile {
        CppStructuralFrontend.parse(source)
    }

    #[test]
    fn signatures_keep_cpp_qualifiers_and_ignore_parameter_names() {
        let source = "template <typename T> const T *first(const T& left, int values[4]) const noexcept { return nullptr; }\ntemplate <typename T> const T *second(const T& right, int items[4]) const noexcept { return nullptr; }";
        let file = parse(source);
        assert!(
            file.error_ranges.is_empty(),
            "unexpected parse errors: {:?}",
            file.error_ranges
        );
        assert_eq!(file.signatures.len(), 2);
        let first = file.signature_for_range(file.signatures[0].0).unwrap();
        let second = file.signature_for_range(file.signatures[1].0).unwrap();
        assert_eq!(first.normalized, second.normalized);
        assert_eq!(first.key, second.key);
        assert!(first.normalized.contains("t5:const"));
        assert!(first.normalized.contains("gtype0;"));
        assert!(first.normalized.contains("t3:int"));
        assert!(first.normalized.contains("t8:noexcept"));
        assert!(first.normalized.contains("template=gtype0;"));
    }

    #[test]
    fn signatures_keep_explicit_template_arguments() {
        let file = parse(
            "template <typename T> int value(T input) { return 0; }\ntemplate <> int value<int>(int input) { return 0; }",
        );
        assert!(
            file.error_ranges.is_empty(),
            "unexpected parse errors: {:?}",
            file.error_ranges
        );
        assert_eq!(file.signatures.len(), 2);
        assert!(file.signatures[1].1.normalized.contains("t1:<"));
        assert!(file.signatures[1].1.normalized.contains("t1:>"));
        assert_ne!(file.signatures[0].1.key, file.signatures[1].1.key);
    }

    #[test]
    fn signatures_alpha_normalize_cpp_template_bindings_and_preserve_constraints() {
        let same = parse(
            "template <typename T, int N = sizeof(T)> T first(T value) requires (N > 0) { return value; }\ntemplate <class U, int M = sizeof(U)> U second(U renamed) requires (M > 0) { return renamed; }",
        );
        assert!(same.error_ranges.is_empty(), "{:?}", same.error_ranges);
        assert_eq!(same.signatures.len(), 2);
        assert_eq!(same.signatures[0].1, same.signatures[1].1);
        assert!(same.signatures[0].1.normalized.contains("gtype0;"));
        assert!(same.signatures[0].1.normalized.contains("gvalue0;"));

        let constraint = parse(
            "template <typename T, int N = sizeof(T)> T first(T value) requires (N > 0) { return value; }\ntemplate <class U, int M = sizeof(U)> U second(U renamed) requires (M >= 0) { return renamed; }",
        );
        assert_eq!(constraint.signatures.len(), 2);
        assert_ne!(
            constraint.signatures[0].1.key,
            constraint.signatures[1].1.key
        );

        let concrete = parse(
            "template <typename T> T first(T value) { return value; }\ntemplate <typename U> int second(int value) { return value; }",
        );
        assert_eq!(concrete.signatures.len(), 2);
        assert_ne!(concrete.signatures[0].1.key, concrete.signatures[1].1.key);

        let explicit = parse(
            "template <typename T> T first(T value) { return value; }\ntemplate <> int first<int>(int value) { return value; }",
        );
        assert_eq!(explicit.signatures.len(), 2);
        assert_ne!(explicit.signatures[0].1.key, explicit.signatures[1].1.key);
        assert!(explicit.signatures[1].1.normalized.contains("t1:<"));

        let leading_binder = parse(
            "template <class T> requires requires(int local) { local > 0; } int first(T value) { return 0; }",
        );
        assert!(leading_binder.error_ranges.is_empty());
        assert!(leading_binder.signatures.is_empty());
    }

    #[test]
    fn signatures_alpha_normalize_enclosing_class_template_bindings() {
        let same = parse(
            "template <typename T> struct Box { template <typename U> U first(U value) { return value; } };\ntemplate <class X> struct Crate { template <class V> V second(V value) { return value; } };",
        );
        assert!(same.error_ranges.is_empty(), "{:?}", same.error_ranges);
        assert_eq!(same.signatures.len(), 2);
        assert_eq!(same.signatures[0].1, same.signatures[1].1);

        let different = parse(
            "template <typename T> struct Box { template <typename U> U first(U value) { return value; } };\ntemplate <class X> struct Crate { template <class V> V second(V value) requires (sizeof(X) > 0) { return value; } };",
        );
        assert_eq!(different.signatures.len(), 2);
        assert_ne!(different.signatures[0].1.key, different.signatures[1].1.key);
    }

    #[test]
    fn signatures_ignore_comments_between_cpp_template_parameters() {
        let file = parse(
            "template <class T /* comment */> T first(T value) { return value; }\ntemplate <class U> U second(U value) { return value; }",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert_eq!(file.signatures.len(), 2);
        assert_eq!(file.signatures[0].1, file.signatures[1].1);

        let unnamed = parse(
            "template <class> int first() { return 0; }\ntemplate <class T> int second() { return 0; }",
        );
        assert!(
            unnamed.error_ranges.is_empty(),
            "{:?}",
            unnamed.error_ranges
        );
        assert_eq!(unnamed.signatures.len(), 2);
        assert_eq!(unnamed.signatures[0].1, unnamed.signatures[1].1);
    }

    #[test]
    fn signatures_alpha_normalize_out_of_class_template_arguments() {
        let file = parse(
            "template <class T> T Box<T>::first(T value) { return value; }\ntemplate <class U> U Crate<U>::second(U value) { return value; }",
        );
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert_eq!(file.signatures.len(), 2);
        assert_eq!(file.signatures[0].1, file.signatures[1].1);
    }

    #[test]
    fn signatures_keep_cpp_member_and_qualified_names_raw_when_they_match_generic_spelling() {
        let member = parse(
            "template <typename T> int first(T value) noexcept(value.T()) { return 0; }\ntemplate <typename U> int second(U value) noexcept(value.U()) { return 0; }",
        );
        assert_eq!(member.signatures.len(), 2);
        assert_ne!(member.signatures[0].1.key, member.signatures[1].1.key);

        let qualified = parse(
            "template <typename T> int first(T value) noexcept(ns::T<T>()) { return 0; }\ntemplate <typename U> int second(U value) noexcept(ns::T<U>()) { return 0; }",
        );
        assert_eq!(qualified.signatures.len(), 2);
        assert_eq!(qualified.signatures[0].1.key, qualified.signatures[1].1.key);

        let ambiguous = parse(
            "template <typename T> int first(int T) requires (T > 0) { return 0; }\ntemplate <int N> int second(int N) requires (N > 0) { return 0; }",
        );
        assert!(ambiguous.error_ranges.is_empty());
        assert!(ambiguous.signatures.is_empty());

        let nested_shadow = parse(
            "template <class T> struct A { template <class T> T first(T value) { return value; } };",
        );
        assert!(nested_shadow.error_ranges.is_empty());
        assert!(nested_shadow.signatures.is_empty());
    }

    #[test]
    fn signatures_distinguish_return_and_method_qualifier_changes() {
        let base = parse("int first(int value) const noexcept { return value; }");
        let return_changed = parse("long first(int value) const noexcept { return value; }");
        let qualifier_changed = parse("int first(int value) noexcept { return value; }");
        assert_ne!(
            base.signatures[0].0,
            ByteRange { start: 0, end: 0 },
            "the exact function range is non-empty"
        );
        assert_ne!(base.signatures[0].1.key, return_changed.signatures[0].1.key);
        assert_ne!(
            base.signatures[0].1.key,
            qualifier_changed.signatures[0].1.key
        );
    }

    #[test]
    fn signatures_distinguish_cpp_receiver_context_without_class_names() {
        let file = parse(
            "int free_one(int value) { return value; }\nstruct A { int member_one(int value) { return value; } static int static_one(int value) { return value; } };\nint A::qualified_one(int value) const { return value; }",
        );
        assert_eq!(file.signatures.len(), 4);
        assert!(file.signatures[0].1.normalized.contains("receiver=free"));
        assert!(
            file.signatures[1]
                .1
                .normalized
                .contains("receiver=in-class")
        );
        assert!(
            file.signatures[2]
                .1
                .normalized
                .contains("receiver=in-class-static")
        );
        assert!(
            file.signatures[3]
                .1
                .normalized
                .contains("receiver=qualified")
        );
        assert_ne!(file.signatures[0].1.key, file.signatures[1].1.key);
        assert_ne!(file.signatures[1].1.key, file.signatures[3].1.key);

        let qualified_names = parse(
            "int A::first(int value) { return value; }\nint B::second(int other) { return other; }",
        );
        assert_eq!(qualified_names.signatures.len(), 2);
        assert_eq!(
            qualified_names.signatures[0].1, qualified_names.signatures[1].1,
            "class names and function names are not part of a qualified receiver kind"
        );
    }

    #[test]
    fn signatures_reject_returnless_cpp_special_members_and_keep_trailing_return_type() {
        let special_members =
            parse("struct S { S(int value) {} ~S() {} operator bool() const { return true; } };");
        assert!(special_members.signatures.is_empty());

        let trailing = parse("auto first(int value) -> long { return value; }");
        assert_eq!(trailing.signatures.len(), 1);
        let normalized = &trailing.signatures[0].1.normalized;
        assert!(normalized.contains("return=t4:long"));
        assert!(!normalized.contains("->"));
    }

    #[test]
    fn signatures_omit_optional_defaults_and_pointer_to_member_parameter_names() {
        let defaults = parse(
            "int first(int value = 1) { return value; }\nint second(int other = 2) { return other; }",
        );
        assert_eq!(defaults.signatures.len(), 2);
        assert_eq!(defaults.signatures[0].1, defaults.signatures[1].1);

        let pointer_members = parse("void first(int S::*left) {}\nvoid second(int S::*right) {}");
        assert_eq!(pointer_members.signatures.len(), 2);
        assert_eq!(
            pointer_members.signatures[0].1,
            pointer_members.signatures[1].1
        );
        assert!(
            pointer_members.signatures[0].1.normalized.contains('S'),
            "{}",
            pointer_members.signatures[0].1.normalized
        );
    }

    #[test]
    fn macro_built_cpp_declarations_are_not_signatures_but_body_macros_are() {
        for source in [
            "API(int) first(int value) { return value; }",
            "API(foo)(int value) { return value; }",
            "TEST(Suite, Case) { return 0; }",
        ] {
            let file = parse(source);
            assert!(
                file.signatures.is_empty(),
                "macro-built declaration must be unsupported: {source:?}"
            );
        }
        let body_macro = parse("int body_macro(int value) { API(value); return value; }");
        assert_eq!(body_macro.signatures.len(), 1);
        let body_error = parse("int body_error(int value) { auto =; return value; }");
        assert!(!body_error.error_ranges.is_empty());
        assert_eq!(body_error.signatures.len(), 1);
    }

    #[test]
    fn signatures_keep_healthy_cpp_units_when_another_header_is_broken() {
        let source = "int healthy(int value) { API(value); return value; }\nint broken(int value { return value; }";
        let file = parse(source);
        assert!(!file.error_ranges.is_empty());
        assert_eq!(file.signatures.len(), 1);
        let (range, _) = &file.signatures[0];
        assert!(source[range.start..range.end].contains("healthy"));
    }

    #[test]
    fn signatures_reject_variadic_and_function_pointer_parameters() {
        for source in [
            "int variadic(int first, ...) { return first; }",
            "int callback(int (*handler)(int)) { return 0; }",
        ] {
            let file = parse(source);
            assert!(
                file.signatures.is_empty(),
                "unsupported signature must not be guessed: {source:?}"
            );
        }
    }

    #[test]
    fn signatures_keep_legal_cpp_call_expressions() {
        let decltype = parse(
            "decltype(factory()) first(int value) { return {}; }\ndecltype(other()) second(int other) { return {}; }",
        );
        assert_eq!(decltype.signatures.len(), 2);
        assert_ne!(decltype.signatures[0].1.key, decltype.signatures[1].1.key);
        assert!(decltype.signatures[0].1.normalized.contains("t8:decltype"));

        let trailing = parse(
            "auto first(int value) -> decltype(factory()) { return {}; }\nauto second(int other) -> decltype(other()) { return {}; }",
        );
        assert_eq!(trailing.signatures.len(), 2);
        assert_ne!(trailing.signatures[0].1.key, trailing.signatures[1].1.key);
        assert!(
            trailing.signatures[0]
                .1
                .normalized
                .contains("return=t8:decltype")
        );
        assert!(!trailing.signatures[0].1.normalized.contains("->"));

        let noexcept = parse(
            "int first(int value) noexcept(check(value)) { return value; }\nint second(int other) noexcept(other_check(other)) { return other; }",
        );
        assert_eq!(noexcept.signatures.len(), 2);
        assert_ne!(noexcept.signatures[0].1.key, noexcept.signatures[1].1.key);
        assert!(noexcept.signatures[0].1.normalized.contains("t8:noexcept"));
    }

    #[test]
    fn signatures_alpha_normalize_cpp_parameter_references_in_qualifiers() {
        let renamed = parse(
            "int first(int value) noexcept(check(value)) { return 0; }\nint second(int renamed) noexcept(check(renamed)) { return 0; }",
        );
        assert_eq!(renamed.signatures.len(), 2);
        assert_eq!(renamed.signatures[0].1, renamed.signatures[1].1);
        assert!(renamed.signatures[0].1.normalized.contains("t8:noexcept"));

        let callee_changed = parse(
            "int first(int value) noexcept(check(value)) { return 0; }\nint second(int value) noexcept(other_check(value)) { return 0; }",
        );
        assert_eq!(callee_changed.signatures.len(), 2);
        assert_ne!(
            callee_changed.signatures[0].1.key,
            callee_changed.signatures[1].1.key
        );

        let multiple = parse(
            "int first(int left, int right) noexcept(check(left, right)) { return 0; }\nint second(int one, int two) noexcept(check(one, two)) { return 0; }\nint swapped(int first, int second) noexcept(check(second, first)) { return 0; }",
        );
        assert_eq!(multiple.signatures.len(), 3);
        assert_eq!(multiple.signatures[0].1, multiple.signatures[1].1);
        assert_ne!(multiple.signatures[0].1.key, multiple.signatures[2].1.key);
        assert!(multiple.signatures[0].1.normalized.contains("t8:noexcept"));

        let requires = parse(
            "template <typename T> int first(int value) requires (value > 0) { return 0; }\ntemplate <typename T> int second(int renamed) requires (renamed > 0) { return 0; }",
        );
        assert_eq!(requires.signatures.len(), 2);
        assert_eq!(requires.signatures[0].1, requires.signatures[1].1);
        assert!(requires.signatures[0].1.normalized.contains("t8:requires"));
    }

    #[test]
    fn signatures_normalize_parameter_callees_trailing_returns_and_comments() {
        let callbacks = parse(
            "int first(Pred callback, int value) noexcept(callback(value)) { return 0; }\nint second(Pred renamed, int other) noexcept(renamed(other)) { return 0; }",
        );
        assert_eq!(callbacks.signatures.len(), 2);
        assert_eq!(callbacks.signatures[0].1, callbacks.signatures[1].1);
        assert!(callbacks.signatures[0].1.normalized.contains("p0;"));

        let non_parameter_callees = parse(
            "int first(int value) noexcept(check(value)) { return 0; }\nint second(int other) noexcept(other_check(other)) { return 0; }",
        );
        assert_ne!(
            non_parameter_callees.signatures[0].1.key,
            non_parameter_callees.signatures[1].1.key
        );

        let member_receiver = parse(
            "int first(int value) noexcept(value.member()) { return 0; }\nint second(int renamed) noexcept(renamed.member()) { return 0; }",
        );
        assert_eq!(member_receiver.signatures.len(), 2);
        assert_eq!(
            member_receiver.signatures[0].1,
            member_receiver.signatures[1].1
        );
        assert!(member_receiver.signatures[0].1.normalized.contains("p0;"));

        let trailing = parse(
            "auto first(int value) -> decltype(value) { return value; }\nauto second(int renamed) -> decltype(renamed) { return renamed; }",
        );
        assert_eq!(trailing.signatures.len(), 2);
        assert_eq!(trailing.signatures[0].1, trailing.signatures[1].1);
        assert!(trailing.signatures[0].1.normalized.contains("return="));

        let comments = parse(
            "int first(int left /* parameter */, /* between */ int right) noexcept(check(left, right)) { return 0; }\nint second(int left, int right) noexcept(check(left, right)) { return 0; }",
        );
        assert!(
            comments.error_ranges.is_empty(),
            "{:?}",
            comments.error_ranges
        );
        assert_eq!(comments.signatures.len(), 2);
        assert_eq!(comments.signatures[0].1, comments.signatures[1].1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signatures_normalize_wrapped_callable_parameters_and_reject_shadowing() {
        let bare = parse(
            "int first(Pred callback, int value) noexcept(callback(value)) { return 0; }\nint second(Pred renamed, int other) noexcept(renamed(other)) { return 0; }",
        );
        assert_eq!(bare.signatures.len(), 2);
        assert_eq!(bare.signatures[0].1, bare.signatures[1].1);
        assert!(bare.signatures[0].1.normalized.contains("p0;"));

        let parenthesized = parse(
            "int first(Pred callback, int value) noexcept((callback)(value)) { return 0; }\nint second(Pred renamed, int other) noexcept((renamed)(other)) { return 0; }",
        );
        assert_eq!(parenthesized.signatures.len(), 2);
        assert_eq!(parenthesized.signatures[0].1, parenthesized.signatures[1].1);
        assert!(parenthesized.signatures[0].1.normalized.contains("p0;"));

        let dereferenced = parse(
            "int first(Pred callback, int value) noexcept((*callback)(value)) { return 0; }\nint second(Pred renamed, int other) noexcept((*renamed)(other)) { return 0; }",
        );
        assert_eq!(dereferenced.signatures.len(), 2);
        assert_eq!(dereferenced.signatures[0].1, dereferenced.signatures[1].1);
        assert!(dereferenced.signatures[0].1.normalized.contains("p0;"));

        let subscripted = parse(
            "int first(Pred callbacks, int index) noexcept(callbacks[index](index)) { return 0; }\nint second(Pred renamed, int offset) noexcept(renamed[offset](offset)) { return 0; }",
        );
        assert_eq!(subscripted.signatures.len(), 2);
        assert_eq!(subscripted.signatures[0].1, subscripted.signatures[1].1);
        assert!(subscripted.signatures[0].1.normalized.contains("p0;"));

        let non_parameter = parse(
            "int first(int value) noexcept((check)(value)) { return 0; }\nint second(int renamed) noexcept((other_check)(renamed)) { return 0; }",
        );
        assert_eq!(non_parameter.signatures.len(), 2);
        assert_ne!(
            non_parameter.signatures[0].1.key,
            non_parameter.signatures[1].1.key
        );

        let qualified = parse(
            "int first(int value) noexcept(ns::check(value)) { return 0; }\nint second(int renamed) noexcept(ns::other_check(renamed)) { return 0; }",
        );
        assert_eq!(qualified.signatures.len(), 2);
        assert_ne!(qualified.signatures[0].1.key, qualified.signatures[1].1.key);

        let nested_calls = parse(
            "int first(Pred callback, int value) noexcept(factory(callback)(value)) { return 0; }\nint second(Pred renamed, int other) noexcept(factory(renamed)(other)) { return 0; }\nint third(Pred callback, int value) noexcept(factory.make(callback)(value)) { return 0; }\nint fourth(Pred renamed, int other) noexcept(factory.make(renamed)(other)) { return 0; }",
        );
        assert_eq!(nested_calls.signatures.len(), 4);
        assert_eq!(nested_calls.signatures[0].1, nested_calls.signatures[1].1);
        assert_eq!(nested_calls.signatures[2].1, nested_calls.signatures[3].1);

        let qualified_decltype = parse(
            "auto first(int value) -> typename decltype(value)::type { return {}; }\nauto second(int renamed) -> typename decltype(renamed)::type { return {}; }\nauto third(int value) -> decltype(other)::type { return {}; }\nauto fourth(int renamed) -> decltype(changed)::type { return {}; }",
        );
        assert_eq!(qualified_decltype.signatures.len(), 4);
        assert_eq!(
            qualified_decltype.signatures[0].1,
            qualified_decltype.signatures[1].1
        );
        assert_ne!(
            qualified_decltype.signatures[2].1.key,
            qualified_decltype.signatures[3].1.key
        );

        let qualified_noexcept = parse(
            "int first(int value) noexcept(decltype(value)::ready()) { return 0; }\nint second(int renamed) noexcept(decltype(renamed)::ready()) { return 0; }",
        );
        assert_eq!(qualified_noexcept.signatures.len(), 2);
        assert_eq!(
            qualified_noexcept.signatures[0].1,
            qualified_noexcept.signatures[1].1
        );

        let qualified_template = parse(
            "int first(int value) noexcept(check<typename decltype(value)::type>()) { return 0; }\nint second(int renamed) noexcept(check<typename decltype(renamed)::type>()) { return 0; }",
        );
        assert_eq!(qualified_template.signatures.len(), 2);
        assert_eq!(
            qualified_template.signatures[0].1,
            qualified_template.signatures[1].1
        );

        let placeholder_collision = parse(
            "int first(int value) noexcept(value) { return 0; }\nint second(int p0) noexcept($0) { return 0; }",
        );
        assert_eq!(placeholder_collision.signatures.len(), 2);
        assert_ne!(
            placeholder_collision.signatures[0].1,
            placeholder_collision.signatures[1].1
        );

        let local_binding = parse(
            "template <typename T> int first(int value) requires requires(int local) { value > local; } { return 0; }\ntemplate <typename T> int second(int renamed) requires requires(int other) { renamed > other; } { return 0; }",
        );
        assert!(local_binding.error_ranges.is_empty());
        assert!(local_binding.signatures.is_empty());

        let leading_requires = parse(
            "template <class T> requires First<T> int first(int value) { return 0; }\ntemplate <class T> requires Second<T> int second(int renamed) { return 0; }",
        );
        assert_eq!(leading_requires.signatures.len(), 2);
        assert_ne!(
            leading_requires.signatures[0].1.key,
            leading_requires.signatures[1].1.key
        );

        let broken_leading_requires =
            parse("template <class T> requires (First<T> && ) int first(int value) { return 0; }");
        assert!(!broken_leading_requires.error_ranges.is_empty());
        assert!(broken_leading_requires.signatures.is_empty());

        let shadowed = parse(
            "template <typename T> int first(int value) requires requires(int value) { value > 0; } { return 0; }\ntemplate <typename T> int second(int renamed) requires requires(int renamed) { renamed > 0; } { return 0; }",
        );
        assert!(shadowed.error_ranges.is_empty());
        assert!(shadowed.signatures.is_empty());

        let lambda = parse(
            "int first(int value) noexcept([&](int local) { return value + local; }(0)) { return value; }\nint second(int renamed) noexcept([&](int local) { return renamed + local; }(0)) { return renamed; }",
        );
        assert!(lambda.error_ranges.is_empty());
        assert!(lambda.signatures.is_empty());

        let default_lambda = parse(
            "int first(int value = [] { return 1; }()) { return value; }\nint second(int renamed = [] { return 2; }()) { return renamed; }",
        );
        assert!(default_lambda.error_ranges.is_empty());
        assert_eq!(default_lambda.signatures.len(), 2);
        assert_eq!(
            default_lambda.signatures[0].1,
            default_lambda.signatures[1].1
        );

        let default_literal = parse(
            "int first(const char *value = \"...\") { return 0; }\nint second(const char *renamed = \"...\") { return 0; }",
        );
        assert!(default_literal.error_ranges.is_empty());
        assert_eq!(default_literal.signatures.len(), 2);
        assert_eq!(
            default_literal.signatures[0].1,
            default_literal.signatures[1].1
        );

        let default_templates = parse(
            "int first(int value = make<A>()) { return 0; }\nint second(int renamed = make<B>()) { return 0; }",
        );
        assert!(default_templates.error_ranges.is_empty());
        assert_eq!(default_templates.signatures.len(), 2);
        assert_eq!(
            default_templates.signatures[0].1,
            default_templates.signatures[1].1
        );

        let default_requires = parse(
            "int first(int value = requires { requires true; }) { return 0; }\nint second(int renamed = 2) { return 0; }",
        );
        assert!(default_requires.error_ranges.is_empty());
        assert_eq!(default_requires.signatures.len(), 2);
        assert_eq!(
            default_requires.signatures[0].1,
            default_requires.signatures[1].1
        );
    }

    #[test]
    fn signatures_preserve_cpp_token_boundaries_and_literal_payload() {
        let words = parse(
            "struct constint {}; const int first(int value) noexcept(+ +value) { return value; }\nconstint second(int value) noexcept(+ +value) { return {}; }",
        );
        assert!(words.error_ranges.is_empty());
        assert_eq!(words.signatures.len(), 2);
        assert_ne!(words.signatures[0].1.key, words.signatures[1].1.key);

        let punctuation = parse(
            "int first(int value) noexcept(+ +value) { return value; }\nint second(int value) noexcept(++value) { return value; }",
        );
        assert!(punctuation.error_ranges.is_empty());
        assert_eq!(punctuation.signatures.len(), 2);
        assert_ne!(
            punctuation.signatures[0].1.key,
            punctuation.signatures[1].1.key
        );

        let literals = parse(
            "decltype(\"a b\") first(int value) { return {}; }\ndecltype(\"ab\") second(int value) { return {}; }",
        );
        assert!(literals.error_ranges.is_empty());
        assert_eq!(literals.signatures.len(), 2);
        assert_ne!(literals.signatures[0].1.key, literals.signatures[1].1.key);
        assert!(literals.signatures[0].1.normalized.contains("\"a b\""));
    }

    #[test]
    fn signatures_reject_cpp_attributes_and_keep_return_declarator_modifiers() {
        let attributes = parse(
            "[[nodiscard]] int discarded(int value) { return value; }\n[[maybe_unused]] int unused(int value) { return value; }",
        );
        assert!(attributes.signatures.is_empty());

        let specifiers = parse(
            "inline int first(int value) { return value; }\nconstexpr int second(int other) { return other; }",
        );
        assert_eq!(specifiers.signatures.len(), 2);
        assert_eq!(specifiers.signatures[0].1, specifiers.signatures[1].1);

        let pointers = parse(
            "int *first(int value) { return nullptr; }\nint *second(int other) { return nullptr; }",
        );
        assert_eq!(pointers.signatures.len(), 2);
        assert_eq!(pointers.signatures[0].1, pointers.signatures[1].1);
        assert!(
            pointers.signatures[0]
                .1
                .normalized
                .contains("return=t3:int")
        );

        let references = parse(
            "const int &first(int value) { static int result = 0; return result; }\nconst int &second(int other) { static int result = 0; return result; }",
        );
        assert_eq!(references.signatures.len(), 2);
        assert_eq!(references.signatures[0].1, references.signatures[1].1);
        assert!(
            references.signatures[0]
                .1
                .normalized
                .contains("return=t5:const")
        );

        let ms_declspec = parse(
            "__declspec(noinline) int first(int value) { return value; }\n__declspec(nothrow) int second(int value) { return value; }",
        );
        assert!(ms_declspec.signatures.is_empty());

        let ms_calling_convention = parse(
            "int __cdecl first(int value) { return value; }\nint __stdcall second(int value) { return value; }",
        );
        assert!(ms_calling_convention.signatures.is_empty());
    }

    fn assert_bounded_depth_truncation(file: &SyntaxIrFile, source_len: usize) {
        assert!(
            file.depth_truncated,
            "a depth-limited parse must be distinguished from ordinary recovery"
        );
        let mut deepest = 0;
        let mut error_leaves = Vec::new();
        let mut pending: Vec<(&IrNode, usize)> = file.roots.iter().map(|root| (root, 1)).collect();
        while let Some((node, depth)) = pending.pop() {
            deepest = deepest.max(depth);
            if node.shape == Shape::Error && node.children.is_empty() {
                error_leaves.push(node.range);
            }
            pending.extend(node.children.iter().rev().map(|child| (child, depth + 1)));
        }

        assert!(
            deepest <= MAX_IR_DEPTH,
            "IR depth {deepest} exceeds the frontend limit {MAX_IR_DEPTH}"
        );
        assert!(
            error_leaves.iter().any(|range| {
                !range.is_empty() && range.end <= source_len && file.error_ranges.contains(range)
            }),
            "depth truncation must be represented by an Error leaf and error range"
        );

        let mut visited = 0;
        file.walk(&mut |_| visited += 1);
        assert_eq!(visited, file.node_count());
    }

    #[test]
    fn deeply_nested_cpp_is_truncated_without_unbounded_ir() {
        let control = parse("int control() { return 0; }");
        assert!(control.error_ranges.is_empty());
        assert!(
            control.roots.iter().all(|node| node.shape != Shape::Error),
            "normal input remains unchanged"
        );

        let depth = 10_000;
        let mut source = String::from("void deeply_nested() ");
        source.push_str(&"{".repeat(depth));
        source.push(';');
        source.push_str(&"}".repeat(depth));

        let file = parse(&source);
        assert_bounded_depth_truncation(&file, source.len());
        drop(file);
        drop(control);
    }

    fn shape_label(shape: &Shape) -> String {
        match shape {
            Shape::Function => "function".to_owned(),
            Shape::Method => "method".to_owned(),
            Shape::Closure => "closure".to_owned(),
            Shape::Record => "record".to_owned(),
            Shape::Impl => "impl".to_owned(),
            Shape::Block => "block".to_owned(),
            Shape::Loop => "loop".to_owned(),
            Shape::Branch => "branch".to_owned(),
            Shape::Match => "match".to_owned(),
            Shape::MatchArm => "match-arm".to_owned(),
            Shape::Call => "call".to_owned(),
            Shape::Assign => "assign".to_owned(),
            Shape::VarDecl => "var-decl".to_owned(),
            Shape::Return => "return".to_owned(),
            Shape::Break => "break".to_owned(),
            Shape::Continue => "continue".to_owned(),
            Shape::Try => "try".to_owned(),
            Shape::ExprStmt => "expr-stmt".to_owned(),
            Shape::MacroDef => "macro-def".to_owned(),
            Shape::MacroCall => "macro-call".to_owned(),
            Shape::Error => "error".to_owned(),
            Shape::Native(kind) => format!("native:{kind}"),
        }
    }

    fn render_node(node: &IrNode, depth: usize, out: &mut String) {
        for _ in 0..depth {
            out.push_str("  ");
        }
        out.push_str(&shape_label(&node.shape));
        if let Some(name) = &node.name {
            out.push(' ');
            out.push_str(name);
        }
        out.push('\n');
        for child in &node.children {
            render_node(child, depth + 1, out);
        }
    }

    /// Render the IR tree as one indented line per node: shape label plus
    /// the recovered name, when present.
    fn render(file: &SyntaxIrFile) -> String {
        let mut out = String::new();
        for root in &file.roots {
            render_node(root, 0, &mut out);
        }
        out
    }

    fn shapes_of(children: &[IrNode]) -> Vec<Shape> {
        children.iter().map(|child| child.shape.clone()).collect()
    }

    const GOLDEN_SOURCE: &str = r"
namespace app {

template <typename T>
T twice(T value) {
    return value + value;
}

class Counter {
public:
    int bump(int by) {
        total_ += by;
        return total_;
    }
    int reset();

private:
    int total_ = 0;
};

int Counter::reset() {
    int old_total = total_;
    total_ = 0;
    return old_total;
}

int run(const int *xs, int n) {
    auto add = [](int a, int b) { return a + b; };
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc = add(acc, xs[i]);
    }
    for (int v : xs) {
        acc += v;
    }
    try {
        if (acc < 0) {
            throw make_error(acc);
        }
    } catch (const error &e) {
        acc = 0;
    }
    return acc;
}

}
";

    #[test]
    fn golden_tree_pins_the_mapping_contract() {
        let file = parse(GOLDEN_SOURCE);
        assert!(
            file.error_ranges.is_empty(),
            "the golden source must parse cleanly: {:?}",
            file.error_ranges
        );
        let expected = "\
native:namespace
  native:template_declaration
    function twice
      block
        return
  record Counter
    method bump
      block
        assign
        return
    var-decl
    var-decl
  function reset
    block
      var-decl
      assign
      return
  function run
    block
      var-decl
        closure
          block
            return
      var-decl
      loop
        var-decl
        block
          assign
            call
      loop
        block
          assign
      try
        block
          branch
            block
              native:throw_statement
                call
        block
          assign
      return
";
        assert_eq!(render(&file), expected);
    }

    #[test]
    fn function_position_separates_methods_from_functions() {
        let source = "\
int free_fn() { return 0; }
struct S {
    int in_class() { return 1; }
    template <typename T> T member_template(T v) { return v; }
};
int S::out_of_class() { return 2; }
";
        let file = parse(source);
        let mut found = Vec::new();
        file.walk(&mut |node| {
            if matches!(node.shape, Shape::Function | Shape::Method) {
                let name = node.name.as_ref().map(ToString::to_string);
                found.push((node.shape.clone(), name));
            }
        });
        assert_eq!(
            found,
            vec![
                (Shape::Function, Some("free_fn".to_owned())),
                (Shape::Method, Some("in_class".to_owned())),
                (Shape::Method, Some("member_template".to_owned())),
                (Shape::Function, Some("out_of_class".to_owned())),
            ]
        );
    }

    #[test]
    fn record_requires_a_body_and_covers_classes() {
        let file = parse("class Fwd;\nclass Def { int a_; };\nvoid f() { Def d; }\n");
        let mut records = Vec::new();
        file.walk(&mut |node| {
            if node.shape == Shape::Record {
                records.push(node.name.as_ref().map(ToString::to_string));
            }
        });
        assert_eq!(
            records,
            vec![Some("Def".to_owned())],
            "the forward declaration and the type reference emit no Record"
        );
    }

    #[test]
    fn expr_stmt_unwraps_to_the_inner_shape() {
        let file = parse("void f() { g(); a + b; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Call, Shape::ExprStmt],
            "a call statement is the Call node itself; an unmapped expression keeps ExprStmt"
        );
        assert!(
            body.children[1].children.is_empty(),
            "plain operands produce no nodes under the ExprStmt"
        );
    }

    #[test]
    fn assignment_operators_map_to_assign_and_comparisons_do_not() {
        let file = parse("void f() { x = 1; x += 1; x == 1; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![Shape::Assign, Shape::Assign, Shape::ExprStmt],
            "`=` and `+=` are assignments; `==` is interior expression detail"
        );
    }

    #[test]
    fn throw_is_native_and_counts_in_statement_summaries() {
        let file = parse("int f(int v) { throw v; v += 1; return v; }");
        let body = &file.roots[0].children[0];
        assert_eq!(
            shapes_of(&body.children),
            vec![
                Shape::Native(Lexeme::from("throw_statement")),
                Shape::Assign,
                Shape::Return,
            ]
        );

        let summaries = body.statement_summaries(&file.tokens);
        assert_eq!(summaries.len(), 3, "the native throw stays in the sequence");
        assert_eq!(
            summaries[0].native_kind,
            Some(Lexeme::from("throw_statement"))
        );
        let head: Vec<&str> = summaries[0]
            .tokens(&file.tokens)
            .iter()
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(head, vec!["throw", "v", ";"]);
    }

    #[test]
    fn try_catch_yields_try_with_plain_block_handlers() {
        let file = parse("void f() { try { g(); } catch (const E &e) { h(); } catch (...) { } }");
        let body = &file.roots[0].children[0];
        let try_node = &body.children[0];
        assert_eq!(try_node.shape, Shape::Try);
        assert_eq!(
            shapes_of(&try_node.children),
            vec![Shape::Block, Shape::Block, Shape::Block],
            "the try block and each transparent catch clause's handler block"
        );
    }

    #[test]
    fn broken_function_between_intact_functions_keeps_both_neighbours() {
        let file =
            parse("int first() { return 1; }\nint broken( { ;\nint second() { return 2; }\n");
        let mut function_names = Vec::new();
        file.walk(&mut |node| {
            if node.shape == Shape::Function {
                function_names.push(node.name.as_ref().map(ToString::to_string));
            }
        });
        assert!(function_names.contains(&Some("first".to_owned())));
        assert!(function_names.contains(&Some("second".to_owned())));
        assert!(!file.error_ranges.is_empty());
    }

    // Observed worst-case truncation behaviour: tree-sitter recovers the
    // unclosed function by inserting a zero-width missing `}` at EOF, so the
    // unit survives with its parsed statements and the missing brace shows up
    // as a (possibly zero-width) error range. The assertions pin what the
    // parser actually does, not an idealised recovery.
    #[test]
    fn truncation_at_eof_keeps_the_function_with_error_ranges() {
        let file = parse("int tail() { int x = 1;");
        assert_eq!(file.roots.len(), 1);
        let function = &file.roots[0];
        assert_eq!(function.shape, Shape::Function);
        assert_eq!(function.name.as_deref(), Some("tail"));
        assert_eq!(shapes_of(&function.children), vec![Shape::Block]);
        assert_eq!(
            shapes_of(&function.children[0].children),
            vec![Shape::VarDecl]
        );
        assert!(!file.error_ranges.is_empty());
    }

    #[test]
    fn token_stream_classification_and_spans() {
        let source = "namespace ns {\nint f(int n) {\n    /* é */ double d = 1.5;\n    auto s = R\"(raw \"text\")\";\n    bool ok = true;\n    auto *self = this;\n    void *none = nullptr;\n    return ns::g(n, 'x', \"lit\");\n}\n}\n";
        let file = parse(source);

        // `None` marks a token that is missing from the stream entirely.
        let kind_of = |text: &str| -> Option<TokenKind> {
            file.tokens
                .iter()
                .find(|token| token.text == text)
                .map(|token| token.kind)
        };
        assert_eq!(kind_of("namespace"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("ns"), Some(TokenKind::Identifier));
        // `auto`, `this` and `nullptr` are named leaves in the grammar but
        // lexically keywords.
        assert_eq!(kind_of("auto"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("this"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("nullptr"), Some(TokenKind::Keyword));
        assert_eq!(kind_of("1.5"), Some(TokenKind::Literal(LiteralKind::Float)));
        assert_eq!(
            kind_of("R\"(raw \"text\")\""),
            Some(TokenKind::Literal(LiteralKind::String)),
            "the raw string is one atomic token, delimiters included"
        );
        assert_eq!(kind_of("true"), Some(TokenKind::Literal(LiteralKind::Bool)));
        assert_eq!(kind_of("'x'"), Some(TokenKind::Literal(LiteralKind::Char)));
        assert_eq!(
            kind_of("\"lit\""),
            Some(TokenKind::Literal(LiteralKind::String))
        );
        assert_eq!(kind_of("::"), Some(TokenKind::Punctuation));
        assert_eq!(kind_of("{"), Some(TokenKind::Punctuation));

        assert!(
            file.tokens
                .iter()
                .all(|token| !token.text.contains('é') && !token.text.trim().is_empty()),
            "comments and whitespace must not appear in the stream"
        );

        // Spans are byte-accurate and positions are 1-based; the column is
        // counted in characters, so `double` sits one byte further right than
        // its column suggests (the `é` in the comment before it is two bytes).
        let double = file
            .tokens
            .iter()
            .find(|token| token.text == "double")
            .unwrap();
        assert_eq!(double.span.start_byte, source.find("double").unwrap());
        assert_eq!(double.span.end_byte, double.span.start_byte + 6);
        assert_eq!(double.span.start_line, 3);
        assert_eq!(double.span.start_column, 13);
    }

    #[test]
    fn parsing_twice_is_deterministic() {
        let first = parse(GOLDEN_SOURCE);
        let second = parse(GOLDEN_SOURCE);
        assert_eq!(first.tokens, second.tokens);
        assert_eq!(first.roots, second.roots);
        assert_eq!(first.error_ranges, second.error_ranges);
    }

    #[test]
    fn a_keyword_the_grammar_spells_as_an_identifier_still_lexes_as_a_keyword() {
        // The named casts are the case that exposed this: the grammar parses
        // `static_cast<T>(x)` as a call whose callee leaf is an `identifier`.
        // Read as an identifier, the word is taken for a callee name and the
        // cast enters the unit's API-call profile as a call to something.
        let file = parse(
            "int f(int x) {\n    static_cast<void>(x);\n    return const_cast<int &>(x);\n}\n",
        );
        for word in ["static_cast", "const_cast"] {
            let token = file.tokens.iter().find(|token| token.text == word);
            assert_eq!(
                token.map(|token| token.kind),
                Some(TokenKind::Keyword),
                "{word} is a C++ keyword, not a name"
            );
        }
        // A real callee in the same file is still an identifier, so the rule
        // has not simply reclassified everything in callee position.
        let file = parse("int f(int x) { return g(x); }\n");
        let g = file.tokens.iter().find(|token| token.text == "g").unwrap();
        assert_eq!(g.kind, TokenKind::Identifier);
    }

    #[test]
    fn file_carries_language_and_versions() {
        let frontend = CppStructuralFrontend;
        assert_eq!(frontend.language(), Language::Cpp);
        assert_eq!(frontend.frontend_version(), "cpp-ir-v1");

        let file = parse("int a;");
        assert_eq!(file.language, Language::Cpp);
        assert_eq!(file.frontend_version, STRUCTURAL_FRONTEND_VERSION);
        assert_eq!(file.ir_schema_version, IR_SCHEMA_VERSION);
        assert!(file.diagnostics.is_empty());
    }
}
