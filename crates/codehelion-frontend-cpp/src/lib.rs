//! C++ frontends for codehelion.
//!
//! Fast mode implements [`codehelion_core::frontend::Frontend`] for C++ on
//! top of the shared C-family machinery from `codehelion-frontend-c`: the
//! same error-tolerant lexer and delimiter-matching unit-boundary detection,
//! driven by a C++ [`Dialect`] that adds the C++ keyword set, the extra
//! operators (`::`, `->*`, `.*`, `<=>`), raw string literals, digit
//! separators, `class` records and lambdas. Structural mode lives in [`ir`]:
//! a real tree-sitter parse mapped onto the language-neutral Syntax IR
//! through the shared CST walker. Nothing here preprocesses, instantiates
//! templates or executes the source.

pub mod ir;

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{Frontend, LexedFile};
use codehelion_frontend_c::dialect::Dialect;
use codehelion_frontend_c::{lexer, units};

/// Version tag of this frontend, used as a fingerprint input. The C++ dialect
/// revision and the shared C-family lexer revision are both part of it.
pub const FRONTEND_VERSION: &str = "cpp-lexer-v1+c-family-lexer-v1";

/// C++ keywords (C++23). Contextual keywords (`override`, `final`, `import`,
/// `module`) lex as identifiers, matching how the grammar treats them.
const CPP_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char16_t",
    "char32_t",
    "char8_t",
    "class",
    "co_await",
    "co_return",
    "co_yield",
    "compl",
    "concept",
    "const",
    "const_cast",
    "consteval",
    "constexpr",
    "constinit",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
];

/// C++ multi-character operators, longest first.
const CPP_MULTI_PUNCT: &[&str] = &[
    "<<=", ">>=", "<=>", "->*", "...", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&",
    "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "::", ".*", "##",
];

/// The C++ dialect.
pub const CPP: Dialect = Dialect {
    keywords: CPP_KEYWORDS,
    multi_punct: CPP_MULTI_PUNCT,
    raw_strings: true,
    digit_separators: true,
    record_keywords: &["class", "struct", "union"],
    lambdas: true,
};

/// The C++ Fast-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CppFrontend;

impl Frontend for CppFrontend {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn frontend_version(&self) -> &'static str {
        FRONTEND_VERSION
    }

    fn lex(&self, source: &str) -> LexedFile {
        let (tokens, mut diagnostics) = lexer::lex(source, &CPP);
        let (units, unit_diagnostics) = units::detect(&tokens, &CPP);
        diagnostics.extend(unit_diagnostics);
        LexedFile {
            language: Language::Cpp,
            frontend_version: FRONTEND_VERSION,
            tokens,
            units,
            diagnostics,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use codehelion_core::frontend::{LiteralKind, TokenKind, UnitKind};
    use codehelion_core::ir::StructuralFrontend;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    fn lexed(source: &str) -> LexedFile {
        CppFrontend.lex(source)
    }

    #[test]
    fn frontend_reports_language_and_version() {
        let frontend = CppFrontend;
        assert_eq!(frontend.language(), Language::Cpp);
        assert_eq!(frontend.frontend_version(), FRONTEND_VERSION);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_text_never_panics(source in proptest::collection::vec(any::<char>(), 0..1024)
            .prop_map(|characters| characters.into_iter().collect::<String>())) {
            let started = Instant::now();
            let _ = CppFrontend.lex(&source);
            let _ = ir::CppStructuralFrontend.parse(&source);
            prop_assert!(
                started.elapsed() < Duration::from_secs(1),
                "a bounded frontend input took too long"
            );
        }
    }

    #[test]
    fn shared_lexer_revision_is_part_of_both_frontend_fingerprints() {
        let shared = codehelion_frontend_c::C_FAMILY_LEXER_VERSION;
        assert!(
            codehelion_frontend_c::FRONTEND_VERSION.ends_with(shared),
            "the C frontend fingerprint carries the shared lexer revision"
        );
        assert!(
            FRONTEND_VERSION.ends_with(shared),
            "the C++ frontend fingerprint carries the shared lexer revision"
        );
    }

    #[test]
    fn cpp_multi_punct_is_ordered_longest_first() {
        let lens: Vec<usize> = CPP.multi_punct.iter().map(|op| op.len()).collect();
        let mut sorted = lens.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(lens, sorted, "greedy matching needs longest-first order");
    }

    #[test]
    fn cpp_operators_lex_as_single_tokens() {
        let out = lexed("a::b c <=> d; p->*q; r.*s;");
        let puncts: Vec<_> = out
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Punctuation)
            .map(|t| t.text.as_str())
            .collect();
        assert!(puncts.contains(&"::"));
        assert!(puncts.contains(&"<=>"));
        assert!(puncts.contains(&"->*"));
        assert!(puncts.contains(&".*"));
    }

    #[test]
    fn less_than_before_scope_resolution_is_not_a_digraph() {
        let compact = lexed("std::vector<::T> compact;");
        let spaced = lexed("std::vector< ::T> spaced;");
        let punctuation = |file: &LexedFile| {
            file.tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Punctuation)
                .map(|token| token.text.to_string())
                .collect::<Vec<_>>()
        };

        assert_eq!(punctuation(&compact), punctuation(&spaced));
        assert_eq!(punctuation(&compact), vec!["::", "<", "::", ">", ";"]);
    }

    #[test]
    fn raw_strings_lex_whole_with_custom_delimiters() {
        let out = lexed("auto s = R\"(a \"quoted\" b)\"; auto t = R\"xy(close )\" here)xy\";");
        let strings: Vec<_> = out
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::String))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(
            strings,
            vec!["R\"(a \"quoted\" b)\"", "R\"xy(close )\" here)xy\"",]
        );
        assert!(out.diagnostics.is_empty());
    }

    #[test]
    fn raw_string_pseudo_directives_do_not_make_code_unreachable() {
        let source = "const char* note = R\"(#if 0\n#endif)\";\nint still_live;\n";
        let file = lexed(source);
        let paths = lexer::conditional_paths(source, &file.tokens, &CPP);
        let index = file
            .tokens
            .iter()
            .position(|token| token.text == "still_live")
            .unwrap_or_else(|| panic!("missing still_live"));
        assert!(!paths[index].is_unreachable());
    }

    #[test]
    fn digit_separators_stay_inside_one_number_token() {
        let out = lexed("long n = 1'000'000; char c = 'x';");
        let ints: Vec<_> = out
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::Integer))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(ints, vec!["1'000'000"]);
        let chars: Vec<_> = out
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::Char))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(chars, vec!["'x'"], "separators must not eat char literals");
    }

    #[test]
    fn classes_are_records_and_member_functions_are_methods() {
        let src = "class Counter {\n\
                   public:\n\
                     void bump() { n_ += 1; }\n\
                     int value() const { return n_; }\n\
                   private:\n\
                     int n_ = 0;\n\
                   };";
        let out = lexed(src);
        assert!(out.units.iter().any(|u| u.kind == UnitKind::Record));
        assert_eq!(
            out.units
                .iter()
                .filter(|u| u.kind == UnitKind::Method)
                .count(),
            2,
            "{:#?}",
            out.units
        );
        let record = out
            .units
            .iter()
            .find(|u| u.kind == UnitKind::Record)
            .unwrap();
        assert_eq!(record.name.as_deref(), Some("Counter"));
    }

    #[test]
    fn out_of_line_definitions_and_constructors_are_units() {
        let src = "Counter::Counter(int start) : n_(start), tag_{0} { init(); }\n\
                   void Counter::reset() { n_ = 0; }";
        let out = lexed(src);
        let names: Vec<_> = out
            .units
            .iter()
            .map(|u| (u.kind, u.name.as_deref().unwrap_or("")))
            .collect();
        assert!(
            names.contains(&(UnitKind::Function, "Counter")),
            "constructor with initialiser list: {names:?}"
        );
        assert!(names.contains(&(UnitKind::Function, "reset")));
    }

    #[test]
    fn operators_destructors_and_trailing_returns_are_units() {
        let src = "struct V {\n\
                     V operator+(const V &o) const { return o; }\n\
                     ~V() { drop(); }\n\
                     auto size() const -> unsigned long { return n; }\n\
                     unsigned long n;\n\
                   };";
        let out = lexed(src);
        let methods: Vec<_> = out
            .units
            .iter()
            .filter(|u| u.kind == UnitKind::Method)
            .map(|u| u.name.as_deref().unwrap_or(""))
            .collect();
        assert!(methods.contains(&"operator"), "{methods:?}");
        assert!(methods.contains(&"V"), "destructor: {methods:?}");
        assert!(methods.contains(&"size"), "trailing return: {methods:?}");
    }

    #[test]
    fn lambdas_are_closures_but_array_initialisers_are_not() {
        let src = "void f() {\n\
                     auto g = [x](int y) { return x + y; };\n\
                     run([&] { tick(); });\n\
                     int a[2] {0, 1};\n\
                   }";
        let out = lexed(src);
        assert_eq!(
            out.units
                .iter()
                .filter(|u| u.kind == UnitKind::Closure)
                .count(),
            2,
            "{:#?}",
            out.units
        );
    }

    #[test]
    fn enum_class_and_template_parameters_are_not_records() {
        let src = "enum class Color { Red, Green };\n\
                   template <class T, class U> struct Pair { T a; U b; };";
        let out = lexed(src);
        let records: Vec<_> = out
            .units
            .iter()
            .filter(|u| u.kind == UnitKind::Record)
            .map(|u| u.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(records, vec!["Pair"], "{:#?}", out.units);
    }

    #[test]
    fn control_flow_and_namespaces_are_not_functions() {
        let src = "namespace app {\n\
                   void f(int n) {\n\
                     if (n > 0) { g(); } else { h(); }\n\
                     try { risky(); } catch (const std::exception &e) { log(e); }\n\
                   }\n\
                   }";
        let out = lexed(src);
        let functions: Vec<_> = out
            .units
            .iter()
            .filter(|u| matches!(u.kind, UnitKind::Function | UnitKind::Method))
            .map(|u| u.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(functions, vec!["f"], "{:#?}", out.units);
    }
}
