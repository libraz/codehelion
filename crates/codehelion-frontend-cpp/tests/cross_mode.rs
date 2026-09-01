//! Agreement between the Fast and the Structural frontend of one language.
//!
//! The two modes read the same text through different machinery — an
//! error-tolerant lexer against a tree-sitter grammar — and each has its own
//! notion of what a lexeme is. Where they disagree the damage is silent: a
//! reserved word the grammar leaves as a plain identifier leaf is taken for a
//! callee and enters the API-call profile as a call that was never written,
//! and it alpha-normalizes against user type names, so two units Fast mode
//! keeps apart merge in Structural mode.
//!
//! This file drives both frontends of both languages from one table, so a rule
//! that lands in only one of them fails here rather than shipping. It lives in
//! the C++ crate because that is the only crate in the C-family dependency
//! chain (`cpp -> c -> core`) that can see all four frontends at once.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use codehelion_core::frontend::{Frontend, TokenKind};
use codehelion_core::ir::StructuralFrontend;
use codehelion_frontend_c::CFrontend;
use codehelion_frontend_c::dialect;
use codehelion_frontend_c::ir::CStructuralFrontend;
use codehelion_frontend_cpp::ir::CppStructuralFrontend;
use codehelion_frontend_cpp::{CPP, CppFrontend};

/// Sources both languages accept, each holding reserved words in a position
/// where at least one of the two grammars does not model them as keywords.
const SHARED_PROBES: &[&str] = &[
    "int classify(int n) {\n    _Bool flag = 0;\n    return flag + n;\n}\n",
    "_Static_assert(1, \"ok\");\nstatic_assert(1, \"ok\");\n",
    "_Thread_local int counter;\nthread_local int other;\n",
    "int copy_of(int n) {\n    typeof(n) copy = n;\n    return copy;\n}\n",
    "int pick(int n) {\n    switch (n) { case 1: return 1; default: break; }\n    return 0;\n}\n",
    "int flags(void) { return sizeof(int) + alignof(int); }\n",
    "int truth(void) { return g(true) + h(false); }\n",
    "const char *nothing(void) { return nullptr; }\n",
    "inline constexpr int limit = 4;\n",
];

/// Sources only C++ accepts.
const CPP_PROBES: &[&str] = &[
    "int narrow(long v) { return static_cast<int>(v); }\n",
    "struct B { virtual ~B() = default; };\nstruct D : B { void go() noexcept { } };\n",
    "template <class T> concept Ok = true;\ntemplate <class T> int f(T a) requires Ok<T> { return 0; }\n",
    "void run() { auto a = []<class T>(T v) mutable { return v; }; }\n",
    "namespace app { struct S { int f() const { return 0; } }; }\n",
    "int guard(int n) { try { return n; } catch (...) { throw; } }\n",
];

/// Assert that both modes give the same [`TokenKind`] to every reserved word
/// of `keywords` that appears in `source`.
///
/// Only words the Fast lexer actually produced are compared: a spelling the
/// probe does not contain, or one a grammar rewrites into a differently
/// spelled lexeme, is not a disagreement about classification.
fn assert_modes_agree(
    fast: &dyn Frontend,
    structural: &dyn StructuralFrontend,
    keywords: &[&str],
    source: &str,
) {
    let fast_file = fast.lex(source);
    let structural_file = structural.parse(source);
    for word in keywords {
        let Some(fast_kind) = fast_file
            .tokens
            .iter()
            .find(|token| token.text == *word)
            .map(|token| token.kind)
        else {
            continue;
        };
        let structural_kind = structural_file
            .tokens
            .iter()
            .find(|token| token.text == *word)
            .map(|token| token.kind);
        assert_eq!(
            structural_kind,
            Some(fast_kind),
            "{:?} disagrees on `{word}` in {source:?}",
            fast.language()
        );
        assert_eq!(
            fast_kind,
            TokenKind::Keyword,
            "a reserved word is a keyword: `{word}` in {source:?}"
        );
    }
}

#[test]
fn both_c_modes_classify_every_reserved_word_alike() {
    for source in SHARED_PROBES {
        assert_modes_agree(
            &CFrontend,
            &CStructuralFrontend,
            dialect::C.keywords,
            source,
        );
    }
}

#[test]
fn both_cpp_modes_classify_every_reserved_word_alike() {
    for source in SHARED_PROBES.iter().chain(CPP_PROBES) {
        assert_modes_agree(&CppFrontend, &CppStructuralFrontend, CPP.keywords, source);
    }
}

#[test]
fn a_reserved_word_is_never_read_as_a_call_target() {
    // The concrete shape the disagreement took: a reserved word the grammar
    // spells as an identifier sits where a callee would, so a structural
    // reader counts a call the program never made.
    for (source, word) in [
        (
            "int check(void) { static_assert(1, \"ok\"); return 0; }",
            "static_assert",
        ),
        (
            "int narrow(long v) { return static_cast<int>(v); }",
            "static_cast",
        ),
    ] {
        let file = CppStructuralFrontend.parse(source);
        let kind = file
            .tokens
            .iter()
            .find(|token| token.text == word)
            .map(|token| token.kind);
        assert_eq!(kind, Some(TokenKind::Keyword), "{word} in {source:?}");
    }
}

#[test]
fn every_fast_dialect_removes_a_line_continuation_inside_a_token() {
    // Line splicing is translation phase 2 and tokenisation is phase 3, so a
    // continuation inside a lexeme must leave the Fast token stream unchanged
    // — in every dialect, because the rule belongs to the shared lexer and not
    // to one language's copy of it.
    //
    // The structural frontends are outside this comparison: the tree-sitter
    // grammars tokenise the physical text, so a continuation splits a lexeme
    // there. That is a property of the grammar, not a rule one mode carries
    // and the other lost, and the two modes are held to agreement above on
    // what they do classify alike.
    let spliced = "int wi\\\ndth = 12\\\n34; int shifted = wi??/\ndth <\\\n< 2;\n";
    let joined = "int width = 1234; int shifted = width << 2;\n";
    let texts = |file: &codehelion_core::frontend::LexedFile| {
        file.tokens
            .iter()
            .map(|token| (token.kind, token.text.to_string()))
            .collect::<Vec<_>>()
    };
    for fast in [&CFrontend as &dyn Frontend, &CppFrontend] {
        assert_eq!(
            texts(&fast.lex(spliced)),
            texts(&fast.lex(joined)),
            "{:?} fast mode",
            fast.language()
        );
    }
}
