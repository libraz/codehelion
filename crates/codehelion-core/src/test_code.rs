//! Recognising units that exist to test other code.
//!
//! Test suites repeat themselves on purpose. The same fixture is built, the
//! same call is made and the same assertion is written across dozens of cases,
//! because a test that shares its setup with its neighbours stops being
//! readable on its own. Reporting that repetition next to duplication in the
//! code under test buries the latter: on a well-tested project most clone
//! groups live in the suite.
//!
//! So the fact is recorded here and left to presentation to act on, exactly as
//! [`crate::boilerplate`] classification is. A unit marked as test code is
//! still parsed, still compared and still grouped; only where its group lands
//! in a report changes, and it can always be shown.
//!
//! # What counts
//!
//! Only an explicit marker in the source: whatever the language's own test
//! tooling makes an author write to declare a case. In Rust that is an
//! attribute; in C and C++ it is the macro the framework defines, which stands
//! where a function's return type and name would. Directory conventions are
//! not consulted, because path rules already express them and expressing one
//! thing two ways invites the two to disagree. A unit inside a marked
//! container — a module compiled only for tests — is test code too, since it
//! exists to serve the cases in it.

use crate::discovery::Language;
use crate::frontend::{Token, TokenKind};

/// Version of the test-code recognition rules.
///
/// Recorded alongside the other detector versions: a change in what counts as
/// test code changes how a report is ordered, so results from two versions are
/// not comparable without saying so.
pub const TEST_CODE_VERSION: &str = "test-code-v1";

/// The identifier a test attribute is built around.
///
/// `#[test]`, `#[cfg(test)]` and the async runtimes' `#[<runtime>::test]` all
/// carry it, and a marker is expected to spell it exactly — a name that merely
/// contains the word (`#[test_util::setup]`) is a different thing.
const TEST_IDENT: &str = "test";

/// The C and C++ macros that declare a case and carry its body.
///
/// A case in these languages is written `MACRO(suite, name) { ... }`, which
/// parses as a definition whose name is the macro. That name is the author's
/// explicit declaration that the body is a test, and it is the same kind of
/// evidence a Rust attribute is.
///
/// Only body-carrying macros are listed. Registration macros
/// (`INSTANTIATE_TEST_SUITE_P`, `BOOST_AUTO_TEST_SUITE`) declare no body, so
/// nothing they mark is a unit, and assertion macros sit inside a body that
/// has already been marked by the case around it.
///
/// The list is deliberately short and exact, and covers `GoogleTest`, Google
/// Benchmark, Boost.Test, Catch2 and doctest. It is kept sorted rather than
/// grouped by framework, because several of these names belong to more than
/// one. A framework that is not here is reached by path rules, which is the
/// same answer any project gets for a convention this module cannot read.
const CASE_MACROS: &[&str] = &[
    "BENCHMARK_DEFINE_F",
    "BENCHMARK_F",
    "BENCHMARK_TEMPLATE_F",
    "BOOST_AUTO_TEST_CASE",
    "BOOST_AUTO_TEST_CASE_TEMPLATE",
    "BOOST_DATA_TEST_CASE",
    "BOOST_FIXTURE_TEST_CASE",
    "SCENARIO",
    "TEMPLATE_TEST_CASE",
    "TEST",
    "TEST_CASE",
    "TEST_CASE_METHOD",
    "TEST_F",
    "TEST_P",
    "TYPED_TEST",
    "TYPED_TEST_P",
];

/// Whether a node's own leading tokens mark it as test code.
///
/// `tokens` is the node's token slice, starting at the first token the node
/// covers; both markers this reads sit at the front of an item, so they are
/// always at the front of that slice.
///
/// Only the front is read, so a `test` or a `TEST` appearing later — as the
/// item's own name, a parameter, a called function — is never a marker.
#[must_use]
pub fn is_marked(language: Language, tokens: &[Token]) -> bool {
    match language {
        Language::Rust => rust_attributes(tokens).any(names_test),
        // C and C++ have no attribute for this and no container the mark could
        // be inherited from: `BOOST_AUTO_TEST_SUITE` and its `_END` are two
        // separate invocations at file scope, not a construct that encloses
        // the cases between them. Each case therefore carries its own marker
        // or is not recognised.
        Language::C | Language::Cpp => opens_a_case(tokens),
    }
}

/// Whether the tokens begin with a case macro applied to something.
///
/// The call parenthesis is required: a bare identifier that happens to spell a
/// macro name is a use of that name, not a declaration.
fn opens_a_case(tokens: &[Token]) -> bool {
    let [name, open, ..] = tokens else {
        return false;
    };
    name.kind == TokenKind::Identifier
        && CASE_MACROS.contains(&&*name.text)
        && open.kind == TokenKind::Punctuation
        && open.text == "("
}

/// The leading `#[...]` attribute bodies of a Rust item, each without its
/// delimiters, in source order.
fn rust_attributes(tokens: &[Token]) -> impl Iterator<Item = &[Token]> {
    let mut rest = tokens;
    std::iter::from_fn(move || {
        // `#[attr]` on the item and `#![attr]` on the enclosing scope both
        // start an attribute; anything else ends the run.
        let after_hash = after_punctuation(rest, "#")?;
        let after_bang = after_punctuation(after_hash, "!").unwrap_or(after_hash);
        let body = after_punctuation(after_bang, "[")?;
        let end = closing_bracket(body)?;
        rest = &body[end + 1..];
        Some(&body[..end])
    })
}

/// The tokens after one leading punctuation token with the given text.
fn after_punctuation<'a>(tokens: &'a [Token], text: &str) -> Option<&'a [Token]> {
    let (first, rest) = tokens.split_first()?;
    (first.kind == TokenKind::Punctuation && first.text == text).then_some(rest)
}

/// Index of the `]` that closes the bracket this body sits in, counting nested
/// pairs, or `None` when the source is truncated before it.
fn closing_bracket(body: &[Token]) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in body.iter().enumerate() {
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        match &*token.text {
            "[" => depth += 1,
            "]" if depth == 0 => return Some(index),
            "]" => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Whether an attribute body names the test identifier.
fn names_test(body: &[Token]) -> bool {
    body.iter().any(|token| {
        matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword) && token.text == TEST_IDENT
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::frontend::{Lexeme, SourceSpan};

    /// One token per piece: alphabetic pieces lex as identifiers, the rest as
    /// punctuation, which is all the attribute scan distinguishes.
    fn tokens(pieces: &[&str]) -> Vec<Token> {
        pieces
            .iter()
            .map(|piece| Token {
                kind: if piece.chars().next().is_some_and(char::is_alphanumeric) {
                    TokenKind::Identifier
                } else {
                    TokenKind::Punctuation
                },
                text: Lexeme::from(*piece),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: 0,
                    start_line: 1,
                    start_column: 1,
                },
            })
            .collect()
    }

    #[test]
    fn a_test_attribute_marks_the_item_it_precedes() {
        let source = tokens(&["#", "[", "test", "]", "fn", "check", "(", ")"]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_configuration_predicate_naming_tests_marks_the_item() {
        let source = tokens(&["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", "{"]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_runtime_qualified_test_attribute_is_still_a_test_attribute() {
        let source = tokens(&["#", "[", "tokio", ":", ":", "test", "]", "fn", "check"]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn the_marker_is_read_only_from_the_leading_attributes() {
        // `test` here is the function's own name and a parameter, past the
        // attribute run. Reading it as a marker would sweep in every unit
        // that merely talks about testing.
        let source = tokens(&["#", "[", "inline", "]", "fn", "test", "(", "test", ")"]);
        assert!(!is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_nested_attribute_is_searched_to_its_own_end() {
        let source = tokens(&[
            "#", "[", "cfg", "(", "all", "(", "unix", ",", "test", ")", ")", "]", "fn", "check",
        ]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_marker_after_an_unrelated_attribute_is_still_found() {
        let source = tokens(&[
            "#",
            "[",
            "allow",
            "(",
            "dead_code",
            ")",
            "]",
            "#",
            "[",
            "test",
            "]",
            "fn",
            "check",
        ]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn an_inner_attribute_is_read_like_an_outer_one() {
        let source = tokens(&["#", "!", "[", "cfg", "(", "test", ")", "]", "fn", "check"]);
        assert!(is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_truncated_attribute_marks_nothing() {
        // The parser is error-tolerant, so an unclosed attribute reaches here.
        // It must end the scan rather than run off the end of the item.
        let source = tokens(&["#", "[", "test", "fn", "check"]);
        assert!(!is_marked(Language::Rust, &source));
    }

    #[test]
    fn a_name_that_merely_contains_the_word_is_not_a_marker() {
        let source = tokens(&["#", "[", "test_util", ":", ":", "setup", "]", "fn", "check"]);
        assert!(!is_marked(Language::Rust, &source));
    }

    #[test]
    fn attribute_syntax_marks_nothing_in_c_or_cpp() {
        // Neither language has the attribute, so a file that spells one is
        // ordinary code that happens to look Rust-like.
        let source = tokens(&["#", "[", "test", "]", "void", "check", "(", ")"]);
        assert!(!is_marked(Language::C, &source));
        assert!(!is_marked(Language::Cpp, &source));
    }

    #[test]
    fn a_case_macro_marks_the_definition_it_opens() {
        for name in ["TEST", "TEST_F", "BOOST_AUTO_TEST_CASE", "TEST_CASE"] {
            let source = tokens(&[name, "(", "Suite", ",", "Name", ")", "{"]);
            assert!(is_marked(Language::Cpp, &source), "{name}");
            assert!(is_marked(Language::C, &source), "{name}");
        }
    }

    #[test]
    fn a_case_macro_is_a_marker_only_where_it_declares_something() {
        // Used as a value, not applied: whatever this is, it is not a case.
        let source = tokens(&["TEST", ";"]);
        assert!(!is_marked(Language::Cpp, &source));
        // Applied, but not at the front — the item is `run`, which calls it.
        let source = tokens(&["void", "run", "(", ")", "{", "TEST", "(", "x", ")"]);
        assert!(!is_marked(Language::Cpp, &source));
    }

    #[test]
    fn a_name_that_merely_starts_with_a_case_macro_is_not_one() {
        let source = tokens(&["TEST_HELPER", "(", "x", ")", "{"]);
        assert!(!is_marked(Language::Cpp, &source));
    }

    #[test]
    fn rust_does_not_read_the_c_markers() {
        // Rust has the attribute, so a bare identifier is never the evidence.
        let source = tokens(&["TEST", "(", "Suite", ",", "Name", ")", "{"]);
        assert!(!is_marked(Language::Rust, &source));
    }

    #[test]
    fn the_case_macro_list_is_sorted_and_free_of_repeats() {
        // Sorted so a reader can find a name, and so an addition lands next to
        // its neighbours rather than wherever it was typed.
        let mut sorted = CASE_MACROS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, CASE_MACROS);
    }

    #[test]
    fn an_empty_item_marks_nothing() {
        assert!(!is_marked(Language::Rust, &[]));
    }
}
