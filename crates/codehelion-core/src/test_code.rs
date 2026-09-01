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
//! An explicit marker in the source is the strongest evidence: whatever the
//! language's own test tooling makes an author write to declare a case. In
//! Rust that is an attribute; in C and C++ it is the macro the framework
//! defines, which stands where a function's return type and name would. A
//! unit inside a marked container — a module compiled only for tests — is test
//! code too, since it exists to serve the cases in it.
//!
//! Paths are also evidence, not a suppression rule. The conventional test
//! paths in [`DEFAULT_TEST_PATHS`] classify otherwise unmarked helpers as test
//! code so presentation can rank them below production findings without hiding
//! them. The caller may replace or disable those patterns. Reports retain
//! whether a group was recognised by a marker or a path, and a marker wins
//! whenever both apply, so the two sources of evidence never disagree
//! silently.
//!
//! # A container the file does not hold
//!
//! A Rust module can be declared in one file and written in another:
//! `#[cfg(test)] mod tests;` beside a `tests.rs`, or a `tests/` directory of
//! them. The marker is on the declaration, so nothing in the file it governs
//! carries it, and reading each file alone leaves every helper in that tree
//! looking like ordinary code — a suite of a hundred cases can come back
//! unrecognised because its `#[test]` functions were the only ones ever
//! marked.
//!
//! [`declared_test_modules`] closes that by following the declaration to the
//! file it names, and onwards through whatever that file declares in turn.
//! This is not the directory convention arriving by another route: what is
//! read is still the author's own `#[cfg(test)]`, and a `tests` directory
//! nobody declared that way is still ordinary code. It needs the whole file
//! set at once, which is why it sits apart from [`is_marked`] rather than
//! inside it.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::discovery::Language;
use crate::frontend::{Token, TokenKind};

/// Version of the test-code recognition rules.
///
/// Recorded alongside the other detector versions: a change in what counts as
/// test code changes how a report is ordered, so results from two versions are
/// not comparable without saying so.
pub const TEST_CODE_VERSION: &str = "test-code-v1";

/// Conventional paths that contain test code.
///
/// The patterns are applied only to source files the scan already selected, so
/// the `.*` suffixes cover the Rust, C, and C++ extensions without classifying
/// files from another language. They are configuration defaults rather than a
/// hidden rule: callers can replace them or set the configured list to empty.
pub const DEFAULT_TEST_PATHS: &[&str] = &[
    "**/tests/**",
    "**/test/**",
    "**/__tests__/**",
    "**/*_test.*",
    "**/*_tests.*",
    "**/test_*.*",
    "**/*_spec.*",
];

/// Why a unit or group is recognised as test code.
///
/// A marker is stronger than a path. For a group, the value is present only
/// when every member is test code; it is `Marker` when any member has marker
/// evidence and `Path` only when every member has path evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TestCodeEvidence {
    /// The source declares the test with a language or framework marker.
    Marker,
    /// The file's path matches a configured test-path convention.
    Path,
}

impl TestCodeEvidence {
    /// The spelling used in persisted reports and database rows.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Marker => "marker",
            Self::Path => "path",
        }
    }

    /// Decode a persisted evidence spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "marker" => Some(Self::Marker),
            "path" => Some(Self::Path),
            _ => None,
        }
    }
}

/// Aggregate member evidence for one group.
///
/// Every member must be test code for a group to be test code. Among those
/// groups, one marker is enough to name the aggregate `marker`; otherwise all
/// members are path-derived and it names `path`.
#[must_use]
pub fn aggregate_evidence(
    evidence: impl IntoIterator<Item = Option<TestCodeEvidence>>,
) -> Option<TestCodeEvidence> {
    let mut any = false;
    let mut marker = false;
    for item in evidence {
        let item = item?;
        any = true;
        marker |= item == TestCodeEvidence::Marker;
    }
    any.then_some(if marker {
        TestCodeEvidence::Marker
    } else {
        TestCodeEvidence::Path
    })
}

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
        let (body, tail) = leading_attribute(rest)?;
        rest = tail;
        Some(body)
    })
}

/// The body of the leading attribute, without its delimiters, and the tokens
/// after it.
///
/// `#[attr]` on the item and `#![attr]` on the enclosing scope both start an
/// attribute; anything else ends the run.
fn leading_attribute(tokens: &[Token]) -> Option<(&[Token], &[Token])> {
    let after_hash = after_punctuation(tokens, "#")?;
    let after_bang = after_punctuation(after_hash, "!").unwrap_or(after_hash);
    let body = after_punctuation(after_bang, "[")?;
    let end = closing_bracket(body)?;
    Some((&body[..end], &body[end + 1..]))
}

/// What an item is left with once its leading attribute run is past.
fn after_attributes(tokens: &[Token]) -> &[Token] {
    let mut rest = tokens;
    while let Some((_, tail)) = leading_attribute(rest) {
        rest = tail;
    }
    rest
}

/// The tokens after one leading punctuation token with the given text.
fn after_punctuation<'a>(tokens: &'a [Token], text: &str) -> Option<&'a [Token]> {
    let (first, rest) = tokens.split_first()?;
    (first.kind == TokenKind::Punctuation && first.text == text).then_some(rest)
}

/// Index of the `]` that closes the bracket this body sits in, counting nested
/// pairs, or `None` when the source is truncated before it.
fn closing_bracket(body: &[Token]) -> Option<usize> {
    closing(body, "[", "]")
}

/// Index of the delimiter closing the group this body sits in, counting nested
/// pairs, or `None` when the source is truncated before it.
fn closing(body: &[Token], open: &str, close: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in body.iter().enumerate() {
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        if &*token.text == open {
            depth += 1;
        } else if &*token.text == close {
            if depth == 0 {
                return Some(index);
            }
            depth -= 1;
        }
    }
    None
}

/// Whether an attribute makes its item test-only or declares a test case.
fn names_test(body: &[Token]) -> bool {
    let Some((head, arguments)) = attribute_parts(body) else {
        return false;
    };
    match (head, arguments) {
        ("cfg", Some(predicate)) => {
            predicate_values(predicate, false) & TRUE_VALUE == 0
                && predicate_values(predicate, true) & TRUE_VALUE != 0
        }
        ("cfg_attr", Some(arguments)) => split_arguments(arguments)
            .into_iter()
            .skip(1)
            .any(names_test),
        (TEST_IDENT, _) => true,
        _ => false,
    }
}

/// Last component of an attribute path and its parenthesized arguments.
fn attribute_parts(body: &[Token]) -> Option<(&str, Option<&[Token]>)> {
    let open = body.iter().position(|token| token.text == "(");
    let path = open.map_or(body, |index| &body[..index]);
    let head = path
        .iter()
        .rev()
        .find(|token| matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword))?
        .text
        .as_str();
    let arguments = open.and_then(|index| {
        let tail = &body[index + 1..];
        closing(tail, "(", ")").map(|end| &tail[..end])
    });
    Some((head, arguments))
}

const FALSE_VALUE: u8 = 1;
const TRUE_VALUE: u8 = 2;
const BOTH_VALUES: u8 = FALSE_VALUE | TRUE_VALUE;

/// Possible truth values of one cfg predicate for a fixed value of `test`.
fn predicate_values(tokens: &[Token], test_enabled: bool) -> u8 {
    let Some((head, arguments)) = attribute_parts(tokens) else {
        return BOTH_VALUES;
    };
    match (head, arguments) {
        (TEST_IDENT, None) => {
            if test_enabled {
                TRUE_VALUE
            } else {
                FALSE_VALUE
            }
        }
        ("not", Some(arguments)) => {
            let values = predicate_values(arguments, test_enabled);
            ((values & FALSE_VALUE) << 1) | ((values & TRUE_VALUE) >> 1)
        }
        ("all", Some(arguments)) => split_arguments(arguments)
            .into_iter()
            .map(|argument| predicate_values(argument, test_enabled))
            .fold(TRUE_VALUE, possible_and),
        ("any", Some(arguments)) => split_arguments(arguments)
            .into_iter()
            .map(|argument| predicate_values(argument, test_enabled))
            .fold(FALSE_VALUE, possible_or),
        _ => BOTH_VALUES,
    }
}

fn possible_and(left: u8, right: u8) -> u8 {
    possible_binary(left, right, |a, b| a && b)
}

fn possible_or(left: u8, right: u8) -> u8 {
    possible_binary(left, right, |a, b| a || b)
}

fn possible_binary(left: u8, right: u8, operation: impl Fn(bool, bool) -> bool) -> u8 {
    let mut values = 0;
    for left_value in [false, true] {
        if left & value_bit(left_value) == 0 {
            continue;
        }
        for right_value in [false, true] {
            if right & value_bit(right_value) != 0 {
                values |= value_bit(operation(left_value, right_value));
            }
        }
    }
    values
}

const fn value_bit(value: bool) -> u8 {
    if value { TRUE_VALUE } else { FALSE_VALUE }
}

/// Split comma-separated predicate or `cfg_attr` arguments at top level.
fn split_arguments(tokens: &[Token]) -> Vec<&[Token]> {
    let mut arguments = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            "," if depth == 0 => {
                arguments.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    arguments.push(&tokens[start..]);
    arguments
}

/// One file, as module resolution needs to see it.
#[derive(Debug, Clone, Copy)]
pub struct ModuleFile<'a> {
    /// Path the file was discovered at. Only its shape matters — the
    /// directory it sits in and its stem — so any consistent root will do,
    /// provided every file in the set shares it.
    pub path: &'a Path,
    /// Language the file was parsed as. Anything but Rust is passed over.
    pub language: Language,
    /// The file's tokens, comments and whitespace already removed.
    pub tokens: &'a [Token],
}

/// Which of these files are the body of a module the tree declares test-only.
///
/// Returns one flag per input, in the same order. A file is flagged when some
/// file declares it with `#[cfg(test)] mod <name>;`, and so is everything that
/// file declares in turn: a test module's own submodules are part of the
/// suite whether or not anybody repeated the attribute on them.
///
/// Only declarations at a file's top level are followed. One written inside an
/// inline `mod` names a file in a directory nested a further level down, and
/// resolving that would mean tracking the module path a declaration sits at —
/// worth doing when a project turns up that needs it, and not before.
#[must_use]
pub fn declared_test_modules(files: &[ModuleFile<'_>]) -> Vec<bool> {
    let mut suite = vec![false; files.len()];
    let by_path: BTreeMap<&Path, usize> = files
        .iter()
        .enumerate()
        .filter(|(_, file)| file.language == Language::Rust)
        .map(|(index, file)| (file.path, index))
        .collect();
    let declared: Vec<Vec<Declaration<'_>>> = files
        .iter()
        .map(|file| {
            if file.language == Language::Rust {
                module_declarations(file.tokens)
            } else {
                Vec::new()
            }
        })
        .collect();

    let mut pending = VecDeque::new();
    let enter = |name: &str, from: &Path, suite: &mut Vec<bool>, pending: &mut VecDeque<_>| {
        for candidate in module_bodies(from, name) {
            if let Some(&index) = by_path.get(candidate.as_path())
                && !suite[index]
            {
                suite[index] = true;
                pending.push_back(index);
            }
        }
    };

    for (index, declarations) in declared.iter().enumerate() {
        for declaration in declarations.iter().filter(|entry| entry.marked) {
            enter(
                declaration.name,
                files[index].path,
                &mut suite,
                &mut pending,
            );
        }
    }
    // Everything a file already in the suite declares is in it too, marked or
    // not: the attribute was written once, on the module the rest hang off.
    while let Some(index) = pending.pop_front() {
        for declaration in &declared[index] {
            enter(
                declaration.name,
                files[index].path,
                &mut suite,
                &mut pending,
            );
        }
    }
    suite
}

/// A module declared without a body, and whether its declaration is marked as
/// test-only.
struct Declaration<'a> {
    name: &'a str,
    marked: bool,
}

/// The bodiless module declarations at a file's top level.
fn module_declarations(tokens: &[Token]) -> Vec<Declaration<'_>> {
    let mut declarations = Vec::new();
    for item in top_level_items(tokens) {
        if let Some(name) = bodiless_module(item) {
            declarations.push(Declaration {
                name,
                marked: rust_attributes(item).any(names_test),
            });
        }
    }
    declarations
}

/// The file's top-level items, each from its first attribute to the `;` or `}`
/// that ends it.
///
/// Nothing here parses; an item is what lies between two terminators found at
/// the outermost nesting level — a `;` written there, or the `}` that closes a
/// body back to it. That is enough for the one shape this reads, and a file it
/// makes no sense of yields items no other rule matches.
fn top_level_items(tokens: &[Token]) -> impl Iterator<Item = &[Token]> {
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut index = 0usize;
    std::iter::from_fn(move || {
        while index < tokens.len() {
            let token = &tokens[index];
            index += 1;
            if token.kind != TokenKind::Punctuation {
                continue;
            }
            let ends = match &*token.text {
                "{" | "(" | "[" => {
                    depth += 1;
                    false
                }
                // Only a brace closes an item: the `]` ending an attribute and
                // the `)` ending a visibility both come back to the outermost
                // level in the middle of one.
                "}" | ")" | "]" => {
                    depth = depth.saturating_sub(1);
                    depth == 0 && token.text == "}"
                }
                ";" => depth == 0,
                _ => false,
            };
            if ends {
                let item = &tokens[start..index];
                start = index;
                return Some(item);
            }
        }
        None
    })
}

/// The name of the module this item declares without a body, if that is what
/// it is.
///
/// `mod name;` and nothing else: once the attributes and the visibility are
/// past, three tokens have to be all that is left, which is what tells a
/// declaration from a `mod name { .. }` whose contents are right there.
fn bodiless_module(item: &[Token]) -> Option<&str> {
    let rest = after_visibility(after_attributes(item));
    let [keyword, name, terminator] = rest else {
        return None;
    };
    let declares = word_is(keyword, "mod")
        && name.kind == TokenKind::Identifier
        && terminator.kind == TokenKind::Punctuation
        && terminator.text == ";";
    declares.then(|| &*name.text)
}

/// What an item is left with once `pub`, with any restriction it carries, is
/// past.
fn after_visibility(tokens: &[Token]) -> &[Token] {
    let Some((first, rest)) = tokens.split_first() else {
        return tokens;
    };
    if !word_is(first, "pub") {
        return tokens;
    }
    let Some(restriction) = after_punctuation(rest, "(") else {
        return rest;
    };
    closing(restriction, "(", ")").map_or(rest, |end| &restriction[end + 1..])
}

/// Whether a token is the given word, however the frontend classified it.
fn word_is(token: &Token, word: &str) -> bool {
    matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword) && token.text == word
}

/// The files that could hold the body of `name` as declared by `from`.
///
/// Rust looks in one place or the other, never both, but which one depends on
/// where the declaring file itself sits; offering both and taking whichever
/// exists costs nothing and spares this a rule it would only get wrong.
fn module_bodies(from: &Path, name: &str) -> [PathBuf; 2] {
    let directory = from.parent().unwrap_or_else(|| Path::new(""));
    // A module's own file gives its name to the directory its children live
    // in — except for the three that stand for a directory already.
    let base = match from.file_stem().and_then(OsStr::to_str) {
        Some("mod" | "lib" | "main") | None => directory.to_path_buf(),
        Some(stem) => directory.join(stem),
    };
    [
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
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
    fn negated_test_cfg_marks_production_code_not_test_code() {
        let source = tokens(&[
            "#",
            "[",
            "cfg",
            "(",
            "not",
            "(",
            "test",
            ")",
            ")",
            "]",
            "fn",
            "production",
        ]);
        assert!(!is_marked(Language::Rust, &source));

        let double_negated = tokens(&[
            "#", "[", "cfg", "(", "not", "(", "not", "(", "test", ")", ")", ")", "]", "fn", "check",
        ]);
        assert!(is_marked(Language::Rust, &double_negated));
    }

    #[test]
    fn cfg_attr_condition_is_not_mistaken_for_the_applied_attribute() {
        let production = tokens(&[
            "#",
            "[",
            "cfg_attr",
            "(",
            "test",
            ",",
            "allow",
            "(",
            "dead_code",
            ")",
            ")",
            "]",
            "fn",
            "production",
        ]);
        assert!(!is_marked(Language::Rust, &production));

        let test = tokens(&[
            "#", "[", "cfg_attr", "(", "feature", "=", "runtime", ",", "tokio", ":", ":", "test",
            ")", "]", "fn", "check",
        ]);
        assert!(is_marked(Language::Rust, &test));
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

    #[test]
    fn default_test_paths_cover_directories_and_rust_c_cpp_file_conventions() {
        assert_eq!(
            DEFAULT_TEST_PATHS,
            [
                "**/tests/**",
                "**/test/**",
                "**/__tests__/**",
                "**/*_test.*",
                "**/*_tests.*",
                "**/test_*.*",
                "**/*_spec.*",
            ]
        );
    }

    #[test]
    fn aggregate_evidence_requires_every_member_and_prefers_markers() {
        assert_eq!(
            aggregate_evidence([Some(TestCodeEvidence::Path), Some(TestCodeEvidence::Path)]),
            Some(TestCodeEvidence::Path)
        );
        assert_eq!(
            aggregate_evidence([Some(TestCodeEvidence::Path), Some(TestCodeEvidence::Marker),]),
            Some(TestCodeEvidence::Marker)
        );
        assert_eq!(
            aggregate_evidence([Some(TestCodeEvidence::Marker), None]),
            None
        );
    }

    /// The suite flags for a set of files given as `(path, source pieces)`,
    /// every one of them Rust.
    fn suite_over(files: &[(&str, &[&str])]) -> Vec<bool> {
        let streams: Vec<Vec<Token>> = files.iter().map(|(_, pieces)| tokens(pieces)).collect();
        let inputs: Vec<ModuleFile<'_>> = files
            .iter()
            .zip(&streams)
            .map(|((path, _), stream)| ModuleFile {
                path: Path::new(path),
                language: Language::Rust,
                tokens: stream,
            })
            .collect();
        declared_test_modules(&inputs)
    }

    #[test]
    fn a_declared_test_module_puts_the_file_it_names_in_the_suite() {
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", ";"],
            ),
            ("src/tests.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, true]);
    }

    #[test]
    fn a_test_module_hands_the_suite_on_to_what_it_declares() {
        // Only the first declaration carries the attribute. Everything below
        // it is the same suite, spelled across as many files as it took.
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", ";"],
            ),
            ("src/tests.rs", &["mod", "parser", ";"]),
            ("src/tests/parser.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, true, true]);
    }

    #[test]
    fn a_declaration_below_the_code_it_covers_is_still_found() {
        // Where the declaration actually sits: after the routines the suite
        // exercises, so everything before it has to be walked past first.
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &[
                    "pub", "fn", "width", "(", ")", "{", "text", ".", "count", "(", ")", "}", "#",
                    "[", "cfg", "(", "test", ")", "]", "mod", "tests", ";",
                ],
            ),
            ("src/tests.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, true]);
    }

    #[test]
    fn a_module_whose_body_is_a_directory_is_found_there() {
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", ";"],
            ),
            ("src/tests/mod.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, true]);
    }

    #[test]
    fn a_module_declared_without_the_marker_is_ordinary_code() {
        let suite = suite_over(&[
            ("src/lib.rs", &["mod", "parser", ";"]),
            ("src/parser.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, false]);
    }

    #[test]
    fn a_directory_named_for_tests_that_nobody_declared_is_not_a_marked_module() {
        // This resolver follows only Rust module declarations. The caller
        // applies configured path evidence later, after it has the whole
        // structural report to classify.
        let suite = suite_over(&[
            ("src/lib.rs", &["fn", "run", "(", ")", "{", "}"]),
            ("src/tests/parser.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, false]);
    }

    #[test]
    fn a_module_written_where_it_is_declared_claims_no_file() {
        // `mod tests { .. }` is its own body; a file of that name beside it is
        // a different module, and the marker here says nothing about it.
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &[
                    "#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", "{", "fn", "check",
                    "(", ")", "{", "}", "}",
                ],
            ),
            ("src/tests.rs", &["fn", "other", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, false]);
    }

    #[test]
    fn a_declaration_is_read_through_its_visibility() {
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &[
                    "#", "[", "cfg", "(", "test", ")", "]", "pub", "(", "crate", ")", "mod",
                    "tests", ";",
                ],
            ),
            ("src/tests.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, true]);
    }

    #[test]
    fn a_declaration_the_source_is_truncated_before_marks_nothing() {
        // The parser is error-tolerant, so an item with no terminator reaches
        // here. It must end the scan rather than run off the end.
        let suite = suite_over(&[
            (
                "src/lib.rs",
                &["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests"],
            ),
            ("src/tests.rs", &["fn", "check", "(", ")", "{", "}"]),
        ]);
        assert_eq!(suite, vec![false, false]);
    }

    #[test]
    fn only_rust_files_are_read_for_declarations() {
        // The syntax belongs to one language. A C++ file whose tokens happen
        // to spell it is saying something else entirely.
        let declaration = tokens(&["#", "[", "cfg", "(", "test", ")", "]", "mod", "tests", ";"]);
        let body = tokens(&["fn", "check", "(", ")", "{", "}"]);
        let suite = declared_test_modules(&[
            ModuleFile {
                path: Path::new("src/lib.rs"),
                language: Language::Cpp,
                tokens: &declaration,
            },
            ModuleFile {
                path: Path::new("src/tests.rs"),
                language: Language::Rust,
                tokens: &body,
            },
        ]);
        assert_eq!(suite, vec![false, false]);
    }
}
