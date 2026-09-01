//! Coarse unit-boundary detection over a C-family token stream.
//!
//! Boundaries are the clone-report anchors: function definitions, methods
//! (functions inside a record body), record bodies (`struct`/`union`/`class`)
//! and, for C++, block-bodied lambdas. Detection is a delimiter-matching
//! heuristic over tokens, not a parse; in Fast mode no syntax tree is built
//! and the preprocessor never runs.
//!
//! A function definition is recognised from its body brace: walking backwards
//! over signature-trailer tokens (`const`, `noexcept`, `requires`, a trailing
//! return type, ...) must reach the parameter list's `)`, whose matching `(`
//! must be preceded by the function's name — directly, or through an explicit
//! template argument list. Constructor initialiser lists are walked through
//! entry by entry. The heuristic is deliberately conservative: constructs a
//! lexer cannot classify with confidence (K&R definitions, function-try-blocks,
//! functions returning function pointers) are left un-anchored rather than
//! risking spurious units.
//!
//! The walking itself — skipping a balanced group, the trailer vocabulary, the
//! record-versus-declarator decision — lives in the crate's private
//! `declarator` module, so C and C++ and every rule below share one
//! implementation of it.

use codehelion_core::frontend::{
    Diagnostic, DiagnosticKind, SourceSpan, Token, TokenKind, Unit, UnitKind,
};

use crate::declarator::{self, DelimPairs, delim_pairs, group_close, group_open};
use crate::dialect::Dialect;

/// Tokens that may immediately precede a lambda's `[` (expression position).
const LAMBDA_PRECEDER_PUNCT: &[&str] = &[
    "=", "(", ",", "{", ";", ":", "?", "&&", "||", "!", "<", ">", "<<", ">>", "+", "-", "*", "/",
    "%",
];

/// Keywords that may immediately precede a lambda's `[`.
const LAMBDA_PRECEDER_KEYWORDS: &[&str] = &[
    "return",
    "co_return",
    "co_yield",
    "co_await",
    "case",
    "else",
    "do",
];

/// Detect unit boundaries and recoverable boundary errors under `dialect`.
#[must_use]
pub fn detect(tokens: &[Token], dialect: &Dialect) -> (Vec<Unit>, Vec<Diagnostic>) {
    let pairs = delim_pairs(tokens);
    let records = record_units(tokens, &pairs, dialect);

    let mut units = records.clone();
    let mut diagnostics = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Punctuation
            && token.text == "{"
            && let Some(result) = function_unit(tokens, &pairs, &records, dialect, i)
        {
            match result {
                Ok(unit) => units.push(unit),
                Err(span) => diagnostics.push(Diagnostic {
                    kind: DiagnosticKind::UnmatchedDelimiter,
                    span,
                }),
            }
        }
        if dialect.lambdas
            && token.kind == TokenKind::Punctuation
            && token.text == "["
            && let Some(unit) = lambda_unit(tokens, &pairs, i)
        {
            units.push(unit);
        }
    }

    units.sort_by_key(|u| (u.token_start, u.token_end));
    (units, diagnostics)
}

/// Record bodies: `struct`/`union` (and for C++ `class`) definitions.
fn record_units(tokens: &[Token], pairs: &DelimPairs, dialect: &Dialect) -> Vec<Unit> {
    let mut out = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if !declarator::is_record_keyword(token, dialect) {
            continue;
        }
        // A record keyword inside a `template <...>` list introduces a type
        // parameter, at any nesting depth; `enum class` names an enumeration.
        if declarator::is_template_parameter_position(tokens, i) {
            continue;
        }
        if i.checked_sub(1)
            .map(|p| &tokens[p])
            .is_some_and(|prev| prev.kind == TokenKind::Keyword && prev.text == "enum")
        {
            continue;
        }
        let Some(header) = declarator::record_header(tokens, pairs, i + 1) else {
            continue;
        };
        let Some(close) = group_close(pairs, header.body_open) else {
            continue;
        };
        out.push(Unit {
            kind: UnitKind::Record,
            name: header.name.map(|name| tokens[name].text.to_string()),
            token_start: i,
            token_end: close + 1,
            span: span_of(tokens, i, close),
        });
    }
    out
}

/// Try to recognise the `{` at `body_open` as a function body.
fn function_unit(
    tokens: &[Token],
    pairs: &DelimPairs,
    records: &[Unit],
    dialect: &Dialect,
    body_open: usize,
) -> Option<Result<Unit, SourceSpan>> {
    // Walk backwards over the signature trailer to the parameter list.
    let mut j = body_open.checked_sub(1)?;
    for _ in 0..64 {
        let token = &tokens[j];
        match token.kind {
            TokenKind::Identifier => j = j.checked_sub(1)?,
            TokenKind::Keyword if declarator::is_trailer_keyword(&token.text) => {
                j = j.checked_sub(1)?;
            }
            TokenKind::Punctuation if declarator::is_trailer_punct(&token.text) => {
                j = j.checked_sub(1)?;
            }
            TokenKind::Punctuation if token.text == ")" => {
                let open = group_open(tokens, pairs, j)?;
                // `noexcept(...)` / `throw()` / `decltype(...)` / `requires
                // (...)` groups belong to the trailer, and so does an
                // attribute specifier's group; skip them whole.
                if let Some(before) = open.checked_sub(1) {
                    let b = &tokens[before];
                    if (b.kind == TokenKind::Keyword
                        && declarator::is_trailer_group_keyword(&b.text))
                        || declarator::is_attribute_specifier(b)
                    {
                        j = before.checked_sub(1)?;
                        continue;
                    }
                }
                return resolve_signature(tokens, pairs, records, dialect, j, body_open);
            }
            // A `}` here can only be the last constructor-initialiser entry
            // (`: a(x), b{y} {`); the resolver walks the entries.
            TokenKind::Punctuation if token.text == "}" => {
                return resolve_signature(tokens, pairs, records, dialect, j, body_open);
            }
            _ => return None,
        }
    }
    None
}

/// Resolve the group closing at `close` back to the parameter list and the
/// function name, walking constructor-initialiser entries in between.
///
/// The name may be spelled with an explicit template argument list, both in an
/// initialiser entry (`: Base<int>(x)`) and on the declarator itself (an
/// explicit function-template specialisation); the shared declarator walk
/// steps over that group, so the two spellings resolve alike.
fn resolve_signature(
    tokens: &[Token],
    pairs: &DelimPairs,
    records: &[Unit],
    dialect: &Dialect,
    close: usize,
    body_open: usize,
) -> Option<Result<Unit, SourceSpan>> {
    let mut close = close;
    for _ in 0..32 {
        let open = group_open(tokens, pairs, close)?;
        let name_i = declarator::declarator_name(tokens, open)?;
        let name_token = &tokens[name_i];

        if name_token.kind == TokenKind::Identifier {
            // An attribute specifier decorates a declaration without naming
            // one, and a record keyword directly before the candidate means
            // the group belongs to that record's header, not to a declarator.
            if declarator::is_attribute_specifier(name_token)
                || name_i
                    .checked_sub(1)
                    .is_some_and(|p| declarator::is_record_keyword(&tokens[p], dialect))
            {
                return None;
            }
            if let Some(sep_i) = name_i.checked_sub(1) {
                let sep = &tokens[sep_i];
                if sep.kind == TokenKind::Punctuation && matches!(sep.text.as_str(), ":" | ",") {
                    // A constructor-initialiser entry (`name(...)` or
                    // `name{...}`); the group before the separator is the
                    // previous entry or the parameter list itself.
                    let prev_i = sep_i.checked_sub(1)?;
                    let prev = &tokens[prev_i];
                    if prev.kind == TokenKind::Punctuation
                        && matches!(prev.text.as_str(), ")" | "}")
                    {
                        close = prev_i;
                        continue;
                    }
                    return None;
                }
            }
            // The parameter list itself must be parenthesised.
            if tokens[close].text != ")" {
                return None;
            }
            // A bare `MACRO(args) { ... }` is a block-bodied macro
            // invocation, not a C/C++ function definition. Apply this only
            // after walking constructor-initialiser entries back to the
            // actual parameter list.
            let inside_record = records
                .iter()
                .any(|record| record.token_start < name_i && name_i < record.token_end);
            if !inside_record && !has_declaration_prefix(tokens, name_i) {
                return None;
            }
            let tilde = name_i
                .checked_sub(1)
                .is_some_and(|p| tokens[p].kind == TokenKind::Punctuation && tokens[p].text == "~");
            let unit_start = if tilde { name_i - 1 } else { name_i };
            return Some(make_function(
                tokens,
                pairs,
                records,
                unit_start,
                name_i,
                name_token.text.to_string(),
                body_open,
            ));
        }

        // Operator overloads: `operator` plus symbol tokens directly before
        // the parameter list (`operator+`, `operator()`, `operator bool`).
        if tokens[close].text == ")" {
            for back in 1..=3 {
                let Some(k) = open.checked_sub(back) else {
                    break;
                };
                if tokens[k].kind == TokenKind::Keyword && tokens[k].text == "operator" {
                    return Some(make_function(
                        tokens,
                        pairs,
                        records,
                        k,
                        k,
                        "operator".to_string(),
                        body_open,
                    ));
                }
            }
        }
        return None;
    }
    None
}

/// Whether tokens before a candidate name can introduce a function declarator.
///
/// This deliberately only rejects the unqualified, bare identifier form. It
/// keeps user-defined return types, pointer/reference declarators, qualified
/// C++ names and destructors available to the conservative boundary finder.
fn has_declaration_prefix(tokens: &[Token], name_i: usize) -> bool {
    name_i.checked_sub(1).is_some_and(|previous| {
        let token = &tokens[previous];
        matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword)
            || (token.kind == TokenKind::Punctuation
                && matches!(token.text.as_str(), "*" | "&" | "&&" | "::" | "~"))
    })
}

fn make_function(
    tokens: &[Token],
    pairs: &DelimPairs,
    records: &[Unit],
    unit_start: usize,
    name_i: usize,
    name: String,
    body_open: usize,
) -> Result<Unit, SourceSpan> {
    let end = group_close(pairs, body_open).ok_or_else(|| {
        // Do not turn a malformed body into a function that extends to EOF.
        // The caller records this at the Fast frontend's ordinary diagnostic
        // boundary, where scan summaries already count recovery events.
        span_of(tokens, body_open, body_open)
    })?;
    let inside_record = records
        .iter()
        .any(|r| r.token_start < name_i && name_i < r.token_end);
    let kind = if inside_record {
        UnitKind::Method
    } else {
        UnitKind::Function
    };
    Ok(Unit {
        kind,
        name: Some(name),
        token_start: unit_start,
        token_end: end + 1,
        span: span_of(tokens, unit_start, end),
    })
}

/// Try to recognise the `[` at `i` as the start of a block-bodied lambda.
///
/// Two shapes look like a capture list without being one. An attribute
/// specifier opens with a second `[`, which a capture list never does, and is
/// followed by whatever it decorates — left alone, `[[nodiscard]] int f() {}`
/// reads as a lambda whose body is the function's. The other is a declarator
/// that follows the capture list: a name and its parameter list are not
/// trailer material, so the search for the body brace stops there rather than
/// swallowing the declaration behind the brackets.
fn lambda_unit(tokens: &[Token], pairs: &DelimPairs, i: usize) -> Option<Unit> {
    if tokens
        .get(i + 1)
        .is_some_and(|next| next.kind == TokenKind::Punctuation && next.text == "[")
    {
        return None;
    }
    if let Some(prev) = i.checked_sub(1).map(|p| &tokens[p]) {
        let allowed = match prev.kind {
            TokenKind::Punctuation => LAMBDA_PRECEDER_PUNCT.contains(&prev.text.as_str()),
            TokenKind::Keyword => LAMBDA_PRECEDER_KEYWORDS.contains(&prev.text.as_str()),
            _ => false,
        };
        if !allowed {
            return None;
        }
    }
    let capture_close = group_close(pairs, i)?;

    // Optional parameter list.
    let mut k = capture_close + 1;
    if tokens.get(k).is_some_and(|t| t.text == "(") {
        k = group_close(pairs, k)? + 1;
    }

    // Forward trailer: specifiers and a trailing return type, then the body.
    for _ in 0..32 {
        let token = tokens.get(k)?;
        match token.kind {
            TokenKind::Punctuation if token.text == "{" => {
                let close = group_close(pairs, k)?;
                return Some(Unit {
                    kind: UnitKind::Closure,
                    name: None,
                    token_start: i,
                    token_end: close + 1,
                    span: span_of(tokens, i, close),
                });
            }
            TokenKind::Punctuation if declarator::is_trailer_punct(&token.text) => k += 1,
            TokenKind::Punctuation if token.text == "(" => {
                // `noexcept(...)` or a parenthesised return-type part.
                k = group_close(pairs, k)? + 1;
            }
            // A name followed by a parameter list is a function declarator,
            // not trailer material: the brackets before it decorate a
            // declaration and open no lambda.
            TokenKind::Identifier => {
                if tokens
                    .get(k + 1)
                    .is_some_and(|next| next.kind == TokenKind::Punctuation && next.text == "(")
                {
                    return None;
                }
                k += 1;
            }
            TokenKind::Keyword if declarator::is_lambda_trailer_keyword(&token.text) => k += 1,
            _ => return None,
        }
    }
    None
}

/// Build a reporting span covering the inclusive token range `[start, end]`.
const fn span_of(tokens: &[Token], start: usize, end: usize) -> SourceSpan {
    let first = tokens[start].span;
    let last = tokens[end].span;
    SourceSpan {
        start_byte: first.start_byte,
        end_byte: last.end_byte,
        start_line: first.start_line,
        start_column: first.start_column,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::declarator::MAX_DECLARATION_LOOKAHEAD;
    use crate::dialect;
    use crate::lexer::lex;

    fn units_of(source: &str) -> Vec<Unit> {
        detect(&lex(source, &dialect::C).0, &dialect::C).0
    }

    #[test]
    fn detects_a_free_function() {
        let units = units_of("int add(int a, int b) { return a + b; }");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("add"));
    }

    #[test]
    fn prototypes_are_not_units() {
        assert!(units_of("int add(int a, int b);").is_empty());
        assert!(units_of("extern void log_msg(const char *fmt, ...);").is_empty());
    }

    #[test]
    fn control_flow_braces_are_not_functions() {
        let src = "void f(int n) { if (n) { g(); } while (n--) { h(); } \
                   for (;;) { break; } switch (n) { default: break; } do { i(); } while (0); }";
        let units = units_of(src);
        assert_eq!(units.len(), 1, "only `f` itself: {units:#?}");
        assert_eq!(units[0].name.as_deref(), Some("f"));
    }

    #[test]
    fn pointer_returning_and_static_functions_are_detected() {
        let units = units_of("static const char *dup(const char *s) { return s; }");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("dup"));
    }

    #[test]
    fn struct_definitions_are_records_but_declarators_are_not() {
        let units = units_of("struct point { int x; int y; };");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Record);
        assert_eq!(units[0].name.as_deref(), Some("point"));

        // `struct` in a return type must not produce a record unit.
        let units = units_of("struct point *make(void) { return 0; }");
        assert_eq!(units.len(), 1, "{units:#?}");
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("make"));
    }

    #[test]
    fn an_attribute_specifier_between_the_keyword_and_the_body_keeps_the_record() {
        for source in [
            "struct __attribute__((packed)) S { int a; int b; };",
            "struct __declspec(align(8)) S { int a; int b; };",
            "struct S __attribute__((packed)) { int a; int b; };",
        ] {
            let units = units_of(source);
            assert_eq!(units.len(), 1, "{source}: {units:#?}");
            assert_eq!(units[0].kind, UnitKind::Record, "{source}");
            assert_eq!(units[0].name.as_deref(), Some("S"), "{source}");
        }
    }

    #[test]
    fn anonymous_typedef_struct_is_a_record_without_a_name() {
        let units = units_of("typedef struct { int a; } pair;");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Record);
        // The first identifier before the brace names the record; an
        // anonymous struct has none.
        assert_eq!(units[0].name, None);
    }

    #[test]
    fn function_like_macro_bodies_do_not_produce_units() {
        // The whole definition is a directive, dropped before unit detection.
        let units = units_of("#define ADD(a, b) ((a) + (b))\n");
        assert!(units.is_empty());
    }

    #[test]
    fn block_bodied_macro_invocations_are_not_function_units() {
        for invocation in [
            "TEST_F(QueueTest, Pushes) { ASSERT_TRUE(1); }",
            "list_for_each(node, head) { visit(node); }",
            "TAILQ_FOREACH(entry, queue, links) { consume(entry); }",
        ] {
            assert!(units_of(invocation).is_empty(), "{invocation}");
        }
    }

    #[test]
    fn initializer_braces_are_not_functions() {
        assert!(units_of("int a[] = {1, 2, 3};").is_empty());
        assert!(
            units_of("struct p q = {1, 2};")
                .iter()
                .all(|u| u.kind != UnitKind::Function)
        );
    }

    #[test]
    fn a_units_token_range_covers_its_body() {
        let src = "int f(void) { return 1; }";
        let tokens = lex(src, &dialect::C).0;
        let (units, diagnostics) = detect(&tokens, &dialect::C);
        assert!(diagnostics.is_empty());
        let f = &units[0];
        assert_eq!(tokens[f.token_end - 1].text, "}");
        assert_eq!(tokens[f.token_start].text, "f");
    }

    #[test]
    fn record_declaration_lookahead_is_bounded() {
        let source = format!(
            "struct {} {{ int value; }};",
            "field ".repeat(MAX_DECLARATION_LOOKAHEAD)
        );
        let tokens = lex(&source, &dialect::C).0;
        let pairs = delim_pairs(&tokens);
        assert!(declarator::record_header(&tokens, &pairs, 1).is_none());
    }

    #[test]
    fn an_unclosed_function_body_is_not_stretched_to_end_of_file() {
        let tokens = lex("int tail(void) { int value = 1;", &dialect::C).0;
        let (units, diagnostics) = detect(&tokens, &dialect::C);

        assert!(units.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, DiagnosticKind::UnmatchedDelimiter);
    }
}
