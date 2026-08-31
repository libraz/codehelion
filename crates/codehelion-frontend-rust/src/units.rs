//! Coarse unit-boundary detection over a Rust token stream.
//!
//! Boundaries are the clone-report anchors: functions, methods, `impl` blocks
//! and block-bodied closures. Detection is a brace-matching heuristic over
//! tokens, not a parse; in Fast mode no syntax tree is built. The heuristic is
//! deliberately conservative for closures (which a lexer cannot tell apart from
//! bitwise-or with certainty) so that a spurious anchor is preferred against
//! rather than invented. A body whose brace never closes yields no unit and a
//! recovery diagnostic, so a file dropping out of unit analysis is visible in
//! scan reports rather than silent.

use std::collections::HashMap;

use codehelion_core::frontend::{
    Diagnostic, DiagnosticKind, SourceSpan, Token, TokenKind, Unit, UnitKind,
};

/// Punctuation after which `impl` names an anonymous type rather than opening
/// an item: `-> impl Trait`, `&impl Trait`, `Vec<impl Trait>`, `(impl A, B)`,
/// `x: impl Trait`.
const TYPE_POSITION_PUNCT: &[&str] = &["->", "&", "&&", "<", ",", "(", ":"];

/// Keywords after which `impl` names an anonymous type: `dyn`, `as`.
const TYPE_POSITION_KEYWORDS: &[&str] = &["dyn", "as"];

/// Tokens that may immediately precede a closure's first `|`.
const CLOSURE_PRECEDERS: &[&str] = &[
    "=", "(", "{", "[", ",", ";", "=>", "return", "&&", "||", "!", ":",
];

/// Punctuation allowed between a closure's bars (parameter patterns).
const CLOSURE_PARAM_PUNCT: &[&str] = &[",", ":", "&", "<", ">", "(", ")", "::", "_"];

/// Maximum tokens one declaration lookahead may inspect before declining an
/// uncertain unit boundary. This prevents a malformed run of declaration-like
/// tokens from turning every `fn`/`impl` marker into a full-file scan.
const MAX_DECLARATION_LOOKAHEAD: usize = 256;

/// Detect unit boundaries and recoverable boundary errors in `tokens`, in
/// source order.
///
/// Crate-internal: the public entry point is
/// [`RustFrontend`](crate::RustFrontend).
#[must_use]
#[allow(clippy::redundant_pub_crate)] // crate-internal API reached from the crate root
pub(crate) fn detect(tokens: &[Token]) -> (Vec<Unit>, Vec<Diagnostic>) {
    let braces = match_braces(tokens);
    let impl_bodies = impl_body_ranges(tokens, &braces);

    let mut units = Vec::new();
    let mut diagnostics = Vec::new();
    let mut closure_bars = std::collections::HashSet::new();

    for i in 0..tokens.len() {
        let token = &tokens[i];
        match token.kind {
            TokenKind::Keyword if token.text == "impl" => {
                record(impl_unit(tokens, &braces, i), &mut units, &mut diagnostics);
            }
            TokenKind::Keyword if token.text == "fn" => {
                record(
                    fn_unit(tokens, &braces, &impl_bodies, i),
                    &mut units,
                    &mut diagnostics,
                );
            }
            _ => {
                if let Some(unit) = closure_unit(tokens, &braces, i, &mut closure_bars) {
                    units.push(unit);
                }
            }
        }
    }

    units.sort_by_key(|u| u.token_start);
    (units, diagnostics)
}

/// Route one boundary attempt: a unit, a recovery event, or neither.
fn record(
    outcome: Option<Result<Unit, SourceSpan>>,
    units: &mut Vec<Unit>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match outcome {
        Some(Ok(unit)) => units.push(unit),
        Some(Err(span)) => diagnostics.push(Diagnostic {
            kind: DiagnosticKind::UnmatchedDelimiter,
            span,
        }),
        None => {}
    }
}

/// Map each `{` token index to its matching `}` token index.
fn match_braces(tokens: &[Token]) -> HashMap<usize, usize> {
    let mut pairs = HashMap::new();
    let mut stack = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Punctuation {
            if token.text == "{" {
                stack.push(i);
            } else if token.text == "}" {
                if let Some(open) = stack.pop() {
                    pairs.insert(open, i);
                }
            }
        }
    }
    pairs
}

/// The `(open_brace, close_brace)` token ranges of every `impl` block body.
fn impl_body_ranges(tokens: &[Token], braces: &HashMap<usize, usize>) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Keyword && token.text == "impl" && opens_impl_item(tokens, i) {
            if let Some(open) = first_brace_after(tokens, i) {
                if let Some(&close) = braces.get(&open) {
                    ranges.push((open, close));
                }
            }
        }
    }
    ranges
}

/// Whether the `impl` keyword at `i` opens an `impl` item.
///
/// In type position the keyword names an anonymous type implementing a trait
/// (`-> impl Iterator<Item = u8>`, `x: &impl Display`), and the next brace
/// belongs to the enclosing declaration. Anchoring an `impl` unit there would
/// take a function's body away from the function's own name and report its
/// clones under the trait's.
fn opens_impl_item(tokens: &[Token], i: usize) -> bool {
    let Some(previous) = i.checked_sub(1).map(|p| &tokens[p]) else {
        return true;
    };
    match previous.kind {
        TokenKind::Punctuation => !TYPE_POSITION_PUNCT.contains(&previous.text.as_str()),
        TokenKind::Keyword => !TYPE_POSITION_KEYWORDS.contains(&previous.text.as_str()),
        _ => true,
    }
}

/// Index of the first declaration-body `{` at or after `from`, stopping at a
/// top-level `;` (which means the construct has no block body).
fn first_brace_after(tokens: &[Token], from: usize) -> Option<usize> {
    let mut brackets = 0usize;
    for (offset, token) in tokens[from..]
        .iter()
        .take(MAX_DECLARATION_LOOKAHEAD)
        .enumerate()
    {
        if token.kind == TokenKind::Punctuation {
            if token.text == "[" {
                brackets = brackets.saturating_add(1);
            } else if token.text == "]" {
                brackets = brackets.saturating_sub(1);
            } else if token.text == "{" && brackets == 0 {
                return Some(from + offset);
            }
            if token.text == ";" && brackets == 0 {
                return None;
            }
        }
    }
    None
}

fn impl_unit(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    i: usize,
) -> Option<Result<Unit, SourceSpan>> {
    if !opens_impl_item(tokens, i) {
        return None;
    }
    let open = first_brace_after(tokens, i)?;
    // Do not turn a body that never closes into a unit reaching EOF. The
    // caller records the recovery event as a lexical diagnostic.
    let Some(&close) = braces.get(&open) else {
        return Some(Err(span_of(tokens, open, open)));
    };
    let name = tokens[i + 1..open]
        .iter()
        .find(|t| t.kind == TokenKind::Identifier)
        .map(|t| t.text.to_string());
    Some(Ok(Unit {
        kind: UnitKind::Impl,
        name,
        token_start: i,
        token_end: close + 1,
        span: span_of(tokens, i, close),
    }))
}

fn fn_unit(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    impl_bodies: &[(usize, usize)],
    i: usize,
) -> Option<Result<Unit, SourceSpan>> {
    let open = first_brace_after(tokens, i)?;
    let Some(&close) = braces.get(&open) else {
        return Some(Err(span_of(tokens, open, open)));
    };
    let name = tokens
        .get(i + 1)
        .filter(|t| t.kind == TokenKind::Identifier)
        .map(|t| t.text.to_string());
    let inside_impl = impl_bodies
        .iter()
        .any(|&(body_open, body_close)| body_open < i && i < body_close);
    let kind = if inside_impl {
        UnitKind::Method
    } else {
        UnitKind::Function
    };
    Some(Ok(Unit {
        kind,
        name,
        token_start: i,
        token_end: close + 1,
        span: span_of(tokens, i, close),
    }))
}

fn closure_unit(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    i: usize,
    seen_bars: &mut std::collections::HashSet<usize>,
) -> Option<Unit> {
    // A closure begins with an optional `move`, then `|params|` or `||`.
    let (start, bar) = if tokens[i].kind == TokenKind::Keyword && tokens[i].text == "move" {
        (i, i + 1)
    } else {
        (i, i)
    };
    if seen_bars.contains(&bar) {
        return None;
    }
    let bar_token = tokens.get(bar)?;
    if bar_token.kind != TokenKind::Punctuation {
        return None;
    }
    if !in_expression_position(tokens, start) {
        return None;
    }

    let body_open = match bar_token.text.as_str() {
        "||" => bar + 1,
        "|" => {
            let close_bar = closing_bar(tokens, bar)?;
            close_bar + 1
        }
        _ => return None,
    };
    if tokens.get(body_open).map(|t| t.text.as_str()) != Some("{") {
        return None;
    }
    let close = *braces.get(&body_open)?;
    seen_bars.insert(bar);
    Some(Unit {
        kind: UnitKind::Closure,
        name: None,
        token_start: start,
        token_end: close + 1,
        span: span_of(tokens, start, close),
    })
}

/// Whether the token before `start` allows an expression (and thus a closure).
fn in_expression_position(tokens: &[Token], start: usize) -> bool {
    if start == 0 {
        return true;
    }
    let prev = &tokens[start - 1];
    match prev.kind {
        TokenKind::Punctuation | TokenKind::Keyword => {
            CLOSURE_PRECEDERS.contains(&prev.text.as_str())
        }
        _ => false,
    }
}

/// Index of the closing `|` for a closure parameter list opened at `bar`, if the
/// content in between looks like parameters.
fn closing_bar(tokens: &[Token], bar: usize) -> Option<usize> {
    // Bound the scan: parameter lists are short.
    let limit = (bar + 32).min(tokens.len());
    for (offset, token) in tokens[bar + 1..limit].iter().enumerate() {
        if token.kind == TokenKind::Punctuation && token.text == "|" {
            return Some(bar + 1 + offset);
        }
        let param_like = match token.kind {
            TokenKind::Identifier | TokenKind::Lifetime => true,
            TokenKind::Keyword => matches!(token.text.as_str(), "mut" | "ref"),
            TokenKind::Punctuation => CLOSURE_PARAM_PUNCT.contains(&token.text.as_str()),
            _ => false,
        };
        if !param_like {
            return None;
        }
    }
    None
}

/// Build a reporting span covering the inclusive token range `[start, end]`.
fn span_of(tokens: &[Token], start: usize, end: usize) -> SourceSpan {
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
    use crate::lexer::lex;

    fn units_of(source: &str) -> Vec<Unit> {
        detect(&lex(source).0).0
    }

    fn diagnostics_of(source: &str) -> Vec<Diagnostic> {
        detect(&lex(source).0).1
    }

    #[test]
    fn detects_a_free_function() {
        let units = units_of("fn add(a: i32, b: i32) -> i32 { a + b }");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("add"));
    }

    #[test]
    fn array_return_types_do_not_hide_a_function_body() {
        let units = units_of("fn digest() -> [u8; 32] { [0; 32] }");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("digest"));
    }

    #[test]
    fn methods_inside_impl_are_methods_and_the_impl_is_a_unit() {
        let src = "impl Foo { fn a(&self) {} fn b(&self) {} }";
        let units = units_of(src);
        let kinds: Vec<_> = units.iter().map(|u| u.kind).collect();
        assert!(kinds.contains(&UnitKind::Impl));
        assert_eq!(
            units.iter().filter(|u| u.kind == UnitKind::Method).count(),
            2
        );
        assert!(!kinds.contains(&UnitKind::Function));
        let impl_unit = units.iter().find(|u| u.kind == UnitKind::Impl).unwrap();
        assert_eq!(impl_unit.name.as_deref(), Some("Foo"));
    }

    #[test]
    fn trait_method_declarations_without_a_body_are_not_units() {
        let units = units_of("trait T { fn required(&self); }");
        assert!(units.iter().all(|u| u.kind != UnitKind::Method));
    }

    #[test]
    fn detects_block_bodied_closures() {
        let units = units_of("fn f() { let g = |x: i32| { x + 1 }; let h = move || { 0 }; }");
        assert_eq!(
            units.iter().filter(|u| u.kind == UnitKind::Closure).count(),
            2
        );
    }

    #[test]
    fn bitwise_or_is_not_mistaken_for_a_closure() {
        // `a | b | c` in an `if` condition must not read as a closure.
        let units = units_of("fn f(a: u8, b: u8, c: u8) { if a | b | c != 0 { let _ = 1; } }");
        assert!(units.iter().all(|u| u.kind != UnitKind::Closure));
    }

    #[test]
    fn a_unit_token_range_covers_its_braces() {
        let units = units_of("fn f() { 1 }");
        let f = &units[0];
        // token_end is exclusive and points one past the closing brace.
        assert_eq!(f.token_start, 0);
        assert!(f.token_end <= lex("fn f() { 1 }").0.len());
    }

    #[test]
    fn declaration_lookahead_is_bounded() {
        let source = format!("fn {} {{}}", "name ".repeat(MAX_DECLARATION_LOOKAHEAD));
        let tokens = lex(&source).0;
        assert_eq!(first_brace_after(&tokens, 0), None);
    }

    #[test]
    fn an_opaque_return_type_does_not_anchor_the_function_body() {
        let units = units_of("fn produce() -> impl Iterator<Item = u8> { std::iter::empty() }");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Function);
        assert_eq!(units[0].name.as_deref(), Some("produce"));
    }

    #[test]
    fn an_opaque_parameter_type_does_not_anchor_the_function_body() {
        for source in [
            "fn show(value: &impl Display) { print(value) }",
            "fn show(value: impl Display) { print(value) }",
            "fn show(value: (impl Display, impl Debug)) { print(value) }",
            "fn show(values: Vec<impl Display>) { print(values) }",
        ] {
            let units = units_of(source);
            assert!(
                units.iter().all(|u| u.kind != UnitKind::Impl),
                "an opaque parameter type became a unit in {source}"
            );
            assert_eq!(units[0].kind, UnitKind::Function);
            assert_eq!(units[0].name.as_deref(), Some("show"));
        }
    }

    #[test]
    fn a_function_nested_under_an_opaque_return_type_is_not_a_method() {
        let units = units_of("fn outer() -> impl Debug { fn helper() -> u8 { 1 } helper() }");
        let kinds: Vec<_> = units.iter().map(|u| u.kind).collect();
        assert_eq!(kinds, vec![UnitKind::Function, UnitKind::Function]);
        assert_eq!(units[0].name.as_deref(), Some("outer"));
        assert_eq!(units[1].name.as_deref(), Some("helper"));
    }

    #[test]
    fn impl_items_after_an_opaque_type_are_still_units() {
        let units = units_of("fn show(v: impl Display) { v } impl Foo { fn g(&self) {} }");
        let impl_unit = units.iter().find(|u| u.kind == UnitKind::Impl).unwrap();
        assert_eq!(impl_unit.name.as_deref(), Some("Foo"));
        assert_eq!(
            units.iter().filter(|u| u.kind == UnitKind::Method).count(),
            1
        );
    }

    #[test]
    fn an_unclosed_function_body_is_reported_and_yields_no_unit() {
        let source = "fn broken() { let x = 1;";
        assert!(units_of(source).is_empty());
        let diagnostics = diagnostics_of(source);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, DiagnosticKind::UnmatchedDelimiter);
        assert_eq!(diagnostics[0].span.start_byte, 12);
    }

    #[test]
    fn an_unclosed_impl_body_is_reported() {
        let diagnostics = diagnostics_of("impl Foo {");
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.kind == DiagnosticKind::UnmatchedDelimiter)
                .count(),
            1
        );
    }

    #[test]
    fn well_formed_boundaries_report_nothing() {
        assert!(diagnostics_of("impl Foo { fn a(&self) -> impl Debug { 1 } }").is_empty());
    }
}
