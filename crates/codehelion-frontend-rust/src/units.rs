//! Coarse unit-boundary detection over a Rust token stream.
//!
//! Boundaries are the clone-report anchors: functions, methods, `impl` blocks
//! and block-bodied closures. Detection is a brace-matching heuristic over
//! tokens, not a parse; in Fast mode no syntax tree is built. The heuristic is
//! deliberately conservative for closures (which a lexer cannot tell apart from
//! bitwise-or with certainty) so that a spurious anchor is preferred against
//! rather than invented.

use std::collections::HashMap;

use codehelion_core::frontend::{SourceSpan, Token, TokenKind, Unit, UnitKind};

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

/// Detect unit boundaries in `tokens`, in source order.
///
/// Crate-internal: the public entry point is
/// [`RustFrontend`](crate::RustFrontend).
#[must_use]
#[allow(clippy::redundant_pub_crate)] // crate-internal API reached from the crate root
pub(crate) fn detect(tokens: &[Token]) -> Vec<Unit> {
    let braces = match_braces(tokens);
    let impl_bodies = impl_body_ranges(tokens, &braces);

    let mut units = Vec::new();
    let mut closure_bars = std::collections::HashSet::new();

    for i in 0..tokens.len() {
        let token = &tokens[i];
        match token.kind {
            TokenKind::Keyword if token.text == "impl" => {
                if let Some(unit) = impl_unit(tokens, &braces, i) {
                    units.push(unit);
                }
            }
            TokenKind::Keyword if token.text == "fn" => {
                if let Some(unit) = fn_unit(tokens, &braces, &impl_bodies, i) {
                    units.push(unit);
                }
            }
            _ => {
                if let Some(unit) = closure_unit(tokens, &braces, i, &mut closure_bars) {
                    units.push(unit);
                }
            }
        }
    }

    units.sort_by_key(|u| u.token_start);
    units
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
        if token.kind == TokenKind::Keyword && token.text == "impl" {
            if let Some(open) = first_brace_after(tokens, i) {
                if let Some(&close) = braces.get(&open) {
                    ranges.push((open, close));
                }
            }
        }
    }
    ranges
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

fn impl_unit(tokens: &[Token], braces: &HashMap<usize, usize>, i: usize) -> Option<Unit> {
    let open = first_brace_after(tokens, i)?;
    let close = *braces.get(&open)?;
    let name = tokens[i + 1..open]
        .iter()
        .find(|t| t.kind == TokenKind::Identifier)
        .map(|t| t.text.to_string());
    Some(Unit {
        kind: UnitKind::Impl,
        name,
        token_start: i,
        token_end: close + 1,
        span: span_of(tokens, i, close),
    })
}

fn fn_unit(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    impl_bodies: &[(usize, usize)],
    i: usize,
) -> Option<Unit> {
    let open = first_brace_after(tokens, i)?;
    let close = *braces.get(&open)?;
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
    Some(Unit {
        kind,
        name,
        token_start: i,
        token_end: close + 1,
        span: span_of(tokens, i, close),
    })
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
        detect(&lex(source).0)
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
}
