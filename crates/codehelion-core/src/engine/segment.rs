//! Token segmentation and candidate-fragment extraction.
//!
//! Segments are the barriers for k-gram formation and match extension: a
//! matched run never crosses a function boundary, because unbounded extension
//! fuses adjacent functions into one giant run and destroys per-function
//! attribution. Fragments are the pre-cut candidate slices that the normalized
//! (Type-2) pass matches whole: function bodies, loop bodies, branch bodies
//! and short statement runs.

#![allow(clippy::redundant_pub_crate)] // internal helpers reached from the engine root

use std::collections::{BTreeSet, HashMap};

use crate::frontend::{Token, TokenKind, Unit, UnitKind};

/// Segment id assigned to every token of one file.
pub(crate) type SegmentId = u32;

/// Map each `{` token index to its matching `}` token index.
pub(crate) fn brace_pairs(tokens: &[Token]) -> HashMap<usize, usize> {
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

/// Assign every token a segment id.
///
/// Functions and methods each get their own segment (painted innermost-last,
/// so a nested function is its own segment). Tokens outside every function
/// get a per-gap segment keyed by how many functions started before them, so
/// two top-level regions separated by a function never share a segment.
/// Closures deliberately inherit their containing function's segment: they are
/// part of its flow, and splitting on them would break up legitimate
/// whole-function matches.
pub(crate) fn segment_ids(tokens: &[Token], units: &[Unit]) -> Vec<SegmentId> {
    let functions: Vec<&Unit> = units
        .iter()
        .filter(|u| matches!(u.kind, UnitKind::Function | UnitKind::Method))
        .collect();

    // Gap ids: partition by the number of function starts at or before i.
    let starts: Vec<usize> = functions.iter().map(|u| u.token_start).collect();
    let gap_count = u32::try_from(starts.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let mut seg: Vec<SegmentId> = (0..tokens.len())
        .map(|i| {
            let gaps_before = starts.partition_point(|&s| s <= i);
            u32::try_from(gaps_before).unwrap_or(u32::MAX)
        })
        .collect();

    // Paint function ranges, larger spans first so nested functions win.
    let mut order: Vec<(usize, usize)> = functions
        .iter()
        .enumerate()
        .map(|(idx, u)| (u.token_end - u.token_start, idx))
        .collect();
    order.sort_by_key(|&(len, idx)| (std::cmp::Reverse(len), idx));
    for (_, idx) in order {
        let unit = functions[idx];
        let id = gap_count + u32::try_from(idx).unwrap_or(u32::MAX);
        for s in seg
            .iter_mut()
            .take(unit.token_end.min(tokens.len()))
            .skip(unit.token_start)
        {
            *s = id;
        }
    }
    seg
}

/// For every token, the index (into `units`) of its innermost enclosing unit.
///
/// This is the clone-report anchor: a partial match is reported as a range
/// inside its nearest enclosing function, method, impl block or closure.
pub(crate) fn anchor_ids(tokens: &[Token], units: &[Unit]) -> Vec<Option<usize>> {
    let mut anchor: Vec<Option<usize>> = vec![None; tokens.len()];
    let mut order: Vec<(usize, usize)> = units
        .iter()
        .enumerate()
        .map(|(idx, u)| (u.token_end - u.token_start, idx))
        .collect();
    order.sort_by_key(|&(len, idx)| (std::cmp::Reverse(len), idx));
    for (_, idx) in order {
        let unit = &units[idx];
        for a in anchor
            .iter_mut()
            .take(unit.token_end.min(tokens.len()))
            .skip(unit.token_start)
        {
            *a = Some(idx);
        }
    }
    anchor
}

/// The syntactic shape a candidate fragment was cut from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FragmentKind {
    /// The body of a function, method or closure.
    Body,
    /// The body of a `for`, `while`, `loop` or `do` loop.
    Loop,
    /// The body of an `if`/`else` branch, a `match`/`switch` body or a `=>`
    /// block arm.
    Branch,
    /// A run of consecutive statements inside a body.
    StmtRun,
}

/// A candidate fragment: a half-open token range within one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fragment {
    pub kind: FragmentKind,
    pub start: usize,
    pub end: usize,
}

/// Extract the candidate fragments of one file.
///
/// Only fragments of at least `min_tokens` tokens are kept. Statement runs of
/// `1..=max_stmt_window` consecutive statements are cut inside every body,
/// which is what recovers a renamed statement run transplanted into an
/// unrelated host function. Identical ranges cut by different rules are
/// emitted once.
pub(crate) fn fragments(
    tokens: &[Token],
    units: &[Unit],
    braces: &HashMap<usize, usize>,
    min_tokens: usize,
    max_stmt_window: usize,
) -> Vec<Fragment> {
    let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut out: Vec<Fragment> = Vec::new();
    // Every block body found below, whatever its kind; statement runs are cut
    // inside each of them, so a transplanted run is recovered wherever it
    // landed (directly in a function, inside a loop, inside a branch).
    let mut bodies: Vec<(usize, usize)> = Vec::new();
    let mut push = |kind: FragmentKind, start: usize, end: usize| {
        if end > start && end - start >= min_tokens && seen.insert((start, end)) {
            out.push(Fragment { kind, start, end });
        }
    };

    // Bodies of functions, methods and closures.
    for unit in units {
        if matches!(
            unit.kind,
            UnitKind::Function | UnitKind::Method | UnitKind::Closure
        ) {
            if let Some((open, close)) = body_braces(tokens, braces, unit) {
                bodies.push((open + 1, close));
                push(FragmentKind::Body, open + 1, close);
            }
        }
    }

    // Loop and branch bodies, found by keyword scan. The keyword texts span
    // every supported language; a frontend only emits its own language's
    // keywords, so `loop`/`match` never fire on C/C++ input nor `do`/`switch`
    // on Rust. Header braces are not a concern in Rust (bare struct literals
    // are forbidden in `if`/`while`/`for` headers) and rare in C/C++ (a
    // compound literal or lambda in the header cuts a small spurious fragment,
    // which the minimum-size gate then usually drops).
    for (i, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Keyword
                if matches!(token.text.as_str(), "for" | "while" | "loop" | "do") =>
            {
                if let Some((open, close)) = block_after(tokens, braces, i) {
                    bodies.push((open + 1, close));
                    push(FragmentKind::Loop, open + 1, close);
                }
            }
            TokenKind::Keyword if matches!(token.text.as_str(), "if" | "match" | "switch") => {
                if let Some((open, close)) = block_after(tokens, braces, i) {
                    bodies.push((open + 1, close));
                    push(FragmentKind::Branch, open + 1, close);
                }
            }
            // `else {` only; `else if` is handled by the `if`.
            TokenKind::Keyword
                if token.text == "else" && tokens.get(i + 1).is_some_and(|t| t.text == "{") =>
            {
                if let Some((open, close)) = block_after(tokens, braces, i) {
                    bodies.push((open + 1, close));
                    push(FragmentKind::Branch, open + 1, close);
                }
            }
            // A block-bodied match arm.
            TokenKind::Punctuation
                if token.text == "=>" && tokens.get(i + 1).is_some_and(|t| t.text == "{") =>
            {
                if let Some(&close) = braces.get(&(i + 1)) {
                    bodies.push((i + 2, close));
                    push(FragmentKind::Branch, i + 2, close);
                }
            }
            _ => {}
        }
    }

    // Statement runs inside every body.
    for (start, end) in bodies {
        let stmts = statements(tokens, start, end);
        for w in 1..=max_stmt_window {
            if w > stmts.len() {
                break;
            }
            for s in 0..=(stmts.len() - w) {
                push(FragmentKind::StmtRun, stmts[s].0, stmts[s + w - 1].1);
            }
        }
    }

    out.sort_by_key(|f| (f.start, f.end));
    out
}

/// The `{`/`}` token indices delimiting a unit's body.
fn body_braces(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    unit: &Unit,
) -> Option<(usize, usize)> {
    let open = (unit.token_start..unit.token_end.min(tokens.len()))
        .find(|&i| tokens[i].kind == TokenKind::Punctuation && tokens[i].text == "{")?;
    let close = *braces.get(&open)?;
    (close < unit.token_end).then_some((open, close))
}

/// The `{`/`}` indices of the first block after position `i`, stopping at a
/// top-level `;`. Semicolons in a C/C++ `for` header are not statement ends.
fn block_after(
    tokens: &[Token],
    braces: &HashMap<usize, usize>,
    i: usize,
) -> Option<(usize, usize)> {
    let mut paren_depth = 0usize;
    for (offset, token) in tokens[i..].iter().enumerate() {
        if token.kind == TokenKind::Punctuation {
            match token.text.as_str() {
                "(" => paren_depth += 1,
                ")" => paren_depth = paren_depth.saturating_sub(1),
                "{" if paren_depth == 0 => {
                    let open = i + offset;
                    let close = *braces.get(&open)?;
                    return Some((open, close));
                }
                ";" if paren_depth == 0 => return None,
                _ => {}
            }
        }
    }
    None
}

/// Split the body range `[start, end)` into statement spans.
///
/// A statement ends after a `;` at the body's own brace depth, or after a `}`
/// that returns to it (a block expression used as a statement). This is a
/// lexical heuristic; it is deliberately simple and errs toward larger spans.
fn statements(tokens: &[Token], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut depth: i32 = 0;
    let mut stmt_start = start;
    for (i, token) in tokens
        .iter()
        .enumerate()
        .take(end.min(tokens.len()))
        .skip(start)
    {
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    spans.push((stmt_start, i + 1));
                    stmt_start = i + 1;
                }
            }
            ";" if depth == 0 => {
                spans.push((stmt_start, i + 1));
                stmt_start = i + 1;
            }
            _ => {}
        }
    }
    if stmt_start < end {
        spans.push((stmt_start, end));
    }
    spans
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::frontend::SourceSpan;

    fn tok(kind: TokenKind, text: &str) -> Token {
        Token {
            kind,
            text: text.into(),
            span: SourceSpan {
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_column: 1,
            },
        }
    }

    /// Tokenize a tiny pseudo-source by whitespace splitting; words starting
    /// with a letter are identifiers, known keywords are keywords.
    fn quick(src: &str) -> Vec<Token> {
        src.split_whitespace()
            .map(|w| match w {
                "fn" | "let" | "for" | "while" | "loop" | "if" | "else" | "match" | "in" => {
                    tok(TokenKind::Keyword, w)
                }
                _ if w
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_') =>
                {
                    tok(TokenKind::Identifier, w)
                }
                _ => tok(TokenKind::Punctuation, w),
            })
            .collect()
    }

    fn unit(kind: UnitKind, token_start: usize, token_end: usize) -> Unit {
        Unit {
            kind,
            name: None,
            token_start,
            token_end,
            span: SourceSpan {
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_column: 1,
            },
        }
    }

    #[test]
    fn segments_separate_adjacent_functions() {
        // fn a ( ) { x } fn b ( ) { y }
        let tokens = quick("fn a ( ) { x } fn b ( ) { y }");
        let units = vec![
            unit(UnitKind::Function, 0, 7),
            unit(UnitKind::Function, 7, 14),
        ];
        let seg = segment_ids(&tokens, &units);
        assert_eq!(seg[0], seg[6], "first fn is one segment");
        assert_eq!(seg[7], seg[13], "second fn is one segment");
        assert_ne!(seg[6], seg[7], "adjacent fns must not share a segment");
    }

    #[test]
    fn closures_inherit_their_functions_segment() {
        // fn a ( ) { | x | { x } }
        let tokens = quick("fn a ( ) { | x | { x } }");
        let units = vec![
            unit(UnitKind::Function, 0, 12),
            unit(UnitKind::Closure, 5, 11),
        ];
        let seg = segment_ids(&tokens, &units);
        assert!(seg.iter().skip(1).all(|&s| s == seg[0]));
    }

    #[test]
    fn anchors_prefer_the_innermost_unit() {
        let tokens = quick("fn a ( ) { | x | { x } }");
        let units = vec![
            unit(UnitKind::Function, 0, 12),
            unit(UnitKind::Closure, 5, 11),
        ];
        let anchor = anchor_ids(&tokens, &units);
        assert_eq!(anchor[1], Some(0), "fn name anchors to the function");
        assert_eq!(anchor[6], Some(1), "closure body anchors to the closure");
    }

    #[test]
    fn statement_runs_are_windowed() {
        // { a ; b ; c ; }  -> stmts [a;][b;][c;]
        let tokens = quick("{ a ; b ; c ; }");
        let stmts = statements(&tokens, 1, 7);
        assert_eq!(stmts, vec![(1, 3), (3, 5), (5, 7)]);
    }

    #[test]
    fn block_statement_counts_as_one_statement() {
        // { if p { q } r ; }
        let tokens = quick("{ if p { q } r ; }");
        let stmts = statements(&tokens, 1, 8);
        assert_eq!(stmts, vec![(1, 6), (6, 8)]);
    }

    #[test]
    fn fragments_include_bodies_loops_and_branches() {
        // fn f ( ) { for x in y { a ; b ; } }
        let tokens = quick("fn f ( ) { for x in y { a ; b ; } }");
        let units = vec![unit(UnitKind::Function, 0, tokens.len())];
        let braces = brace_pairs(&tokens);
        let frags = fragments(&tokens, &units, &braces, 2, 8);
        assert!(frags.iter().any(|f| f.kind == FragmentKind::Body));
        assert!(frags.iter().any(|f| f.kind == FragmentKind::Loop));
        assert!(frags.iter().any(|f| f.kind == FragmentKind::StmtRun));
    }

    #[test]
    fn c_for_header_semicolons_do_not_hide_the_loop_body() {
        // fn f ( ) { for ( int i = 0 ; i < n ; i ++ ) { a ; b ; } }
        let tokens = quick("fn f ( ) { for ( int i = 0 ; i < n ; i ++ ) { a ; b ; } }");
        let units = vec![unit(UnitKind::Function, 0, tokens.len())];
        let braces = brace_pairs(&tokens);
        let frags = fragments(&tokens, &units, &braces, 2, 8);

        assert!(
            frags
                .iter()
                .any(|fragment| fragment.kind == FragmentKind::Loop),
            "the C for body must become a loop fragment"
        );
    }

    #[test]
    fn short_fragments_are_dropped_and_ranges_deduplicated() {
        let tokens = quick("fn f ( ) { a ; }");
        let units = vec![unit(UnitKind::Function, 0, tokens.len())];
        let braces = brace_pairs(&tokens);
        // min_tokens larger than everything -> nothing.
        assert!(fragments(&tokens, &units, &braces, 50, 8).is_empty());
        // The whole body and the 1-statement window are the same range: once.
        let frags = fragments(&tokens, &units, &braces, 1, 8);
        let ranges: Vec<(usize, usize)> = frags.iter().map(|f| (f.start, f.end)).collect();
        let mut dedup = ranges.clone();
        dedup.dedup();
        assert_eq!(ranges, dedup);
    }
}
