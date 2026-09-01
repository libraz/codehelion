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
            } else if token.text == "}"
                && let Some(open) = stack.pop()
            {
                pairs.insert(open, i);
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

/// A token's innermost enclosing unit, as an index into one file's `units`.
///
/// One entry exists per token of the whole corpus, so the width of this is a
/// per-token cost on every scan. The value it holds is an index into the units
/// of a single file, which the file-size ceiling keeps far inside `u32`, and
/// [`NO_ANCHOR`] stands for the tokens no unit encloses — the same four bytes
/// [`SegmentId`] uses for the other per-token table.
pub(crate) type AnchorId = u32;

/// The anchor of a token that sits inside no unit at all.
pub(crate) const NO_ANCHOR: AnchorId = AnchorId::MAX;

/// The unit an anchor names, or `None` where no unit encloses the token.
pub(crate) const fn anchored_unit(anchor: AnchorId) -> Option<usize> {
    if anchor == NO_ANCHOR {
        None
    } else {
        Some(anchor as usize)
    }
}

/// For every token, the index (into `units`) of its innermost enclosing unit.
///
/// This is the clone-report anchor: a partial match is reported as a range
/// inside its nearest enclosing function, method, impl block or closure. A file
/// holding more units than an [`AnchorId`] can name leaves the ones past that
/// unanchored rather than misattributed; the file-size ceiling puts that far
/// out of reach of real input.
pub(crate) fn anchor_ids(tokens: &[Token], units: &[Unit]) -> Vec<AnchorId> {
    let mut anchor: Vec<AnchorId> = vec![NO_ANCHOR; tokens.len()];
    let mut order: Vec<(usize, usize)> = units
        .iter()
        .enumerate()
        .map(|(idx, u)| (u.token_end - u.token_start, idx))
        .collect();
    order.sort_by_key(|&(len, idx)| (std::cmp::Reverse(len), idx));
    for (_, idx) in order {
        let unit = &units[idx];
        let id = AnchorId::try_from(idx).unwrap_or(NO_ANCHOR);
        for a in anchor
            .iter_mut()
            .take(unit.token_end.min(tokens.len()))
            .skip(unit.token_start)
        {
            *a = id;
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

/// Fragments extracted from one file and the bounded searches that gave up.
#[derive(Debug, Default)]
pub(crate) struct FragmentExtraction {
    /// Candidate fragments that survived the minimum-size gate.
    pub(crate) fragments: Vec<Fragment>,
    /// Control headers too long or malformed to locate a block safely.
    pub(crate) control_headers_over_limit: usize,
    /// Blocks left uncut because they nest deeper than the extraction limit.
    pub(crate) bodies_over_nesting_limit: usize,
}

/// Most real control headers are a few tokens. A fixed limit prevents a
/// malformed file full of keywords from making extraction quadratic.
const MAX_CONTROL_HEADER_TOKENS: usize = 256;

/// Blocks nested deeper than this are not cut into fragments.
///
/// Every enclosing block covers the tokens of the blocks inside it, so cutting
/// each level of a nesting chain costs, and emits, the file over again per
/// level: a chain of thousands of blocks is quadratic in its own depth. Real
/// code nests a couple of dozen levels at most, so the depth is capped and the
/// total cut volume stays a linear multiple of the file.
const MAX_BODY_NESTING_DEPTH: u32 = 64;

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
) -> FragmentExtraction {
    let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut out: Vec<Fragment> = Vec::new();
    // Every block found below, whatever its kind, keyed by its `{`. Statement
    // runs are cut inside each of them, so a transplanted run is recovered
    // wherever it landed (directly in a function, inside a loop, inside a
    // branch).
    let mut blocks: Vec<(FragmentKind, usize, usize)> = Vec::new();
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
        ) && let Some((open, close)) = body_braces(tokens, braces, unit)
        {
            blocks.push((FragmentKind::Body, open, close));
        }
    }

    // Loop and branch bodies, found by keyword scan. The keyword texts span
    // every supported language; a frontend only emits its own language's
    // keywords, so `loop`/`match` never fire on C/C++ input nor `do`/`switch`
    // on Rust. Header braces are not a concern in Rust (bare struct literals
    // are forbidden in `if`/`while`/`for` headers) and rare in C/C++ (a
    // compound literal or lambda in the header cuts a small spurious fragment,
    // which the minimum-size gate then usually drops).
    let mut control_headers_over_limit = 0;
    for (i, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Keyword
                if matches!(token.text.as_str(), "for" | "while" | "loop" | "do") =>
            {
                match block_after(tokens, braces, i) {
                    BlockAfter::Found(open, close) => {
                        blocks.push((FragmentKind::Loop, open, close));
                    }
                    BlockAfter::Limit => control_headers_over_limit += 1,
                    BlockAfter::None => {}
                }
            }
            TokenKind::Keyword if matches!(token.text.as_str(), "if" | "match" | "switch") => {
                match block_after(tokens, braces, i) {
                    BlockAfter::Found(open, close) => {
                        blocks.push((FragmentKind::Branch, open, close));
                    }
                    BlockAfter::Limit => control_headers_over_limit += 1,
                    BlockAfter::None => {}
                }
            }
            // `else {` only; `else if` is handled by the `if`.
            TokenKind::Keyword
                if token.text == "else" && tokens.get(i + 1).is_some_and(|t| t.text == "{") =>
            {
                match block_after(tokens, braces, i) {
                    BlockAfter::Found(open, close) => {
                        blocks.push((FragmentKind::Branch, open, close));
                    }
                    BlockAfter::Limit => control_headers_over_limit += 1,
                    BlockAfter::None => {}
                }
            }
            // A block-bodied match arm.
            TokenKind::Punctuation
                if token.text == "=>" && tokens.get(i + 1).is_some_and(|t| t.text == "{") =>
            {
                if let Some(&close) = braces.get(&(i + 1)) {
                    blocks.push((FragmentKind::Branch, i + 1, close));
                }
            }
            _ => {}
        }
    }

    // Several rules reach the same block: a closure whose body is an `if`, or
    // a run of control keywords sharing one header. Cutting a range twice
    // cannot add a fragment, so each block is cut once, which also keeps the
    // work per block from multiplying by the number of rules that found it.
    let depths = brace_depths(tokens);
    let mut cut_blocks: BTreeSet<usize> = BTreeSet::new();
    let mut bodies: Vec<(usize, usize)> = Vec::new();
    let mut bodies_over_nesting_limit = 0;
    for (kind, open, close) in blocks {
        if depths[open] >= MAX_BODY_NESTING_DEPTH {
            bodies_over_nesting_limit += 1;
            continue;
        }
        if !cut_blocks.insert(open) {
            continue;
        }
        bodies.push((open + 1, close));
        push(kind, open + 1, close);
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
    FragmentExtraction {
        fragments: out,
        control_headers_over_limit,
        bodies_over_nesting_limit,
    }
}

/// The `{` nesting depth of every token.
///
/// A `{` carries the number of blocks enclosing it, zero at the outermost
/// level, and a `}` the depth it closes back to; the depth of a block is the
/// depth of its `{`. Unbalanced braces saturate at zero rather than wrapping.
fn brace_depths(tokens: &[Token]) -> Vec<u32> {
    let mut depths = Vec::with_capacity(tokens.len());
    let mut depth: u32 = 0;
    for token in tokens {
        if token.kind == TokenKind::Punctuation && token.text == "}" {
            depth = depth.saturating_sub(1);
        }
        depths.push(depth);
        if token.kind == TokenKind::Punctuation && token.text == "{" {
            depth = depth.saturating_add(1);
        }
    }
    depths
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
enum BlockAfter {
    Found(usize, usize),
    None,
    Limit,
}

fn block_after(tokens: &[Token], braces: &HashMap<usize, usize>, i: usize) -> BlockAfter {
    let mut paren_depth = 0usize;
    for (offset, token) in tokens[i..]
        .iter()
        .take(MAX_CONTROL_HEADER_TOKENS)
        .enumerate()
    {
        if token.kind == TokenKind::Punctuation {
            match token.text.as_str() {
                "(" => paren_depth += 1,
                ")" => paren_depth = paren_depth.saturating_sub(1),
                "{" if paren_depth == 0 => {
                    let open = i + offset;
                    let Some(&close) = braces.get(&open) else {
                        return BlockAfter::None;
                    };
                    return BlockAfter::Found(open, close);
                }
                ";" if paren_depth == 0 => return BlockAfter::None,
                _ => {}
            }
        }
    }
    if tokens.len().saturating_sub(i) > MAX_CONTROL_HEADER_TOKENS {
        BlockAfter::Limit
    } else {
        BlockAfter::None
    }
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
        assert_eq!(
            anchored_unit(anchor[1]),
            Some(0),
            "fn name anchors to the function"
        );
        assert_eq!(
            anchored_unit(anchor[6]),
            Some(1),
            "closure body anchors to the closure"
        );
    }

    #[test]
    fn the_per_token_tables_are_as_wide_as_their_values_need() {
        // Both tables exist once per token of the whole corpus, so their
        // element width is a memory cost that scales with the tree rather than
        // with any of the ceilings a run is configured with. An anchor names a
        // unit of one file and a segment id a region of one file; neither has a
        // value range a machine word is needed for.
        let tokens = quick("fn a ( ) { x } fn b ( ) { y }");
        let units = vec![
            unit(UnitKind::Function, 0, 7),
            unit(UnitKind::Function, 7, 14),
        ];

        let anchors = anchor_ids(&tokens, &units);
        let segments = segment_ids(&tokens, &units);

        assert_eq!(size_of::<AnchorId>(), 4);
        assert_eq!(size_of::<AnchorId>(), size_of::<SegmentId>());
        assert_eq!(size_of_val(&anchors[0]) * tokens.len(), 4 * tokens.len());
        assert_eq!(size_of_val(&segments[0]) * tokens.len(), 4 * tokens.len());
        // The token no unit encloses is still a token with an entry.
        assert_eq!(anchors.len(), tokens.len());
        assert_eq!(anchored_unit(anchors[0]), Some(0));
    }

    #[test]
    fn a_token_outside_every_unit_has_no_anchor() {
        let tokens = quick("let x = 1 ;");

        let anchors = anchor_ids(&tokens, &[]);

        assert!(anchors.iter().all(|&anchor| anchor == NO_ANCHOR));
        assert!(
            anchors
                .iter()
                .all(|&anchor| anchored_unit(anchor).is_none())
        );
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
        let frags = fragments(&tokens, &units, &braces, 2, 8).fragments;
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
        let frags = fragments(&tokens, &units, &braces, 2, 8).fragments;

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
        assert!(
            fragments(&tokens, &units, &braces, 50, 8)
                .fragments
                .is_empty()
        );
        // The whole body and the 1-statement window are the same range: once.
        let frags = fragments(&tokens, &units, &braces, 1, 8).fragments;
        let ranges: Vec<(usize, usize)> = frags.iter().map(|f| (f.start, f.end)).collect();
        let mut dedup = ranges.clone();
        dedup.dedup();
        assert_eq!(ranges, dedup);
    }

    #[test]
    fn brace_depth_counts_enclosing_blocks_and_survives_unbalanced_braces() {
        // { { } } }
        let tokens = quick("{ { } } }");
        assert_eq!(brace_depths(&tokens), vec![0, 1, 1, 0, 0]);
    }

    #[test]
    fn blocks_nested_past_the_limit_are_not_cut_and_are_accounted_for() {
        // Nesting depth grows with the file: every enclosing block covers the
        // ones inside it, so cutting all of them would cover the file once per
        // level.
        const DEPTH: usize = 20_000;
        let limit = usize::try_from(MAX_BODY_NESTING_DEPTH).unwrap();
        let source = "if ( a ) { ".repeat(DEPTH) + &"} ".repeat(DEPTH);
        let tokens = quick(&source);
        let braces = brace_pairs(&tokens);

        let extraction = fragments(&tokens, &[], &braces, 1, 1);

        assert_eq!(extraction.bodies_over_nesting_limit, DEPTH - limit);
        // One fragment per cut block plus its single statement window, each at
        // most the whole file: the cut volume is a linear multiple of the
        // input rather than growing with the square of the nesting depth.
        let volume: usize = extraction
            .fragments
            .iter()
            .map(|fragment| fragment.end - fragment.start)
            .sum();
        assert!(
            volume <= 2 * limit * tokens.len(),
            "cut {volume} tokens out of {}",
            tokens.len()
        );

        // Same bytes, same settings, same fragments in the same order.
        let again = fragments(&tokens, &[], &braces, 1, 1);
        assert_eq!(extraction.fragments, again.fragments);
        assert_eq!(
            extraction.bodies_over_nesting_limit,
            again.bodies_over_nesting_limit
        );
    }

    #[test]
    fn one_block_found_by_several_rules_is_cut_once() {
        // `else {` and the `if` that follows it share nothing, but a closure
        // body that is itself a branch block is reached twice.
        let tokens = quick("| | if p { a ; b ; }");
        let units = vec![unit(UnitKind::Closure, 0, tokens.len())];
        let braces = brace_pairs(&tokens);

        let extraction = fragments(&tokens, &units, &braces, 1, 4);

        assert_eq!(extraction.bodies_over_nesting_limit, 0);
        let body = extraction
            .fragments
            .iter()
            .filter(|fragment| (fragment.start, fragment.end) == (5, 9))
            .count();
        assert_eq!(body, 1, "the shared block yields one fragment");
    }

    #[test]
    fn an_unclosed_control_header_has_a_bounded_search_and_is_accounted_for() {
        let mut tokens = vec![tok(TokenKind::Keyword, "if")];
        tokens.extend((0..MAX_CONTROL_HEADER_TOKENS).map(|_| tok(TokenKind::Identifier, "x")));

        let extraction = fragments(&tokens, &[], &brace_pairs(&tokens), 1, 1);

        assert!(extraction.fragments.is_empty());
        assert_eq!(extraction.control_headers_over_limit, 1);
    }
}
