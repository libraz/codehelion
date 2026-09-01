//! Coarse unit-boundary detection over a Rust token stream.
//!
//! Boundaries are the clone-report anchors: functions, methods, `impl` blocks,
//! record definitions and block-bodied closures. Detection is a brace-matching
//! heuristic over tokens, not a parse; in Fast mode no syntax tree is built.
//! The heuristic is deliberately conservative for closures (which a lexer
//! cannot tell apart from bitwise-or with certainty) so that a spurious anchor
//! is preferred against rather than invented. A body whose brace never closes,
//! and a declaration too wide for the boundary walk to finish, yield no unit
//! and a recovery diagnostic, so a file dropping out of unit analysis is
//! visible in scan reports rather than silent.
//!
//! What an item *is* — its kind, and which identifier names it — is decided in
//! [`crate::item`], which Structural mode reads from as well.

use std::collections::{HashMap, HashSet};

use codehelion_core::frontend::{
    Diagnostic, DiagnosticKind, SourceSpan, Token, TokenKind, Unit, UnitKind,
};

use crate::item::{self, HeaderToken, ItemKind};

/// Punctuation after which an item keyword names a type rather than opening an
/// item: `-> impl Trait`, `&impl Trait`, `Vec<impl Trait>`, `(impl A, B)`,
/// `x: fn(u32)`, `[fn(); 4]`, `type F = fn();`.
const TYPE_POSITION_PUNCT: &[&str] = &["->", "&", "&&", "<", ",", "(", "[", ":", "="];

/// Keywords after which an item keyword names a type: `dyn Trait`, `as fn()`.
const TYPE_POSITION_KEYWORDS: &[&str] = &["dyn", "as"];

/// Tokens that may immediately precede a closure's first `|`.
const CLOSURE_PRECEDERS: &[&str] = &[
    "=", "(", "{", "[", ",", ";", "=>", "return", "&&", "||", "!", ":",
];

/// Punctuation allowed between a closure's bars (parameter patterns).
const CLOSURE_PARAM_PUNCT: &[&str] = &[",", ":", "&", "<", ">", "(", ")", "::", "_"];

/// Maximum steps one declaration walk may take before declining an uncertain
/// unit boundary. This prevents a malformed run of declaration-like tokens
/// from turning every item keyword into a full-file scan. A balanced group is
/// one step, so a wide parameter list costs no more than a narrow one.
const MAX_DECLARATION_LOOKAHEAD: usize = 256;

/// Maximum tokens the walk from a macro definition's name to its template body
/// may inspect. A macro definition header is a name and at most one parameter
/// list.
const MAX_MACRO_HEADER_LOOKAHEAD: usize = 4;

/// Detect unit boundaries and recoverable boundary errors in `tokens`, in
/// source order.
///
/// Crate-internal: the public entry point is
/// [`RustFrontend`](crate::RustFrontend).
#[must_use]
#[allow(clippy::redundant_pub_crate)] // crate-internal API reached from the crate root
pub(crate) fn detect(tokens: &[Token]) -> (Vec<Unit>, Vec<Diagnostic>) {
    let pairs = delimiter_pairs(tokens);
    let in_macro_body = macro_body_mask(tokens, &pairs);
    let assoc_bodies = assoc_body_opens(tokens, &pairs, &in_macro_body);
    let enclosing = enclosing_brace_of_fn(tokens);

    let mut units = Vec::new();
    let mut diagnostics = Vec::new();
    let mut closure_bars = HashSet::new();

    for i in 0..tokens.len() {
        // A macro definition's body is a template, not code: the tokens in it
        // are substituted somewhere else, if at all, so they anchor nothing.
        if in_macro_body[i] {
            continue;
        }
        let token = &tokens[i];
        match token.kind {
            TokenKind::Keyword if token.text == "impl" => {
                push_outcome(
                    item_unit(tokens, &pairs, i, ItemKind::Impl),
                    &mut units,
                    &mut diagnostics,
                );
            }
            TokenKind::Keyword if token.text == "fn" => {
                let directly_in_assoc_body = enclosing
                    .get(&i)
                    .is_some_and(|open| assoc_bodies.contains(open));
                push_outcome(
                    item_unit(tokens, &pairs, i, ItemKind::of_fn(directly_in_assoc_body)),
                    &mut units,
                    &mut diagnostics,
                );
            }
            TokenKind::Keyword | TokenKind::Identifier
                if item::is_record_keyword(&token.text) && opens_record_item(tokens, i) =>
            {
                push_outcome(
                    item_unit(tokens, &pairs, i, ItemKind::Record),
                    &mut units,
                    &mut diagnostics,
                );
            }
            _ => {
                if let Some(unit) = closure_unit(tokens, &pairs, i, &mut closure_bars) {
                    units.push(unit);
                }
            }
        }
    }

    units.sort_by_key(|u| u.token_start);
    (units, diagnostics)
}

/// Route one boundary attempt: a unit, a recovery event, or neither.
fn push_outcome(
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

/// Map each `{`, `(` and `[` token index to its matching closer.
///
/// The three families are matched independently, so an unbalanced one leaves
/// the others usable: a declaration walk that meets an unmatched group declines
/// rather than reading past it.
fn delimiter_pairs(tokens: &[Token]) -> HashMap<usize, usize> {
    const BRACES: usize = 0;
    const PARENS: usize = 1;
    const BRACKETS: usize = 2;

    let mut pairs = HashMap::new();
    let mut stacks: [Vec<usize>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (i, token) in tokens.iter().enumerate() {
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        match token.text.as_str() {
            "{" => stacks[BRACES].push(i),
            "(" => stacks[PARENS].push(i),
            "[" => stacks[BRACKETS].push(i),
            "}" | ")" | "]" => {
                let family = match token.text.as_str() {
                    "}" => BRACES,
                    ")" => PARENS,
                    _ => BRACKETS,
                };
                if let Some(open) = stacks[family].pop() {
                    pairs.insert(open, i);
                }
            }
            _ => {}
        }
    }
    pairs
}

/// Whether the token at `index` is punctuation spelled `text`.
fn is_punct(token: Option<&Token>, text: &str) -> bool {
    token.is_some_and(|token| token.kind == TokenKind::Punctuation && token.text == text)
}

/// Index of the delimiter opening a balanced group at `index`.
fn opening_delimiter(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    index: usize,
) -> Option<usize> {
    let token = tokens.get(index)?;
    if token.kind != TokenKind::Punctuation || !matches!(token.text.as_str(), "{" | "(" | "[") {
        return None;
    }
    pairs.contains_key(&index).then_some(index)
}

/// Index of the delimiter opening the template body of the macro definition
/// starting at `i`, if one starts there.
///
/// `macro_rules!` accepts any of the three delimiters around its rule set;
/// a declarative macro definition carries its rules in a brace, optionally
/// after one parameter list.
fn macro_definition_body(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    i: usize,
) -> Option<usize> {
    let token = tokens.get(i)?;
    if token.kind != TokenKind::Identifier {
        return None;
    }
    match token.text.as_str() {
        "macro_rules" if is_punct(tokens.get(i + 1), "!") => {
            opening_delimiter(tokens, pairs, i + 3)
        }
        "macro"
            if tokens
                .get(i + 1)
                .is_some_and(|next| next.kind == TokenKind::Identifier) =>
        {
            let mut index = i + 2;
            for _ in 0..MAX_MACRO_HEADER_LOOKAHEAD {
                if is_punct(tokens.get(index), "(") {
                    index = pairs.get(&index)? + 1;
                    continue;
                }
                return opening_delimiter(tokens, pairs, index)
                    .filter(|&open| tokens[open].text == "{");
            }
            None
        }
        _ => None,
    }
}

/// One flag per token: whether it sits inside a macro definition's template
/// body.
fn macro_body_mask(tokens: &[Token], pairs: &HashMap<usize, usize>) -> Vec<bool> {
    let mut mask = vec![false; tokens.len()];
    for i in 0..tokens.len() {
        // A macro definition nested in another one is already covered.
        if mask[i] {
            continue;
        }
        let Some(open) = macro_definition_body(tokens, pairs, i) else {
            continue;
        };
        let Some(&close) = pairs.get(&open) else {
            continue;
        };
        for flag in mask.iter_mut().take(close).skip(open + 1) {
            *flag = true;
        }
    }
    mask
}

/// The `{` token indices opening an associated-item body: the body of an
/// `impl` block or of a `trait` definition.
///
/// Both hold associated items, so a function written directly in either is a
/// method. Reading only `impl` bodies would report a trait's default method as
/// a free function, which is what the same source parsed in Structural mode
/// never does.
fn assoc_body_opens(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    in_macro_body: &[bool],
) -> HashSet<usize> {
    let mut opens = HashSet::new();
    for (i, token) in tokens.iter().enumerate() {
        if in_macro_body[i] || token.kind != TokenKind::Keyword {
            continue;
        }
        if !matches!(token.text.as_str(), "impl" | "trait") || !opens_item(tokens, i) {
            continue;
        }
        if let DeclarationBody::Block(open) = declaration_body(tokens, pairs, i) {
            opens.insert(open);
        }
    }
    opens
}

/// The innermost `{` still open at each `fn` keyword, by token index.
///
/// Only the innermost one decides a function's kind: a helper declared inside a
/// method's body is a free function, not a second method, however deep in an
/// `impl` block it is written.
fn enclosing_brace_of_fn(tokens: &[Token]) -> HashMap<usize, usize> {
    let mut open_braces = Vec::new();
    let mut enclosing = HashMap::new();
    for (i, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Punctuation if token.text == "{" => open_braces.push(i),
            TokenKind::Punctuation if token.text == "}" => {
                open_braces.pop();
            }
            TokenKind::Keyword if token.text == "fn" => {
                if let Some(&open) = open_braces.last() {
                    enclosing.insert(i, open);
                }
            }
            _ => {}
        }
    }
    enclosing
}

/// Whether the item keyword at `i` opens an item.
///
/// In type position the keyword names a type instead: an anonymous type
/// implementing a trait (`-> impl Iterator<Item = u8>`, `x: &impl Display`) or
/// a function pointer (`f: fn(u32) -> u32`, `type Handler = fn();`). The next
/// brace there belongs to the enclosing declaration, so anchoring a unit on it
/// would take a function's body away from the function's own name, leave the
/// clone report without the name, and produce a unit that is a proper subset of
/// the correctly anchored one.
fn opens_item(tokens: &[Token], i: usize) -> bool {
    let Some(previous) = i.checked_sub(1).map(|p| &tokens[p]) else {
        return true;
    };
    match previous.kind {
        TokenKind::Punctuation => !TYPE_POSITION_PUNCT.contains(&previous.text.as_str()),
        TokenKind::Keyword => !TYPE_POSITION_KEYWORDS.contains(&previous.text.as_str()),
        _ => true,
    }
}

/// Whether the record keyword at `i` opens a record definition.
///
/// `union` is a contextual keyword, so the Fast lexer hands it over as an
/// identifier and it may just as well be a variable. A definition always names
/// the record straight after the keyword, which a use of the word never does.
fn opens_record_item(tokens: &[Token], i: usize) -> bool {
    opens_item(tokens, i)
        && tokens
            .get(i + 1)
            .is_some_and(|next| next.kind == TokenKind::Identifier)
}

/// Where an item's body starts, or why the declaration walk could not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclarationBody {
    /// Index of the `{` opening the item's block body.
    Block(usize),
    /// Index of the `;` that ended a declaration having no block body.
    Absent(usize),
    /// The lookahead budget ran out, or a group in the declaration never
    /// closed, before either was reached.
    Undecided,
}

/// Walk the declaration starting at `from` to the start of its body.
///
/// The `{` that opens a body is the one written at the declaration's own
/// bracket depth. A brace nested in `(...)`, `[...]` or `<...>` belongs to a
/// parameter list, an array length or a const generic argument — `fn make() ->
/// Matrix<{ 1 + 2 }> { .. }` writes both — and taking one of those for the body
/// would end the unit before the item's own code begins, silently, since the
/// brace it grabbed is correctly matched. Balanced groups are stepped over
/// whole, so nothing written inside one can unbalance the walk; angle brackets
/// are counted instead, because a lexer cannot know which `<` is a bracket.
fn declaration_body(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    from: usize,
) -> DeclarationBody {
    let mut angle = 0usize;
    let mut index = from;
    for _ in 0..MAX_DECLARATION_LOOKAHEAD {
        let Some(token) = tokens.get(index) else {
            return DeclarationBody::Undecided;
        };
        if token.kind == TokenKind::Punctuation {
            match token.text.as_str() {
                "{" if angle == 0 => return DeclarationBody::Block(index),
                "{" | "(" | "[" => {
                    let Some(&close) = pairs.get(&index) else {
                        return DeclarationBody::Undecided;
                    };
                    index = close + 1;
                    continue;
                }
                ";" if angle == 0 => return DeclarationBody::Absent(index),
                // The lexer glues a closing run, so one token can give back
                // both of the levels it closes.
                "<" => angle += 1,
                "<<" => angle += 2,
                ">" => angle = angle.saturating_sub(1),
                ">>" => angle = angle.saturating_sub(2),
                _ => {}
            }
        }
        index += 1;
    }
    DeclarationBody::Undecided
}

/// Build the unit for the item of `kind` whose keyword is at `i`, a recovery
/// event where the item's boundary cannot be established, or neither.
///
/// The three ways this ends are kept apart on purpose. A declaration with no
/// block body (`fn f();`, `struct Point;`) is not an error: a record still
/// anchors a unit over its declaration, and a function has nothing to anchor.
/// A body whose brace never closes, and a declaration wider than the walk can
/// follow, both mean the boundary is unknown — reported, never guessed, so
/// that an item dropping out of unit analysis is visible.
fn item_unit(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    i: usize,
    kind: ItemKind,
) -> Option<Result<Unit, SourceSpan>> {
    if !opens_item(tokens, i) {
        return None;
    }
    let unit_kind = kind.unit_kind()?;
    let (name_end, end) = match declaration_body(tokens, pairs, i) {
        DeclarationBody::Block(open) => {
            let Some(&close) = pairs.get(&open) else {
                return Some(Err(span_of(tokens, open, open)));
            };
            (open, close)
        }
        DeclarationBody::Absent(semicolon) => {
            if unit_kind != UnitKind::Record {
                return None;
            }
            (semicolon, semicolon)
        }
        DeclarationBody::Undecided => return Some(Err(span_of(tokens, i, i))),
    };
    Some(Ok(Unit {
        kind: unit_kind,
        name: item_name(tokens, i, name_end, unit_kind),
        token_start: i,
        token_end: end + 1,
        span: span_of(tokens, i, end),
    }))
}

/// The name an item is reported under, read from the header tokens between the
/// item keyword at `i` and `header_end`.
fn item_name(tokens: &[Token], i: usize, header_end: usize, kind: UnitKind) -> Option<String> {
    if kind == UnitKind::Impl {
        let header = tokens
            .get(i + 1..header_end)?
            .iter()
            .map(|token| HeaderToken {
                kind: token.kind,
                text: token.text.as_str(),
            });
        return item::impl_self_type_name(header).map(ToOwned::to_owned);
    }
    // A function and a record are named by the identifier written straight
    // after the keyword, which is where the grammar puts the name.
    tokens
        .get(i + 1)
        .filter(|token| token.kind == TokenKind::Identifier)
        .map(|token| token.text.to_string())
}

fn closure_unit(
    tokens: &[Token],
    pairs: &HashMap<usize, usize>,
    i: usize,
    seen_bars: &mut HashSet<usize>,
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
    let close = *pairs.get(&body_open)?;
    seen_bars.insert(bar);
    Some(Unit {
        kind: ItemKind::Closure.unit_kind()?,
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
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn units_of(source: &str) -> Vec<Unit> {
        detect(&lex(source).0).0
    }

    fn diagnostics_of(source: &str) -> Vec<Diagnostic> {
        detect(&lex(source).0).1
    }

    fn named(units: &[Unit], kind: UnitKind) -> Vec<Option<&str>> {
        units
            .iter()
            .filter(|unit| unit.kind == kind)
            .map(|unit| unit.name.as_deref())
            .collect()
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
    fn a_default_method_in_a_trait_is_a_method() {
        let units = units_of("trait T { fn f(&self) -> u8 { 1 } }");
        assert_eq!(named(&units, UnitKind::Method), vec![Some("f")]);
        assert!(units.iter().all(|unit| unit.kind != UnitKind::Function));
    }

    #[test]
    fn a_helper_inside_a_method_body_is_a_free_function() {
        let units = units_of("impl Foo { fn a(&self) { fn helper() -> u8 { 1 } } }");
        assert_eq!(named(&units, UnitKind::Method), vec![Some("a")]);
        assert_eq!(named(&units, UnitKind::Function), vec![Some("helper")]);
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
    fn a_declaration_too_wide_to_follow_is_reported_rather_than_dropped() {
        let source = format!("fn {} {{}}", "name ".repeat(MAX_DECLARATION_LOOKAHEAD));
        let tokens = lex(&source).0;
        let pairs = delimiter_pairs(&tokens);
        assert_eq!(
            declaration_body(&tokens, &pairs, 0),
            DeclarationBody::Undecided
        );

        let (units, diagnostics) = detect(&tokens);
        assert!(units.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, DiagnosticKind::UnmatchedDelimiter);
        assert_eq!(diagnostics[0].span.start_byte, 0);
    }

    /// A valid function with `count` bounded generic parameters. Twenty-six of
    /// them already spell a signature over 288 tokens wide.
    fn function_with_generic_parameters(count: usize) -> String {
        let parameters: Vec<String> = (0..count)
            .map(|index| format!("T{index}: Into<u64> + Clone"))
            .collect();
        let arguments: Vec<String> = (0..count)
            .map(|index| format!("p{index}: T{index}"))
            .collect();
        format!(
            "fn wide<{}>({}) -> u64 {{ 1 }}",
            parameters.join(", "),
            arguments.join(", ")
        )
    }

    #[test]
    fn a_wide_but_valid_signature_still_yields_its_unit() {
        let source = function_with_generic_parameters(26);
        let units = units_of(&source);
        assert_eq!(named(&units, UnitKind::Function), vec![Some("wide")]);
    }

    #[test]
    fn a_signature_wider_than_the_walk_is_reported_rather_than_dropped() {
        // Past the walk's budget the boundary is unknown, which is not the same
        // as a declaration with no body: it is reported, so the item cannot
        // leave unit analysis without a trace.
        let source = function_with_generic_parameters(40);
        let (units, diagnostics) = detect(&lex(&source).0);
        assert!(units.is_empty(), "{units:?}");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, DiagnosticKind::UnmatchedDelimiter);
        assert_eq!(
            diagnostics[0].span.start_byte, 0,
            "the diagnostic names the item"
        );
    }

    #[test]
    fn a_parameter_list_costs_one_step_of_the_declaration_walk() {
        // A single balanced group is stepped over whole, so a signature that is
        // only wide (rather than deeply generic) still yields its unit.
        let parameters: Vec<String> = (0..300).map(|index| format!("p{index}: u8")).collect();
        let source = format!("fn wide({}) {{ 1 }}", parameters.join(", "));
        let units = units_of(&source);
        assert_eq!(named(&units, UnitKind::Function), vec![Some("wide")]);
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
    fn a_function_pointer_type_does_not_anchor_a_unit() {
        for source in [
            "fn dispatch(f: fn(u32) -> u32, v: u32) -> u32 { f(v) }",
            "fn dispatch(f: &fn(u32), v: u32) -> u32 { v }",
            "fn dispatch(f: [fn(); 2], v: u32) -> u32 { v }",
            "fn dispatch(f: (fn(), fn()), v: u32) -> u32 { v }",
            "fn dispatch(f: Vec<fn()>, v: u32) -> u32 { v }",
        ] {
            let units = units_of(source);
            assert_eq!(
                named(&units, UnitKind::Function),
                vec![Some("dispatch")],
                "in {source}"
            );
            assert!(
                units.iter().all(|unit| unit.name.is_some()),
                "an unnamed unit stole the anchor in {source}"
            );
        }
    }

    #[test]
    fn a_function_pointer_outside_a_parameter_list_does_not_anchor_a_unit() {
        for source in [
            "type Handler = fn(u32) -> u32; fn run(h: Handler) -> u32 { h(1) }",
            "static HANDLER: fn(u32) -> u32 = double; fn run() -> u32 { HANDLER(1) }",
            "struct Table { hook: fn(u32) }",
            "fn cast(v: u32) -> u32 { (double as fn(u32) -> u32)(v) }",
        ] {
            let units = units_of(source);
            assert!(
                units
                    .iter()
                    .all(|unit| unit.kind != UnitKind::Function || unit.name.is_some()),
                "an unnamed function unit appeared in {source}"
            );
        }
    }

    #[test]
    fn a_function_body_stays_inside_its_unit_when_the_signature_holds_braces() {
        for (source, name) in [
            ("fn f(x: Foo<{ 1 + 2 }>) { 1 }", "f"),
            ("fn make() -> Matrix<{ 1 + 2 }> { 1 }", "make"),
            ("fn sized() -> [u8; 4] { [0; 4] }", "sized"),
        ] {
            let tokens = lex(source).0;
            let units = detect(&tokens).0;
            let unit = units
                .iter()
                .find(|unit| unit.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("no unit named {name} in {source}"));
            assert_eq!(
                unit.token_end,
                tokens.len(),
                "the unit stops short of the body in {source}"
            );
            assert_eq!(unit.span.end_byte, source.len(), "in {source}");
        }
    }

    #[test]
    fn an_impl_with_const_generic_braces_covers_its_body() {
        let source = "impl<const N: usize> Foo<{ N }> { fn len(&self) -> usize { N } }";
        let tokens = lex(source).0;
        let units = detect(&tokens).0;
        let block = units
            .iter()
            .find(|unit| unit.kind == UnitKind::Impl)
            .unwrap();
        assert_eq!(block.token_end, tokens.len());
        assert_eq!(named(&units, UnitKind::Method), vec![Some("len")]);
    }

    #[test]
    fn an_impl_is_named_by_the_type_it_implements_for() {
        for (source, expected) in [
            ("impl Foo { }", Some("Foo")),
            ("impl<T> Foo<T> { }", Some("Foo")),
            ("impl Display for Foo { }", Some("Foo")),
            (
                "impl<'a, T: Clone> Trait<'a> for Wrapper<T> { }",
                Some("Wrapper"),
            ),
            ("impl<T> Trait for Foo<T> where T: Clone { }", Some("Foo")),
            ("impl fmt::Display for std::vec::Vec<u8> { }", Some("Vec")),
        ] {
            let units = units_of(source);
            assert_eq!(named(&units, UnitKind::Impl), vec![expected], "in {source}");
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
    fn a_record_definition_is_a_unit() {
        for (source, expected) in [
            ("struct Point { x: i32, y: i32 }", Some("Point")),
            ("struct Wrapper<T> { inner: T }", Some("Wrapper")),
            ("struct Handle;", Some("Handle")),
            ("struct Pair(u8, u8);", Some("Pair")),
            ("enum Op { Add, Sub }", Some("Op")),
            ("union Bits { raw: u32, parts: [u8; 4] }", Some("Bits")),
        ] {
            let units = units_of(source);
            assert_eq!(
                named(&units, UnitKind::Record),
                vec![expected],
                "in {source}"
            );
        }
    }

    #[test]
    fn a_record_unit_covers_its_whole_definition() {
        let source = "struct Point { x: i32, y: i32 }";
        let tokens = lex(source).0;
        let units = detect(&tokens).0;
        let record = units
            .iter()
            .find(|unit| unit.kind == UnitKind::Record)
            .unwrap();
        assert_eq!(record.token_start, 0);
        assert_eq!(record.token_end, tokens.len());
        assert_eq!(record.span.end_byte, source.len());
    }

    #[test]
    fn a_word_that_is_only_contextually_a_record_keyword_is_not_one() {
        // `union` is an identifier outside a definition, so a use of it must
        // not turn the next braced expression into a record.
        let units = units_of("fn f() { let union = Point { x: 1 }; }");
        assert!(units.iter().all(|unit| unit.kind != UnitKind::Record));
    }

    #[test]
    fn a_macro_definition_body_anchors_nothing() {
        let source = "macro_rules! m { ($x:expr) => { fn hidden() { $x } }; }";
        let units = units_of(source);
        assert!(
            units.is_empty(),
            "a macro template produced units: {units:?}"
        );
    }

    #[test]
    fn items_around_a_macro_definition_are_still_units() {
        let source = "\
fn before() { 1 }
macro_rules! m {
    ($x:expr) => { fn hidden() { $x } };
}
struct After { v: u8 }
fn after() { 2 }
";
        let units = units_of(source);
        assert_eq!(
            named(&units, UnitKind::Function),
            vec![Some("before"), Some("after")]
        );
        assert_eq!(named(&units, UnitKind::Record), vec![Some("After")]);
    }

    #[test]
    fn a_macro_definition_body_in_any_delimiter_anchors_nothing() {
        for source in [
            "macro_rules! m ( ($x:expr) => { fn hidden() { $x } }; );",
            "macro_rules! m [ ($x:expr) => { fn hidden() { $x } }; ];",
            "macro m($x:expr) { fn hidden() { $x } }",
        ] {
            let units = units_of(source);
            assert!(units.is_empty(), "{source} produced {units:?}");
        }
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
