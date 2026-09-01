//! Declarator-shaped token walking, shared by every C-family unit rule.
//!
//! Fast mode recognises unit boundaries by walking outwards from a brace over
//! declarator material rather than by parsing. Three things that walk needs
//! live here so that no rule carries its own copy of them:
//!
//! - **skipping a balanced group**, in either direction and for either bracket
//!   family — `()`, `{}` and `[]` come out of a pre-computed delimiter map,
//!   while `<...>` is matched by counting, because angle brackets are brackets
//!   only in context;
//! - **the trailer vocabulary**, the keywords and punctuation that may sit
//!   between a parameter list and a body brace. A function trailer and a
//!   lambda trailer differ by a handful of specifiers, so both are derived
//!   from one table instead of being spelled out twice;
//! - **the record-versus-declarator decision**, which reads the same tables
//!   whether it is asked about a record keyword (does it introduce a body?) or
//!   about a candidate function name (is it a declarator name at all?).
//!
//! Everything here is dialect-agnostic: C and C++ differ in which keywords
//! exist, not in how a declarator is shaped, so the C++ frontend reaches these
//! rules through the same [`crate::units`] entry point the C frontend uses.

#![allow(clippy::redundant_pub_crate)] // internal helpers reached from the crate root

use std::collections::HashMap;

use codehelion_core::frontend::{Token, TokenKind};

use crate::dialect::Dialect;

/// Maximum tokens one declaration walk may inspect before declining an
/// uncertain boundary. This keeps malformed declarations from making every
/// record keyword scan the rest of the file.
pub(crate) const MAX_DECLARATION_LOOKAHEAD: usize = 256;

/// Maximum nesting of angle-bracket groups a template-position test looks
/// through. Template template parameters nest in practice; unbounded nesting
/// does not.
const MAX_TEMPLATE_NESTING: usize = 8;

/// The two interchangeable spellings of a template type parameter. C++ treats
/// them as synonyms, so no unit rule may depend on which one is written; both
/// trailer vocabularies below include this table for that reason.
const TEMPLATE_PARAMETER_KEYWORDS: &[&str] = &["class", "typename"];

/// Keywords that may appear between a parameter list and a body brace:
/// qualifiers, constraint clauses and trailing-return-type material.
const TRAILER_KEYWORDS: &[&str] = &[
    "const", "volatile", "noexcept", "throw", "requires", "mutable", "auto", "decltype",
    "unsigned", "signed", "long", "short", "int", "char", "float", "double", "bool", "void",
    "restrict", "_Atomic",
];

/// Specifiers a lambda's forward trailer allows on top of [`TRAILER_KEYWORDS`].
/// A function's own specifiers precede its declarator instead, so they never
/// appear in the backward walk.
const LAMBDA_ONLY_TRAILER_KEYWORDS: &[&str] = &["constexpr", "consteval", "static"];

/// Punctuation that may appear between a parameter list and a body brace.
const TRAILER_PUNCT: &[&str] = &["::", "<", ">", ">>", "*", "&", "&&", "->"];

/// Keywords whose parenthesised group belongs to the signature trailer
/// (`noexcept(...)`, `throw()`, `decltype(...)`, `requires (...)`), not to the
/// parameter list.
const TRAILER_GROUP_KEYWORDS: &[&str] = &["noexcept", "throw", "decltype", "requires"];

/// Vendor attribute specifiers whose parenthesised group decorates a
/// declaration without declaring anything: it neither ends a record header nor
/// names a function. The GCC and MSVC spellings appear on ABI-boundary
/// declarations everywhere, and the alignment specifiers take the same shape.
const ATTRIBUTE_SPECIFIERS: &[&str] = &[
    "__attribute__",
    "__attribute",
    "__declspec",
    "alignas",
    "_Alignas",
];

/// Whether a keyword spelled `text` may appear in a function signature's
/// backward trailer.
pub(crate) fn is_trailer_keyword(text: &str) -> bool {
    TRAILER_KEYWORDS.contains(&text) || TEMPLATE_PARAMETER_KEYWORDS.contains(&text)
}

/// Whether a keyword spelled `text` may appear in a lambda's forward trailer.
pub(crate) fn is_lambda_trailer_keyword(text: &str) -> bool {
    is_trailer_keyword(text) || LAMBDA_ONLY_TRAILER_KEYWORDS.contains(&text)
}

/// Whether `text` is punctuation a trailer walk may step over.
pub(crate) fn is_trailer_punct(text: &str) -> bool {
    TRAILER_PUNCT.contains(&text)
}

/// Whether a parenthesised group introduced by `text` belongs to the trailer
/// rather than being the parameter list.
pub(crate) fn is_trailer_group_keyword(text: &str) -> bool {
    TRAILER_GROUP_KEYWORDS.contains(&text)
}

/// Whether `token` introduces a vendor attribute specifier.
pub(crate) fn is_attribute_specifier(token: &Token) -> bool {
    matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword)
        && ATTRIBUTE_SPECIFIERS.contains(&token.text.as_str())
}

/// Whether `token` is a record-introducing keyword of `dialect`.
pub(crate) fn is_record_keyword(token: &Token, dialect: &Dialect) -> bool {
    token.kind == TokenKind::Keyword && dialect.record_keywords.contains(&token.text.as_str())
}

/// Matched delimiter pairs of every kind (`()`, `{}`, `[]`), in both
/// directions.
pub(crate) struct DelimPairs {
    /// Opening token index -> closing token index.
    close_of: HashMap<usize, usize>,
    /// Closing token index -> opening token index.
    open_of: HashMap<usize, usize>,
}

/// Match every `()`, `{}` and `[]` pair in `tokens`.
pub(crate) fn delim_pairs(tokens: &[Token]) -> DelimPairs {
    let mut close_of = HashMap::new();
    let mut open_of = HashMap::new();
    let mut parens = Vec::new();
    let mut braces = Vec::new();
    let mut brackets = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        let (stack, closing) = match token.text.as_str() {
            "(" | "{" | "[" => {
                match token.text.as_str() {
                    "(" => parens.push(i),
                    "{" => braces.push(i),
                    _ => brackets.push(i),
                }
                continue;
            }
            ")" => (&mut parens, i),
            "}" => (&mut braces, i),
            "]" => (&mut brackets, i),
            _ => continue,
        };
        if let Some(open) = stack.pop() {
            close_of.insert(open, closing);
            open_of.insert(closing, open);
        }
    }
    DelimPairs { close_of, open_of }
}

/// Index of the token closing the group opened at `open`.
pub(crate) fn group_close(pairs: &DelimPairs, open: usize) -> Option<usize> {
    pairs.close_of.get(&open).copied()
}

/// Index of the token opening the balanced group that closes at `close`.
///
/// This is the one place a declarator walk steps over a whole group. `)`, `}`
/// and `]` are looked up in the delimiter map; `>` and `>>` are not in it,
/// because a lexer cannot know which `<` is a bracket, so they are matched by
/// counting angle brackets backwards instead.
pub(crate) fn group_open(tokens: &[Token], pairs: &DelimPairs, close: usize) -> Option<usize> {
    let token = tokens.get(close)?;
    if token.kind != TokenKind::Punctuation {
        return None;
    }
    match token.text.as_str() {
        ")" | "}" | "]" => pairs.open_of.get(&close).copied(),
        ">" | ">>" => angle_group_open(tokens, close),
        _ => None,
    }
}

/// Whether `token` closes an angle-bracket group. `>>` closes two at once, so
/// a counting walk weighs it accordingly.
fn angle_close_weight(token: &Token) -> Option<usize> {
    if token.kind != TokenKind::Punctuation {
        return None;
    }
    match token.text.as_str() {
        ">" => Some(1),
        ">>" => Some(2),
        _ => None,
    }
}

/// Index of the `<` matching the `>` or `>>` at `close`.
///
/// The walk stops at a token that cannot occur inside a template argument
/// list, and declines rather than guessing when a `<<` would have to be split
/// to balance the count.
fn angle_group_open(tokens: &[Token], close: usize) -> Option<usize> {
    let mut depth = angle_close_weight(tokens.get(close)?)?;
    let mut index = close;
    for _ in 0..MAX_DECLARATION_LOOKAHEAD {
        index = index.checked_sub(1)?;
        let token = &tokens[index];
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        match token.text.as_str() {
            ";" | "{" | "}" => return None,
            ">" => depth += 1,
            ">>" => depth += 2,
            "<" => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            "<<" => {
                if depth < 2 {
                    return None;
                }
                depth -= 2;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Index of the innermost angle-bracket group still open before `from`.
fn enclosing_angle_open(tokens: &[Token], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = from;
    for _ in 0..MAX_DECLARATION_LOOKAHEAD {
        index = index.checked_sub(1)?;
        let token = &tokens[index];
        if token.kind != TokenKind::Punctuation {
            continue;
        }
        match token.text.as_str() {
            ";" | "{" | "}" => return None,
            ">" => depth += 1,
            ">>" => depth += 2,
            "<" => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            "<<" => {
                if depth < 2 {
                    return None;
                }
                depth -= 2;
            }
            _ => {}
        }
    }
    None
}

/// Whether the token at `index` sits inside a `template <...>` parameter list.
///
/// A record keyword there introduces a template parameter, not a definition —
/// including the keyword of a template template parameter, which is nested one
/// angle-bracket group deeper than the parameter list that owns it.
pub(crate) fn is_template_parameter_position(tokens: &[Token], index: usize) -> bool {
    let mut position = index;
    for _ in 0..MAX_TEMPLATE_NESTING {
        let Some(open) = enclosing_angle_open(tokens, position) else {
            return false;
        };
        let Some(before) = open.checked_sub(1) else {
            return false;
        };
        if tokens[before].kind == TokenKind::Keyword && tokens[before].text == "template" {
            return true;
        }
        position = open;
    }
    false
}

/// Index of the declarator name directly before the group opening at `open`.
///
/// Usually that is the preceding token. When it closes an explicit template
/// argument list — a constructor initialising a templated base, or an explicit
/// function-template specialisation — the name is the token before the whole
/// `<...>`, so the group is skipped as one unit.
pub(crate) fn declarator_name(tokens: &[Token], open: usize) -> Option<usize> {
    let candidate = open.checked_sub(1)?;
    if angle_close_weight(&tokens[candidate]).is_some() {
        return angle_group_open(tokens, candidate)?.checked_sub(1);
    }
    Some(candidate)
}

/// The header of a record definition: its declared tag name, if any, and the
/// `{` that opens its body.
pub(crate) struct RecordHeader {
    /// Index of the tag-name token; `None` for an anonymous record.
    pub name: Option<usize>,
    /// Index of the `{` opening the body.
    pub body_open: usize,
}

/// Read the record header starting at `from`, the token after a record
/// keyword.
///
/// A `;` means a forward declaration or a variable of record type; a paren
/// means the keyword is part of a declarator or expression (`struct Foo
/// *make(void)`, `sizeof(struct S)`), not a definition. An attribute
/// specifier's own parenthesised group is neither: it is skipped whole, and
/// its name is not mistaken for the tag.
pub(crate) fn record_header(
    tokens: &[Token],
    pairs: &DelimPairs,
    from: usize,
) -> Option<RecordHeader> {
    let mut name = None;
    let mut index = from;
    for _ in 0..MAX_DECLARATION_LOOKAHEAD {
        let token = tokens.get(index)?;
        if is_attribute_specifier(token)
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.kind == TokenKind::Punctuation && next.text == "(")
        {
            index = group_close(pairs, index + 1)? + 1;
            continue;
        }
        match token.kind {
            TokenKind::Punctuation => match token.text.as_str() {
                "{" => {
                    return Some(RecordHeader {
                        name,
                        body_open: index,
                    });
                }
                ";" | "(" | ")" | "=" => return None,
                _ => index += 1,
            },
            TokenKind::Identifier => {
                if name.is_none() {
                    name = Some(index);
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dialect;
    use crate::lexer::lex;

    fn cpp_tokens(source: &str) -> Vec<Token> {
        // The C++ operator inventory is the wider one, so it exercises the
        // `>>` and `::` paths the C dialect never produces.
        let dialect = Dialect {
            keywords: &["template", "class", "typename", "struct", "union", "int"],
            multi_punct: &["<<=", ">>=", "->", "<<", ">>", "&&", "::"],
            raw_strings: true,
            digit_separators: true,
            record_keywords: &["class", "struct", "union"],
            lambdas: true,
        };
        lex(source, &dialect).0
    }

    fn index_of(tokens: &[Token], text: &str, occurrence: usize) -> usize {
        tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| token.text == text)
            .map(|(index, _)| index)
            .nth(occurrence)
            .expect("token present")
    }

    #[test]
    fn an_angle_group_is_skipped_whole_including_a_shared_closer() {
        let tokens = cpp_tokens("Base<Inner<int>>(value)");
        let close = index_of(&tokens, ">>", 0);
        let open = angle_group_open(&tokens, close).expect("matched angle group");
        assert_eq!(tokens[open].text, "<");
        assert_eq!(open, index_of(&tokens, "<", 0));
    }

    #[test]
    fn a_declarator_name_is_read_through_its_template_arguments() {
        let tokens = cpp_tokens("void f<int>(int a) {}");
        let open = index_of(&tokens, "(", 0);
        let name = declarator_name(&tokens, open).expect("declarator name");
        assert_eq!(tokens[name].text, "f");

        let tokens = cpp_tokens("void g(int a) {}");
        let open = index_of(&tokens, "(", 0);
        let name = declarator_name(&tokens, open).expect("declarator name");
        assert_eq!(tokens[name].text, "g");
    }

    #[test]
    fn template_parameter_positions_are_recognised_at_every_nesting_depth() {
        let tokens = cpp_tokens("template <template <class> class C> struct Holder {};");
        assert!(is_template_parameter_position(
            &tokens,
            index_of(&tokens, "class", 0)
        ));
        assert!(is_template_parameter_position(
            &tokens,
            index_of(&tokens, "class", 1)
        ));
        assert!(
            !is_template_parameter_position(&tokens, index_of(&tokens, "struct", 0)),
            "the templated record itself is not a parameter"
        );
    }

    #[test]
    fn a_record_header_skips_an_attribute_group_without_naming_it() {
        let tokens = cpp_tokens("struct __attribute__((packed)) S { int f; };");
        let pairs = delim_pairs(&tokens);
        let header = record_header(&tokens, &pairs, 1).expect("record header");
        assert_eq!(tokens[header.name.expect("named record")].text, "S");
        assert_eq!(tokens[header.body_open].text, "{");
    }

    #[test]
    fn a_declarator_paren_still_ends_a_record_header() {
        let tokens = lex("struct point *make(void) { return 0; }", &dialect::C).0;
        let pairs = delim_pairs(&tokens);
        assert!(record_header(&tokens, &pairs, 1).is_none());
    }

    #[test]
    fn both_trailer_vocabularies_accept_either_template_parameter_spelling() {
        for spelling in ["class", "typename"] {
            assert!(is_trailer_keyword(spelling), "{spelling}");
            assert!(is_lambda_trailer_keyword(spelling), "{spelling}");
        }
        assert!(
            TRAILER_KEYWORDS
                .iter()
                .all(|keyword| is_lambda_trailer_keyword(keyword)),
            "the lambda trailer is derived from the function trailer"
        );
    }
}
