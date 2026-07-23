//! Minimal deterministic line lexer for whole-token substitution.
//!
//! Type-2 mutation renames identifiers and swaps literals. A naive string
//! replace would also rewrite substrings of longer identifiers, comment text
//! and string contents; this lexer splits a line into whole tokens so
//! substitution can match complete identifier and literal tokens only.
//!
//! The lexer works line by line and assumes the controlled corpus authoring
//! style: no block comments, no multi-line or raw string literals. Keywords
//! lex as identifiers; a spec simply must not use a keyword as a rename key.

use std::collections::BTreeMap;

/// One lexed region of a source line. Concatenating the token texts in order
/// reproduces the line exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    /// An identifier (or keyword): `[A-Za-z_][A-Za-z0-9_]*`.
    Ident(&'a str),
    /// A numeric, string or character literal, quotes included.
    Literal(&'a str),
    /// A line comment, from `//` to the end of the line.
    Comment(&'a str),
    /// Anything else: whitespace, punctuation, operators.
    Other(&'a str),
}

impl<'a> Token<'a> {
    /// The exact source text of this token.
    #[must_use]
    pub const fn text(self) -> &'a str {
        match self {
            Self::Ident(text) | Self::Literal(text) | Self::Comment(text) | Self::Other(text) => {
                text
            }
        }
    }
}

const fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

const fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Split `line` into [`Token`]s. Lossless: the concatenation of all token
/// texts equals `line`.
#[must_use]
pub fn tokenize(line: &str) -> Vec<Token<'_>> {
    fn flush_other<'a>(tokens: &mut Vec<Token<'a>>, line: &'a str, start: usize, end: usize) {
        if start < end {
            tokens.push(Token::Other(&line[start..end]));
        }
    }

    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0;
    let mut other_start = 0;

    while pos < bytes.len() {
        let rest = &line[pos..];
        let Some(c) = rest.chars().next() else { break };

        if rest.starts_with("//") {
            flush_other(&mut tokens, line, other_start, pos);
            tokens.push(Token::Comment(rest));
            pos = bytes.len();
            other_start = pos;
        } else if is_ident_start(c) {
            flush_other(&mut tokens, line, other_start, pos);
            let len = rest
                .char_indices()
                .find(|&(_, ch)| !is_ident_continue(ch))
                .map_or(rest.len(), |(i, _)| i);
            tokens.push(Token::Ident(&rest[..len]));
            pos += len;
            other_start = pos;
        } else if c.is_ascii_digit() {
            flush_other(&mut tokens, line, other_start, pos);
            let len = number_len(rest);
            tokens.push(Token::Literal(&rest[..len]));
            pos += len;
            other_start = pos;
        } else if c == '"' {
            flush_other(&mut tokens, line, other_start, pos);
            let len = string_len(rest);
            tokens.push(Token::Literal(&rest[..len]));
            pos += len;
            other_start = pos;
        } else if c == '\'' {
            if let Some(len) = char_literal_len(rest) {
                flush_other(&mut tokens, line, other_start, pos);
                tokens.push(Token::Literal(&rest[..len]));
                pos += len;
                other_start = pos;
            } else {
                // A lifetime or a lone quote: passthrough.
                pos += c.len_utf8();
            }
        } else {
            pos += c.len_utf8();
        }
    }
    flush_other(&mut tokens, line, other_start, pos);
    tokens
}

/// Length of a numeric literal at the start of `rest`. Consumes digits,
/// identifier characters (type suffixes, hex digits) and a `.` only when it is
/// followed by a digit, so range expressions such as `0..n` are not swallowed.
fn number_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let mut len = 0;
    while len < bytes.len() {
        let c = bytes[len] as char;
        if c.is_ascii_alphanumeric()
            || c == '_'
            || (c == '.' && bytes.get(len + 1).is_some_and(u8::is_ascii_digit))
        {
            len += 1;
        } else {
            break;
        }
    }
    len
}

/// Length of a string literal at the start of `rest`, honouring `\` escapes.
/// An unterminated string extends to the end of the line.
const fn string_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let mut len = 1; // opening quote
    while len < bytes.len() {
        match bytes[len] {
            b'\\' => len += 2,
            b'"' => return len + 1,
            _ => len += 1,
        }
    }
    bytes.len()
}

/// Length of a character literal (`'a'` or `'\n'`) at the start of `rest`, or
/// `None` when the quote starts a lifetime instead.
fn char_literal_len(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices().skip(1);
    let (second_pos, second) = chars.next()?;
    if second == '\\' {
        let _escaped = chars.next()?;
        let (close_pos, close) = chars.next()?;
        (close == '\'').then(|| close_pos + close.len_utf8())
    } else {
        let (close_pos, close) = chars.next()?;
        (close == '\'' && second_pos == 1).then(|| close_pos + close.len_utf8())
    }
}

/// Apply whole-token substitution to `line`: identifiers through `rename`,
/// literals through `literals`. Comments, string contents and substrings of
/// longer identifiers are never rewritten.
#[must_use]
pub fn substitute(
    line: &str,
    rename: &BTreeMap<String, String>,
    literals: &BTreeMap<String, String>,
) -> String {
    let mut out = String::with_capacity(line.len());
    for token in tokenize(line) {
        let text = token.text();
        let replacement = match token {
            Token::Ident(_) => rename.get(text),
            Token::Literal(_) => literals.get(text),
            Token::Comment(_) | Token::Other(_) => None,
        };
        out.push_str(replacement.map_or(text, String::as_str));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rename_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn tokenize_is_lossless() {
        let lines = [
            "    let mut total = 0;",
            "fn sum_even(values: &[i32]) -> i32 {",
            "    // total is a comment mentioning total",
            r#"    let s = "total = 0"; // trailing"#,
            "    for i in 0..10 {",
            "    let c = 'x';",
            "    let f = 1.5f64;",
        ];
        for line in lines {
            let rebuilt: String = tokenize(line).iter().map(|t| t.text()).collect();
            assert_eq!(rebuilt, line);
        }
    }

    #[test]
    fn rename_matches_whole_identifiers_only() {
        let rename = rename_map(&[("total", "acc")]);
        let literals = BTreeMap::new();
        assert_eq!(
            substitute("    total += subtotal + total_count;", &rename, &literals),
            "    acc += subtotal + total_count;"
        );
    }

    #[test]
    fn rename_leaves_comments_untouched() {
        let rename = rename_map(&[("total", "acc")]);
        let literals = BTreeMap::new();
        assert_eq!(
            substitute("    total += 1; // add to total", &rename, &literals),
            "    acc += 1; // add to total"
        );
    }

    #[test]
    fn rename_leaves_string_contents_untouched() {
        let rename = rename_map(&[("total", "acc")]);
        let literals = BTreeMap::new();
        assert_eq!(
            substitute(r#"    println!("total: {}", total);"#, &rename, &literals),
            r#"    println!("total: {}", acc);"#
        );
    }

    #[test]
    fn literal_substitution_matches_whole_literals_only() {
        let rename = BTreeMap::new();
        let literals = rename_map(&[("0", "1")]);
        assert_eq!(
            substitute(
                "    let x = 0; let y = 10; let z = 0.5;",
                &rename,
                &literals
            ),
            "    let x = 1; let y = 10; let z = 0.5;"
        );
    }

    #[test]
    fn literal_substitution_skips_numbers_in_comments() {
        let rename = BTreeMap::new();
        let literals = rename_map(&[("0", "1")]);
        assert_eq!(
            substitute("    let x = 0; // starts at 0", &rename, &literals),
            "    let x = 1; // starts at 0"
        );
    }

    #[test]
    fn range_expression_is_not_one_number() {
        let tokens = tokenize("0..10");
        assert_eq!(
            tokens,
            vec![
                Token::Literal("0"),
                Token::Other(".."),
                Token::Literal("10"),
            ]
        );
    }

    #[test]
    fn lifetime_is_not_a_char_literal() {
        let tokens = tokenize("fn f<'a>(x: &'a str) {}");
        assert!(
            tokens
                .iter()
                .all(|t| !matches!(t, Token::Literal(text) if text.starts_with('\''))),
            "lifetimes must not lex as char literals: {tokens:?}"
        );
    }

    #[test]
    fn c_lines_substitute_whole_tokens_only() {
        let rename = rename_map(&[("total", "acc")]);
        let literals = rename_map(&[("0", "1")]);
        assert_eq!(
            substitute(
                "    total += self->count; // keep total",
                &rename,
                &literals
            ),
            "    acc += self->count; // keep total"
        );
        // Hex and char literals stay whole, so a `0` key never rewrites them.
        assert_eq!(
            substitute("    char c = 'x'; int mask = 0x0F;", &rename, &literals),
            "    char c = 'x'; int mask = 0x0F;"
        );
        let header = "int sum_even(const int *values, int count) {";
        let rebuilt: String = tokenize(header).iter().map(|t| t.text()).collect();
        assert_eq!(rebuilt, header);
    }

    #[test]
    fn char_literal_is_one_token() {
        let tokens = tokenize("let c = 'x';");
        assert!(tokens.contains(&Token::Literal("'x'")));
        let tokens = tokenize(r"let n = '\n';");
        assert!(tokens.contains(&Token::Literal(r"'\n'")));
    }
}
