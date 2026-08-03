//! Error-tolerant Rust lexer.
//!
//! Whitespace and comments are dropped. Every other lexeme becomes a token
//! carrying its raw text and a reporting-only source span. Malformed spans
//! (unterminated strings, characters and block comments) are recorded as
//! diagnostics and lexing resumes, so a single broken construct never discards
//! the rest of the file. Macros are not expanded: `name!` is an identifier
//! followed by punctuation, and the invocation's delimiters are ordinary
//! tokens.

use codehelion_core::frontend::{
    Diagnostic, DiagnosticKind, LexemeInterner, LiteralKind, SourceSpan, Token, TokenKind,
};
use std::str::Chars;

/// Rust keywords. `true`/`false` are lexed as keywords rather than boolean
/// literals, keeping token granularity uniform, which the minimum-clone-length
/// threshold relies on.
const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while",
];

/// Multi-character operators, matched greedily (longest first).
const MULTI_PUNCT: &[&str] = &[
    "<<=", ">>=", "..=", "...", "::", "->", "=>", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=",
    "%=", "^=", "&=", "|=", "&&", "||", "<<", ">>", "..",
];

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

struct Lexer<'s> {
    source: &'s str,
    chars: Chars<'s>,
    byte: usize,
    line: u32,
    column: u32,
    interner: LexemeInterner,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
}

/// A position captured at the start of a token.
#[derive(Clone, Copy)]
struct Mark {
    byte: usize,
    line: u32,
    column: u32,
}

impl<'s> Lexer<'s> {
    fn new(source: &'s str) -> Self {
        Self {
            source,
            chars: source.chars(),
            byte: 0,
            line: 1,
            column: 1,
            interner: LexemeInterner::new(),
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// The source text between a mark and the current position.
    fn text_from(&self, start: Mark) -> &'s str {
        &self.source[start.byte..self.byte]
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.clone().nth(ahead)
    }

    const fn mark(&self) -> Mark {
        Mark {
            byte: self.byte,
            line: self.line,
            column: self.column,
        }
    }

    /// Consume the current character, tracking line and column.
    fn bump(&mut self) {
        if let Some(c) = self.chars.next() {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.byte += c.len_utf8();
        }
    }

    const fn span_from(&self, start: Mark) -> SourceSpan {
        SourceSpan {
            start_byte: start.byte,
            end_byte: self.byte,
            start_line: start.line,
            start_column: start.column,
        }
    }

    fn push(&mut self, kind: TokenKind, start: Mark) {
        let text = self.interner.intern(self.text_from(start));
        self.tokens.push(Token {
            kind,
            text,
            span: self.span_from(start),
        });
    }

    fn diagnose(&mut self, kind: DiagnosticKind, start: Mark) {
        let span = self.span_from(start);
        self.diagnostics.push(Diagnostic { kind, span });
    }

    fn run(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        while let Some(c) = self.peek(0) {
            // A UTF-8 BOM is an encoding marker, not source text. Consume it
            // only at byte zero. Keep its byte width in spans without letting
            // it shift the source column visible to users.
            if self.byte == 0 && c == '\u{feff}' {
                let _ = self.chars.next();
                self.byte += c.len_utf8();
                continue;
            }
            if c.is_whitespace() {
                self.bump();
                continue;
            }
            if c == '/' && self.peek(1) == Some('/') {
                self.consume_line_comment();
                continue;
            }
            if c == '/' && self.peek(1) == Some('*') {
                self.consume_block_comment();
                continue;
            }
            if self.try_prefixed_literal() {
                continue;
            }
            if c == '\'' {
                self.consume_quote();
                continue;
            }
            if c == '"' {
                self.consume_string();
                continue;
            }
            if c.is_ascii_digit() {
                self.consume_number();
                continue;
            }
            if is_ident_start(c) {
                self.consume_ident();
                continue;
            }
            self.consume_punct();
        }
        // Streams are long-lived (the whole scan holds every file's tokens),
        // so growth slack is returned to the allocator.
        self.tokens.shrink_to_fit();
        (self.tokens, self.diagnostics)
    }

    fn consume_line_comment(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }

    fn consume_block_comment(&mut self) {
        let start = self.mark();
        // Skip the opening `/*`.
        self.bump();
        self.bump();
        let mut depth = 1u32;
        while depth > 0 {
            match (self.peek(0), self.peek(1)) {
                (Some('/'), Some('*')) => {
                    self.bump();
                    self.bump();
                    depth += 1;
                }
                (Some('*'), Some('/')) => {
                    self.bump();
                    self.bump();
                    depth -= 1;
                }
                (Some(_), _) => self.bump(),
                (None, _) => {
                    self.diagnose(DiagnosticKind::UnterminatedBlockComment, start);
                    return;
                }
            }
        }
    }

    /// Handle raw strings, byte strings and byte/raw-byte literals, plus raw
    /// identifiers. Returns `true` if a token was produced.
    fn try_prefixed_literal(&mut self) -> bool {
        let c = self.peek(0);
        let n1 = self.peek(1);
        match (c, n1) {
            (Some('r'), Some('"')) => {
                let start = self.mark();
                self.bump();
                self.consume_raw_string_body(start);
                true
            }
            (Some('r'), Some('#')) if self.raw_string_opens_at(1) => {
                let start = self.mark();
                self.bump();
                self.consume_raw_string_body(start);
                true
            }
            (Some('b' | 'c'), Some('"')) => {
                let start = self.mark();
                self.bump();
                self.consume_string_from(start);
                true
            }
            (Some('b' | 'c'), Some('r')) if self.raw_string_opens_at(2) => {
                let start = self.mark();
                self.bump();
                self.bump();
                self.consume_raw_string_body(start);
                true
            }
            (Some('b'), Some('\'')) => {
                let start = self.mark();
                self.bump();
                self.consume_char_from(start);
                true
            }
            _ => false,
        }
    }

    /// Whether `offset` begins the hash delimiter of a raw string literal.
    ///
    /// The delimiter contains zero or more `#` characters followed by `"`.
    /// Checking its full shape here keeps multi-hash raw strings separate from
    /// raw identifiers such as `r#type`.
    fn raw_string_opens_at(&self, offset: usize) -> bool {
        let mut index = offset;
        while self.peek(index) == Some('#') {
            index += 1;
        }
        self.peek(index) == Some('"')
    }

    /// A `'`: either a character literal or a lifetime/label.
    fn consume_quote(&mut self) {
        // A lifetime is `'` followed by an identifier that is not immediately
        // closed by another `'` (which would make it a character literal).
        if self.peek(1).is_some_and(is_ident_start) && self.peek(2) != Some('\'') {
            let start = self.mark();
            self.bump();
            while self.peek(0).is_some_and(is_ident_continue) {
                self.bump();
            }
            self.push(TokenKind::Lifetime, start);
            return;
        }
        let start = self.mark();
        self.consume_char_from(start);
    }

    fn consume_char_from(&mut self, start: Mark) {
        // At entry, the current char is the opening `'` (possibly preceded by a
        // consumed `b`). Consume it, one char or escape, then the closing `'`.
        self.bump();
        if self.peek(0) == Some('\\') {
            self.bump();
            match self.peek(0) {
                Some('x') => {
                    self.bump();
                    for _ in 0..2 {
                        self.bump();
                    }
                }
                Some('u') if self.peek(1) == Some('{') => {
                    self.bump();
                    self.bump();
                    while let Some(ch) = self.peek(0) {
                        self.bump();
                        if ch == '}' {
                            break;
                        }
                    }
                }
                Some(_) => self.bump(),
                None => {}
            }
        } else if self.peek(0).is_some_and(|c| c != '\'') {
            self.bump();
        }
        if self.peek(0) == Some('\'') {
            self.bump();
            self.push(TokenKind::Literal(LiteralKind::Char), start);
        } else {
            // No closing quote: still emit what we have, with a diagnostic.
            self.push(TokenKind::Literal(LiteralKind::Char), start);
            self.diagnose(DiagnosticKind::UnterminatedChar, start);
        }
    }

    fn consume_string(&mut self) {
        let start = self.mark();
        self.consume_string_from(start);
    }

    fn consume_string_from(&mut self, start: Mark) {
        // Opening `"`.
        self.bump();
        loop {
            match self.peek(0) {
                None => {
                    self.push(TokenKind::Literal(LiteralKind::String), start);
                    self.diagnose(DiagnosticKind::UnterminatedString, start);
                    return;
                }
                Some('\\') => {
                    self.bump();
                    self.bump();
                }
                Some('"') => {
                    self.bump();
                    self.push(TokenKind::Literal(LiteralKind::String), start);
                    return;
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// Consume a raw string body starting at the leading `#`s or `"`. `start`
    /// marks the beginning of the whole literal (including any `r`/`br`).
    fn consume_raw_string_body(&mut self, start: Mark) {
        let mut hashes = 0usize;
        while self.peek(0) == Some('#') {
            hashes += 1;
            self.bump();
        }
        // Opening quote.
        if self.peek(0) == Some('"') {
            self.bump();
        }
        loop {
            match self.peek(0) {
                None => {
                    self.push(TokenKind::Literal(LiteralKind::String), start);
                    self.diagnose(DiagnosticKind::UnterminatedString, start);
                    return;
                }
                Some('"') => {
                    // A closing quote followed by `hashes` `#`s ends the string.
                    if (1..=hashes).all(|k| self.peek(k) == Some('#')) {
                        self.bump();
                        for _ in 0..hashes {
                            self.bump();
                        }
                        self.push(TokenKind::Literal(LiteralKind::String), start);
                        return;
                    }
                    self.bump();
                }
                Some(_) => self.bump(),
            }
        }
    }

    fn consume_number(&mut self) {
        let start = self.mark();
        let is_hex_oct_bin = self.peek(0) == Some('0')
            && matches!(self.peek(1), Some('x' | 'X' | 'o' | 'O' | 'b' | 'B'));
        if is_hex_oct_bin {
            self.bump();
            self.bump();
            while self.peek(0).is_some_and(is_ident_continue) {
                self.bump();
            }
            self.push(TokenKind::Literal(LiteralKind::Integer), start);
            return;
        }

        while self
            .peek(0)
            .is_some_and(|ch| ch.is_ascii_digit() || ch == '_')
        {
            self.bump();
        }
        let mut is_float = false;
        // Do not swallow `..` ranges or a method call on a literal.
        if self.peek(0) == Some('.')
            && !matches!(self.peek(1), Some('.' | '_'))
            && !self.peek(1).is_some_and(char::is_alphabetic)
        {
            is_float = true;
            self.bump();
            while self
                .peek(0)
                .is_some_and(|ch| ch.is_ascii_digit() || ch == '_')
            {
                self.bump();
            }
        }
        if matches!(self.peek(0), Some('e' | 'E'))
            && (self.peek(1).is_some_and(|ch| ch.is_ascii_digit())
                || (matches!(self.peek(1), Some('+' | '-'))
                    && self.peek(2).is_some_and(|ch| ch.is_ascii_digit())))
        {
            is_float = true;
            self.bump();
            if matches!(self.peek(0), Some('+' | '-')) {
                self.bump();
            }
            while self
                .peek(0)
                .is_some_and(|ch| ch.is_ascii_digit() || ch == '_')
            {
                self.bump();
            }
        }
        while self.peek(0).is_some_and(is_ident_continue) {
            self.bump();
        }
        let kind = if is_float {
            LiteralKind::Float
        } else {
            LiteralKind::Integer
        };
        self.push(TokenKind::Literal(kind), start);
    }

    fn consume_ident(&mut self) {
        let start = self.mark();
        // Raw identifier `r#name`.
        if self.peek(0) == Some('r') && self.peek(1) == Some('#') {
            self.bump();
            self.bump();
        }
        while self.peek(0).is_some_and(is_ident_continue) {
            self.bump();
        }
        let kind = if KEYWORDS.contains(&self.text_from(start)) {
            TokenKind::Keyword
        } else {
            TokenKind::Identifier
        };
        self.push(kind, start);
    }

    fn consume_punct(&mut self) {
        let start = self.mark();
        for op in MULTI_PUNCT {
            let len = op.chars().count();
            if self.matches_ahead(op, len) {
                for _ in 0..len {
                    self.bump();
                }
                self.push(TokenKind::Punctuation, start);
                return;
            }
        }
        // Single character. ASCII punctuation is punctuation; anything else that
        // reached here is not lexable.
        let c = self.peek(0).unwrap_or('\0');
        self.bump();
        if c.is_ascii() && !c.is_alphanumeric() {
            self.push(TokenKind::Punctuation, start);
        } else {
            self.push(TokenKind::Unknown, start);
            self.diagnose(DiagnosticKind::UnexpectedCharacter, start);
        }
    }

    fn matches_ahead(&self, op: &str, len: usize) -> bool {
        op.chars()
            .enumerate()
            .all(|(k, ch)| self.peek(k) == Some(ch))
            && len > 0
    }
}

/// Lex `source` into tokens and diagnostics.
///
/// Crate-internal: the public entry point is
/// [`RustFrontend`](crate::RustFrontend).
#[must_use]
#[allow(clippy::redundant_pub_crate)] // crate-internal API reached from the crate root
pub(crate) fn lex(source: &str) -> (Vec<Token>, Vec<Diagnostic>) {
    Lexer::new(source).run()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<TokenKind> {
        lex(source).0.into_iter().map(|t| t.kind).collect()
    }

    fn texts(source: &str) -> Vec<String> {
        lex(source).0.iter().map(|t| t.text.to_string()).collect()
    }

    #[test]
    fn splits_keywords_identifiers_and_operators() {
        let (tokens, diags) = lex("fn add(a: i32) -> i32 { a + 1 }");
        assert!(diags.is_empty());
        let pairs: Vec<_> = tokens.iter().map(|t| (t.kind, t.text.as_str())).collect();
        assert_eq!(pairs[0], (TokenKind::Keyword, "fn"));
        assert_eq!(pairs[1], (TokenKind::Identifier, "add"));
        assert!(pairs.contains(&(TokenKind::Punctuation, "->")));
        assert!(
            pairs
                .iter()
                .any(|(k, t)| *k == TokenKind::Literal(LiteralKind::Integer) && *t == "1")
        );
    }

    #[test]
    fn cursor_tracks_utf8_bytes_without_a_character_index() {
        let mut lexer = Lexer::new("é fn");
        assert_eq!(lexer.chars.as_str(), "é fn");
        lexer.bump();
        assert_eq!(lexer.byte, "é".len());
        assert_eq!(lexer.chars.as_str(), " fn");
    }

    #[test]
    fn drops_comments_and_whitespace() {
        let src = "let x = 1; // trailing\n/* block /* nested */ */ let y = 2;";
        let texts = texts(src);
        assert!(!texts.iter().any(|t| t.contains("trailing")));
        assert!(!texts.iter().any(|t| t.contains("nested")));
        assert!(texts.contains(&"x".to_string()));
        assert!(texts.contains(&"y".to_string()));
    }

    #[test]
    fn distinguishes_lifetimes_from_char_literals() {
        let k = kinds("fn f<'a>(x: &'a str) -> char { 'z' }");
        assert!(k.contains(&TokenKind::Lifetime));
        assert!(k.contains(&TokenKind::Literal(LiteralKind::Char)));
    }

    #[test]
    fn keeps_hex_and_unicode_character_escapes_together() {
        let (tokens, diagnostics) =
            lex("let a = '\\x41'; let b = '\\u{1f980}'; let c = b'\\xFF'; let tail = 1;");
        assert!(diagnostics.is_empty());
        let characters: Vec<_> = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Literal(LiteralKind::Char))
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(characters, vec!["'\\x41'", "'\\u{1f980}'", "b'\\xFF'"]);
        assert!(tokens.iter().any(|token| token.text.as_str() == "tail"));
    }

    #[test]
    fn integer_suffixes_do_not_turn_into_exponents() {
        let (tokens, diagnostics) = lex("a[1usize+x]; b[1isize+y]; c[1e2+z]");
        assert!(diagnostics.is_empty());
        let literals: Vec<_> = tokens
            .iter()
            .filter(|token| matches!(token.kind, TokenKind::Literal(_)))
            .map(|token| (token.kind, token.text.as_str()))
            .collect();
        assert_eq!(
            literals,
            vec![
                (TokenKind::Literal(LiteralKind::Integer), "1usize"),
                (TokenKind::Literal(LiteralKind::Integer), "1isize"),
                (TokenKind::Literal(LiteralKind::Float), "1e2"),
            ]
        );
    }

    #[test]
    fn handles_raw_and_byte_strings() {
        // Source: let a = r#"x "q" y"#; let b = b"z"; let c = br#"w"#;
        let src = "let a = r#\"x \"q\" y\"#; let b = b\"z\"; let c = br#\"w\"#;";
        let (tokens, diags) = lex(src);
        assert!(diags.is_empty());
        let strings: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::String))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(strings, vec!["r#\"x \"q\" y\"#", "b\"z\"", "br#\"w\"#"]);
    }

    #[test]
    fn keeps_multi_hash_raw_strings_and_following_tokens() {
        let hashes_255 = "#".repeat(255);
        let source = format!(
            "let a = r##\"a \" b\"##; let b = r###\"c \" d\"###; let c = r{hashes_255}\"e \" f\"{hashes_255}; let tail = 1;"
        );
        let (tokens, diagnostics) = lex(&source);
        assert!(diagnostics.is_empty());

        let strings: Vec<_> = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Literal(LiteralKind::String))
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(
            strings,
            vec![
                "r##\"a \" b\"##",
                "r###\"c \" d\"###",
                format!("r{hashes_255}\"e \" f\"{hashes_255}").as_str(),
            ]
        );
        assert!(tokens.iter().any(|token| token.text.as_str() == "tail"));
    }

    #[test]
    fn handles_c_and_raw_c_strings() {
        let (tokens, diagnostics) = lex("let a = c\"path\"; let b = cr#\"raw # path\"#; tail();");
        assert!(diagnostics.is_empty());
        let strings: Vec<_> = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Literal(LiteralKind::String))
            .map(|token| token.text.as_str())
            .collect();
        assert_eq!(strings, vec!["c\"path\"", "cr#\"raw # path\"#"]);
        assert!(tokens.iter().any(|token| token.text.as_str() == "tail"));
    }

    #[test]
    fn unterminated_string_is_diagnosed() {
        // A string runs to end of file (Rust strings may span newlines), so an
        // unterminated one is diagnosed rather than silently accepted.
        let (_tokens, diags) = lex("let s = \"open;\nfn next() {}");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::UnterminatedString);
    }

    #[test]
    fn recovers_after_an_unexpected_character() {
        // A stray non-lexable character is diagnosed, then lexing continues and
        // the following function is still tokenized.
        let (tokens, diags) = lex("let x = \u{20ac}; fn next() {}");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::UnexpectedCharacter);
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Keyword && t.text == "fn")
        );
    }

    #[test]
    fn macro_invocation_is_plain_tokens() {
        let pairs: Vec<_> = lex("println!(\"{}\", x);")
            .0
            .into_iter()
            .map(|t| (t.kind, t.text))
            .collect();
        assert_eq!(pairs[0].0, TokenKind::Identifier);
        assert_eq!(pairs[0].1, "println");
        assert_eq!(pairs[1].0, TokenKind::Punctuation);
        assert_eq!(pairs[1].1, "!");
    }

    #[test]
    fn spans_are_byte_accurate_for_multibyte_source() {
        // The identifier `x` follows a two-byte `é` and a space.
        let (tokens, _) = lex("é x");
        let x = tokens.iter().find(|t| t.text == "x").expect("x token");
        assert_eq!(x.span.start_byte, 3);
        assert_eq!(x.span.end_byte, 4);
    }

    #[test]
    fn skips_a_leading_utf8_bom_without_shifting_source_columns() {
        let (tokens, diagnostics) = lex("\u{feff}fn f() {}");
        assert!(diagnostics.is_empty());

        let keyword = &tokens[0];
        assert_eq!(keyword.kind, TokenKind::Keyword);
        assert_eq!(keyword.text, "fn");
        assert_eq!(keyword.span.start_byte, 3);
        assert_eq!(keyword.span.start_line, 1);
        assert_eq!(keyword.span.start_column, 1);
    }
}
