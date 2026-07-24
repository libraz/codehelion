//! Error-tolerant lexer for the C language family.
//!
//! Whitespace and comments are dropped. Preprocessor directives are dropped
//! whole (through their `\` line continuations): Fast mode does not
//! preprocess, so both sides of an `#if` stay in the stream as ordinary
//! tokens while the directive lines themselves never pollute clone content.
//! Every other lexeme becomes a token carrying its raw text and a
//! reporting-only source span. Malformed spans (unterminated strings,
//! characters and block comments) are recorded as diagnostics and lexing
//! resumes, so a single broken construct never discards the rest of the file.
//! Macros are not expanded: an invocation's name and delimiters are ordinary
//! tokens.
//!
//! The lexer is parameterized by a [`Dialect`], which supplies the keyword
//! set, the operator inventory and the dialect-only literal forms (raw
//! strings, digit separators), so the same machinery lexes both C and C++.

use codehelion_core::frontend::{
    Diagnostic, DiagnosticKind, LexemeInterner, LiteralKind, SourceSpan, Token, TokenKind,
};

use crate::dialect::Dialect;

/// Raw-string prefixes, longest first (C++ only; gated by the dialect).
const RAW_STRING_PREFIXES: &[&str] = &["u8R", "LR", "uR", "UR", "R"];

/// Encoding prefixes of ordinary string and character literals, longest first.
const TEXT_PREFIXES: &[&str] = &["u8", "L", "u", "U"];

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

struct Lexer<'d, 's> {
    dialect: &'d Dialect,
    source: &'s str,
    chars: Vec<char>,
    byte_at: Vec<usize>,
    i: usize,
    line: u32,
    column: u32,
    /// Whether a token has been emitted on the current line; a `#` may only
    /// start a preprocessor directive when nothing but whitespace and
    /// comments precede it on its line.
    line_has_token: bool,
    interner: LexemeInterner,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
}

/// A position captured at the start of a token.
#[derive(Clone, Copy)]
struct Mark {
    index: usize,
    line: u32,
    column: u32,
}

impl<'d, 's> Lexer<'d, 's> {
    fn new(source: &'s str, dialect: &'d Dialect) -> Self {
        let chars: Vec<char> = source.chars().collect();
        let mut byte_at = Vec::with_capacity(chars.len() + 1);
        let mut byte = 0;
        for c in &chars {
            byte_at.push(byte);
            byte += c.len_utf8();
        }
        byte_at.push(source.len());
        Self {
            dialect,
            source,
            chars,
            byte_at,
            i: 0,
            line: 1,
            column: 1,
            line_has_token: false,
            interner: LexemeInterner::new(),
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// The source text between a mark and the current position.
    fn text_from(&self, start: Mark) -> &'s str {
        &self.source[self.byte_at[start.index]..self.byte_at[self.i]]
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.i + ahead).copied()
    }

    const fn mark(&self) -> Mark {
        Mark {
            index: self.i,
            line: self.line,
            column: self.column,
        }
    }

    /// Consume the current character, tracking line and column.
    fn bump(&mut self) {
        if let Some(c) = self.chars.get(self.i) {
            if *c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.i += 1;
        }
    }

    fn span_from(&self, start: Mark) -> SourceSpan {
        SourceSpan {
            start_byte: self.byte_at[start.index],
            end_byte: self.byte_at[self.i],
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

    /// Whether a `\` at the current position splices the line; if so consume
    /// it together with its line break.
    fn try_line_splice(&mut self) -> bool {
        if self.peek(0) != Some('\\') {
            return false;
        }
        match (self.peek(1), self.peek(2)) {
            (Some('\n'), _) => {
                self.bump();
                self.bump();
                true
            }
            (Some('\r'), Some('\n')) => {
                self.bump();
                self.bump();
                self.bump();
                true
            }
            _ => false,
        }
    }

    fn run(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        while let Some(c) = self.peek(0) {
            if c.is_whitespace() {
                if c == '\n' {
                    self.line_has_token = false;
                }
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
            if c == '#' && !self.line_has_token {
                self.consume_directive();
                continue;
            }
            if self.try_line_splice() {
                continue;
            }
            self.line_has_token = true;
            if self.try_prefixed_literal() {
                continue;
            }
            if c == '"' {
                let start = self.mark();
                self.consume_string_from(start);
                continue;
            }
            if c == '\'' {
                let start = self.mark();
                self.consume_char_from(start);
                continue;
            }
            if c.is_ascii_digit() || (c == '.' && self.peek(1).is_some_and(|d| d.is_ascii_digit()))
            {
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
            if self.try_line_splice() {
                // A spliced line continues the comment.
                continue;
            }
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }

    /// Consume a `/* ... */` comment. C-family block comments do not nest.
    fn consume_block_comment(&mut self) {
        let start = self.mark();
        // Skip the opening `/*`.
        self.bump();
        self.bump();
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some('*'), Some('/')) => {
                    self.bump();
                    self.bump();
                    break;
                }
                (Some(_), _) => self.bump(),
                (None, _) => {
                    self.diagnose(DiagnosticKind::UnterminatedBlockComment, start);
                    break;
                }
            }
        }
        // A comment that crossed onto a new line leaves that line still
        // "empty": a `#` after it is that line's first token and may start a
        // directive.
        if self.line > start.line {
            self.line_has_token = false;
        }
    }

    /// Consume a preprocessor directive from its `#` through the end of the
    /// logical line, honouring `\` line continuations and embedded comments.
    fn consume_directive(&mut self) {
        while let Some(c) = self.peek(0) {
            if self.try_line_splice() {
                continue;
            }
            if c == '\\' {
                self.bump();
                continue;
            }
            if c == '\n' {
                // Leave the newline for the main loop, which resets the
                // line state.
                return;
            }
            if c == '/' && self.peek(1) == Some('*') {
                self.consume_block_comment();
                continue;
            }
            if c == '/' && self.peek(1) == Some('/') {
                self.consume_line_comment();
                return;
            }
            self.bump();
        }
    }

    fn matches_ahead(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(k, ch)| self.peek(k) == Some(ch))
    }

    /// Handle encoding-prefixed and raw string/character literals (`L"..."`,
    /// `u8'...'`, `R"(...)"`, ...). Returns `true` if a token was produced.
    fn try_prefixed_literal(&mut self) -> bool {
        if self.dialect.raw_strings {
            for prefix in RAW_STRING_PREFIXES {
                if self.matches_ahead(prefix) && self.peek(prefix.len()) == Some('"') {
                    let start = self.mark();
                    for _ in 0..prefix.len() {
                        self.bump();
                    }
                    self.consume_raw_string_body(start);
                    return true;
                }
            }
        }
        for prefix in TEXT_PREFIXES {
            if !self.matches_ahead(prefix) {
                continue;
            }
            match self.peek(prefix.len()) {
                Some('"') => {
                    let start = self.mark();
                    for _ in 0..prefix.len() {
                        self.bump();
                    }
                    self.consume_string_from(start);
                    return true;
                }
                Some('\'') => {
                    let start = self.mark();
                    for _ in 0..prefix.len() {
                        self.bump();
                    }
                    self.consume_char_from(start);
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Consume a string literal; the current character is the opening `"` and
    /// `start` marks the beginning of the whole literal (including any
    /// encoding prefix). An unescaped line break ends the literal with a
    /// diagnostic, so a missing quote never swallows the rest of the file.
    fn consume_string_from(&mut self, start: Mark) {
        // Opening `"`.
        self.bump();
        loop {
            match self.peek(0) {
                None | Some('\n') => {
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

    /// Consume a character literal (multi-character constants included); the
    /// current character is the opening `'`.
    fn consume_char_from(&mut self, start: Mark) {
        // Opening `'`.
        self.bump();
        loop {
            match self.peek(0) {
                None | Some('\n') => {
                    self.push(TokenKind::Literal(LiteralKind::Char), start);
                    self.diagnose(DiagnosticKind::UnterminatedChar, start);
                    return;
                }
                Some('\\') => {
                    self.bump();
                    self.bump();
                }
                Some('\'') => {
                    self.bump();
                    self.push(TokenKind::Literal(LiteralKind::Char), start);
                    return;
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// Consume a raw string body; the current character is the opening `"`
    /// and `start` marks the whole literal including its `R` prefix.
    fn consume_raw_string_body(&mut self, start: Mark) {
        // Opening `"`.
        self.bump();
        let mut delim: Vec<char> = Vec::new();
        loop {
            match self.peek(0) {
                Some('(') => {
                    self.bump();
                    break;
                }
                Some(c)
                    if c != '"'
                        && c != ')'
                        && c != '\\'
                        && !c.is_whitespace()
                        && delim.len() < 16 =>
                {
                    delim.push(c);
                    self.bump();
                }
                _ => {
                    // Malformed delimiter: emit what we have as a broken string.
                    self.push(TokenKind::Literal(LiteralKind::String), start);
                    self.diagnose(DiagnosticKind::UnterminatedString, start);
                    return;
                }
            }
        }
        loop {
            match self.peek(0) {
                None => {
                    self.push(TokenKind::Literal(LiteralKind::String), start);
                    self.diagnose(DiagnosticKind::UnterminatedString, start);
                    return;
                }
                Some(')') => {
                    let closes = delim
                        .iter()
                        .enumerate()
                        .all(|(k, &dc)| self.peek(1 + k) == Some(dc))
                        && self.peek(1 + delim.len()) == Some('"');
                    if closes {
                        for _ in 0..(delim.len() + 2) {
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
        let hex = self.peek(0) == Some('0') && matches!(self.peek(1), Some('x' | 'X'));
        let mut is_float = false;
        while let Some(ch) = self.peek(0) {
            if ch == '.' {
                // Do not swallow a `...` (GNU case ranges like `1 ... 5`).
                if self.peek(1) == Some('.') {
                    break;
                }
                is_float = true;
                self.bump();
            } else if !hex && matches!(ch, 'e' | 'E') {
                is_float = true;
                self.bump();
                if matches!(self.peek(0), Some('+' | '-')) {
                    self.bump();
                }
            } else if hex && matches!(ch, 'p' | 'P') {
                // Hexadecimal floats use a `p` exponent.
                is_float = true;
                self.bump();
                if matches!(self.peek(0), Some('+' | '-')) {
                    self.bump();
                }
            } else if ch == '\''
                && self.dialect.digit_separators
                && self.peek(1).is_some_and(|c| c.is_ascii_alphanumeric())
            {
                // Digit separator, kept in the raw text.
                self.bump();
            } else if is_ident_continue(ch) {
                self.bump();
            } else {
                break;
            }
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
        while self.peek(0).is_some_and(is_ident_continue) {
            self.bump();
        }
        let kind = if self.dialect.keywords.contains(&self.text_from(start)) {
            TokenKind::Keyword
        } else {
            TokenKind::Identifier
        };
        self.push(kind, start);
    }

    fn consume_punct(&mut self) {
        let start = self.mark();
        for op in self.dialect.multi_punct {
            if self.matches_ahead(op) {
                for _ in 0..op.chars().count() {
                    self.bump();
                }
                self.push(TokenKind::Punctuation, start);
                return;
            }
        }
        // Single character. ASCII punctuation is punctuation; anything else
        // that reached here is not lexable.
        let c = self.peek(0).unwrap_or('\0');
        self.bump();
        if c.is_ascii() && !c.is_alphanumeric() {
            self.push(TokenKind::Punctuation, start);
        } else {
            self.push(TokenKind::Unknown, start);
            self.diagnose(DiagnosticKind::UnexpectedCharacter, start);
        }
    }
}

/// Lex `source` under `dialect` into tokens and diagnostics.
#[must_use]
pub fn lex(source: &str, dialect: &Dialect) -> (Vec<Token>, Vec<Diagnostic>) {
    Lexer::new(source, dialect).run()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dialect;

    fn lex_c(source: &str) -> (Vec<Token>, Vec<Diagnostic>) {
        lex(source, &dialect::C)
    }

    fn texts(source: &str) -> Vec<String> {
        lex_c(source).0.iter().map(|t| t.text.to_string()).collect()
    }

    #[test]
    fn splits_keywords_identifiers_and_operators() {
        let (tokens, diags) = lex_c("static int add(int a, struct pair *p) { return a + p->x; }");
        assert!(diags.is_empty());
        let pairs: Vec<_> = tokens.iter().map(|t| (t.kind, t.text.as_str())).collect();
        assert_eq!(pairs[0], (TokenKind::Keyword, "static"));
        assert_eq!(pairs[1], (TokenKind::Keyword, "int"));
        assert_eq!(pairs[2], (TokenKind::Identifier, "add"));
        assert!(pairs.contains(&(TokenKind::Punctuation, "->")));
        assert!(pairs.contains(&(TokenKind::Keyword, "struct")));
    }

    #[test]
    fn drops_comments_and_whitespace() {
        let src = "int x; // trailing\n/* block\nspanning lines */ int y;";
        let texts = texts(src);
        assert!(!texts.iter().any(|t| t.contains("trailing")));
        assert!(!texts.iter().any(|t| t.contains("spanning")));
        assert!(texts.contains(&"x".to_string()));
        assert!(texts.contains(&"y".to_string()));
    }

    #[test]
    fn preprocessor_directives_are_dropped_whole() {
        let src = "#include <stdio.h>\n#define TWICE(x) \\\n    ((x) + (x))\nint y;\n";
        let (tokens, diags) = lex_c(src);
        assert!(diags.is_empty());
        let texts: Vec<_> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, vec!["int", "y", ";"]);
    }

    #[test]
    fn directive_after_a_multiline_comment_is_still_a_directive() {
        let src = "int x; /* comment\nspanning */ #define GONE 1\nint y;";
        let texts = texts(src);
        assert_eq!(texts, vec!["int", "x", ";", "int", "y", ";"]);
    }

    #[test]
    fn a_hash_after_code_on_the_same_line_is_ordinary_punctuation() {
        // Not a directive: `#` is not the first token of its line.
        let (tokens, _) = lex_c("int a; # 1\nint b;");
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Punctuation && t.text == "#")
        );
    }

    #[test]
    fn conditional_compilation_keeps_both_branches() {
        let src = "#if FLAG\nint a;\n#else\nint b;\n#endif\n";
        let texts = texts(src);
        assert_eq!(texts, vec!["int", "a", ";", "int", "b", ";"]);
    }

    #[test]
    fn strings_and_chars_lex_with_escapes_and_prefixes() {
        let (tokens, diags) = lex_c("char *s = \"a \\\"q\\\" b\"; char c = 'x'; int m = 'ab';");
        assert!(diags.is_empty());
        let strings: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::String))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(strings, vec!["\"a \\\"q\\\" b\""]);
        let chars: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::Char))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(chars, vec!["'x'", "'ab'"]);

        let (tokens, diags) = lex_c("const wchar_t *w = L\"wide\"; int u = u8\"n\"[0];");
        assert!(diags.is_empty());
        let strings: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Literal(LiteralKind::String))
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(strings, vec!["L\"wide\"", "u8\"n\""]);
    }

    #[test]
    fn unterminated_string_recovers_at_the_line_break() {
        let (tokens, diags) = lex_c("char *s = \"open;\nint next;");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::UnterminatedString);
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Keyword && t.text == "int"),
            "lexing must continue on the next line"
        );
    }

    #[test]
    fn unterminated_char_and_block_comment_are_diagnosed() {
        let (_, diags) = lex_c("char c = 'x\nint y;");
        assert!(
            diags
                .iter()
                .any(|d| d.kind == DiagnosticKind::UnterminatedChar)
        );
        let (_, diags) = lex_c("int x; /* open");
        assert!(
            diags
                .iter()
                .any(|d| d.kind == DiagnosticKind::UnterminatedBlockComment)
        );
    }

    #[test]
    fn numbers_cover_hex_float_and_suffix_forms() {
        let (tokens, diags) = lex_c(
            "int a = 0xFF; double b = 1.5e3; double c = 0x1.8p3; long d = 100UL; float e = .5f; float f = 1.f;",
        );
        assert!(diags.is_empty());
        let by_text = |needle: &str| {
            tokens
                .iter()
                .find(|t| t.text == needle)
                .unwrap_or_else(|| panic!("token {needle} missing"))
                .kind
        };
        assert_eq!(by_text("0xFF"), TokenKind::Literal(LiteralKind::Integer));
        assert_eq!(by_text("1.5e3"), TokenKind::Literal(LiteralKind::Float));
        assert_eq!(by_text("0x1.8p3"), TokenKind::Literal(LiteralKind::Float));
        assert_eq!(by_text("100UL"), TokenKind::Literal(LiteralKind::Integer));
        assert_eq!(by_text(".5f"), TokenKind::Literal(LiteralKind::Float));
        assert_eq!(by_text("1.f"), TokenKind::Literal(LiteralKind::Float));
    }

    #[test]
    fn recovers_after_an_unexpected_character() {
        let (tokens, diags) = lex_c("int x = \u{20ac}; int next;");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::UnexpectedCharacter);
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Identifier && t.text == "next")
        );
    }

    #[test]
    fn line_splices_join_code_lines() {
        // A backslash-newline inside ordinary code is consumed as whitespace.
        let texts = texts("int a \\\n= 1;");
        assert_eq!(texts, vec!["int", "a", "=", "1", ";"]);
    }

    #[test]
    fn raw_strings_do_not_exist_in_c() {
        // `R"(x)"` in C is the identifier `R` followed by an ordinary string.
        let (tokens, diags) = lex_c("R\"(x)\"");
        assert!(diags.is_empty());
        assert_eq!(tokens[0].kind, TokenKind::Identifier);
        assert_eq!(tokens[0].text, "R");
        assert_eq!(tokens[1].kind, TokenKind::Literal(LiteralKind::String));
    }

    #[test]
    fn spans_are_byte_accurate() {
        let (tokens, _) = lex_c("int x;");
        let x = tokens.iter().find(|t| t.text == "x").expect("x token");
        assert_eq!(x.span.start_byte, 4);
        assert_eq!(x.span.end_byte, 5);
        assert_eq!(x.span.start_line, 1);
    }
}
