//! The Fast-frontend interface.
//!
//! A frontend turns a source file into a flat token stream with comments and
//! whitespace removed, plus the coarse unit boundaries (functions, methods,
//! `impl` blocks, closures) used later as clone-report anchors. Lexing is
//! error-tolerant: a malformed span becomes a [`Diagnostic`] and lexing
//! continues, so one broken construct never discards the rest of a file.
//!
//! The frontend deliberately stops at lexing. Macros and templates are not
//! expanded; their invocations pass through as ordinary tokens. Normalization
//! (identifier renaming, literal folding) is applied downstream at fragment
//! scope, so the stream here carries each token's raw lexeme unchanged.
//!
//! Source positions are recorded for reporting only. They are never used as
//! stable identifiers: fingerprints are built from token kinds and normalized
//! text, never from a line number or token offset.

use crate::discovery::Language;

/// Category of a literal token, used by literal-normalization strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteralKind {
    /// Integer literal, e.g. `42`, `0xff`, `1_000`.
    Integer,
    /// Floating-point literal, e.g. `1.5`, `2e10`.
    Float,
    /// String literal, including raw and byte strings.
    String,
    /// Character or byte-character literal.
    Char,
    /// Boolean literal (`true` / `false`).
    Bool,
}

/// The lexical category of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// An identifier (including raw identifiers).
    Identifier,
    /// A language keyword.
    Keyword,
    /// A literal of the given category.
    Literal(LiteralKind),
    /// A lifetime or label, e.g. `'a`.
    Lifetime,
    /// An operator or delimiter.
    Punctuation,
    /// Input that could not be lexed into any of the above.
    Unknown,
}

impl TokenKind {
    /// A stable one-byte tag for this kind, for use as fingerprint input.
    ///
    /// The literal sub-category does not affect the tag: whether two literals
    /// are considered equal is a normalization decision, made downstream.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Identifier => 1,
            Self::Keyword => 2,
            Self::Literal(_) => 3,
            Self::Punctuation => 4,
            Self::Lifetime => 5,
            Self::Unknown => 6,
        }
    }
}

/// A source position span, recorded for reporting only.
///
/// `start_byte`/`end_byte` are byte offsets into the source; `start_line` and
/// `start_column` are 1-based and counted in characters. None of these fields
/// may be used to derive a stable identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// Byte offset of the span start.
    pub start_byte: usize,
    /// Byte offset one past the span end.
    pub end_byte: usize,
    /// 1-based line of the span start.
    pub start_line: u32,
    /// 1-based column (in characters) of the span start.
    pub start_column: u32,
}

/// One lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Lexical category.
    pub kind: TokenKind,
    /// The raw lexeme exactly as it appeared in the source.
    pub text: String,
    /// Source position, for reporting only.
    pub span: SourceSpan,
}

/// The kind of a lexing problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    /// A string literal was not closed before end of file.
    UnterminatedString,
    /// A character or byte literal was not closed before end of file.
    UnterminatedChar,
    /// A block comment was not closed before end of file.
    UnterminatedBlockComment,
    /// A byte that does not begin any valid token.
    UnexpectedCharacter,
}

/// A recoverable lexing problem. Lexing continues past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// What went wrong.
    pub kind: DiagnosticKind,
    /// Where it happened.
    pub span: SourceSpan,
}

/// The kind of a coarse code unit used as a clone-report anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKind {
    /// A free function.
    Function,
    /// A method (a function inside an `impl` block).
    Method,
    /// An `impl` block.
    Impl,
    /// A closure with a block body.
    Closure,
}

impl UnitKind {
    /// Stable lowercase identifier used in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::Impl => "impl",
            Self::Closure => "closure",
        }
    }
}

/// A coarse code unit: a token range plus its source span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The unit's kind.
    pub kind: UnitKind,
    /// The unit's name, when the frontend can recover one.
    pub name: Option<String>,
    /// Index of the unit's first token in the stream.
    pub token_start: usize,
    /// Index one past the unit's last token in the stream.
    pub token_end: usize,
    /// Source span covering the unit, for reporting.
    pub span: SourceSpan,
}

/// The result of lexing one source file.
#[derive(Debug, Clone)]
pub struct LexedFile {
    /// Language the file was lexed as.
    pub language: Language,
    /// Version tag of the frontend that produced this result; a fingerprint
    /// input, so a change to lexing that alters output must change it.
    pub frontend_version: &'static str,
    /// Tokens in source order, comments and whitespace removed.
    pub tokens: Vec<Token>,
    /// Coarse unit boundaries, in source order.
    pub units: Vec<Unit>,
    /// Recoverable problems encountered while lexing.
    pub diagnostics: Vec<Diagnostic>,
}

/// A Fast-mode lexer for one language.
pub trait Frontend {
    /// The language this frontend lexes.
    fn language(&self) -> Language;

    /// The frontend's version tag, used as a fingerprint input.
    fn frontend_version(&self) -> &'static str;

    /// Lex `source` into a token stream with unit boundaries and diagnostics.
    fn lex(&self, source: &str) -> LexedFile;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_tags_are_distinct_and_stable() {
        let tags = [
            TokenKind::Identifier.tag(),
            TokenKind::Keyword.tag(),
            TokenKind::Literal(LiteralKind::Integer).tag(),
            TokenKind::Punctuation.tag(),
            TokenKind::Lifetime.tag(),
            TokenKind::Unknown.tag(),
        ];
        let mut sorted = tags.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len(), "tags must be distinct");
        // The literal sub-category does not change the tag.
        assert_eq!(
            TokenKind::Literal(LiteralKind::Integer).tag(),
            TokenKind::Literal(LiteralKind::String).tag()
        );
    }

    #[test]
    fn unit_kind_names_are_stable() {
        assert_eq!(UnitKind::Function.name(), "function");
        assert_eq!(UnitKind::Method.name(), "method");
        assert_eq!(UnitKind::Impl.name(), "impl");
        assert_eq!(UnitKind::Closure.name(), "closure");
    }
}
