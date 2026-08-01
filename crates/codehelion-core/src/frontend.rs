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

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use crate::discovery::Language;

/// A shared, immutable lexeme.
///
/// Token text is stored behind a shared pointer so that every occurrence of
/// the same lexeme in a file shares one allocation instead of owning a copy;
/// with millions of tokens in scope this is the difference between hundreds
/// of megabytes and a few. Equality, ordering and hashing follow the text
/// content, and the type dereferences to [`str`], so call sites treat it
/// like a borrowed string.
#[derive(Debug, Clone, Eq)]
pub struct Lexeme(Arc<str>);

impl Lexeme {
    /// The lexeme text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Lexeme {
    fn eq(&self, other: &Self) -> bool {
        // Interned lexemes of one file share their allocation, so pointer
        // identity settles most comparisons without touching the bytes.
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}

impl std::hash::Hash for Lexeme {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Must agree with `str::hash` for `Borrow<str>` lookups.
        self.0.hash(state);
    }
}

impl Deref for Lexeme {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Lexeme {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Lexeme {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Lexeme {
    fn from(text: &str) -> Self {
        Self(Arc::from(text))
    }
}

impl PartialEq<str> for Lexeme {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for Lexeme {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl fmt::Display for Lexeme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deduplicating store of [`Lexeme`]s, typically one per lexed file.
///
/// Interning the same text twice returns two handles to one allocation. The
/// interner is an implementation detail of memory layout: it never affects
/// token equality or fingerprints, which follow text content only.
#[derive(Debug, Default)]
pub struct LexemeInterner {
    known: HashSet<Lexeme>,
}

impl LexemeInterner {
    /// Create an empty interner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the shared lexeme for `text`, allocating it once.
    pub fn intern(&mut self, text: &str) -> Lexeme {
        if let Some(found) = self.known.get(text) {
            return found.clone();
        }
        let lexeme = Lexeme::from(text);
        self.known.insert(lexeme.clone());
        lexeme
    }
}

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
    pub text: Lexeme,
    /// Source position, for reporting only.
    pub span: SourceSpan,
}

/// The kind of a recoverable Fast-frontend problem.
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
    /// An opening delimiter needed by a unit boundary had no matching closer.
    UnmatchedDelimiter,
}

/// A recoverable Fast-frontend problem. Analysis continues past it.
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
    /// A method (a function inside an `impl` block or a record body).
    Method,
    /// An `impl` block.
    Impl,
    /// A record body: a `class`, `struct` or `union` definition.
    Record,
    /// A closure or lambda with a block body.
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
            Self::Record => "record",
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
    fn interning_shares_one_allocation_per_text() {
        let mut interner = LexemeInterner::new();
        let a = interner.intern("alpha");
        let b = interner.intern("alpha");
        let c = interner.intern("beta");
        assert!(Arc::ptr_eq(&a.0, &b.0), "same text must share storage");
        assert!(!Arc::ptr_eq(&a.0, &c.0));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn lexeme_equality_and_hash_follow_content_across_interners() {
        let a = LexemeInterner::new().intern("shared");
        let b = LexemeInterner::new().intern("shared");
        assert!(
            !Arc::ptr_eq(&a.0, &b.0),
            "distinct interners allocate separately"
        );
        assert_eq!(a, b, "equality is by content, not by pointer");
        let set: HashSet<Lexeme> = [a].into();
        assert!(set.contains("shared"), "str lookups must hash consistently");
    }

    #[test]
    fn lexeme_compares_against_plain_strings() {
        let lexeme = Lexeme::from("fn");
        assert_eq!(lexeme, "fn");
        assert_eq!(lexeme.as_str(), "fn");
        assert_eq!(lexeme.to_string(), "fn");
        assert_eq!(lexeme.as_bytes(), b"fn");
    }

    #[test]
    fn unit_kind_names_are_stable() {
        assert_eq!(UnitKind::Function.name(), "function");
        assert_eq!(UnitKind::Method.name(), "method");
        assert_eq!(UnitKind::Impl.name(), "impl");
        assert_eq!(UnitKind::Closure.name(), "closure");
    }
}
