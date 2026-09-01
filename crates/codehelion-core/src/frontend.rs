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
//!
//! The module also owns [`IrAssembly`], the parser-independent half of a
//! Structural frontend: line mapping, token interning, byte-to-token lookup
//! and the recovery data a depth-limited walk produces. Every Structural
//! frontend assembles its file through it, so a fix to any of those concerns
//! reaches all languages at once instead of one grammar at a time.

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use crate::discovery::Language;
use crate::ir::{ByteRange, IrNode, Shape};

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

/// The tokens a recorded range covers, clamped to the stream it addresses.
///
/// An error-tolerant frontend may hand back a unit whose token range reaches
/// past the tokens it recovered, and a range recorded against one stream may be
/// read against another. Every reader clamps here rather than at its own call
/// site: two call sites that clamp differently would fingerprint the same code
/// under two identities, which is a worse defect than the out-of-range read the
/// clamp exists to prevent. A start past the end yields an empty slice, as does
/// an end before the start.
#[must_use]
pub fn tokens_in_range(tokens: &[Token], token_start: usize, token_end: usize) -> &[Token] {
    let start = token_start.min(tokens.len());
    let end = token_end.min(tokens.len()).max(start);
    &tokens[start..end]
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

/// The token stream and recovery data of one assembled Structural file.
///
/// Produced by [`IrAssembly::finish`]; the error ranges are sorted by start
/// then end and deduplicated, which is the order every frontend records them
/// in.
#[derive(Debug, Clone)]
pub struct AssembledIr {
    /// Tokens in source order, comments and whitespace removed.
    pub tokens: Vec<Token>,
    /// Byte ranges the frontend could not map onto shapes.
    pub error_ranges: Vec<ByteRange>,
    /// Whether any subtree was cut short by the IR depth budget.
    pub depth_truncated: bool,
}

/// The parser-independent half of a Structural frontend.
///
/// A frontend owns its grammar cursor and its node-classification table; the
/// rest — interning lexemes, converting byte offsets to line/column, mapping a
/// node's byte range onto token indices, and recording what a depth-limited
/// walk had to leave out — is the same work in every language and lives here.
///
/// Token indices address the stream this type accumulates, so nodes must be
/// built after the file's tokens have been pushed.
#[derive(Debug)]
pub struct IrAssembly<'s> {
    source: &'s str,
    /// Byte offset of the start of each source line.
    line_starts: Vec<usize>,
    interner: LexemeInterner,
    tokens: Vec<Token>,
    /// Byte start of each emitted token, for mapping node byte ranges onto
    /// token index ranges by binary search.
    token_starts: Vec<usize>,
    error_ranges: Vec<ByteRange>,
    depth_truncated: bool,
}

impl<'s> IrAssembly<'s> {
    /// Start assembling the file `source`.
    #[must_use]
    pub fn new(source: &'s str) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }
        Self {
            source,
            line_starts,
            interner: LexemeInterner::new(),
            tokens: Vec::new(),
            token_starts: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
        }
    }

    /// The source text being assembled.
    #[must_use]
    pub const fn source(&self) -> &'s str {
        self.source
    }

    /// Return the shared lexeme for `text`, allocating it once per file.
    pub fn intern(&mut self, text: &str) -> Lexeme {
        self.interner.intern(text)
    }

    /// 1-based line and character column of a byte offset.
    #[must_use]
    pub fn line_column(&self, byte: usize) -> (u32, u32) {
        let line_index = self
            .line_starts
            .partition_point(|&start| start <= byte)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        let column_chars = self
            .source
            .get(line_start..byte)
            .map_or(0, |prefix| prefix.chars().count());
        (
            u32::try_from(line_index + 1).unwrap_or(u32::MAX),
            u32::try_from(column_chars + 1).unwrap_or(u32::MAX),
        )
    }

    /// The reporting span of `start_byte..end_byte` in this source.
    #[must_use]
    pub fn span(&self, start_byte: usize, end_byte: usize) -> SourceSpan {
        let (start_line, start_column) = self.line_column(start_byte);
        SourceSpan {
            start_byte,
            end_byte,
            start_line,
            start_column,
        }
    }

    /// Append a token covering `start_byte..end_byte`, computing its position.
    ///
    /// Tokens must be pushed in source order: the byte-to-token lookup binary
    /// searches the starts recorded here.
    pub fn push_token(&mut self, kind: TokenKind, text: &str, start_byte: usize, end_byte: usize) {
        let span = self.span(start_byte, end_byte);
        self.push_spanned_token(kind, text, span);
    }

    /// Append a token whose span was established elsewhere.
    ///
    /// Used where the positions come from a stream lexed over the whole file
    /// while the assembly itself only covers a prefix of it.
    pub fn push_spanned_token(&mut self, kind: TokenKind, text: &str, span: SourceSpan) {
        let text = self.interner.intern(text);
        self.token_starts.push(span.start_byte);
        self.tokens.push(Token { kind, text, span });
    }

    /// Number of tokens appended so far, which is also the index the next one
    /// will take.
    #[must_use]
    pub const fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Index of the first appended token starting at or after `byte`.
    #[must_use]
    pub fn token_index_at(&self, byte: usize) -> usize {
        self.token_starts.partition_point(|&start| start < byte)
    }

    /// The token index range a node's byte range covers.
    #[must_use]
    pub fn token_bounds(&self, range: ByteRange) -> (usize, usize) {
        (
            self.token_index_at(range.start),
            self.token_index_at(range.end),
        )
    }

    /// Record a byte range the frontend could not map onto shapes.
    pub fn record_error_range(&mut self, range: ByteRange) {
        self.error_ranges.push(range);
    }

    /// Whether a subtree was cut short by the IR depth budget.
    #[must_use]
    pub const fn depth_truncated(&self) -> bool {
        self.depth_truncated
    }

    /// Preserve an unvisited subtree as recoverable truncation data.
    ///
    /// Marks the file truncated, records `range` as an error range, and
    /// returns the [`Shape::Error`] leaf that stands in for the subtree. The
    /// leaf's token range covers the tokens the omitted subtree contributed,
    /// so a truncated file still addresses its own token stream correctly.
    pub fn truncate_at_depth(&mut self, range: ByteRange) -> IrNode {
        self.depth_truncated = true;
        self.record_error_range(range);
        self.error_node(range)
    }

    /// A childless [`Shape::Error`] leaf over `range`.
    #[must_use]
    pub fn error_node(&self, range: ByteRange) -> IrNode {
        let (token_start, token_end) = self.token_bounds(range);
        IrNode {
            shape: Shape::Error,
            name: None,
            token_start,
            token_end,
            range,
            children: Vec::new(),
        }
    }

    /// Finish the file: take the token stream and normalize the error ranges.
    #[must_use]
    pub fn finish(mut self) -> AssembledIr {
        self.error_ranges
            .sort_unstable_by_key(|range| (range.start, range.end));
        self.error_ranges.dedup();
        AssembledIr {
            tokens: self.tokens,
            error_ranges: self.error_ranges,
            depth_truncated: self.depth_truncated,
        }
    }
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

    /// The shared clamp answers exactly what every call site computed for
    /// itself before, including for the ranges an error-tolerant frontend can
    /// hand back: a fingerprint that moved because the clamp moved would be a
    /// worse defect than the out-of-range read the clamp prevents.
    #[test]
    fn the_shared_clamp_covers_the_tokens_each_call_site_clamped_to() {
        let token = |text: &str| Token {
            kind: TokenKind::Identifier,
            text: text.into(),
            span: SourceSpan {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_column: 1,
            },
        };
        let tokens = [token("a"), token("b"), token("c")];
        // What the call sites computed inline before there was one helper.
        let previous = |start: usize, end: usize| {
            let start = start.min(tokens.len());
            let end = end.min(tokens.len()).max(start);
            &tokens[start..end]
        };

        for (start, end) in [
            (0, 3),
            (1, 2),
            (2, 2),
            (0, 9),
            (5, 9),
            (3, 3),
            (2, 1),
            (9, 1),
        ] {
            assert_eq!(
                tokens_in_range(&tokens, start, end),
                previous(start, end),
                "range {start}..{end}"
            );
        }
        assert!(tokens_in_range(&tokens, 5, 9).is_empty());
        assert!(tokens_in_range(&tokens, 2, 1).is_empty());
        assert!(tokens_in_range(&[], 0, 4).is_empty());
        assert_eq!(tokens_in_range(&tokens, 1, 9).len(), 2);
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
    fn assembly_columns_count_characters_not_bytes() {
        let source = "let é = 1;\nlet b = 2;\n";
        let assembly = IrAssembly::new(source);
        let e_acute = source.find('é').unwrap_or_default();
        assert_eq!(assembly.line_column(0), (1, 1));
        assert_eq!(assembly.line_column(e_acute), (1, 5));
        // The token after the two-byte character is one column further right,
        // not two.
        assert_eq!(assembly.line_column(e_acute + 'é'.len_utf8()), (1, 6));
        let second_line = source.find("let b").unwrap_or_default();
        assert_eq!(assembly.line_column(second_line), (2, 1));
    }

    #[test]
    fn assembly_maps_byte_ranges_onto_token_indices() {
        let source = "a bb ccc";
        let mut assembly = IrAssembly::new(source);
        for (start, end) in [(0, 1), (2, 4), (5, 8)] {
            let text = source.get(start..end).unwrap_or_default();
            assembly.push_token(TokenKind::Identifier, text, start, end);
        }
        assert_eq!(assembly.token_count(), 3);
        // A range starting inside a token begins at the next whole token.
        assert_eq!(assembly.token_index_at(1), 1);
        assert_eq!(
            assembly.token_bounds(ByteRange { start: 2, end: 8 }),
            (1, 3)
        );
        assert_eq!(
            assembly.token_bounds(ByteRange {
                start: 0,
                end: source.len()
            }),
            (0, 3)
        );
    }

    #[test]
    fn assembly_records_a_depth_limited_subtree_as_an_error_leaf() {
        let source = "a bb ccc";
        let mut assembly = IrAssembly::new(source);
        for (start, end) in [(0, 1), (2, 4), (5, 8)] {
            let text = source.get(start..end).unwrap_or_default();
            assembly.push_token(TokenKind::Identifier, text, start, end);
        }
        assert!(!assembly.depth_truncated());
        let omitted = ByteRange { start: 2, end: 8 };
        let leaf = assembly.truncate_at_depth(omitted);
        assert_eq!(leaf.shape, Shape::Error);
        assert_eq!(leaf.name, None);
        assert_eq!((leaf.token_start, leaf.token_end), (1, 3));
        assert_eq!(leaf.range, omitted);
        assert!(leaf.children.is_empty());
        assert!(assembly.depth_truncated());
        let assembled = assembly.finish();
        assert!(assembled.depth_truncated);
        assert_eq!(assembled.error_ranges, vec![omitted]);
    }

    #[test]
    fn assembly_finishes_with_ordered_unique_error_ranges() {
        let mut assembly = IrAssembly::new("abc");
        for range in [(2, 3), (0, 1), (2, 3), (0, 2)] {
            assembly.record_error_range(ByteRange {
                start: range.0,
                end: range.1,
            });
        }
        let assembled = assembly.finish();
        assert_eq!(
            assembled.error_ranges,
            vec![
                ByteRange { start: 0, end: 1 },
                ByteRange { start: 0, end: 2 },
                ByteRange { start: 2, end: 3 },
            ]
        );
        assert!(!assembled.depth_truncated);
    }

    #[test]
    fn assembly_keeps_spans_established_elsewhere() {
        // Tokens of a region the assembly's own source does not cover carry
        // the positions the whole-file stream gave them.
        let mut assembly = IrAssembly::new("fn a() {}");
        let span = SourceSpan {
            start_byte: 900,
            end_byte: 901,
            start_line: 42,
            start_column: 7,
        };
        assembly.push_spanned_token(TokenKind::Punctuation, "}", span);
        let assembled = assembly.finish();
        assert_eq!(assembled.tokens.len(), 1);
        assert_eq!(assembled.tokens[0].span, span);
        assert_eq!(assembled.tokens[0].text, "}");
    }

    #[test]
    fn unit_kind_names_are_stable() {
        assert_eq!(UnitKind::Function.name(), "function");
        assert_eq!(UnitKind::Method.name(), "method");
        assert_eq!(UnitKind::Impl.name(), "impl");
        assert_eq!(UnitKind::Closure.name(), "closure");
    }
}
