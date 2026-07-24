//! Lexical dialect descriptions for the C language family.
//!
//! C and C++ share almost all of their lexical structure; what differs is the
//! keyword set, the operator inventory and a handful of literal forms. A
//! [`Dialect`] captures exactly those differences, so one lexer and one
//! unit-boundary detector serve both languages. The C dialect lives here; the
//! C++ dialect is defined by the C++ frontend crate on top of the same
//! machinery.

/// The lexical parameters distinguishing one C-family language from another.
#[derive(Debug, Clone, Copy)]
pub struct Dialect {
    /// Reserved words, lexed as [`TokenKind::Keyword`]. Contextual keywords
    /// (`override`, `final`) are deliberately absent: they lex as identifiers,
    /// matching how the language grammar treats them.
    ///
    /// [`TokenKind::Keyword`]: codehelion_core::frontend::TokenKind::Keyword
    pub keywords: &'static [&'static str],
    /// Multi-character operators, ordered longest first for greedy matching.
    pub multi_punct: &'static [&'static str],
    /// Whether `R"delim(...)delim"` raw string literals exist (C++ only).
    pub raw_strings: bool,
    /// Whether `'` may separate digits inside a number (C++14 and later).
    pub digit_separators: bool,
    /// Keywords that introduce a record body (`struct`, `union`, and for C++
    /// also `class`), reported as [`UnitKind::Record`] units.
    ///
    /// [`UnitKind::Record`]: codehelion_core::frontend::UnitKind::Record
    pub record_keywords: &'static [&'static str],
    /// Whether `[capture](params) { ... }` lambdas exist (C++ only).
    pub lambdas: bool,
}

/// C keywords: C11 plus the C23 spellings (`bool`, `true`, `nullptr`, ...).
///
/// Lexing a C11 file with C23 keywords is harmless — those spellings appear in
/// practice via `<stdbool.h>` and friends, and treating them uniformly keeps
/// token granularity stable across standard revisions.
const C_KEYWORDS: &[&str] = &[
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "alignas",
    "alignof",
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "constexpr",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "false",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "nullptr",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "struct",
    "switch",
    "thread_local",
    "true",
    "typedef",
    "typeof",
    "typeof_unqual",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
];

/// C multi-character operators, longest first.
const C_MULTI_PUNCT: &[&str] = &[
    "<<=", ">>=", "...", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=",
    "-=", "*=", "/=", "%=", "&=", "|=", "^=", "##",
];

/// The C dialect.
pub const C: Dialect = Dialect {
    keywords: C_KEYWORDS,
    multi_punct: C_MULTI_PUNCT,
    raw_strings: false,
    digit_separators: false,
    record_keywords: &["struct", "union"],
    lambdas: false,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_multi_punct_is_ordered_longest_first() {
        let lens: Vec<usize> = C.multi_punct.iter().map(|op| op.len()).collect();
        let mut sorted = lens.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(lens, sorted, "greedy matching needs longest-first order");
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // guards the dialect's shape
    fn c_dialect_has_no_cpp_only_features() {
        assert!(!C.raw_strings);
        assert!(!C.digit_separators);
        assert!(!C.lambdas);
        assert!(!C.keywords.contains(&"class"));
        assert!(!C.multi_punct.contains(&"::"));
    }
}
