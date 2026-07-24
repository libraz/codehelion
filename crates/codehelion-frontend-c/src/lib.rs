//! C Fast frontend for codehelion.
//!
//! Implements [`codehelion_core::frontend::Frontend`] for C: an error-tolerant
//! lexer paired with delimiter-matching unit-boundary detection. Nothing here
//! parses, preprocesses or executes the source; directives are dropped whole
//! and macros pass through as ordinary tokens.
//!
//! The lexing machinery is shared with the C++ frontend crate: both languages
//! are lexed by the same code, parameterized by a [`dialect::Dialect`] that
//! carries the keyword set, operator inventory and dialect-only literal
//! forms.

pub mod dialect;
pub mod lexer;
pub mod units;

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{Frontend, LexedFile};

/// Version tag of this frontend, used as a fingerprint input. Bump it whenever
/// a change alters the token stream or unit boundaries for unchanged input.
pub const FRONTEND_VERSION: &str = "c-lexer-v0";

/// The C Fast-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CFrontend;

impl Frontend for CFrontend {
    fn language(&self) -> Language {
        Language::C
    }

    fn frontend_version(&self) -> &'static str {
        FRONTEND_VERSION
    }

    fn lex(&self, source: &str) -> LexedFile {
        let (tokens, diagnostics) = lexer::lex(source, &dialect::C);
        let units = units::detect(&tokens, &dialect::C);
        LexedFile {
            language: Language::C,
            frontend_version: FRONTEND_VERSION,
            tokens,
            units,
            diagnostics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_reports_language_and_version() {
        let frontend = CFrontend;
        assert_eq!(frontend.language(), Language::C);
        assert_eq!(frontend.frontend_version(), FRONTEND_VERSION);
    }

    #[test]
    fn lexing_a_file_yields_tokens_units_and_the_version() {
        let lexed = CFrontend.lex("int main(void) { return 0; }");
        assert_eq!(lexed.language, Language::C);
        assert_eq!(lexed.frontend_version, FRONTEND_VERSION);
        assert!(!lexed.tokens.is_empty());
        assert_eq!(lexed.units.len(), 1);
        assert!(lexed.diagnostics.is_empty());
    }
}
