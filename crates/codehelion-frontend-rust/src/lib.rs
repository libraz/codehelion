//! Rust Fast frontend for codehelion.
//!
//! Implements [`codehelion_core::frontend::Frontend`] for Rust: an
//! error-tolerant lexer paired with brace-matching unit-boundary detection.
//! Nothing here parses or executes the source; macros and generics pass through
//! as tokens.

mod lexer;
mod units;

use codehelion_core::discovery::Language;
use codehelion_core::frontend::{Frontend, LexedFile};

/// Version tag of this frontend, used as a fingerprint input. Bump it whenever
/// a change alters the token stream or unit boundaries for unchanged input.
pub const FRONTEND_VERSION: &str = "rust-lexer-v0";

/// The Rust Fast-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustFrontend;

impl Frontend for RustFrontend {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn frontend_version(&self) -> &'static str {
        FRONTEND_VERSION
    }

    fn lex(&self, source: &str) -> LexedFile {
        let (tokens, diagnostics) = lexer::lex(source);
        let units = units::detect(&tokens);
        LexedFile {
            language: Language::Rust,
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
        let frontend = RustFrontend;
        assert_eq!(frontend.language(), Language::Rust);
        assert_eq!(frontend.frontend_version(), FRONTEND_VERSION);
    }

    #[test]
    fn lexing_a_file_yields_tokens_units_and_the_version() {
        let lexed = RustFrontend.lex("fn main() { let x = 1; }");
        assert_eq!(lexed.language, Language::Rust);
        assert_eq!(lexed.frontend_version, FRONTEND_VERSION);
        assert!(!lexed.tokens.is_empty());
        assert_eq!(lexed.units.len(), 1);
        assert!(lexed.diagnostics.is_empty());
    }
}
