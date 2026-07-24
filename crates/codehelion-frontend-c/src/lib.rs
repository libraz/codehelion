//! C frontends for codehelion.
//!
//! Fast mode implements [`codehelion_core::frontend::Frontend`]: an
//! error-tolerant lexer paired with delimiter-matching unit-boundary
//! detection. Nothing here preprocesses or executes the source; directives
//! are dropped whole and macros pass through as ordinary tokens. Structural
//! mode lives in [`ir`]: a real tree-sitter parse mapped onto the
//! language-neutral Syntax IR.
//!
//! Both modes share their machinery with the C++ frontend crate: the lexer is
//! parameterized by a [`dialect::Dialect`] carrying the keyword set, operator
//! inventory and dialect-only literal forms, and the structural CST walker is
//! parameterized by an [`ir::IrMapping`] carrying the node-mapping table.

pub mod dialect;
pub mod ir;
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
