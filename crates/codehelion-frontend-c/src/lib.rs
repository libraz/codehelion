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

use codehelion_core::conditional::ArmPath;
use codehelion_core::discovery::Language;
use codehelion_core::frontend::{Frontend, LexedFile};

use dialect::Dialect;

/// Version of the lexer and unit-boundary machinery shared by C and C++.
///
/// It is embedded in both Fast frontend fingerprint tags. Bump it whenever a
/// change to the shared implementation changes tokens or unit boundaries.
pub const C_FAMILY_LEXER_VERSION: &str = "c-family-lexer-v1";

/// Version tag of this frontend, used as a fingerprint input. The C dialect
/// revision and the shared C-family lexer revision are both part of it.
pub const FRONTEND_VERSION: &str = "c-lexer-v1+c-family-lexer-v1";

/// Run one Fast-mode pass over a C-family source: the lexed file plus the
/// preprocessor arm each of its tokens sits in.
///
/// Both halves come out of a single lex, so a pipeline that needs arm paths
/// reads the text once. This is the shared entry point of the C-family Fast
/// frontends, as [`ir::parse_to_ir`] is of the structural ones.
#[must_use]
pub fn fast_pass(
    source: &str,
    dialect: &Dialect,
    language: Language,
    frontend_version: &'static str,
) -> (LexedFile, Vec<ArmPath>) {
    let (tokens, mut diagnostics, directives) = lexer::lex_with_directives(source, dialect);
    let (units, unit_diagnostics) = units::detect(&tokens, dialect);
    diagnostics.extend(unit_diagnostics);
    let arm_paths = lexer::conditional_paths(&tokens, &directives);
    (
        LexedFile {
            language,
            frontend_version,
            tokens,
            units,
            diagnostics,
        },
        arm_paths,
    )
}

/// The C Fast-mode frontend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CFrontend;

impl CFrontend {
    /// Lex `source` and record the preprocessor arm each token sits in.
    #[must_use]
    pub fn lex_with_arm_paths(&self, source: &str) -> (LexedFile, Vec<ArmPath>) {
        fast_pass(source, &dialect::C, Language::C, FRONTEND_VERSION)
    }
}

impl Frontend for CFrontend {
    fn language(&self) -> Language {
        Language::C
    }

    fn frontend_version(&self) -> &'static str {
        FRONTEND_VERSION
    }

    fn lex(&self, source: &str) -> LexedFile {
        let (tokens, mut diagnostics) = lexer::lex(source, &dialect::C);
        let (units, unit_diagnostics) = units::detect(&tokens, &dialect::C);
        diagnostics.extend(unit_diagnostics);
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
    use codehelion_core::ir::StructuralFrontend;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    #[test]
    fn frontend_reports_language_and_version() {
        let frontend = CFrontend;
        assert_eq!(frontend.language(), Language::C);
        assert_eq!(frontend.frontend_version(), FRONTEND_VERSION);
        assert!(FRONTEND_VERSION.ends_with(C_FAMILY_LEXER_VERSION));
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_text_never_panics(source in proptest::collection::vec(any::<char>(), 0..1024)
            .prop_map(|characters| characters.into_iter().collect::<String>())) {
            let started = Instant::now();
            let _ = CFrontend.lex(&source);
            let _ = ir::CStructuralFrontend.parse(&source);
            prop_assert!(
                started.elapsed() < Duration::from_secs(1),
                "a bounded frontend input took too long"
            );
        }
    }
}
