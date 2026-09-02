use std::collections::BTreeSet;

use super::*;
use crate::discovery::LanguageSelection;
use crate::frontend::{LiteralKind, SourceSpan, TokenKind};
use crate::semantic::{
    DirectPropagation, FallibleKind, OperationObservation, normalize_registered_apis,
};

mod content;
mod cross_program;
mod golden;
mod groups;
mod occurrences;
mod report;
mod semantic;

fn variant() -> BuildVariant {
    BuildVariant::fast(LanguageSelection::default(), Language::C)
}

fn ctx() -> FileContext<'static> {
    FileContext {
        frontend_version: "test-lexer-v1",
        language: Language::Rust,
    }
}

/// Build a token stream from `(kind, text)` pairs; spans are dummies and
/// must never influence any identifier.
fn toks(spec: &[(TokenKind, &str)]) -> Vec<Token> {
    spec.iter()
        .enumerate()
        .map(|(i, (kind, text))| Token {
            kind: *kind,
            text: (*text).into(),
            span: SourceSpan {
                start_byte: i * 7,
                end_byte: i * 7 + 1,
                start_line: u32::try_from(i).unwrap() + 1,
                start_column: 1,
            },
        })
        .collect()
}

use TokenKind::{Identifier as Id, Keyword as Kw, Punctuation as Pu};
const INT: TokenKind = TokenKind::Literal(LiteralKind::Integer);

fn sample() -> Vec<Token> {
    toks(&[
        (Kw, "let"),
        (Id, "total"),
        (Pu, "="),
        (Id, "base"),
        (Pu, "+"),
        (INT, "1"),
        (Pu, ";"),
    ])
}

fn renamed_sample() -> Vec<Token> {
    toks(&[
        (Kw, "let"),
        (Id, "sum"),
        (Pu, "="),
        (Id, "seed"),
        (Pu, "+"),
        (INT, "2"),
        (Pu, ";"),
    ])
}
