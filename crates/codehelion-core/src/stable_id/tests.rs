use super::*;
use crate::discovery::LanguageSelection;
use crate::frontend::{LiteralKind, SourceSpan, TokenKind};
use crate::semantic::{OperationObservation, normalize_registered_apis};

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

#[test]
fn hex_form_is_32_lowercase_chars_and_bytes_roundtrip() {
    let fp = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let hex = fp.to_hex();
    assert_eq!(hex.len(), 32);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_eq!(UnitFingerprint::from_bytes(*fp.as_bytes()), fp);
}

#[test]
fn spans_never_influence_identifiers() {
    let mut moved = sample();
    for token in &mut moved {
        token.span.start_byte += 1000;
        token.span.start_line += 50;
    }
    assert_eq!(
        unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw),
        unit_fingerprint(&variant(), &ctx(), &moved, ContentNorm::Raw),
    );
}

#[test]
fn raw_and_normalized_digests_are_distinct_domains() {
    let tokens = sample();
    let raw = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
    let norm = unit_fingerprint(
        &variant(),
        &ctx(),
        &tokens,
        ContentNorm::Normalized(LiteralNorm::Full),
    );
    assert_ne!(raw.as_bytes(), norm.as_bytes());
}

#[test]
fn unit_and_fragment_digests_of_equal_content_differ() {
    let tokens = sample();
    let unit = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
    let fragment = fragment_fingerprint(&variant(), &ctx(), "member", &tokens, ContentNorm::Raw);
    assert_ne!(unit.as_bytes(), fragment.as_bytes());
}

#[test]
fn consistent_renames_survive_normalized_fingerprints_only() {
    let a = sample();
    let b = renamed_sample();
    assert_ne!(
        unit_fingerprint(&variant(), &ctx(), &a, ContentNorm::Raw),
        unit_fingerprint(&variant(), &ctx(), &b, ContentNorm::Raw),
    );
    assert_eq!(
        unit_fingerprint(
            &variant(),
            &ctx(),
            &a,
            ContentNorm::Normalized(LiteralNorm::Full)
        ),
        unit_fingerprint(
            &variant(),
            &ctx(),
            &b,
            ContentNorm::Normalized(LiteralNorm::Full)
        ),
    );
}

#[test]
fn context_changes_change_the_digest() {
    let tokens = sample();
    let base = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
    let other_frontend = FileContext {
        frontend_version: "other-test-lexer-v1",
        ..ctx()
    };
    assert_ne!(
        base,
        unit_fingerprint(&variant(), &other_frontend, &tokens, ContentNorm::Raw)
    );
    let other_language = FileContext {
        language: Language::C,
        ..ctx()
    };
    assert_ne!(
        base,
        unit_fingerprint(&variant(), &other_language, &tokens, ContentNorm::Raw)
    );
}

#[test]
fn group_fingerprint_is_order_independent_and_deduplicated() {
    let a = fragment_fingerprint(&variant(), &ctx(), "member", &sample(), ContentNorm::Raw);
    let b = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &renamed_sample(),
        ContentNorm::Raw,
    );
    let forward = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a, b]);
    let reversed = clone_group_fingerprint(&variant(), CloneClass::Type1, &[b, a]);
    assert_eq!(forward, reversed);
    // Another copy of known content leaves the fingerprint unchanged.
    let duplicated = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a, b, a]);
    assert_eq!(forward, duplicated);
    // New member content changes it.
    let single = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a]);
    assert_ne!(forward, single);
}

#[test]
fn structural_group_fingerprint_is_anchored_and_order_independent() {
    let a = fragment_fingerprint(&variant(), &ctx(), "member", &sample(), ContentNorm::Raw);
    let b = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &renamed_sample(),
        ContentNorm::Raw,
    );
    let members = [a, b];
    let forward = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &members);
    // Member order does not matter.
    let reversed = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &[b, a]);
    assert_eq!(forward, reversed);
    // A different canonical instance (medoid) over the same set hashes apart.
    let other_anchor =
        structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &b, &members);
    assert_ne!(forward, other_anchor);
    // New member content changes it.
    let c = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &toks(&[(Kw, "let"), (Id, "z"), (Pu, ";")]),
        ContentNorm::Raw,
    );
    let grown = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &[a, b, c]);
    assert_ne!(forward, grown);
}

#[test]
fn semantic_fingerprints_are_position_free_and_rule_versioned() {
    let graph = |offset| {
        normalize_registered_apis(
            Language::Rust,
            [13; 32],
            vec![
                OperationObservation {
                    source_offset: offset,
                    api_name: "rust::Iterator::filter".to_owned(),
                    type_tag: None,
                },
                OperationObservation {
                    source_offset: offset + 1,
                    api_name: "rust::Iterator::collect".to_owned(),
                    type_tag: None,
                },
            ],
        )
        .expect("registered observations normalize")
        .graph
        .expect("registered observations produce a graph")
    };
    let first = semantic_fragment_fingerprint(&variant(), &graph(5));
    let moved = semantic_fragment_fingerprint(&variant(), &graph(500));
    assert_eq!(first, moved);
    let group =
        semantic_clone_group_fingerprint(&variant(), "sequence-pipeline-v1", 1, &[first, moved]);
    let reversed =
        semantic_clone_group_fingerprint(&variant(), "sequence-pipeline-v1", 1, &[moved, first]);
    assert_eq!(group, reversed);
    assert_ne!(
        group,
        semantic_clone_group_fingerprint(&variant(), "sequence-pipeline-v1", 2, &[first, moved],)
    );
}

#[test]
fn cross_language_comparison_identity_is_order_independent_and_policy_distinct() {
    let origins = vec!["cpp-variant".to_string(), "rust-variant".to_string()];
    let reverse = vec!["rust-variant".to_string(), "cpp-variant".to_string()];
    let language = cross_language_comparison_id(&origins);
    assert_eq!(language, cross_language_comparison_id(&reverse));
    assert_ne!(
        language.to_hex(),
        cross_variant_comparison_id(&origins).to_hex(),
        "the exact-build and semantic policies cannot share a comparison domain"
    );
}

#[test]
fn cross_language_group_identity_is_member_order_independent_and_rule_bound() {
    let comparison =
        cross_language_comparison_id(&["cpp-variant".to_string(), "rust-variant".to_string()]);
    let first = fragment_fingerprint(&variant(), &ctx(), "first", &sample(), ContentNorm::Raw);
    let second = fragment_fingerprint(
        &variant(),
        &ctx(),
        "second",
        &renamed_sample(),
        ContentNorm::Raw,
    );
    let forward = cross_language_group_id(
        &comparison,
        "cross-language-sequence-pipeline-v1",
        1,
        &[first, second],
    );
    let reverse = cross_language_group_id(
        &comparison,
        "cross-language-sequence-pipeline-v1",
        1,
        &[second, first],
    );
    assert_eq!(forward, reverse);
    assert_ne!(
        forward,
        cross_language_group_id(
            &comparison,
            "cross-language-sequence-pipeline-v1",
            2,
            &[first, second],
        )
    );
}

#[test]
fn finding_ids_discriminate_host_and_rank() {
    let group = clone_group_fingerprint(
        &variant(),
        CloneClass::Type1,
        &[fragment_fingerprint(
            &variant(),
            &ctx(),
            "member",
            &sample(),
            ContentNorm::Raw,
        )],
    );
    let host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let first = finding_id(&group, Some(&host), 0);
    let second = finding_id(&group, Some(&host), 1);
    let hostless = finding_id(&group, None, 0);
    assert_ne!(first, second);
    assert_ne!(first, hostless);
    // Deterministic: same inputs, same id.
    assert_eq!(first, finding_id(&group, Some(&host), 0));
}
