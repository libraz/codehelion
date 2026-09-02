//! Unit and fragment fingerprints over token content.

use super::*;

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
