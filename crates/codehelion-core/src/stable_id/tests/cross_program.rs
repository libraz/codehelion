//! Comparison and group identifiers spanning build variants and languages.

use super::*;

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
fn cross_language_group_identity_keeps_content_identical_occurrences_distinct() {
    let comparison = cross_language_comparison_id(&["cpp".to_owned(), "rust".to_owned()]);
    let content = fragment_fingerprint(&variant(), &ctx(), "semantic", &sample(), ContentNorm::Raw);
    let rust_host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let cpp_host = unit_fingerprint(&variant(), &ctx(), &renamed_sample(), ContentNorm::Raw);
    let first = cross_language_group_id(
        &comparison,
        "cross-language-sequence-pipeline-v1",
        1,
        &[
            semantic_occurrence_fingerprint(content, &rust_host, 0),
            semantic_occurrence_fingerprint(content, &cpp_host, 0),
        ],
    );
    let second = cross_language_group_id(
        &comparison,
        "cross-language-sequence-pipeline-v1",
        1,
        &[
            semantic_occurrence_fingerprint(content, &rust_host, 1),
            semantic_occurrence_fingerprint(content, &cpp_host, 0),
        ],
    );
    assert_ne!(first, second);
}
