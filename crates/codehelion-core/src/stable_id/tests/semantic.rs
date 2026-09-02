//! Fingerprints over semantic operation graphs and source structure.

use super::*;

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
    assert_ne!(
        group,
        semantic_clone_group_fingerprint(
            &variant(),
            "sequence-pipeline-v1",
            1,
            &[first, moved, first],
        )
    );
}

#[test]
fn semantic_fragment_fingerprint_includes_direct_construct_attributes() {
    let graph = |fallible_kind, direct_propagation| {
        let mut graph = normalize_registered_apis(
            Language::Rust,
            [13; 32],
            vec![OperationObservation {
                source_offset: 5,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: None,
            }],
        )
        .expect("registered observations normalize")
        .graph
        .expect("registered observations produce a graph");
        graph.nodes[0].attributes.fallible_kind = fallible_kind;
        graph.nodes[0].attributes.direct_propagation = direct_propagation;
        graph
    };
    let result = semantic_fragment_fingerprint(
        &variant(),
        &graph(
            Some(FallibleKind::Result),
            Some(DirectPropagation::ResultAdapter),
        ),
    );
    let option = semantic_fragment_fingerprint(
        &variant(),
        &graph(
            Some(FallibleKind::Option),
            Some(DirectPropagation::OptionAdapter),
        ),
    );
    assert_ne!(result, option);
}

#[test]
fn semantic_structure_fingerprint_is_position_free_and_retains_expression_text() {
    let tokens = sample();
    let fingerprint = semantic_structure_fingerprint(&variant(), &ctx(), &tokens);
    let mut moved = tokens;
    for token in &mut moved {
        token.span.start_byte += 1_000;
        token.span.end_byte += 1_000;
        token.span.start_line += 100;
    }
    assert_eq!(
        fingerprint,
        semantic_structure_fingerprint(&variant(), &ctx(), &moved)
    );

    let distinct = toks(&[(Id, "filter"), (Pu, "("), (Id, "is_prime"), (Pu, ")")]);
    let original = toks(&[(Id, "filter"), (Pu, "("), (Id, "is_even"), (Pu, ")")]);
    assert_ne!(
        semantic_structure_fingerprint(&variant(), &ctx(), &original),
        semantic_structure_fingerprint(&variant(), &ctx(), &distinct)
    );
}

#[test]
fn semantic_occurrence_fingerprint_includes_host_and_rank() {
    let content = fragment_fingerprint(&variant(), &ctx(), "semantic", &sample(), ContentNorm::Raw);
    let first_host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let second_host = unit_fingerprint(&variant(), &ctx(), &renamed_sample(), ContentNorm::Raw);
    let first = semantic_occurrence_fingerprint(content, &first_host, 0);
    assert_ne!(
        first,
        semantic_occurrence_fingerprint(content, &first_host, 1)
    );
    assert_ne!(
        first,
        semantic_occurrence_fingerprint(content, &second_host, 0)
    );
}
