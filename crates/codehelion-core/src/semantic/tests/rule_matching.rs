use super::super::*;
use std::collections::BTreeMap;

#[test]
fn a_plain_compiler_confirmed_loop_matches_a_registered_collection_pipeline() {
    let explicit_loop = normalize_registered_observations(
        Language::Rust,
        [13; 32],
        Vec::new(),
        vec![
            ConstructObservation {
                source_offset: 10,
                kind: OperationKind::Source,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            ConstructObservation {
                source_offset: 20,
                kind: OperationKind::Collect,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
        ],
    )
    .expect("explicit loop constructs form a graph")
    .graph
    .expect("loop constructs produce a graph");
    let pipeline = normalize_registered_apis(
        Language::Rust,
        [13; 32],
        vec![
            OperationObservation {
                source_offset: 10,
                api_name: "rust::IntoIterator::into_iter".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 20,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("registered pipeline constructs form a graph")
    .graph
    .expect("registered APIs produce a graph");
    assert_eq!(
        match_registered_pipeline(&explicit_loop, &pipeline).map(|matched| matched.rule.id),
        Some("sequence-pipeline-v1")
    );
}

#[test]
fn same_variant_rules_never_join_different_languages() {
    let rust = normalize_registered_apis(
        Language::Rust,
        [13; 32],
        vec![
            OperationObservation {
                source_offset: 10,
                api_name: "rust::IntoIterator::into_iter".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 20,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("registered pipeline constructs form a graph")
    .graph
    .expect("registered APIs produce a graph");
    let cpp = SemanticOperationGraph {
        language: Language::Cpp,
        ..rust.clone()
    };

    assert!(match_registered_pipeline(&rust, &cpp).is_none());
    let candidates =
        extract_registered_candidates(&[rust, cpp], SemanticCandidateConfig::default());
    assert!(candidates.pairs.is_empty());
    assert_eq!(candidates.stats.buckets, 2);
}

/// The expressions supplied to a registered API are what the rule looks past.
/// Two pipelines filtering on different predicates are the case it exists for,
/// so differing source structure must not withhold the match; a differing
/// operation sequence still must.
#[test]
fn same_variant_pipelines_compare_operations_rather_than_source_structure() {
    let graph = |names: &[&str], structure_fingerprint| {
        let mut graph = normalize_registered_apis(
            Language::Rust,
            [13; 32],
            names
                .iter()
                .enumerate()
                .map(|(index, name)| OperationObservation {
                    source_offset: (index as u64 + 1) * 10,
                    api_name: (*name).to_owned(),
                    type_tag: None,
                })
                .collect(),
        )
        .expect("registered pipeline constructs form a graph")
        .graph
        .expect("registered APIs produce a graph");
        for node in &mut graph.nodes {
            node.attributes.structure_fingerprint = Some(structure_fingerprint);
        }
        graph
    };
    let filter_then_map = ["rust::Iterator::filter", "rust::Iterator::map"];
    let even_then_square = graph(&filter_then_map, [1; 16]);
    let prime_then_cube = graph(&filter_then_map, [2; 16]);
    assert!(match_registered_pipeline(&even_then_square, &prime_then_cube).is_some());

    let mapped_only = graph(&["rust::Iterator::map"], [2; 16]);
    assert_eq!(
        match_registered_pipeline(&even_then_square, &mapped_only),
        None
    );
}

#[test]
fn resource_lifecycle_requires_one_matching_acquire_release_pair() {
    let graph = |release_kind: &str| {
        normalize_registered_observations(
            Language::Rust,
            [31; 32],
            Vec::new(),
            vec![
                ConstructObservation {
                    source_offset: 10,
                    kind: OperationKind::AcquireResource,
                    fallible_kind: None,
                    direct_propagation: None,
                    resource_kind: Some("file".to_owned()),
                },
                ConstructObservation {
                    source_offset: 20,
                    kind: OperationKind::ReleaseResource,
                    fallible_kind: None,
                    direct_propagation: None,
                    resource_kind: Some(release_kind.to_owned()),
                },
            ],
        )
        .expect("resource constructs form a graph")
        .graph
        .expect("resource constructs produce a graph")
    };
    let file = graph("file");
    let lock = graph("lock");
    assert!(file.edges.contains(&OperationEdge {
        from: 0,
        to: 1,
        kind: OperationEdgeKind::ResourceLifetime,
    }));
    assert_eq!(
        match_registered_rule(&file, &file).map(|matched| matched.rule.id),
        Some("resource-lifecycle-v1")
    );
    assert_eq!(match_registered_rule(&file, &lock), None);
}

#[test]
fn direct_result_propagation_requires_the_closed_adapter_form() {
    let graph = |direct_propagation| {
        normalize_registered_observations(
            Language::Rust,
            [14; 32],
            Vec::new(),
            vec![ConstructObservation {
                source_offset: 10,
                kind: OperationKind::PropagateError,
                fallible_kind: Some(FallibleKind::Result),
                direct_propagation,
                resource_kind: None,
            }],
        )
        .expect("propagation construct forms a graph")
        .graph
        .expect("propagation construct produces a graph")
    };
    let adapter = graph(Some(DirectPropagation::ResultAdapter));
    let ordinary = graph(None);
    assert_eq!(
        match_registered_rule(&adapter, &adapter).map(|matched| matched.rule.id),
        Some("result-direct-propagation-v1")
    );
    assert_eq!(match_registered_rule(&adapter, &ordinary), None);
    assert_eq!(match_registered_rule(&ordinary, &ordinary), None);
}

#[test]
fn direct_option_propagation_requires_the_closed_adapter_form() {
    let graph = |fallible_kind, direct_propagation| {
        normalize_registered_observations(
            Language::Rust,
            [15; 32],
            Vec::new(),
            vec![ConstructObservation {
                source_offset: 10,
                kind: OperationKind::PropagateError,
                fallible_kind: Some(fallible_kind),
                direct_propagation,
                resource_kind: None,
            }],
        )
        .expect("propagation construct forms a graph")
        .graph
        .expect("propagation construct produces a graph")
    };
    let adapter = graph(FallibleKind::Option, Some(DirectPropagation::OptionAdapter));
    let ordinary = graph(FallibleKind::Option, None);
    let result_adapter = graph(FallibleKind::Result, Some(DirectPropagation::ResultAdapter));
    assert_eq!(
        match_registered_rule(&adapter, &adapter).map(|matched| matched.rule.id),
        Some("option-direct-propagation-v1")
    );
    assert_eq!(match_registered_rule(&adapter, &ordinary), None);
    assert_eq!(match_registered_rule(&adapter, &result_adapter), None);
}

#[test]
fn optional_validation_requires_compiler_confirmed_option_evidence() {
    let graph = |language, variant, fallible_kind| {
        normalize_registered_observations(
            language,
            variant,
            Vec::new(),
            vec![ConstructObservation {
                source_offset: 10,
                kind: OperationKind::Validate,
                fallible_kind,
                direct_propagation: None,
                resource_kind: None,
            }],
        )
        .expect("validation construct forms a graph")
        .graph
        .expect("validation construct produces a graph")
    };
    let rust = graph(Language::Rust, [24; 32], Some(FallibleKind::Option));
    let same_variant = graph(Language::Rust, [24; 32], Some(FallibleKind::Option));
    let result = graph(Language::Rust, [24; 32], Some(FallibleKind::Result));
    assert_eq!(
        match_registered_rule(&rust, &same_variant).map(|matched| matched.rule.id),
        Some("optional-validation-v1")
    );
    assert_eq!(match_registered_rule(&rust, &result), None);

    let cpp = graph(Language::Cpp, [25; 32], Some(FallibleKind::Option));
    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [26; 16],
            graph: rust,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [26; 16],
            graph: cpp,
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert_eq!(
        candidates.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
    assert_eq!(verified.len(), 1);
    assert_eq!(
        verified[0].1.rule.id,
        "cross-language-optional-validation-v1"
    );
    assert_eq!(
        verified[0].1.correspondence_ids,
        vec!["optional-presence-validation-v1"]
    );
}

#[test]
fn result_validation_crosses_languages_only_as_a_presence_check() {
    let graph = |language, variant, kind| {
        normalize_registered_observations(
            language,
            variant,
            Vec::new(),
            vec![ConstructObservation {
                source_offset: 10,
                kind,
                fallible_kind: Some(FallibleKind::Result),
                direct_propagation: None,
                resource_kind: None,
            }],
        )
        .expect("result construct forms a graph")
        .graph
        .expect("result construct produces a graph")
    };
    let rust = graph(Language::Rust, [27; 32], OperationKind::Validate);
    let same_variant = graph(Language::Rust, [27; 32], OperationKind::Validate);
    let cpp = graph(Language::Cpp, [28; 32], OperationKind::Validate);
    let propagation = graph(Language::Cpp, [28; 32], OperationKind::PropagateError);
    assert_eq!(
        match_registered_rule(&rust, &same_variant).map(|matched| matched.rule.id),
        Some("result-validation-v1")
    );
    assert_eq!(match_registered_rule(&rust, &propagation), None);

    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: rust,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: cpp,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: propagation,
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert_eq!(
        candidates.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].1.rule.id, "cross-language-result-validation-v1");
    assert_eq!(
        verified[0].1.correspondence_ids,
        vec!["result-expected-validation-v1"]
    );
}

#[test]
fn direct_result_adapters_cross_languages_only_in_the_registered_form() {
    let graph = |language, variant, direct_propagation| {
        normalize_registered_observations(
            language,
            variant,
            Vec::new(),
            vec![ConstructObservation {
                source_offset: 10,
                kind: OperationKind::PropagateError,
                fallible_kind: Some(FallibleKind::Result),
                direct_propagation,
                resource_kind: None,
            }],
        )
        .expect("propagation construct forms a graph")
        .graph
        .expect("propagation construct produces a graph")
    };
    let rust = graph(
        Language::Rust,
        [27; 32],
        Some(DirectPropagation::ResultAdapter),
    );
    let cpp = graph(
        Language::Cpp,
        [28; 32],
        Some(DirectPropagation::ResultAdapter),
    );
    let ordinary = graph(Language::Cpp, [28; 32], None);
    assert_eq!(
        match_cross_language_result_direct_propagation(&rust, &cpp).map(|matched| matched.rule.id),
        Some("cross-language-result-direct-propagation-v1")
    );
    assert_eq!(
        match_cross_language_result_direct_propagation(&rust, &ordinary),
        None
    );

    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: rust,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: cpp,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [29; 16],
            graph: ordinary,
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert_eq!(
        candidates.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
    assert_eq!(verified.len(), 1);
    assert_eq!(
        verified[0].1.rule.id,
        "cross-language-result-direct-propagation-v1"
    );
    assert_eq!(
        verified[0].1.correspondence_ids,
        vec!["result-expected-direct-propagation-v1"]
    );
}

#[test]
fn registered_rules_declare_their_closed_matchers() {
    let rules: BTreeMap<_, _> = registered_rules()
        .iter()
        .map(|rule| (rule.id, rule.matcher))
        .collect();
    assert_eq!(
        rules["sequence-pipeline-v1"],
        SemanticRuleMatcher::EquivalentSequence
    );
    assert_eq!(
        rules["rust-serialization-round-trip-v1"],
        SemanticRuleMatcher::ExactApiSequence {
            api_names: &["rust::ToString::to_string", "rust::str::parse"],
        }
    );
    assert_eq!(
        rules["cpp-serialization-round-trip-v1"],
        SemanticRuleMatcher::ExactApiSequence {
            api_names: &["std::to_string", "std::stoull"],
        }
    );
    assert_eq!(
        rules["result-direct-propagation-v1"],
        SemanticRuleMatcher::DirectConstruct {
            kind: OperationKind::PropagateError,
            fallible_kind: FallibleKind::Result,
            direct_propagation: Some(DirectPropagation::ResultAdapter),
        }
    );
    assert_eq!(
        rules["option-direct-propagation-v1"],
        SemanticRuleMatcher::DirectConstruct {
            kind: OperationKind::PropagateError,
            fallible_kind: FallibleKind::Option,
            direct_propagation: Some(DirectPropagation::OptionAdapter),
        }
    );
    assert_eq!(
        rules["optional-validation-v1"],
        SemanticRuleMatcher::DirectConstruct {
            kind: OperationKind::Validate,
            fallible_kind: FallibleKind::Option,
            direct_propagation: None,
        }
    );
    assert_eq!(
        rules["result-validation-v1"],
        SemanticRuleMatcher::DirectConstruct {
            kind: OperationKind::Validate,
            fallible_kind: FallibleKind::Result,
            direct_propagation: None,
        }
    );
    assert_eq!(registered_rules().len(), 12);
    assert_eq!(
        rules["resource-lifecycle-v1"],
        SemanticRuleMatcher::ResourceLifecycle
    );
    let cross_language: Vec<_> = registered_rules()
        .iter()
        .filter(|rule| rule.scope == SemanticRuleScope::RustCpp)
        .collect();
    assert_eq!(cross_language.len(), 4);
    assert!(
        cross_language
            .iter()
            .all(|rule| rule.id.starts_with("cross-language-"))
    );
}
