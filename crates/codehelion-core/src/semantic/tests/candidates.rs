use super::super::*;
use crate::grouping::GroupingConfig;

fn node(kind: OperationKind) -> OperationNode {
    OperationNode {
        kind,
        attributes: OperationAttributes::default(),
    }
}

#[test]
fn registered_pipeline_rule_stays_within_one_language_and_build_variant() {
    let rust = normalize_registered_apis(
        Language::Rust,
        [4; 32],
        vec![
            OperationObservation {
                source_offset: 1,
                api_name: "rust::Iterator::filter".to_owned(),
                type_tag: Some(TypeTag::Integer),
            },
            OperationObservation {
                source_offset: 2,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: Some(TypeTag::Sequence),
            },
        ],
    )
    .expect("valid Rust SOG")
    .graph
    .expect("pipeline graph");
    let same_language = rust.clone();
    assert_eq!(
        match_registered_pipeline(&rust, &same_language).map(|matched| matched.rule.id),
        Some("sequence-pipeline-v1")
    );
    let other = SemanticOperationGraph {
        build_variant_fingerprint: [5; 32],
        ..same_language
    };
    assert_eq!(match_registered_pipeline(&rust, &other), None);
}

#[test]
fn serialization_rule_requires_its_exact_closed_api_sequence() {
    let round_trip = normalize_registered_apis(
        Language::Rust,
        [44; 32],
        vec![
            OperationObservation {
                source_offset: 1,
                api_name: "rust::ToString::to_string".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 2,
                api_name: "rust::str::parse".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("valid round trip")
    .graph
    .expect("round-trip graph");
    let verified = verify_registered_candidates(
        &[round_trip.clone(), round_trip],
        &[SemanticCandidatePair { left: 0, right: 1 }],
    );
    assert_eq!(verified[0].1.rule.id, "rust-serialization-round-trip-v1");

    let ordinary_maps = normalize_registered_apis(
        Language::Rust,
        [44; 32],
        vec![
            OperationObservation {
                source_offset: 1,
                api_name: "rust::Iterator::map".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 2,
                api_name: "rust::Iterator::map".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("valid ordinary maps")
    .graph
    .expect("ordinary map graph");
    let verified = verify_registered_candidates(
        &[ordinary_maps.clone(), ordinary_maps],
        &[SemanticCandidatePair { left: 0, right: 1 }],
    );
    assert!(verified.is_empty(), "a map-only pair is not a pipeline");
}

#[test]
fn explicit_cross_language_candidates_require_one_registered_mapping_per_node() {
    let rust = cross_language_pipeline(
        Language::Rust,
        [16; 32],
        &[
            (OperationKind::Source, "rust::IntoIterator::into_iter"),
            (OperationKind::Map, "rust::Iterator::map"),
            (OperationKind::Collect, "rust::Iterator::collect"),
        ],
    );
    let cpp = cross_language_pipeline(
        Language::Cpp,
        [17; 32],
        &[
            (OperationKind::Source, "std::begin"),
            (OperationKind::Map, "std::transform"),
            (OperationKind::Collect, "std::push_back"),
        ],
    );
    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [18; 16],
            graph: rust,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [18; 16],
            graph: cpp,
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert_eq!(
        candidates.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    assert_eq!(candidates.stats.buckets, 1);
    let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].1.rule.id, "cross-language-sequence-pipeline-v1");
    assert_eq!(
        verified[0].1.correspondence_ids,
        vec![
            "sequence-source-v1",
            "sequence-map-v1",
            "sequence-collect-v1"
        ]
    );
    let mut type_mismatched_rust = inputs[0].graph.clone();
    let mut type_mismatched_cpp = inputs[1].graph.clone();
    type_mismatched_rust.nodes[1].attributes.type_tag = Some(TypeTag::Integer);
    type_mismatched_cpp.nodes[1].attributes.type_tag = Some(TypeTag::Text);
    assert!(match_cross_language_pipeline(&type_mismatched_rust, &type_mismatched_cpp).is_none());

    let same_variant_cpp = SemanticOperationGraph {
        build_variant_fingerprint: inputs[0].graph.build_variant_fingerprint,
        ..inputs[1].graph.clone()
    };
    assert!(match_cross_language_pipeline(&inputs[0].graph, &same_variant_cpp).is_none());
}

#[test]
fn cross_language_candidates_do_not_join_domains_or_unregistered_apis() {
    let rust = cross_language_pipeline(
        Language::Rust,
        [19; 32],
        &[
            (OperationKind::Map, "rust::Iterator::map"),
            (OperationKind::Collect, "rust::Iterator::collect"),
        ],
    );
    let cpp = cross_language_pipeline(
        Language::Cpp,
        [20; 32],
        &[
            (OperationKind::Map, "std::transform"),
            (OperationKind::Collect, "std::push_back"),
        ],
    );
    let unregistered = cross_language_pipeline(
        Language::Rust,
        [21; 32],
        &[
            (OperationKind::Map, "project::map"),
            (OperationKind::Collect, "rust::Iterator::collect"),
        ],
    );
    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [22; 16],
            graph: rust,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [23; 16],
            graph: cpp,
        },
        CrossLanguageCandidateInput {
            comparison_partition: [22; 16],
            graph: unregistered,
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert!(candidates.pairs.is_empty());
    assert_eq!(candidates.stats.buckets, 2);
    assert_eq!(candidates.stats.ineligible_graphs, 1);
}

#[test]
fn sequence_rule_rejects_operations_outside_its_declared_pattern() {
    let validation = pipeline(
        Language::Rust,
        [6; 32],
        &[OperationKind::Validate, OperationKind::PropagateError],
    );
    assert_eq!(match_registered_pipeline(&validation, &validation), None);
    let extracted =
        extract_registered_candidates(&[validation], SemanticCandidateConfig::default());
    assert_eq!(extracted.stats.ineligible_graphs, 1);
    assert!(extracted.pairs.is_empty());
}

fn pipeline(
    language: Language,
    variant: [u8; 32],
    operations: &[OperationKind],
) -> SemanticOperationGraph {
    let nodes = operations.iter().copied().map(node).collect();
    SemanticOperationGraph::new(language, variant, nodes, Vec::new()).expect("valid pipeline graph")
}

fn semantic_grouping_units(count: usize) -> Vec<SemanticGroupingUnit> {
    (0..count)
        .map(|index| SemanticGroupingUnit {
            key: [u8::try_from(index).expect("small test index"); 16],
        })
        .collect()
}

fn verified_semantic_pair(left: usize, right: usize, rule: SemanticRule) -> VerifiedSemanticPair {
    VerifiedSemanticPair {
        candidate: SemanticCandidatePair { left, right },
        matched: RuleMatch { rule },
    }
}

#[test]
fn semantic_grouping_does_not_turn_a_nontransitive_chain_into_one_group() {
    let units = semantic_grouping_units(3);
    let rule = registered_rules()[0];
    let grouping = group_verified_semantic_pairs(
        &units,
        &[
            verified_semantic_pair(0, 1, rule),
            verified_semantic_pair(1, 2, rule),
        ],
        &GroupingConfig::default(),
    );

    assert_eq!(grouping.groups.len(), 1);
    assert_eq!(grouping.groups[0].rule, rule);
    assert_eq!(grouping.groups[0].members.len(), 2);
    assert_eq!(grouping.ungrouped.len(), 1);
    assert!(!grouping.ungrouped[0].severed_by_the_ceiling);
    assert_eq!(grouping.stats.grouped_pairs, 1);
    assert_eq!(grouping.stats.ungrouped_pairs, 1);
}

#[test]
fn semantic_grouping_keeps_registered_rules_in_separate_groups() {
    let units = semantic_grouping_units(3);
    let first = registered_rules()[0];
    let second = registered_rules()[1];
    let grouping = group_verified_semantic_pairs(
        &units,
        &[
            verified_semantic_pair(0, 1, first),
            verified_semantic_pair(1, 2, second),
        ],
        &GroupingConfig::default(),
    );

    assert_eq!(grouping.groups.len(), 2);
    let mut expected = vec![first.id, second.id];
    expected.sort_unstable();
    assert_eq!(
        grouping
            .groups
            .iter()
            .map(|group| group.rule.id)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(grouping.ungrouped.is_empty());
}

#[test]
fn semantic_grouping_accounts_for_invalid_and_duplicate_pairs() {
    let units = semantic_grouping_units(2);
    let rule = registered_rules()[0];
    let grouping = group_verified_semantic_pairs(
        &units,
        &[
            verified_semantic_pair(1, 0, rule),
            verified_semantic_pair(0, 1, rule),
            verified_semantic_pair(0, 0, rule),
            verified_semantic_pair(0, 2, rule),
        ],
        &GroupingConfig::default(),
    );

    assert_eq!(grouping.groups.len(), 1);
    assert_eq!(grouping.stats.verified_pairs, 1);
    assert_eq!(grouping.stats.duplicate_pairs, 1);
    assert_eq!(grouping.stats.invalid_pairs, 2);
}

/// The counters are an account of what the stage was given, so they have to
/// add up: a reader who sums them must arrive back at the input.
#[test]
fn every_input_pair_leaves_semantic_grouping_through_exactly_one_counter() {
    let units = semantic_grouping_units(4);
    let rule = registered_rules()[0];
    let verified = [
        // Grouped: 0 and 1 hold each other.
        verified_semantic_pair(0, 1, rule),
        // The same relation stated again, and stated the other way round.
        verified_semantic_pair(1, 0, rule),
        // Ungrouped: a chain no single cohesive set can hold.
        verified_semantic_pair(1, 2, rule),
        verified_semantic_pair(2, 3, rule),
        // Neither endpoint names a unit the caller supplied.
        verified_semantic_pair(0, 9, rule),
        verified_semantic_pair(3, 3, rule),
    ];
    let grouping = group_verified_semantic_pairs(&units, &verified, &GroupingConfig::default());
    let stats = &grouping.stats;

    assert_eq!(stats.considered_pairs(), verified.len());
    assert_eq!(
        stats.grouped_pairs + stats.ungrouped_pairs,
        stats.verified_pairs
    );
    assert_eq!(stats.ungrouped_pairs, grouping.ungrouped.len());
    assert_eq!(
        stats.declined_pairs() + stats.ceiling_severed_pairs,
        stats.ungrouped_pairs
    );
    assert_eq!(stats.invalid_pairs, 2);
    assert_eq!(stats.duplicate_pairs, 1);
}

/// Severed pairs are part of the ungrouped population and not a second one
/// beside it. A caller stating both reasons has to take the remainder, or the
/// pairs the ceiling cut are subtracted twice from the same total.
#[test]
fn ceiling_severed_pairs_are_part_of_the_ungrouped_population() {
    let profile = crate::execution::Limits::untrusted();
    let count = profile.max_component + 8;
    let units = semantic_grouping_units(count);
    let rule = registered_rules()[0];
    let verified: Vec<_> = (0..count)
        .flat_map(|left| {
            (left + 1..count).map(move |right| verified_semantic_pair(left, right, rule))
        })
        .collect();

    let grouping = group_verified_semantic_pairs(
        &units,
        &verified,
        &crate::config::StageLimits::of(&profile).grouping.grouping(),
    );
    let stats = &grouping.stats;

    assert!(stats.ceiling_severed_pairs > 0);
    assert!(stats.ceiling_severed_pairs <= stats.ungrouped_pairs);
    assert_eq!(
        stats.declined_pairs() + stats.ceiling_severed_pairs,
        stats.ungrouped_pairs
    );
    assert_eq!(
        stats.declined_pairs(),
        grouping
            .ungrouped
            .iter()
            .filter(|entry| !entry.severed_by_the_ceiling)
            .count()
    );
    assert_eq!(stats.considered_pairs(), verified.len());
}

fn cross_language_pipeline(
    language: Language,
    variant: [u8; 32],
    operations: &[(OperationKind, &str)],
) -> SemanticOperationGraph {
    let nodes = operations
        .iter()
        .map(|(kind, api_name)| OperationNode {
            kind: *kind,
            attributes: OperationAttributes {
                api_names: BTreeSet::from([(*api_name).to_owned()]),
                ..OperationAttributes::default()
            },
        })
        .collect();
    SemanticOperationGraph::new(language, variant, nodes, Vec::new())
        .expect("valid cross-language pipeline graph")
}

fn direct_loop_pipeline(
    language: Language,
    variant: [u8; 32],
    terminal: OperationKind,
) -> SemanticOperationGraph {
    SemanticOperationGraph::new(
        language,
        variant,
        vec![
            OperationNode {
                kind: OperationKind::Source,
                attributes: OperationAttributes::default(),
            },
            OperationNode {
                kind: terminal,
                attributes: OperationAttributes::default(),
            },
        ],
        Vec::new(),
    )
    .expect("valid direct loop graph")
}

#[test]
fn cross_language_direct_loops_need_the_closed_construct_pair() {
    let rust = direct_loop_pipeline(Language::Rust, [38; 32], OperationKind::Collect);
    let cpp = direct_loop_pipeline(Language::Cpp, [39; 32], OperationKind::Collect);
    let inputs = vec![
        CrossLanguageCandidateInput {
            graph: rust.clone(),
            comparison_partition: [4; 16],
        },
        CrossLanguageCandidateInput {
            graph: cpp,
            comparison_partition: [4; 16],
        },
    ];
    let extracted = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    assert_eq!(
        extracted.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    let verified = verify_cross_language_candidates(&inputs, &extracted.pairs);
    assert_eq!(verified.len(), 1);
    assert_eq!(
        verified[0].1.correspondence_ids,
        vec![DIRECT_LOOP_SEQUENCE_CORRESPONDENCE_ID]
    );

    let transformed = SemanticOperationGraph::new(
        Language::Cpp,
        [40; 32],
        vec![
            OperationNode {
                kind: OperationKind::Source,
                attributes: OperationAttributes::default(),
            },
            OperationNode {
                kind: OperationKind::Collect,
                attributes: OperationAttributes {
                    api_names: BTreeSet::from(["std::push_back".to_owned()]),
                    ..OperationAttributes::default()
                },
            },
        ],
        Vec::new(),
    )
    .expect("valid transformed loop lookalike");
    assert!(match_cross_language_pipeline(&rust, &transformed).is_none());

    let reduction = direct_loop_pipeline(Language::Cpp, [41; 32], OperationKind::Reduce);
    assert!(match_cross_language_pipeline(&rust, &reduction).is_none());
}

#[test]
fn candidate_index_partitions_build_variants_and_avoids_other_sequences() {
    let graphs = vec![
        pipeline(
            Language::Rust,
            [8; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
        pipeline(
            Language::Rust,
            [8; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
        pipeline(
            Language::Rust,
            [9; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
        pipeline(
            Language::Rust,
            [8; 32],
            &[OperationKind::Map, OperationKind::Collect],
        ),
    ];
    let extracted = extract_registered_candidates(&graphs, SemanticCandidateConfig::default());
    assert_eq!(
        extracted.pairs,
        vec![SemanticCandidatePair { left: 0, right: 1 }]
    );
    assert_eq!(extracted.stats.buckets, 3);
    assert_eq!(extracted.stats.pairs_available, 1);
    assert_eq!(
        verify_registered_candidates(&graphs, &extracted.pairs)
            .iter()
            .map(|(_, matched)| matched.rule.id)
            .collect::<Vec<_>>(),
        vec!["sequence-pipeline-v1"]
    );
}

#[test]
fn candidate_limits_drop_complete_buckets_and_account_for_them() {
    let graphs = vec![
        pipeline(
            Language::Rust,
            [10; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
        pipeline(
            Language::Rust,
            [10; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
        pipeline(
            Language::Rust,
            [10; 32],
            &[OperationKind::Filter, OperationKind::Collect],
        ),
    ];
    let oversized = extract_registered_candidates(
        &graphs,
        SemanticCandidateConfig {
            max_bucket_members: 2,
            max_candidate_pairs: 10,
        },
    );
    assert!(oversized.pairs.is_empty());
    assert_eq!(oversized.stats.oversized_buckets, 1);
    assert_eq!(oversized.stats.pairs_available, 0);

    let budgeted = extract_registered_candidates(
        &graphs,
        SemanticCandidateConfig {
            max_bucket_members: 3,
            max_candidate_pairs: 2,
        },
    );
    assert!(budgeted.pairs.is_empty());
    assert_eq!(budgeted.stats.pairs_available, 3);
    assert_eq!(budgeted.stats.pairs_budget_dropped, 3);
}

#[test]
fn verifier_rejects_type_mismatch_and_out_of_range_candidate() {
    let mut rust = pipeline(
        Language::Rust,
        [11; 32],
        &[OperationKind::Filter, OperationKind::Collect],
    );
    rust.nodes[0].attributes.type_tag = Some(TypeTag::Integer);
    let mut cpp = pipeline(
        Language::Cpp,
        [11; 32],
        &[OperationKind::Filter, OperationKind::Collect],
    );
    cpp.nodes[0].attributes.type_tag = Some(TypeTag::Text);
    let graphs = vec![rust, cpp];
    assert!(
        verify_registered_candidates(
            &graphs,
            &[
                SemanticCandidatePair { left: 0, right: 1 },
                SemanticCandidatePair { left: 0, right: 2 },
            ],
        )
        .is_empty()
    );
}

/// A profile that states a posting ceiling states it for every pairing path,
/// and the registered-rule bucket index is one of them. Taken from the same
/// mapping the other stages take theirs from, so the number a run reports is
/// the number the buckets are cut at.
#[test]
fn the_registered_bucket_index_cuts_at_the_stated_posting_ceiling() {
    let profile = crate::execution::Limits::untrusted();
    let bucket: Vec<_> = (0..=profile.posting_cap)
        .map(|_| {
            pipeline(
                Language::Rust,
                [12; 32],
                &[OperationKind::Filter, OperationKind::Collect],
            )
        })
        .collect();
    let stated = crate::config::StageLimits::of(&profile)
        .pairing
        .semantic_candidates();
    assert_eq!(stated.max_bucket_members, profile.posting_cap);

    let contained = extract_registered_candidates(&bucket, stated);
    assert!(contained.pairs.is_empty());
    assert_eq!(contained.stats.oversized_buckets, 1);

    let default_profile = crate::execution::Limits::default();
    let admitted = extract_registered_candidates(
        &bucket,
        crate::config::StageLimits::of(&default_profile)
            .pairing
            .semantic_candidates(),
    );
    assert_eq!(admitted.stats.oversized_buckets, 0);
    assert!(!admitted.pairs.is_empty());
}

/// Refinement is quadratic in the size of the set it refines, so a profile that
/// lowers the component ceiling has to lower what semantic grouping refines.
/// Everything here matches everything else, which is the shape that makes the
/// ceiling the only thing standing between the profile and that cost.
#[test]
fn semantic_grouping_refines_no_more_than_the_stated_component_ceiling() {
    let profile = crate::execution::Limits::untrusted();
    let count = profile.max_component + 72;
    let units = semantic_grouping_units(count);
    let rule = registered_rules()[0];
    let verified: Vec<_> = (0..count)
        .flat_map(|left| {
            (left + 1..count).map(move |right| verified_semantic_pair(left, right, rule))
        })
        .collect();

    let contained = group_verified_semantic_pairs(
        &units,
        &verified,
        &crate::config::StageLimits::of(&profile).grouping.grouping(),
    );
    assert!(
        contained
            .groups
            .iter()
            .all(|group| group.members.len() <= profile.max_component),
        "{:?}",
        contained
            .groups
            .iter()
            .map(|group| group.members.len())
            .collect::<Vec<_>>()
    );
    assert!(contained.stats.ceiling_severed_pairs > 0);

    let whole = group_verified_semantic_pairs(
        &units,
        &verified,
        &crate::config::StageLimits::of(&crate::execution::Limits::default())
            .grouping
            .grouping(),
    );
    assert_eq!(whole.groups.len(), 1);
    assert_eq!(whole.groups[0].members.len(), count);
}
