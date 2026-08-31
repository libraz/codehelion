use super::*;

/// Units keyed `0x00..`, `0x01..`, ... so key order matches index order.
fn units(count: usize) -> Vec<GroupingUnit> {
    (0..count)
        .map(|i| GroupingUnit {
            key: [u8::try_from(i).unwrap(); 16],
        })
        .collect()
}

fn edge(a: usize, b: usize, similarity: f64) -> SimilarityEdge {
    SimilarityEdge {
        a,
        b,
        similarity,
        breakdown: None,
        class: CloneClass::Type3,
        confidence: Confidence::Medium,
    }
}

#[test]
fn a_transitive_chain_does_not_fuse_into_one_group() {
    // 0-1-2-3-4, each adjacent pair strong, ends never compared. A plain
    // connected-component grouping would return one group of five; medoid +
    // complete-linkage must not, because 0 and 4 are dissimilar.
    let units = units(5);
    let edges = vec![
        edge(0, 1, 0.9),
        edge(1, 2, 0.9),
        edge(2, 3, 0.9),
        edge(3, 4, 0.9),
    ];
    let set = group(&units, &edges, &GroupingConfig::default());
    assert_eq!(set.stats.components, 1, "the chain is one component");
    assert!(
        set.groups.iter().all(|g| g.members.len() < 5),
        "no group may span the whole chain"
    );
    // Every reported group clears the cohesion floor on every internal pair.
    for reported in &set.groups {
        assert!(reported.min_pairwise >= 0.60);
    }
}

#[test]
fn a_clique_is_one_group_with_a_deterministic_medoid() {
    // A fully connected trio: one cohesive group, medoid is the smallest key
    // on the total-similarity tie.
    let units = units(3);
    let edges = vec![edge(0, 1, 0.9), edge(1, 2, 0.9), edge(0, 2, 0.9)];
    let set = group(&units, &edges, &GroupingConfig::default());
    assert_eq!(set.groups.len(), 1);
    let only = &set.groups[0];
    assert_eq!(only.members.len(), 3);
    assert_eq!(only.canonical, 0);
    assert_eq!(only.members[0], 0, "medoid comes first");
}

#[test]
fn medoid_sampling_covers_distinct_content_across_the_component() {
    let mut units = vec![GroupingUnit { key: [0; 16] }; 32];
    units.extend((32_u8..40).map(|key| GroupingUnit { key: [key; 16] }));
    let mut edges = clique(units.len());
    for edge in &mut edges {
        if edge.a == 39 || edge.b == 39 {
            edge.similarity = 0.99;
        } else {
            edge.similarity = 0.61;
        }
    }
    let config = GroupingConfig {
        sampling_threshold: 8,
        sample_size: 4,
        max_component: 64,
        ..GroupingConfig::default()
    };

    let set = group(&units, &edges, &config);

    assert_eq!(set.groups[0].canonical, 39);
    assert_eq!(set.stats.sampled_medoids, 1);
    assert_eq!(set.stats.sampled_medoid_candidates, 4);
}

/// Every pair among `count` units, all similar enough to group: one
/// component that refinement would otherwise handle as one piece.
fn clique(count: usize) -> Vec<SimilarityEdge> {
    let mut edges = Vec::new();
    for left in 0..count {
        for right in (left + 1)..count {
            edges.push(edge(left, right, 0.9));
        }
    }
    edges
}

#[test]
fn a_component_over_the_ceiling_is_cut_into_pieces_and_the_cut_is_counted() {
    let units = units(10);
    let config = GroupingConfig {
        max_component: 4,
        ..GroupingConfig::default()
    };
    let set = group(&units, &clique(10), &config);
    assert_eq!(set.stats.components, 1, "still one component");
    assert_eq!(set.stats.oversized_components, 1, "the ceiling is reported");

    // Recall is what the ceiling costs: the ten stay clones of each other
    // but are reported as three groups instead of one.
    assert_eq!(set.groups.len(), 3);
    assert!(set.groups.iter().all(|g| g.members.len() <= 4));
    let grouped: usize = set.groups.iter().map(|g| g.members.len()).sum();
    assert_eq!(grouped, 10, "no member is lost to the cut");

    // Soundness is what it does not cost: each piece is refined by the
    // same rules, so every reported group is still cohesive.
    assert!(
        set.groups
            .iter()
            .all(|g| g.min_pairwise >= config.min_pairwise_similarity)
    );
}

#[test]
fn an_equal_content_class_is_never_split_by_the_component_ceiling() {
    // Cutting this class into arbitrary chunks would emit several groups
    // with the same content-derived clone-group and finding identifiers.
    // The one class is intentionally allowed to exceed the ceiling.
    let units = vec![GroupingUnit { key: [7; 16] }; 10];
    let config = GroupingConfig {
        max_component: 4,
        ..GroupingConfig::default()
    };
    let set = group(&units, &clique(10), &config);

    assert_eq!(set.stats.oversized_components, 1);
    assert_eq!(set.groups.len(), 1);
    assert_eq!(set.groups[0].members.len(), 10);
    assert!(
        (0..10).all(|member| !set.severed_by_the_ceiling(0, member)),
        "one content class is not severed by the ceiling"
    );
}

#[test]
fn equal_similarity_ties_choose_the_pair_by_content_key() {
    let units = vec![
        GroupingUnit { key: [2; 16] },
        GroupingUnit { key: [0; 16] },
        GroupingUnit { key: [1; 16] },
    ];
    let sim = SimilarityGraph::build(3, &clique(3));
    let config = GroupingConfig {
        min_pairwise_similarity: 0.95,
        ..GroupingConfig::default()
    };
    let mut forward = vec![0, 1, 2];
    let mut backward = vec![2, 1, 0];
    let mut forward_rest = Vec::new();
    let mut backward_rest = Vec::new();
    let mut forward_stats = GroupingStats::default();
    let mut backward_stats = GroupingStats::default();

    complete_linkage_trim(
        1,
        &mut forward,
        &mut forward_rest,
        &units,
        &sim,
        &config,
        &mut forward_stats,
    );
    complete_linkage_trim(
        1,
        &mut backward,
        &mut backward_rest,
        &units,
        &sim,
        &config,
        &mut backward_stats,
    );

    assert_eq!(forward_rest, vec![2, 0]);
    assert_eq!(backward_rest, forward_rest);
    assert_eq!(canonical_pair(1, 2, &units), ([0; 16], [1; 16]));
}

#[test]
fn the_cut_follows_the_keys_not_the_order_the_edges_arrived_in() {
    let units = units(10);
    let config = GroupingConfig {
        max_component: 4,
        ..GroupingConfig::default()
    };
    let mut reversed = clique(10);
    reversed.reverse();
    let forward = group(&units, &clique(10), &config);
    let backward = group(&units, &reversed, &config);
    assert_eq!(forward.groups, backward.groups);
}

#[test]
fn a_component_at_the_ceiling_is_refined_whole() {
    let units = units(4);
    let config = GroupingConfig {
        max_component: 4,
        ..GroupingConfig::default()
    };
    let set = group(&units, &clique(4), &config);
    assert_eq!(set.stats.oversized_components, 0);
    assert_eq!(set.groups.len(), 1);
    assert_eq!(set.groups[0].members.len(), 4);
    assert!(
        !set.severed_by_the_ceiling(0, 3),
        "nothing was cut, so nothing was severed"
    );
}

#[test]
fn the_cut_says_which_pairs_it_kept_from_ever_meeting() {
    // Ten mutual clones under a ceiling of four: cut into three pieces, so
    // members of different pieces were never weighed against each other.
    // A caller carrying out the relations no group holds has to tell that
    // apart from a relation refinement considered and declined.
    let units = units(10);
    let config = GroupingConfig {
        max_component: 4,
        ..GroupingConfig::default()
    };
    let set = group(&units, &clique(10), &config);

    let piece_of = |unit: usize| {
        set.groups
            .iter()
            .position(|group| group.members.contains(&unit))
            .expect("every member is grouped")
    };
    for left in 0..10 {
        for right in (left + 1)..10 {
            assert_eq!(
                set.severed_by_the_ceiling(left, right),
                piece_of(left) != piece_of(right),
                "{left} and {right}"
            );
        }
    }
}

#[test]
fn a_member_far_from_the_medoid_is_ejected() {
    // 0,1,2 form a tight clique; 3 hangs off 2 weakly. 3 must not join the
    // clique's group.
    let units = units(4);
    let edges = vec![
        edge(0, 1, 0.95),
        edge(0, 2, 0.95),
        edge(1, 2, 0.95),
        edge(2, 3, 0.62),
    ];
    let set = group(&units, &edges, &GroupingConfig::default());
    let big = set
        .groups
        .iter()
        .find(|g| g.members.contains(&0))
        .expect("the clique forms a group");
    assert!(
        !big.members.contains(&3),
        "the weakly attached member stays out of the clique"
    );
}

#[test]
fn union_find_components_are_not_emitted_verbatim() {
    // Two disjoint cliques: two components, two groups, and never one merged
    // group.
    let units = units(6);
    let edges = vec![
        edge(0, 1, 0.9),
        edge(1, 2, 0.9),
        edge(0, 2, 0.9),
        edge(3, 4, 0.9),
        edge(4, 5, 0.9),
        edge(3, 5, 0.9),
    ];
    let set = group(&units, &edges, &GroupingConfig::default());
    assert_eq!(set.stats.components, 2);
    assert_eq!(set.groups.len(), 2);
    assert!(set.groups.iter().all(|g| g.members.len() == 3));
}

#[test]
fn a_lone_unit_is_not_a_group() {
    let units = units(2);
    // No edges: two singletons, no group.
    let set = group(&units, &[], &GroupingConfig::default());
    assert!(set.groups.is_empty());
}

#[test]
fn component_collection_omits_isolated_units_before_bucket_allocation() {
    let components = connected_components(1_000, &[edge(17, 843, 0.9)]);
    assert_eq!(components, vec![vec![17, 843]]);
}

#[test]
fn the_group_takes_the_weakest_class_and_confidence() {
    let units = units(3);
    let edges = vec![
        SimilarityEdge {
            a: 0,
            b: 1,
            similarity: 0.95,
            breakdown: None,
            class: CloneClass::Type1,
            confidence: Confidence::High,
        },
        SimilarityEdge {
            a: 1,
            b: 2,
            similarity: 0.9,
            breakdown: None,
            class: CloneClass::Type3,
            confidence: Confidence::Low,
        },
        SimilarityEdge {
            a: 0,
            b: 2,
            similarity: 0.9,
            breakdown: None,
            class: CloneClass::Type2,
            confidence: Confidence::Medium,
        },
    ];
    let set = group(&units, &edges, &GroupingConfig::default());
    let only = &set.groups[0];
    assert_eq!(only.clone_type, CloneClass::Type3);
    assert_eq!(only.confidence, Confidence::Low);
}

#[test]
fn a_group_a_registered_rule_alone_explains_is_not_a_verbatim_copy() {
    // Every internal edge is justified by a registered rule, so the group is
    // no more than that. Reporting it as a verbatim copy would say the members
    // agree token for token, and `is_exact` would agree.
    let units = units(3);
    let edges: Vec<SimilarityEdge> = clique(3)
        .into_iter()
        .map(|mut edge| {
            edge.class = CloneClass::RestrictedSemantic;
            edge
        })
        .collect();
    let set = group(&units, &edges, &GroupingConfig::default());
    let only = &set.groups[0];
    assert_eq!(only.clone_type, CloneClass::RestrictedSemantic);
    assert!(!only.clone_type.is_exact());
}

#[test]
fn two_listings_of_one_pair_are_settled_by_what_they_say_not_by_their_order() {
    // The same pair stated twice at the same score, once as a renamed copy and
    // once as a gapped one. The stronger reading is kept whichever way round
    // the two arrive, and whichever way round their endpoints are written.
    let units = units(3);
    let renamed = SimilarityEdge {
        a: 0,
        b: 1,
        similarity: 0.9,
        breakdown: None,
        class: CloneClass::Type2,
        confidence: Confidence::High,
    };
    let gapped = SimilarityEdge {
        a: 1,
        b: 0,
        similarity: 0.9,
        breakdown: None,
        class: CloneClass::Type3,
        confidence: Confidence::Low,
    };
    let rest = [
        SimilarityEdge {
            a: 1,
            b: 2,
            ..renamed
        },
        SimilarityEdge {
            a: 0,
            b: 2,
            ..renamed
        },
    ];

    let mut forward = vec![renamed, gapped];
    forward.extend_from_slice(&rest);
    let mut backward = vec![gapped, renamed];
    backward.extend_from_slice(&rest);

    let a = group(&units, &forward, &GroupingConfig::default());
    let b = group(&units, &backward, &GroupingConfig::default());
    assert_eq!(a.groups, b.groups);
    assert_eq!(a.groups[0].clone_type, CloneClass::Type2);
    assert_eq!(a.groups[0].confidence, Confidence::High);
}

#[test]
fn grouping_is_deterministic_regardless_of_edge_order() {
    let units = units(5);
    let forward = vec![
        edge(0, 1, 0.9),
        edge(1, 2, 0.9),
        edge(2, 3, 0.9),
        edge(3, 4, 0.9),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();
    let a = group(&units, &forward, &GroupingConfig::default());
    let b = group(&units, &reversed, &GroupingConfig::default());
    assert_eq!(a.groups, b.groups);
}
