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
    let mut position = vec![0usize; units.len()];
    let similarities = ComponentMatrix::build(&[0, 1, 2], &sim, &mut position, &mut forward_stats);

    complete_linkage_trim(
        1,
        &mut forward,
        &mut forward_rest,
        &units,
        &similarities,
        &config,
        &mut forward_stats,
    );
    complete_linkage_trim(
        1,
        &mut backward,
        &mut backward_rest,
        &units,
        &similarities,
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

/// Units keyed by index over the whole `u64` range, so a component may hold
/// more members than a single byte can name.
fn wide_units(count: usize) -> Vec<GroupingUnit> {
    (0..count)
        .map(|index| {
            let mut key = [0u8; 16];
            let index = u64::try_from(index).unwrap();
            key[0..8].copy_from_slice(&index.to_be_bytes());
            GroupingUnit { key }
        })
        .collect()
}

/// A chain 0-1-2-...-n: one component refinement peels a couple of members
/// off at a time, so the members it ejects are regrouped as many times as the
/// chain is long. This is the shape whose cost the module states a bound for.
fn chain(count: usize) -> Vec<SimilarityEdge> {
    (0..count.saturating_sub(1))
        .map(|index| edge(index, index + 1, 0.9))
        .collect()
}

/// One member every other member is related to, half of them too weakly to
/// keep, so refinement both ejects and regroups.
fn hub(count: usize) -> Vec<SimilarityEdge> {
    let mut edges: Vec<SimilarityEdge> = (1..count)
        .map(|index| edge(0, index, if index % 2 == 0 { 0.9 } else { 0.5 }))
        .collect();
    edges.extend((1..count).map(|index| edge(index, (index % (count - 1)) + 1, 0.55)));
    edges
}

#[test]
fn refinement_weighs_each_pair_of_a_component_once_however_often_it_regroups() {
    // Rebuilding what a component knows about itself once per level of the
    // regrouping multiplies the work by the number of levels, which is what
    // turns the stated O(k² log k) into a cubic cost on exactly the shapes
    // this module exists for: a similarity chain, and a family around one
    // widely copied unit.
    for shape in [chain as fn(usize) -> Vec<SimilarityEdge>, hub] {
        let mut previous: Option<(usize, usize)> = None;
        for &size in &[128usize, 256, 512, 1024] {
            let units = wide_units(size);
            let edges = shape(size);

            let _ = taken_graph_queries();
            let set = group(&units, &edges, &GroupingConfig::default());
            let queries = taken_graph_queries();

            assert_eq!(set.stats.components, 1, "the shape is one component");
            assert_eq!(
                set.stats.oversized_components, 0,
                "the component ceiling did not fire, so it explains nothing"
            );
            assert_eq!(
                queries,
                size * (size - 1) / 2,
                "each pair of a {size}-member component is weighed once"
            );
            if let Some((smaller, fewer)) = previous {
                assert_eq!(size, smaller * 2);
                // Twice the members is four times the pairs. Eight times would
                // be a level of regrouping charged for the whole component.
                assert!(
                    queries <= fewer * 5,
                    "{queries} queries at {size} members against {fewer} at {smaller}"
                );
            }
            previous = Some((size, queries));
        }
    }
}

#[test]
fn refinement_reports_what_it_weighed_even_when_no_ceiling_fired() {
    let size = 512;
    let units = wide_units(size);

    let set = group(&units, &hub(size), &GroupingConfig::default());

    assert_eq!(set.stats.oversized_components, 0);
    assert!(
        set.stats.refinement_comparisons >= size * (size - 1) / 2,
        "the comparisons a run spent its time on are reported: {:?}",
        set.stats
    );
}

#[test]
fn one_components_similarities_do_not_leak_into_another() {
    // Two components refined one after the other reuse the same position
    // scratch; a member of the second must read its own table, not whatever
    // the first left behind.
    let units = wide_units(6);
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
    for reported in &set.groups {
        assert_eq!(reported.members.len(), 3);
        assert!((reported.min_pairwise - 0.9).abs() < 1e-12);
        for &similarity in &reported.medoid_similarities {
            assert!(similarity >= 0.9);
        }
    }
}

/// A group over one pair of units, given as spans into two files.
fn cut(clone_type: CloneClass, members: [usize; 2]) -> StructuralGroup {
    StructuralGroup {
        clone_type,
        confidence: Confidence::High,
        canonical: members[0],
        members: members.to_vec(),
        medoid_similarities: vec![1.0, 1.0],
        min_pairwise: 1.0,
    }
}

/// Three cuts of one duplication: units 0-1 are the widest, then 2-3, then
/// 4-5, each pair nested inside the one before it, on both sides.
///
/// Units 0 and 1 are the declarations; every other unit is an expression
/// written inside one of them, so it names that declaration and is that unit
/// at a smaller extent.
fn nested_cut_spans() -> Vec<MemberSpan> {
    vec![
        MemberSpan {
            file: 0,
            start: 305,
            end: 330,
            declaration: 0,
        },
        MemberSpan {
            file: 1,
            start: 605,
            end: 630,
            declaration: 1,
        },
        MemberSpan {
            file: 0,
            start: 305,
            end: 322,
            declaration: 0,
        },
        MemberSpan {
            file: 1,
            start: 605,
            end: 622,
            declaration: 1,
        },
        MemberSpan {
            file: 0,
            start: 305,
            end: 313,
            declaration: 0,
        },
        MemberSpan {
            file: 1,
            start: 605,
            end: 613,
            declaration: 1,
        },
    ]
}

#[test]
fn nested_cuts_of_one_duplication_leave_only_the_longest() {
    let spans = nested_cut_spans();
    let groups = [
        cut(CloneClass::Type3, [4, 5]),
        cut(CloneClass::Type3, [0, 1]),
        cut(CloneClass::Type3, [2, 3]),
    ];

    let folded = contained_groups(&groups, &spans);

    assert_eq!(folded, vec![true, false, true]);
}

#[test]
fn a_cut_reaching_outside_its_cover_stays_a_group_of_its_own() {
    // The second side sits where the longer cut does not reach, so the longer
    // cut does not report this duplication at all.
    let mut spans = nested_cut_spans();
    spans[5] = MemberSpan {
        file: 1,
        start: 900,
        end: 908,
        declaration: 1,
    };
    let groups = [
        cut(CloneClass::Type3, [0, 1]),
        cut(CloneClass::Type3, [4, 5]),
    ];

    assert_eq!(contained_groups(&groups, &spans), vec![false, false]);
}

#[test]
fn a_verbatim_cut_survives_a_longer_one_that_only_matches_renamed() {
    // "These lines match up to renaming, and these of them match verbatim" is
    // two facts, so the stricter one is not folded into the looser.
    let spans = nested_cut_spans();
    let groups = [
        cut(CloneClass::Type3, [0, 1]),
        cut(CloneClass::Type1, [4, 5]),
    ];

    assert_eq!(contained_groups(&groups, &spans), vec![false, false]);
}

#[test]
fn a_nested_declaration_is_a_finding_of_its_own_while_a_cut_of_one_is_not() {
    // Units 2 and 3 declare themselves — helpers written inside 0 and 1, the
    // way a nested function is — while 4 and 5 are expressions of 0 and 1.
    // Both pairs sit inside the covering units by position, and only the
    // second pair is those units seen smaller.
    let mut spans = nested_cut_spans();
    spans[2].declaration = 2;
    spans[3].declaration = 3;
    let groups = [
        cut(CloneClass::Type3, [0, 1]),
        cut(CloneClass::Type3, [2, 3]),
        cut(CloneClass::Type3, [4, 5]),
    ];

    assert_eq!(
        contained_groups(&groups, &spans),
        vec![false, false, true],
        "a duplicated helper is a duplication, a smaller cut of one is not"
    );
}

#[test]
fn two_groups_over_one_stretch_cannot_remove_each_other() {
    // Equal covers contain each other both ways. Neither is the longer cut of
    // the other, so containment has nothing to say about the pair.
    let spans = nested_cut_spans();
    let groups = [
        cut(CloneClass::Type3, [0, 1]),
        cut(CloneClass::Type2, [0, 1]),
    ];

    assert_eq!(contained_groups(&groups, &spans), vec![false, false]);
}
