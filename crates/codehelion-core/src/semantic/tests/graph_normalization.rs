use super::super::*;

fn node(kind: OperationKind) -> OperationNode {
    OperationNode {
        kind,
        attributes: OperationAttributes::default(),
    }
}

#[test]
fn graph_canonicalizes_edge_order_without_changing_the_fixed_vocabulary() {
    let graph = SemanticOperationGraph::new(
        Language::Rust,
        [7; 32],
        vec![node(OperationKind::Source), node(OperationKind::Collect)],
        vec![
            OperationEdge {
                from: 1,
                to: 0,
                kind: OperationEdgeKind::Ordering,
            },
            OperationEdge {
                from: 0,
                to: 1,
                kind: OperationEdgeKind::Data,
            },
        ],
    )
    .expect("valid graph");
    assert_eq!(graph.schema_version, SOG_SCHEMA_VERSION);
    assert_eq!(graph.edges[0].from, 0);
    assert_eq!(graph.edges[1].from, 1);
    assert_eq!(
        serde_json::to_string(&graph).expect("serializable graph"),
        serde_json::to_string(&graph).expect("deterministic serialization")
    );
}

#[test]
fn closed_cross_language_api_table_has_only_explicit_standard_pairs() {
    let rust = cross_language_api_correspondence(Language::Rust, "rust::Iterator::map")
        .expect("registered Rust map API");
    let cpp = cross_language_api_correspondence(Language::Cpp, "std::transform")
        .expect("registered C++ transform API");
    assert_eq!(rust.id, "sequence-map-v1");
    assert_eq!(rust, cpp);
    assert_eq!(rust.operation, OperationKind::Map);
    assert!(cross_language_api_correspondence(Language::Rust, "project::map").is_none());
    assert!(cross_language_api_correspondence(Language::C, "transform").is_none());
}

#[test]
fn resource_lifetime_requires_matching_explicit_categories() {
    let mut acquire = node(OperationKind::AcquireResource);
    acquire.attributes.resource_kind = Some("file".to_owned());
    let mut release = node(OperationKind::ReleaseResource);
    release.attributes.resource_kind = Some("socket".to_owned());
    assert_eq!(
        SemanticOperationGraph::new(
            Language::Cpp,
            [0; 32],
            vec![acquire, release],
            vec![OperationEdge {
                from: 0,
                to: 1,
                kind: OperationEdgeKind::ResourceLifetime,
            }],
        ),
        Err(SemanticGraphError::InvalidResourceLifetime)
    );
}

#[test]
fn nonrepresentable_resource_information_is_rejected_instead_of_generalized() {
    let mut map = node(OperationKind::Map);
    map.attributes.resource_kind = Some("file".to_owned());
    assert_eq!(
        SemanticOperationGraph::new(Language::C, [1; 32], vec![map], Vec::new()),
        Err(SemanticGraphError::UnexpectedResourceKind { index: 0 })
    );
}

#[test]
fn registered_apis_normalize_in_source_order_and_leave_other_calls_out() {
    let normalized = normalize_registered_apis(
        Language::Rust,
        [2; 32],
        vec![
            OperationObservation {
                source_offset: 30,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: Some(TypeTag::Sequence),
            },
            OperationObservation {
                source_offset: 10,
                api_name: "rust::Iterator::filter".to_owned(),
                type_tag: Some(TypeTag::Integer),
            },
            OperationObservation {
                source_offset: 20,
                api_name: "static:project::log".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 40,
                api_name: "project::map".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("registered sequence APIs form a valid graph");
    assert_eq!(normalized.excluded_observations, 2);
    let graph = normalized.graph.expect("two registered operations");
    assert_eq!(
        graph.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
        vec![OperationKind::Filter, OperationKind::Collect]
    );
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].kind, OperationEdgeKind::Data);
}

#[test]
fn registered_api_normalization_is_deterministic_when_observations_arrive_reordered() {
    let observations = vec![
        OperationObservation {
            source_offset: 30,
            api_name: "rust::Iterator::collect".to_owned(),
            type_tag: Some(TypeTag::Sequence),
        },
        OperationObservation {
            source_offset: 10,
            api_name: "rust::Iterator::filter".to_owned(),
            type_tag: Some(TypeTag::Integer),
        },
    ];
    let first = normalize_registered_apis(Language::Rust, [3; 32], observations.clone())
        .expect("first normalization");
    let mut reversed = observations;
    reversed.reverse();
    let second =
        normalize_registered_apis(Language::Rust, [3; 32], reversed).expect("second normalization");
    assert_eq!(first, second);
}

#[test]
fn compiler_confirmed_constructs_join_registered_apis_in_source_order() {
    let normalized = normalize_registered_observations(
        Language::Rust,
        [12; 32],
        vec![OperationObservation {
            source_offset: 20,
            api_name: "rust::Iterator::collect".to_owned(),
            type_tag: Some(TypeTag::Sequence),
        }],
        vec![ConstructObservation {
            source_offset: 10,
            kind: OperationKind::PropagateError,
            fallible_kind: Some(FallibleKind::Result),
            direct_propagation: None,
            resource_kind: None,
        }],
    )
    .expect("registered observations form a graph");
    let graph = normalized.graph.expect("two registered operations");
    assert_eq!(
        graph.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
        vec![OperationKind::PropagateError, OperationKind::Collect]
    );
    assert_eq!(
        graph.nodes[0].attributes.fallible_kind,
        Some(FallibleKind::Result)
    );
    assert_eq!(normalized.excluded_observations, 0);
}

#[test]
fn one_source_operation_is_not_duplicated_by_construct_and_api_evidence() {
    let normalized = normalize_registered_observations_with_ranges(
        Language::Rust,
        [44; 32],
        vec![(
            OperationObservation {
                source_offset: 10,
                api_name: "rust::Vec::push".to_owned(),
                type_tag: Some(TypeTag::Sequence),
            },
            SemanticSourceRange { start: 10, end: 14 },
        )],
        vec![(
            ConstructObservation {
                source_offset: 10,
                kind: OperationKind::Collect,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticSourceRange { start: 10, end: 14 },
        )],
    )
    .expect("overlapping observations form a graph");
    let graph = normalized.graph.expect("one registered operation");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind, OperationKind::Collect);
    assert!(graph.nodes[0].attributes.api_names.is_empty());
}

#[test]
fn coincident_macro_calls_keep_expansion_order_and_repeated_operations() {
    let range = SemanticSourceRange { start: 10, end: 14 };
    let observations = [
        "rust::Iterator::map",
        "rust::Iterator::filter",
        "rust::Iterator::map",
    ]
    .into_iter()
    .map(|api_name| {
        (
            OperationObservation {
                source_offset: 10,
                api_name: api_name.to_owned(),
                type_tag: Some(TypeTag::Sequence),
            },
            range,
        )
    })
    .collect();

    let normalized = normalize_registered_observations_with_ranges(
        Language::Rust,
        [45; 32],
        observations,
        Vec::new(),
    )
    .expect("macro expansion calls form a graph");
    let graph = normalized.graph.expect("three registered operations");

    assert_eq!(
        graph.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
        vec![
            OperationKind::Map,
            OperationKind::Filter,
            OperationKind::Map
        ]
    );
    assert_eq!(normalized.node_source_ranges, vec![range; 3]);
}

#[test]
fn registered_windows_keep_maximal_pipeline_ranges_outside_other_operations() {
    let normalized = normalize_registered_observations_with_ranges(
        Language::Rust,
        [32; 32],
        vec![
            (
                OperationObservation {
                    source_offset: 30,
                    api_name: "rust::IntoIterator::into_iter".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 30, end: 40 },
            ),
            (
                OperationObservation {
                    source_offset: 40,
                    api_name: "rust::Iterator::filter".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 40, end: 50 },
            ),
            (
                OperationObservation {
                    source_offset: 50,
                    api_name: "rust::Iterator::collect".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 50, end: 60 },
            ),
        ],
        vec![
            (
                ConstructObservation {
                    source_offset: 10,
                    kind: OperationKind::PropagateError,
                    fallible_kind: Some(FallibleKind::Result),
                    direct_propagation: Some(DirectPropagation::ResultAdapter),
                    resource_kind: None,
                },
                SemanticSourceRange { start: 10, end: 20 },
            ),
            (
                ConstructObservation {
                    source_offset: 70,
                    kind: OperationKind::Validate,
                    fallible_kind: Some(FallibleKind::Option),
                    direct_propagation: None,
                    resource_kind: None,
                },
                SemanticSourceRange { start: 70, end: 80 },
            ),
        ],
    )
    .expect("observations form a graph");
    let windows = registered_semantic_windows(&normalized).expect("windows rebase safely");
    assert_eq!(windows.len(), 3);
    assert_eq!(
        windows[1]
            .graph
            .nodes
            .iter()
            .map(|node| node.kind)
            .collect::<Vec<_>>(),
        vec![
            OperationKind::Source,
            OperationKind::Filter,
            OperationKind::Collect
        ]
    );
    assert_eq!(
        windows[1].source_range,
        SemanticSourceRange { start: 30, end: 60 }
    );
    assert!(
        windows
            .iter()
            .all(|window| { match_registered_rule(&window.graph, &window.graph).is_some() })
    );
}

#[test]
fn exact_api_windows_survive_an_adjacent_map_operation() {
    let normalized = normalize_registered_observations_with_ranges(
        Language::Rust,
        [46; 32],
        vec![
            (
                OperationObservation {
                    source_offset: 10,
                    api_name: "rust::ToString::to_string".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 10, end: 20 },
            ),
            (
                OperationObservation {
                    source_offset: 20,
                    api_name: "rust::str::parse".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 20, end: 30 },
            ),
            (
                OperationObservation {
                    source_offset: 30,
                    api_name: "rust::Iterator::map".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 30, end: 40 },
            ),
        ],
        Vec::new(),
    )
    .expect("observations form a graph");

    let windows = registered_semantic_windows(&normalized).expect("windows rebase safely");
    assert!(windows.iter().any(|window| {
        window.source_range == SemanticSourceRange { start: 10, end: 30 }
            && match_registered_rule(&window.graph, &window.graph)
                .is_some_and(|matched| matched.rule.id == "rust-serialization-round-trip-v1")
    }));
}

#[test]
fn registered_windows_reject_reversed_source_ranges() {
    assert_eq!(
        normalize_registered_observations_with_ranges(
            Language::Rust,
            [33; 32],
            vec![(
                OperationObservation {
                    source_offset: 10,
                    api_name: "rust::Iterator::collect".to_owned(),
                    type_tag: None,
                },
                SemanticSourceRange { start: 11, end: 10 },
            )],
            Vec::new(),
        ),
        Err(SemanticGraphError::InvalidSourceRange)
    );
}
