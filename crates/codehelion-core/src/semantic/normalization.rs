use super::cross_language::cross_language_api_correspondence;
use super::graph::{
    DirectPropagation, FallibleKind, OperationAttributes, OperationEdge, OperationEdgeKind,
    OperationKind, OperationNode, SemanticGraphError, SemanticOperationGraph,
};
use super::rules::{
    SemanticRuleMatcher, SemanticRuleScope, match_same_variant_rule, registered_rules,
};
use crate::discovery::Language;
use crate::types::TypeTag;
use std::collections::BTreeSet;

/// One compiler-independent observation eligible for a registered SOG rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationObservation {
    /// Source-order position supplied by the adapter; it is not a stable ID.
    pub source_offset: u64,
    /// Compiler-resolved API spelling, without a helper-specific wrapper.
    pub api_name: String,
    /// Resolved operated-value category, when the compiler supplied one.
    pub type_tag: Option<TypeTag>,
}

/// One compiler-confirmed non-API operation eligible for a registered SOG rule.
///
/// The protocol adapter maps its helper-specific construct vocabulary into
/// this closed core vocabulary before calling the normalizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructObservation {
    /// Source-order position supplied by the adapter; it is not a stable ID.
    pub source_offset: u64,
    /// Closed SOG operation the compiler established.
    pub kind: OperationKind,
    /// Standard fallible container the compiler resolved for this operation.
    ///
    /// `None` is never treated as interchangeable with either known variant
    /// by a registered rule.
    pub fallible_kind: Option<FallibleKind>,
    /// Closed direct-propagation spelling the helper confirmed, when any.
    pub direct_propagation: Option<DirectPropagation>,
    /// Registered resource category for a compiler-confirmed acquire or
    /// release operation. It is absent for every other construct.
    pub resource_kind: Option<String>,
}

/// Ephemeral source range attached to one normalized operation.
///
/// This is reporting evidence rather than graph data. In particular, changing
/// a range does not change [`SemanticOperationGraph`] serialization or its
/// fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticSourceRange {
    /// Inclusive source byte offset.
    pub start: u64,
    /// Exclusive source byte offset.
    pub end: u64,
}

/// One bounded source fragment whose graph satisfies a registered rule when
/// compared with itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticGraphWindow {
    /// Normalized graph for this fragment only.
    pub graph: SemanticOperationGraph,
    /// Source range covering the retained operations.
    pub source_range: SemanticSourceRange,
}

/// The result of normalizing registered API observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiNormalization {
    /// A graph when at least one observation matches a registered operation.
    pub graph: Option<SemanticOperationGraph>,
    /// Source ranges aligned with [`Self::graph`] nodes.
    ///
    /// These ranges are intentionally omitted from the graph and therefore do
    /// not affect its schema or stable fingerprints.
    pub node_source_ranges: Vec<SemanticSourceRange>,
    /// Observations deliberately left outside the restricted vocabulary.
    pub excluded_observations: usize,
}

/// Normalize only APIs covered by the initial, explicit operation registry.
///
/// The caller supplies compiler-resolved names and source order. Every
/// unregistered name is counted but not approximated; this function therefore
/// remains a core-side normalization stage rather than a helper dependency.
///
/// # Errors
///
/// Returns [`SemanticGraphError`] only if the deterministic graph assembled
/// from registered operations violates its own invariant.
pub fn normalize_registered_apis(
    language: Language,
    build_variant_fingerprint: [u8; 32],
    observations: Vec<OperationObservation>,
) -> Result<ApiNormalization, SemanticGraphError> {
    normalize_registered_observations(
        language,
        build_variant_fingerprint,
        observations,
        Vec::new(),
    )
}

/// Normalize registered API and compiler-confirmed construct observations.
///
/// API names remain fail-closed against the registry. Constructs have already
/// crossed the compiler/protocol boundary and are accepted only when they use
/// the fixed SOG vocabulary; no frontend syntax type enters core.
///
/// # Errors
///
/// Returns [`SemanticGraphError`] only if the deterministic graph assembled
/// from registered operations violates its own invariant.
pub fn normalize_registered_observations(
    language: Language,
    build_variant_fingerprint: [u8; 32],
    observations: Vec<OperationObservation>,
    constructs: Vec<ConstructObservation>,
) -> Result<ApiNormalization, SemanticGraphError> {
    let api_with_ranges = observations.into_iter().map(|observation| {
        let range = SemanticSourceRange {
            start: observation.source_offset,
            end: observation.source_offset,
        };
        (observation, range)
    });
    let constructs_with_ranges = constructs.into_iter().map(|construct| {
        let range = SemanticSourceRange {
            start: construct.source_offset,
            end: construct.source_offset,
        };
        (construct, range)
    });
    normalize_registered_observations_with_ranges(
        language,
        build_variant_fingerprint,
        api_with_ranges.collect(),
        constructs_with_ranges.collect(),
    )
}

/// Normalize registered observations with their exact source ranges.
///
/// This variant is for protocol adapters that retain anchors. The ranges stay
/// beside the normalized graph so a caller can report a bounded fragment
/// without introducing source positions into fingerprints.
///
/// # Errors
///
/// Returns [`SemanticGraphError`] when a range is reversed or when the
/// deterministic graph assembled from registered operations is invalid.
pub fn normalize_registered_observations_with_ranges(
    language: Language,
    build_variant_fingerprint: [u8; 32],
    observations: Vec<(OperationObservation, SemanticSourceRange)>,
    constructs: Vec<(ConstructObservation, SemanticSourceRange)>,
) -> Result<ApiNormalization, SemanticGraphError> {
    if observations
        .iter()
        .map(|(_, range)| range)
        .chain(constructs.iter().map(|(_, range)| range))
        .any(|range| range.end < range.start)
    {
        return Err(SemanticGraphError::InvalidSourceRange);
    }
    let observation_count = observations.len();
    let mut nodes: Vec<_> = observations
        .into_iter()
        .enumerate()
        .filter_map(|(source_index, (observation, source_range))| {
            let kind = registered_api_kind(language, &observation.api_name)?;
            let order = observation.api_name.clone();
            Some((
                observation.source_offset,
                source_index,
                order,
                source_range,
                OperationNode {
                    kind,
                    attributes: OperationAttributes {
                        type_tag: observation.type_tag,
                        api_names: BTreeSet::from([observation.api_name]),
                        resource_kind: None,
                        fallible_kind: None,
                        direct_propagation: None,
                        structure_fingerprint: None,
                    },
                },
                ObservationSource::Api,
            ))
        })
        .collect();
    let recognized_api_count = nodes.len();
    nodes.extend(constructs.into_iter().enumerate().map(
        |(source_index, (construct, source_range))| {
            (
                construct.source_offset,
                source_index,
                construct.kind.name().to_owned(),
                source_range,
                OperationNode {
                    kind: construct.kind,
                    attributes: OperationAttributes {
                        fallible_kind: construct.fallible_kind,
                        direct_propagation: construct.direct_propagation,
                        resource_kind: construct.resource_kind,
                        ..OperationAttributes::default()
                    },
                },
                ObservationSource::Construct,
            )
        },
    ));
    nodes.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    nodes.dedup_by(coincident_operation);
    let node_source_ranges = nodes.iter().map(|(_, _, _, range, _, _)| *range).collect();
    let nodes: Vec<_> = nodes
        .into_iter()
        .map(|(_, _, _, _, node, _)| node)
        .collect();
    // The initial registry covers only data-sequence APIs. It never guesses
    // that an unrelated call is a transformation simply because it is nearby.
    let excluded_observations = observation_count.saturating_sub(recognized_api_count);
    if nodes.is_empty() {
        return Ok(ApiNormalization {
            graph: None,
            node_source_ranges,
            excluded_observations,
        });
    }
    let edges = operation_edges(&nodes)?;
    Ok(ApiNormalization {
        graph: Some(SemanticOperationGraph::new(
            language,
            build_variant_fingerprint,
            nodes,
            edges,
        )?),
        node_source_ranges,
        excluded_observations,
    })
}

/// Build the ordered data edges and any explicit resource-lifetime edge.
fn operation_edges(nodes: &[OperationNode]) -> Result<Vec<OperationEdge>, SemanticGraphError> {
    let mut edges = (1..nodes.len())
        .map(|index| {
            Ok(OperationEdge {
                from: u32::try_from(index - 1).map_err(|_| SemanticGraphError::GraphTooLarge)?,
                to: u32::try_from(index).map_err(|_| SemanticGraphError::GraphTooLarge)?,
                kind: OperationEdgeKind::Data,
            })
        })
        .collect::<Result<Vec<_>, SemanticGraphError>>()?;
    for (index, pair) in nodes.windows(2).enumerate() {
        let [acquire, release] = pair else {
            continue;
        };
        if acquire.kind == OperationKind::AcquireResource
            && release.kind == OperationKind::ReleaseResource
            && acquire.attributes.resource_kind == release.attributes.resource_kind
        {
            edges.push(OperationEdge {
                from: u32::try_from(index).map_err(|_| SemanticGraphError::GraphTooLarge)?,
                to: u32::try_from(index + 1).map_err(|_| SemanticGraphError::GraphTooLarge)?,
                kind: OperationEdgeKind::ResourceLifetime,
            });
        }
    }
    Ok(edges)
}

/// Whether two construct/API observations describe one source operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationSource {
    Api,
    Construct,
}

fn coincident_operation(
    left: &mut (
        u64,
        usize,
        String,
        SemanticSourceRange,
        OperationNode,
        ObservationSource,
    ),
    right: &mut (
        u64,
        usize,
        String,
        SemanticSourceRange,
        OperationNode,
        ObservationSource,
    ),
) -> bool {
    left.0 == right.0
        && left.3 == right.3
        && left.4.kind == right.4.kind
        && (left.5 != right.5 || left.1 == right.1)
}

/// Extract the largest source-contiguous windows that a same-variant rule can
/// justify on its own.
///
/// The extractor never enumerates arbitrary subgraphs. Sequence rules receive
/// their maximal contiguous run, direct constructs receive one node, and a
/// resource rule receives only an explicit acquire/release pair. This bounds
/// partial matching before candidate indexing and preserves a concise rule
/// explanation for every returned fragment.
///
/// An empty result is two different facts, and a caller that accounts for what
/// it analysed has to keep them apart. When
/// [`ApiNormalization::graph`] is absent, nothing the compiler resolved landed
/// in the registered vocabulary and the unit was never representable as a
/// graph. When a graph is present and no window comes back, the operations are
/// registered and no registered *rule* explains any fragment of them — a gap in
/// rule coverage rather than in what a compiler could speak for. A single
/// sequence operation is the ordinary case of the second: every sequence rule
/// states a minimum of two operations, so one alone is a graph no rule claims.
///
/// # Errors
///
/// Returns [`SemanticGraphError`] only if a validated graph cannot be rebased
/// into one of its own windows.
pub fn registered_semantic_windows(
    normalization: &ApiNormalization,
) -> Result<Vec<SemanticGraphWindow>, SemanticGraphError> {
    let Some(graph) = &normalization.graph else {
        return Ok(Vec::new());
    };
    if graph.nodes.len() != normalization.node_source_ranges.len() {
        return Err(SemanticGraphError::SourceRangeCountMismatch);
    }
    let mut windows = Vec::new();
    for rule in registered_rules()
        .iter()
        .copied()
        .filter(|rule| rule.scope == SemanticRuleScope::SameBuildVariant)
    {
        match rule.matcher {
            SemanticRuleMatcher::EquivalentSequence => {
                let mut start = 0;
                while start < graph.nodes.len() {
                    while start < graph.nodes.len()
                        && !rule
                            .pattern
                            .permitted_kinds
                            .contains(&graph.nodes[start].kind)
                    {
                        start += 1;
                    }
                    let end = graph.nodes[start..]
                        .iter()
                        .position(|node| !rule.pattern.permitted_kinds.contains(&node.kind))
                        .map_or(graph.nodes.len(), |length| start + length);
                    if start < end {
                        let window = semantic_graph_window(
                            graph,
                            &normalization.node_source_ranges,
                            start,
                            end,
                        )?;
                        if match_same_variant_rule(rule, &window.graph, &window.graph).is_some() {
                            windows.push(window);
                        }
                    }
                    start = end.saturating_add(1);
                }
            }
            SemanticRuleMatcher::ExactApiSequence { api_names } => {
                // Exact API rules prove a fixed-width sequence. A neighbouring
                // operation of the same kind must not make that sequence
                // disappear by extending the maximal general-purpose run.
                if !api_names.is_empty() && api_names.len() <= graph.nodes.len() {
                    for start in 0..=graph.nodes.len() - api_names.len() {
                        let window = semantic_graph_window(
                            graph,
                            &normalization.node_source_ranges,
                            start,
                            start + api_names.len(),
                        )?;
                        if match_same_variant_rule(rule, &window.graph, &window.graph).is_some() {
                            windows.push(window);
                        }
                    }
                }
            }
            SemanticRuleMatcher::DirectConstruct { .. } => {
                for index in 0..graph.nodes.len() {
                    let window = semantic_graph_window(
                        graph,
                        &normalization.node_source_ranges,
                        index,
                        index + 1,
                    )?;
                    if match_same_variant_rule(rule, &window.graph, &window.graph).is_some() {
                        windows.push(window);
                    }
                }
            }
            SemanticRuleMatcher::ResourceLifecycle => {
                for index in 0..graph.nodes.len().saturating_sub(1) {
                    let window = semantic_graph_window(
                        graph,
                        &normalization.node_source_ranges,
                        index,
                        index + 2,
                    )?;
                    if match_same_variant_rule(rule, &window.graph, &window.graph).is_some() {
                        windows.push(window);
                    }
                }
            }
        }
    }
    windows.sort_by_key(|window| window.source_range);
    windows.dedup_by(|left, right| {
        left.source_range == right.source_range && left.graph == right.graph
    });
    Ok(windows)
}

fn semantic_graph_window(
    graph: &SemanticOperationGraph,
    ranges: &[SemanticSourceRange],
    start: usize,
    end: usize,
) -> Result<SemanticGraphWindow, SemanticGraphError> {
    let source_range = SemanticSourceRange {
        start: ranges[start].start,
        end: ranges[end - 1].end,
    };
    let offset = u32::try_from(start).map_err(|_| SemanticGraphError::GraphTooLarge)?;
    let limit = u32::try_from(end).map_err(|_| SemanticGraphError::GraphTooLarge)?;
    let edges = graph
        .edges
        .iter()
        .filter(|edge| {
            edge.from >= offset && edge.from < limit && edge.to >= offset && edge.to < limit
        })
        .map(|edge| OperationEdge {
            from: edge.from - offset,
            to: edge.to - offset,
            kind: edge.kind,
        })
        .collect();
    Ok(SemanticGraphWindow {
        graph: SemanticOperationGraph::new(
            graph.language,
            graph.build_variant_fingerprint,
            graph.nodes[start..end].to_vec(),
            edges,
        )?,
        source_range,
    })
}

fn registered_api_kind(language: Language, api_name: &str) -> Option<OperationKind> {
    cross_language_api_correspondence(language, api_name)
        .map(|entry| entry.operation)
        .or_else(|| {
            matches!(
                (language, api_name),
                (
                    Language::Rust,
                    "rust::ToString::to_string" | "rust::str::parse"
                ) | (Language::Cpp, "std::to_string" | "std::stoull")
            )
            .then_some(OperationKind::Map)
        })
}
