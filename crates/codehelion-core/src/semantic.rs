//! Restricted Semantic Operation Graphs.
//!
//! This is deliberately a closed vocabulary. The graph is a target for
//! compiler-independent normalization, not a generic program representation:
//! code that cannot be expressed by one of these operations is left outside
//! semantic matching. That restriction keeps later findings explainable as a
//! sequence of registered transformations instead of turning this mode into a
//! claim of general semantic equivalence.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clone_class::CloneClass;
use crate::discovery::Language;
use crate::grouping::{self, GroupingConfig, GroupingUnit, SimilarityEdge};
use crate::types::TypeTag;
use crate::verify::Confidence;

/// Version of the closed SOG vocabulary and normalization contract.
pub const SOG_SCHEMA_VERSION: &str = "sog-v1";

/// Version of the coarse index used to bound registered SOG comparisons.
///
/// The index is deliberately only a candidate filter. A matching rule still
/// checks all of its conditions after extraction, so changing this version
/// can affect cost and recall but never turns an unchecked pair into a
/// finding.
pub const SEMANTIC_CANDIDATE_INDEX_VERSION: &str = "sog-candidate-index-v1";

/// Version of the bounded source-window extraction for registered SOG rules.
///
/// Source ranges are deliberately sidecar evidence: they select the reported
/// fragment but never enter a SOG fingerprint or a stable finding identity.
pub const SEMANTIC_WINDOWING_VERSION: &str = "sog-windowing-v1";

/// Version of the opt-in Rust-to-C++ candidate index.
///
/// This index is separate from ordinary semantic detection: it accepts only
/// caller-supplied explicit comparison partitions and never joins a normal
/// build-variant bucket.
pub const CROSS_LANGUAGE_CANDIDATE_INDEX_VERSION: &str = "cross-language-sog-candidate-v1";

/// Version of the built-in restricted-semantic rule registry.
///
/// This changes when the set of rule identifiers or their default enabled
/// state changes. A scan records it beside the SOG schema so its evidence is
/// never interpreted under a different rule selection unnoticed.
pub const SEMANTIC_RULE_REGISTRY_VERSION: &str = "semantic-rule-registry-v1";

/// One permitted semantic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Read elements from a source sequence or stream.
    Source,
    /// Retain elements that satisfy a predicate.
    Filter,
    /// Transform each element independently.
    Map,
    /// Combine elements into one accumulated value.
    Reduce,
    /// Materialize elements into a collection.
    Collect,
    /// Check a precondition or select a valid branch.
    Validate,
    /// Propagate an absent or erroneous value without handling it here.
    PropagateError,
    /// Acquire a resource whose lifetime is tracked in this graph.
    AcquireResource,
    /// Release a previously acquired resource.
    ReleaseResource,
}

/// A standard fallible container retained by a compiler-confirmed operation.
///
/// This closed category lets a rule distinguish `Result` error propagation
/// from `Option` absence propagation without importing a helper's type model
/// or guessing from syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallibleKind {
    /// A standard `Option` value.
    Option,
    /// A standard `Result` value.
    Result,
}

impl FallibleKind {
    /// Stable identifier used in normalized evidence.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Option => "option",
            Self::Result => "result",
        }
    }
}

/// A closed propagation form established by a compiler helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectPropagation {
    /// A `Result` error is propagated while its success value is unchanged.
    ResultAdapter,
    /// An `Option` absence is propagated while its success value is unchanged.
    OptionAdapter,
}

impl DirectPropagation {
    /// Stable identifier used in normalized evidence.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ResultAdapter => "result_adapter",
            Self::OptionAdapter => "option_adapter",
        }
    }
}

impl OperationKind {
    /// Stable identifier used in reports and rule definitions.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Filter => "filter",
            Self::Map => "map",
            Self::Reduce => "reduce",
            Self::Collect => "collect",
            Self::Validate => "validate",
            Self::PropagateError => "propagate_error",
            Self::AcquireResource => "acquire_resource",
            Self::ReleaseResource => "release_resource",
        }
    }
}

/// Attributes retained for an operation without importing compiler internals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAttributes {
    /// Resolved type category of the operated value, when available.
    pub type_tag: Option<TypeTag>,
    /// Stable structural fingerprint of a predicate or transformation.
    pub structure_fingerprint: Option<[u8; 16]>,
    /// Compiler-resolved API names used by this operation.
    pub api_names: BTreeSet<String>,
    /// Registered resource category for acquire/release operations.
    pub resource_kind: Option<String>,
    /// Standard fallible container established for a propagation or validation
    /// operation, when the helper schema retained it.
    pub fallible_kind: Option<FallibleKind>,
    /// Closed direct-propagation spelling the compiler confirmed, when any.
    pub direct_propagation: Option<DirectPropagation>,
}

/// One operation in source order; its position is a graph-local reference.
///
/// The position is never a stable finding identifier. Stable identifiers are
/// minted only after a versioned normalization and rule application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationNode {
    /// The fixed semantic operation this node represents.
    pub kind: OperationKind,
    /// Compiler-independent evidence used by registered rules.
    pub attributes: OperationAttributes,
}

/// Why one operation precedes or is paired with another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEdgeKind {
    /// A value produced by the source operation feeds the target operation.
    Data,
    /// Observable side effects require the source operation to precede target.
    Ordering,
    /// An acquire operation is paired with its corresponding release.
    ResourceLifetime,
}

impl OperationEdgeKind {
    /// Stable identifier used in canonical semantic evidence.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Ordering => "ordering",
            Self::ResourceLifetime => "resource_lifetime",
        }
    }
}

/// A directed graph edge addressed by graph-local node positions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperationEdge {
    /// Zero-based source node position.
    pub from: u32,
    /// Zero-based target node position.
    pub to: u32,
    /// The dependency relation.
    pub kind: OperationEdgeKind,
}

/// A versioned, compiler-independent restricted semantic graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticOperationGraph {
    /// Vocabulary and normalization contract version.
    pub schema_version: String,
    /// Language that supplied the compiler evidence.
    pub language: Language,
    /// Build variant that produced the compiler evidence.
    pub build_variant_fingerprint: [u8; 32],
    /// Operations in deterministic source order.
    pub nodes: Vec<OperationNode>,
    /// Canonically ordered dependencies between operations.
    pub edges: Vec<OperationEdge>,
}

impl SemanticOperationGraph {
    /// Construct a validated graph under the current schema version.
    ///
    /// Edges are sorted into one canonical order. Inputs that attempt to add a
    /// generic operation, an invalid local reference, or an incoherent
    /// resource pairing are rejected rather than approximated.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticGraphError`] when a node attribute or edge is outside
    /// the restricted graph contract.
    pub fn new(
        language: Language,
        build_variant_fingerprint: [u8; 32],
        nodes: Vec<OperationNode>,
        mut edges: Vec<OperationEdge>,
    ) -> Result<Self, SemanticGraphError> {
        validate_nodes(&nodes)?;
        edges.sort();
        if edges.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SemanticGraphError::DuplicateEdge);
        }
        for edge in &edges {
            validate_edge(&nodes, edge)?;
        }
        Ok(Self {
            schema_version: SOG_SCHEMA_VERSION.to_owned(),
            language,
            build_variant_fingerprint,
            nodes,
            edges,
        })
    }
}

fn validate_nodes(nodes: &[OperationNode]) -> Result<(), SemanticGraphError> {
    for (index, node) in nodes.iter().enumerate() {
        let has_resource_kind = node.attributes.resource_kind.is_some();
        let resource_node = matches!(
            node.kind,
            OperationKind::AcquireResource | OperationKind::ReleaseResource
        );
        if resource_node && !has_resource_kind {
            return Err(SemanticGraphError::ResourceKindMissing { index });
        }
        if !resource_node && has_resource_kind {
            return Err(SemanticGraphError::UnexpectedResourceKind { index });
        }
    }
    Ok(())
}

fn validate_edge(nodes: &[OperationNode], edge: &OperationEdge) -> Result<(), SemanticGraphError> {
    let from = usize::try_from(edge.from)
        .map_err(|_| SemanticGraphError::NodeOutOfRange { index: edge.from })?;
    let to = usize::try_from(edge.to)
        .map_err(|_| SemanticGraphError::NodeOutOfRange { index: edge.to })?;
    let Some(source) = nodes.get(from) else {
        return Err(SemanticGraphError::NodeOutOfRange { index: edge.from });
    };
    let Some(target) = nodes.get(to) else {
        return Err(SemanticGraphError::NodeOutOfRange { index: edge.to });
    };
    if edge.from == edge.to {
        return Err(SemanticGraphError::SelfEdge { index: edge.from });
    }
    if edge.kind == OperationEdgeKind::ResourceLifetime
        && (source.kind != OperationKind::AcquireResource
            || target.kind != OperationKind::ReleaseResource
            || source.attributes.resource_kind != target.attributes.resource_kind)
    {
        return Err(SemanticGraphError::InvalidResourceLifetime);
    }
    Ok(())
}

/// A graph rejected an operation or relationship outside the restricted model.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SemanticGraphError {
    /// A caller supplied a source range whose end precedes its start.
    #[error("semantic source range ends before it starts")]
    InvalidSourceRange,
    /// Sidecar source ranges no longer align with the normalized graph.
    #[error("semantic source range count does not match graph node count")]
    SourceRangeCountMismatch,
    /// The graph cannot represent more nodes than its local references allow.
    #[error("semantic graph has more nodes than local references can represent")]
    GraphTooLarge,
    /// An edge referenced no operation in this graph.
    #[error("operation index {index} is outside the graph")]
    NodeOutOfRange {
        /// Graph-local node position that no node occupies.
        index: u32,
    },
    /// An operation cannot depend on itself.
    #[error("operation index {index} has a self edge")]
    SelfEdge {
        /// Graph-local node position used as both endpoints.
        index: u32,
    },
    /// The same edge was supplied more than once.
    #[error("semantic graph has a duplicate edge")]
    DuplicateEdge,
    /// An acquire or release omitted the category required to pair it safely.
    #[error("resource operation at index {index} has no resource kind")]
    ResourceKindMissing {
        /// Graph-local node position of the incomplete resource operation.
        index: usize,
    },
    /// A non-resource operation attempted to carry a resource category.
    #[error("non-resource operation at index {index} has a resource kind")]
    UnexpectedResourceKind {
        /// Graph-local node position carrying unsupported resource metadata.
        index: usize,
    },
    /// A resource edge must pair matching acquire and release operations.
    #[error("resource lifetime edge does not join matching acquire and release operations")]
    InvalidResourceLifetime,
}

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
    mut observations: Vec<(OperationObservation, SemanticSourceRange)>,
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
    observations.sort_by(|left, right| {
        left.0
            .source_offset
            .cmp(&right.0.source_offset)
            .then_with(|| left.0.api_name.cmp(&right.0.api_name))
    });
    let observation_count = observations.len();
    let mut nodes: Vec<_> = observations
        .into_iter()
        .filter_map(|(observation, source_range)| {
            let kind = registered_api_kind(language, &observation.api_name)?;
            let order = observation.api_name.clone();
            Some((
                observation.source_offset,
                order,
                source_range,
                OperationNode {
                    kind,
                    attributes: OperationAttributes {
                        type_tag: observation.type_tag,
                        structure_fingerprint: None,
                        api_names: BTreeSet::from([observation.api_name]),
                        resource_kind: None,
                        fallible_kind: None,
                        direct_propagation: None,
                    },
                },
            ))
        })
        .collect();
    let recognized_api_count = nodes.len();
    nodes.extend(constructs.into_iter().map(|(construct, source_range)| {
        (
            construct.source_offset,
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
        )
    }));
    nodes.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let node_source_ranges = nodes.iter().map(|(_, _, range, _)| *range).collect();
    let nodes: Vec<_> = nodes.into_iter().map(|(_, _, _, node)| node).collect();
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

/// Extract the largest source-contiguous windows that a same-variant rule can
/// justify on its own.
///
/// The extractor never enumerates arbitrary subgraphs. Sequence rules receive
/// their maximal contiguous run, direct constructs receive one node, and a
/// resource rule receives only an explicit acquire/release pair. This bounds
/// partial matching before candidate indexing and preserves a concise rule
/// explanation for every returned fragment.
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
    cross_language_api_correspondence(language, api_name).map(|entry| entry.operation)
}

/// One explicit correspondence between Rust and C++ standard-library APIs.
///
/// The strings are supplemental API evidence emitted by compiler helpers, not
/// source spellings and never stable call identifiers.  A correspondence is
/// intentionally absent for C and for every API that is not listed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossLanguageApiCorrespondence {
    /// Stable identifier shown when a cross-language rule uses this entry.
    pub id: &'static str,
    /// The closed SOG operation the paired APIs establish.
    pub operation: OperationKind,
    /// Compiler-confirmed Rust API names covered by this entry.
    pub rust_api_names: &'static [&'static str],
    /// Compiler-confirmed C++ API names covered by this entry.
    pub cpp_api_names: &'static [&'static str],
}

const CROSS_LANGUAGE_API_CORRESPONDENCES: &[CrossLanguageApiCorrespondence] = &[
    CrossLanguageApiCorrespondence {
        id: "sequence-source-v1",
        operation: OperationKind::Source,
        rust_api_names: &["rust::IntoIterator::into_iter", "rust::slice::iter"],
        cpp_api_names: &["std::begin"],
    },
    CrossLanguageApiCorrespondence {
        id: "sequence-filter-v1",
        operation: OperationKind::Filter,
        rust_api_names: &["rust::Iterator::filter"],
        cpp_api_names: &["std::copy_if"],
    },
    CrossLanguageApiCorrespondence {
        id: "sequence-map-v1",
        operation: OperationKind::Map,
        rust_api_names: &["rust::Iterator::map"],
        cpp_api_names: &["std::transform"],
    },
    CrossLanguageApiCorrespondence {
        id: "sequence-reduce-v1",
        operation: OperationKind::Reduce,
        rust_api_names: &["rust::Iterator::fold"],
        cpp_api_names: &["std::accumulate"],
    },
    CrossLanguageApiCorrespondence {
        id: "sequence-collect-v1",
        operation: OperationKind::Collect,
        rust_api_names: &["rust::Iterator::collect", "rust::Vec::push"],
        cpp_api_names: &["std::push_back"],
    },
];

/// Return the complete closed Rust-to-C++ API correspondence table.
#[must_use]
pub const fn cross_language_api_correspondences() -> &'static [CrossLanguageApiCorrespondence] {
    CROSS_LANGUAGE_API_CORRESPONDENCES
}

/// Find the correspondence entry for one compiler-confirmed standard API.
///
/// The lookup is exact and language-aware.  It does not interpret a call
/// target, infer an API from a suffix, or map a project-owned method name.
#[must_use]
pub fn cross_language_api_correspondence(
    language: Language,
    api_name: &str,
) -> Option<&'static CrossLanguageApiCorrespondence> {
    CROSS_LANGUAGE_API_CORRESPONDENCES
        .iter()
        .find(|entry| match language {
            Language::Rust => entry.rust_api_names.contains(&api_name),
            Language::Cpp => entry.cpp_api_names.contains(&api_name),
            Language::C => false,
        })
}

/// A registered, explainable SOG correspondence rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SemanticRule {
    /// Stable registry identifier.
    pub id: &'static str,
    /// Rule semantics revision.
    pub version: u32,
    /// Conservative confidence before later data-flow evidence is applied.
    pub confidence: f64,
    /// Comparison domain where the rule may run.
    pub scope: SemanticRuleScope,
    /// Closed operation pattern the rule is allowed to explain.
    pub pattern: SemanticRulePattern,
    /// Closed matching strategy selected by this rule's declaration.
    pub matcher: SemanticRuleMatcher,
}

/// The explicit comparison domain a registered rule may inspect.
///
/// A rule cannot cross from ordinary scan partitions into another language by
/// omission: Rust-to-C++ matching is opt-in and carries a separate comparison
/// identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticRuleScope {
    /// Two graphs produced under one complete build variant.
    SameBuildVariant,
    /// One caller-selected Rust graph and one caller-selected C++ graph.
    RustCpp,
}

/// A declarative, closed SOG pattern for one registered semantic rule.
///
/// This deliberately describes only which operation kinds a rule may accept
/// and its minimum length. A rule must still provide a concrete matcher; the
/// pattern is a fail-closed precondition, not a generic graph-rewrite DSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticRulePattern {
    /// The least number of operations that make the registered pattern useful.
    pub minimum_operations: usize,
    /// Every node kind the rule may explain, in any permitted source order.
    pub permitted_kinds: &'static [OperationKind],
}

impl SemanticRulePattern {
    /// Whether a graph lies entirely inside this rule's closed vocabulary.
    #[must_use]
    pub fn accepts(self, graph: &SemanticOperationGraph) -> bool {
        graph.nodes.len() >= self.minimum_operations
            && graph
                .nodes
                .iter()
                .all(|node| self.permitted_kinds.contains(&node.kind))
    }
}

/// A closed, declarative matching strategy for a registered semantic rule.
///
/// This is deliberately a small enum rather than an open rewrite language:
/// adding an unreviewed syntax form must not turn the registry into a general
/// equivalence engine. Rules select a pre-audited strategy and provide all
/// values that strategy needs in their declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticRuleMatcher {
    /// Match equal-length operation sequences when every aligned node has the
    /// same kind and compatible compiler-confirmed type evidence.
    EquivalentSequence,
    /// Match exactly one compiler-confirmed construct with the supplied
    /// operation, fallible family, and optional direct-propagation form.
    DirectConstruct {
        /// The only operation kind the construct may carry.
        kind: OperationKind,
        /// The standard fallible family the helper must have resolved.
        fallible_kind: FallibleKind,
        /// An additional closed direct-propagation fact, when required.
        direct_propagation: Option<DirectPropagation>,
    },
    /// Match one compiler-confirmed acquire/release pair of the same closed
    /// resource category, including its explicit lifetime edge.
    ResourceLifecycle,
}

/// One successful registered rule application.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuleMatch {
    /// Rule that justified this match.
    pub rule: SemanticRule,
}

const SEQUENCE_PIPELINE_RULE: SemanticRule = SemanticRule {
    id: "sequence-pipeline-v1",
    version: 1,
    confidence: 0.7,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 2,
        permitted_kinds: &[
            OperationKind::Source,
            OperationKind::Filter,
            OperationKind::Map,
            OperationKind::Reduce,
            OperationKind::Collect,
        ],
    },
    matcher: SemanticRuleMatcher::EquivalentSequence,
};

const RESULT_DIRECT_PROPAGATION_RULE: SemanticRule = SemanticRule {
    id: "result-direct-propagation-v1",
    version: 1,
    confidence: 0.95,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::PropagateError],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::PropagateError,
        fallible_kind: FallibleKind::Result,
        direct_propagation: Some(DirectPropagation::ResultAdapter),
    },
};

const OPTION_DIRECT_PROPAGATION_RULE: SemanticRule = SemanticRule {
    id: "option-direct-propagation-v1",
    version: 1,
    confidence: 0.95,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::PropagateError],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::PropagateError,
        fallible_kind: FallibleKind::Option,
        direct_propagation: Some(DirectPropagation::OptionAdapter),
    },
};

const OPTIONAL_VALIDATION_RULE: SemanticRule = SemanticRule {
    id: "optional-validation-v1",
    version: 1,
    confidence: 0.85,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::Validate],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::Validate,
        fallible_kind: FallibleKind::Option,
        direct_propagation: None,
    },
};

const RESULT_VALIDATION_RULE: SemanticRule = SemanticRule {
    id: "result-validation-v1",
    version: 1,
    confidence: 0.85,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::Validate],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::Validate,
        fallible_kind: FallibleKind::Result,
        direct_propagation: None,
    },
};

const RESOURCE_LIFECYCLE_RULE: SemanticRule = SemanticRule {
    id: "resource-lifecycle-v1",
    version: 1,
    confidence: 0.9,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 2,
        permitted_kinds: &[
            OperationKind::AcquireResource,
            OperationKind::ReleaseResource,
        ],
    },
    matcher: SemanticRuleMatcher::ResourceLifecycle,
};

const CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE: SemanticRule = SemanticRule {
    id: "cross-language-sequence-pipeline-v1",
    version: 1,
    confidence: 0.55,
    scope: SemanticRuleScope::RustCpp,
    pattern: SemanticRulePattern {
        minimum_operations: 2,
        permitted_kinds: &[
            OperationKind::Source,
            OperationKind::Filter,
            OperationKind::Map,
            OperationKind::Reduce,
            OperationKind::Collect,
        ],
    },
    matcher: SemanticRuleMatcher::EquivalentSequence,
};

const CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE: SemanticRule = SemanticRule {
    id: "cross-language-optional-validation-v1",
    version: 1,
    confidence: 0.55,
    scope: SemanticRuleScope::RustCpp,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::Validate],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::Validate,
        fallible_kind: FallibleKind::Option,
        direct_propagation: None,
    },
};

const CROSS_LANGUAGE_RESULT_VALIDATION_RULE: SemanticRule = SemanticRule {
    id: "cross-language-result-validation-v1",
    version: 1,
    confidence: 0.55,
    scope: SemanticRuleScope::RustCpp,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::Validate],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::Validate,
        fallible_kind: FallibleKind::Result,
        direct_propagation: None,
    },
};

const CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE: SemanticRule = SemanticRule {
    id: "cross-language-result-direct-propagation-v1",
    version: 1,
    confidence: 0.55,
    scope: SemanticRuleScope::RustCpp,
    pattern: SemanticRulePattern {
        minimum_operations: 1,
        permitted_kinds: &[OperationKind::PropagateError],
    },
    matcher: SemanticRuleMatcher::DirectConstruct {
        kind: OperationKind::PropagateError,
        fallible_kind: FallibleKind::Result,
        direct_propagation: Some(DirectPropagation::ResultAdapter),
    },
};

/// Closed compiler-construct correspondence retained beside the optional
/// validation rule. It is intentionally distinct from the API table: a
/// presence check is established by a resolved standard fallible type and a
/// compiler-parsed branch, not by recovering an arbitrary method spelling.
const OPTIONAL_VALIDATION_CORRESPONDENCE_ID: &str = "optional-presence-validation-v1";

/// Closed compiler-construct correspondence for Rust `Result::is_ok()` and
/// C++ `expected::has_value()`/`operator bool`. Both helpers resolve the
/// standard family before this rule can compare the branch.
const RESULT_VALIDATION_CORRESPONDENCE_ID: &str = "result-expected-validation-v1";

/// Closed compiler-construct correspondence for a Rust `Result` adapter and a
/// C++ `expected` identity return. It remains distinct from the API table:
/// neither side depends on an API-call sequence.
const RESULT_DIRECT_PROPAGATION_CORRESPONDENCE_ID: &str = "result-expected-direct-propagation-v1";

/// Rules enabled by default because each has an explicit, bounded meaning.
///
/// Cross-language entries still require the separate opt-in comparison path;
/// appearing here makes their enabled state visible and configurable beside
/// same-variant rules.
#[must_use]
pub const fn registered_rules() -> &'static [SemanticRule] {
    &[
        SEQUENCE_PIPELINE_RULE,
        RESULT_DIRECT_PROPAGATION_RULE,
        OPTION_DIRECT_PROPAGATION_RULE,
        OPTIONAL_VALIDATION_RULE,
        RESULT_VALIDATION_RULE,
        RESOURCE_LIFECYCLE_RULE,
        CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
        CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE,
        CROSS_LANGUAGE_RESULT_VALIDATION_RULE,
        CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE,
    ]
}

/// Limits for the registered SOG candidate index.
///
/// Both limits cut whole index buckets. Cutting part of a bucket would make
/// the answer depend on incidental graph order, and could leave a reported
/// group with unexamined peers that look equally eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticCandidateConfig {
    /// Largest operation-sequence bucket that may enter verification.
    pub max_bucket_members: usize,
    /// Largest number of candidate pairs the extraction may return.
    pub max_candidate_pairs: usize,
}

impl Default for SemanticCandidateConfig {
    fn default() -> Self {
        Self {
            max_bucket_members: 256,
            max_candidate_pairs: 16_384,
        }
    }
}

/// Accounting for registered SOG candidate extraction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticCandidateStats {
    /// Graphs presented to the extractor.
    pub graphs: usize,
    /// Graphs outside the current schema or too short for a registered rule.
    pub ineligible_graphs: usize,
    /// Distinct BuildVariant-and-operation-sequence buckets formed.
    pub buckets: usize,
    /// Buckets omitted in full for exceeding [`SemanticCandidateConfig::max_bucket_members`].
    pub oversized_buckets: usize,
    /// Pairs in eligible buckets before the run-wide ceiling is applied.
    pub pairs_available: usize,
    /// Pairs omitted in full because accepting their bucket would exceed the ceiling.
    pub pairs_budget_dropped: usize,
    /// Candidate pairs returned to a registered rule verifier.
    pub pairs_emitted: usize,
}

/// One pair selected by the bounded SOG candidate index.
///
/// The positions index the caller's graph slice. They are not source anchors
/// and never become stable finding identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticCandidatePair {
    /// Position of the first graph in caller order.
    pub left: usize,
    /// Position of the second graph in caller order.
    pub right: usize,
}

/// Position-free identity of one SOG-owning unit supplied to semantic
/// grouping.
///
/// The index in the input slice identifies the unit only for this invocation.
/// `key` is its normalized semantic fragment fingerprint, used solely for
/// deterministic medoid selection and output ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticGroupingUnit {
    /// Stable normalized semantic fragment identity.
    pub key: [u8; 16],
}

/// One verified semantic candidate paired with the rule that justified it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VerifiedSemanticPair {
    /// Endpoints into the `SemanticGroupingUnit` input slice.
    pub candidate: SemanticCandidatePair,
    /// The closed registered rule that accepted the endpoints.
    pub matched: RuleMatch,
}

/// A cohesive set of SOG-owning units justified by one registered rule.
///
/// Every pair of members was separately accepted by `rule`. In particular,
/// this is not a connected component of pair matches: an absent pair is
/// treated as incompatible by complete-linkage refinement.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticRuleGroup {
    /// The sole registered rule that explains every internal relation.
    pub rule: SemanticRule,
    /// The deterministic medoid, indexed into the caller's unit slice.
    pub canonical: usize,
    /// Member unit indices, with the canonical unit first.
    pub members: Vec<usize>,
    /// Weakest accepted internal relation. This is always `1.0` for the
    /// binary registered-rule relation, but is retained as explicit evidence
    /// of the complete-linkage contract.
    pub min_pairwise: f64,
}

/// Semantic pairs left outside a cohesive group, with an explicit reason.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UngroupedSemanticPair {
    /// The verified pair that no emitted group jointly represents.
    pub pair: VerifiedSemanticPair,
    /// Whether the grouping ceiling prevented this pair from being considered
    /// alongside the other endpoint, rather than complete-linkage rejecting a
    /// non-transitive chain.
    pub severed_by_the_ceiling: bool,
}

/// Accounting for registered semantic grouping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticGroupingStats {
    /// Input pairs whose endpoints were in range and non-identical.
    pub verified_pairs: usize,
    /// Duplicate copies of one rule-and-endpoint relation ignored
    /// deterministically.
    pub duplicate_pairs: usize,
    /// Input pairs rejected because an endpoint was outside the unit slice or
    /// both endpoints named the same unit.
    pub invalid_pairs: usize,
    /// Pairs expressed by an emitted cohesive group.
    pub grouped_pairs: usize,
    /// Verified pairs that no emitted group jointly represents.
    pub ungrouped_pairs: usize,
    /// Ungrouped pairs separated only by the grouping ceiling.
    pub ceiling_severed_pairs: usize,
    /// Cohesive rule groups emitted.
    pub groups: usize,
}

/// Cohesive semantic groups and the verified pairs they do not represent.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticGrouping {
    /// Groups partitioned by registered rule and refined with complete linkage.
    pub groups: Vec<SemanticRuleGroup>,
    /// Verified pairs retained separately when no group holds both endpoints.
    pub ungrouped: Vec<UngroupedSemanticPair>,
    /// Full grouping accounting, including bounded-refinement effects.
    pub stats: SemanticGroupingStats,
}

/// Candidate pairs and their complete accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCandidateExtraction {
    /// Pairs narrowed by the coarse index, in deterministic order.
    pub pairs: Vec<SemanticCandidatePair>,
    /// What the extractor considered and deliberately omitted.
    pub stats: SemanticCandidateStats,
}

/// One graph admitted to a caller-selected Rust-to-C++ comparison domain.
///
/// `comparison_partition` is deliberately distinct from the graph's complete
/// `BuildVariant` fingerprint. The latter continues to identify how the graph
/// was produced; the former proves that a caller explicitly chose its two
/// origin variants for this comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossLanguageCandidateInput {
    /// Opaque identity of the explicit comparison domain.
    pub comparison_partition: [u8; 16],
    /// Graph retaining its language and original `BuildVariant` identity.
    pub graph: SemanticOperationGraph,
}

/// Accounting for opt-in Rust-to-C++ candidate extraction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossLanguageCandidateStats {
    /// Graphs presented by the explicit comparison caller.
    pub graphs: usize,
    /// Graphs outside the current schema, operation rule, language pair, or
    /// closed API correspondence table.
    pub ineligible_graphs: usize,
    /// Distinct explicit-partition and operation-sequence buckets formed.
    pub buckets: usize,
    /// Buckets omitted in full for exceeding the configured member ceiling.
    pub oversized_buckets: usize,
    /// Pairs in eligible buckets before the run-wide ceiling is applied.
    pub pairs_available: usize,
    /// Pairs omitted in full because accepting their bucket exceeds the ceiling.
    pub pairs_budget_dropped: usize,
    /// Candidate pairs returned to the cross-language verifier.
    pub pairs_emitted: usize,
}

/// Candidate pairs and accounting for an opt-in Rust-to-C++ comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossLanguageCandidateExtraction {
    /// Candidate positions in the corresponding input slice.
    pub pairs: Vec<SemanticCandidatePair>,
    /// What the extractor considered and deliberately omitted.
    pub stats: CrossLanguageCandidateStats,
}

/// One verified Rust-to-C++ rule application with its API-table evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossLanguageRuleMatch {
    /// Rule that justified the correspondence.
    pub rule: SemanticRule,
    /// One registered API correspondence identifier for each matched node.
    pub api_correspondence_ids: Vec<&'static str>,
}

/// Extract bounded candidates for an explicit Rust-to-C++ comparison.
///
/// Ordinary semantic findings must use [`extract_registered_candidates`].
/// This function considers only graphs that carry the same caller-provided
/// comparison partition, have a Rust/C++ language pairing, and consist solely
/// of APIs in [`cross_language_api_correspondences`]. It never compares C,
/// joins normal `BuildVariants`, or falls back to matching API-name suffixes.
#[must_use]
pub fn extract_cross_language_candidates(
    inputs: &[CrossLanguageCandidateInput],
    config: SemanticCandidateConfig,
) -> CrossLanguageCandidateExtraction {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct CandidateKey {
        comparison_partition: [u8; 16],
        operations: Vec<OperationKind>,
    }

    #[derive(Default)]
    struct Bucket {
        rust: Vec<usize>,
        cpp: Vec<usize>,
    }

    let mut stats = CrossLanguageCandidateStats {
        graphs: inputs.len(),
        ..CrossLanguageCandidateStats::default()
    };
    let mut index: BTreeMap<CandidateKey, Bucket> = BTreeMap::new();
    for (index_in_input, input) in inputs.iter().enumerate() {
        let graph = &input.graph;
        let pipeline = CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE.pattern.accepts(graph)
            && graph.nodes.iter().all(|node| {
                node.attributes.api_names.len() == 1
                    && node.attributes.api_names.iter().next().is_some_and(|api| {
                        cross_language_api_correspondence(graph.language, api)
                            .is_some_and(|entry| entry.operation == node.kind)
                    })
            });
        let optional_validation = is_optional_validation(graph);
        let result_validation = is_result_validation(graph);
        let result_direct_propagation = is_result_direct_propagation(graph);
        if graph.schema_version != SOG_SCHEMA_VERSION
            || !matches!(graph.language, Language::Rust | Language::Cpp)
            || !(pipeline || optional_validation || result_validation || result_direct_propagation)
        {
            stats.ineligible_graphs += 1;
            continue;
        }
        let bucket = index
            .entry(CandidateKey {
                comparison_partition: input.comparison_partition,
                operations: graph.nodes.iter().map(|node| node.kind).collect(),
            })
            .or_default();
        match graph.language {
            Language::Rust => bucket.rust.push(index_in_input),
            Language::Cpp => bucket.cpp.push(index_in_input),
            Language::C => unreachable!("C graphs are excluded before indexing"),
        }
    }
    stats.buckets = index.len();

    let mut pairs = Vec::new();
    for bucket in index.into_values() {
        let members = bucket.rust.len().saturating_add(bucket.cpp.len());
        if members > config.max_bucket_members {
            stats.oversized_buckets += 1;
            continue;
        }
        let available = bucket.rust.len().saturating_mul(bucket.cpp.len());
        stats.pairs_available = stats.pairs_available.saturating_add(available);
        if pairs.len().saturating_add(available) > config.max_candidate_pairs {
            stats.pairs_budget_dropped = stats.pairs_budget_dropped.saturating_add(available);
            continue;
        }
        for rust in &bucket.rust {
            for cpp in &bucket.cpp {
                pairs.push(SemanticCandidatePair {
                    left: (*rust).min(*cpp),
                    right: (*rust).max(*cpp),
                });
            }
        }
    }
    pairs.sort_unstable();
    stats.pairs_emitted = pairs.len();
    CrossLanguageCandidateExtraction { pairs, stats }
}

/// Verify explicit Rust-to-C++ candidates using every registered API mapping.
#[must_use]
pub fn verify_cross_language_candidates(
    inputs: &[CrossLanguageCandidateInput],
    candidates: &[SemanticCandidatePair],
) -> Vec<(SemanticCandidatePair, CrossLanguageRuleMatch)> {
    candidates
        .iter()
        .filter_map(|&candidate| {
            let (Some(left), Some(right)) =
                (inputs.get(candidate.left), inputs.get(candidate.right))
            else {
                return None;
            };
            (left.comparison_partition == right.comparison_partition)
                .then(|| {
                    match_cross_language_pipeline(&left.graph, &right.graph).or_else(|| {
                        match_cross_language_optional_validation(&left.graph, &right.graph)
                            .or_else(|| {
                                match_cross_language_result_validation(&left.graph, &right.graph)
                            })
                            .or_else(|| {
                                match_cross_language_result_direct_propagation(
                                    &left.graph,
                                    &right.graph,
                                )
                            })
                    })
                })
                .flatten()
                .map(|rule_match| (candidate, rule_match))
        })
        .collect()
}

/// Extract bounded candidate pairs for registered SOG rules.
///
/// The inverted index partitions first by the complete `BuildVariant`
/// fingerprint and then by the operation-kind sequence. It therefore never
/// reconnects independent build variants and avoids a project-wide all-pairs
/// comparison. API names and type categories remain evidence for the rule
/// verifier rather than becoming a lossy cross-language index key.
#[must_use]
pub fn extract_registered_candidates(
    graphs: &[SemanticOperationGraph],
    config: SemanticCandidateConfig,
) -> SemanticCandidateExtraction {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct CandidateKey {
        variant: [u8; 32],
        operations: Vec<OperationKind>,
    }

    let mut stats = SemanticCandidateStats {
        graphs: graphs.len(),
        ..SemanticCandidateStats::default()
    };
    let mut index: BTreeMap<CandidateKey, Vec<usize>> = BTreeMap::new();
    for (index_in_input, graph) in graphs.iter().enumerate() {
        if graph.schema_version != SOG_SCHEMA_VERSION
            || !registered_rules()
                .iter()
                .any(|rule| rule.pattern.accepts(graph))
        {
            stats.ineligible_graphs += 1;
            continue;
        }
        index
            .entry(CandidateKey {
                variant: graph.build_variant_fingerprint,
                operations: graph.nodes.iter().map(|node| node.kind).collect(),
            })
            .or_default()
            .push(index_in_input);
    }
    stats.buckets = index.len();

    let mut pairs = Vec::new();
    for members in index.into_values() {
        if members.len() > config.max_bucket_members {
            stats.oversized_buckets += 1;
            continue;
        }
        let available = members
            .len()
            .saturating_mul(members.len().saturating_sub(1))
            / 2;
        stats.pairs_available = stats.pairs_available.saturating_add(available);
        if pairs.len().saturating_add(available) > config.max_candidate_pairs {
            stats.pairs_budget_dropped = stats.pairs_budget_dropped.saturating_add(available);
            continue;
        }
        for (offset, &left) in members.iter().enumerate() {
            pairs.extend(
                members[offset + 1..]
                    .iter()
                    .copied()
                    .map(|right| SemanticCandidatePair { left, right }),
            );
        }
    }
    stats.pairs_emitted = pairs.len();
    SemanticCandidateExtraction { pairs, stats }
}

/// Verify candidate pairs against the registered rules.
///
/// A pair outside the provided slice is ignored rather than guessed at. The
/// extractor only produces in-range pairs, but this makes callers that load
/// persisted candidate data fail closed as well.
#[must_use]
pub fn verify_registered_candidates(
    graphs: &[SemanticOperationGraph],
    candidates: &[SemanticCandidatePair],
) -> Vec<(SemanticCandidatePair, RuleMatch)> {
    candidates
        .iter()
        .filter_map(|&candidate| {
            let (Some(left), Some(right)) =
                (graphs.get(candidate.left), graphs.get(candidate.right))
            else {
                return None;
            };
            match_registered_rule(left, right).map(|rule_match| (candidate, rule_match))
        })
        .collect()
}

/// Group verified registered-rule pairs without treating pair compatibility as
/// transitive.
///
/// Rules are grouped independently, so a unit cannot connect two different
/// semantic claims merely because it participates in both. Within a rule, a
/// verified pair is a binary relation with similarity `1.0`; any pair the
/// verifier did not accept is absent and therefore reads as incompatible to
/// complete-linkage refinement. This turns a partially connected match graph
/// into cohesive groups while retaining every accepted relation no group can
/// express as an [`UngroupedSemanticPair`].
///
/// Invalid and duplicate inputs are ignored with explicit accounting. The
/// normal verifier cannot create either, but this keeps persisted or adapter
/// supplied pair data fail-closed.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the adapter keeps validation, per-rule partitioning, complete-linkage refinement, and every ungrouped-pair reason in one auditable boundary"
)]
pub fn group_verified_semantic_pairs(
    units: &[SemanticGroupingUnit],
    verified: &[VerifiedSemanticPair],
    config: &GroupingConfig,
) -> SemanticGrouping {
    let mut stats = SemanticGroupingStats::default();
    let mut partitions: BTreeMap<(&str, u32), SemanticRulePartition> = BTreeMap::new();
    for &pair in verified {
        let candidate = ordered_semantic_pair(pair.candidate);
        if candidate.left == candidate.right
            || candidate.left >= units.len()
            || candidate.right >= units.len()
        {
            stats.invalid_pairs = stats.invalid_pairs.saturating_add(1);
            continue;
        }
        let key = (pair.matched.rule.id, pair.matched.rule.version);
        let partition = partitions
            .entry(key)
            .or_insert_with(|| SemanticRulePartition::new(pair.matched.rule));
        if partition
            .pairs
            .insert(
                (candidate.left, candidate.right),
                VerifiedSemanticPair {
                    candidate,
                    matched: pair.matched,
                },
            )
            .is_some()
        {
            stats.duplicate_pairs = stats.duplicate_pairs.saturating_add(1);
        }
    }

    let mut groups = Vec::new();
    let mut ungrouped = Vec::new();
    for partition in partitions.into_values() {
        stats.verified_pairs = stats.verified_pairs.saturating_add(partition.pairs.len());
        let mut global_members = BTreeSet::new();
        for pair in partition.pairs.values() {
            global_members.insert(pair.candidate.left);
            global_members.insert(pair.candidate.right);
        }
        let global_members: Vec<_> = global_members.into_iter().collect();
        let local_positions: BTreeMap<_, _> = global_members
            .iter()
            .copied()
            .enumerate()
            .map(|(local, global)| (global, local))
            .collect();
        let grouping_units: Vec<_> = global_members
            .iter()
            .map(|&global| GroupingUnit {
                key: units[global].key,
            })
            .collect();
        let edges: Vec<_> = partition
            .pairs
            .values()
            .map(|pair| SimilarityEdge {
                a: local_positions[&pair.candidate.left],
                b: local_positions[&pair.candidate.right],
                similarity: 1.0,
                class: CloneClass::RestrictedSemantic,
                confidence: Confidence::High,
            })
            .collect();
        let grouped = grouping::group(&grouping_units, &edges, config);
        let mut represented = BTreeSet::new();
        for group in &grouped.groups {
            let members: Vec<_> = group
                .members
                .iter()
                .map(|&local| global_members[local])
                .collect();
            for (offset, &left) in members.iter().enumerate() {
                for &right in &members[offset + 1..] {
                    represented.insert(ordered_usize_pair(left, right));
                }
            }
            groups.push(SemanticRuleGroup {
                rule: partition.rule,
                canonical: global_members[group.canonical],
                members,
                min_pairwise: group.min_pairwise,
            });
        }
        for pair in partition.pairs.into_values() {
            let endpoints = (pair.candidate.left, pair.candidate.right);
            if represented.contains(&endpoints) {
                stats.grouped_pairs = stats.grouped_pairs.saturating_add(1);
                continue;
            }
            let severed_by_the_ceiling = grouped.severed_by_the_ceiling(
                local_positions[&pair.candidate.left],
                local_positions[&pair.candidate.right],
            );
            if severed_by_the_ceiling {
                stats.ceiling_severed_pairs = stats.ceiling_severed_pairs.saturating_add(1);
            }
            ungrouped.push(UngroupedSemanticPair {
                pair,
                severed_by_the_ceiling,
            });
        }
    }
    stats.ungrouped_pairs = ungrouped.len();
    groups.sort_by(|left, right| {
        left.rule
            .id
            .cmp(right.rule.id)
            .then(left.rule.version.cmp(&right.rule.version))
            .then(units[left.canonical].key.cmp(&units[right.canonical].key))
            .then(left.members.len().cmp(&right.members.len()))
    });
    ungrouped.sort_by(|left, right| {
        left.pair
            .matched
            .rule
            .id
            .cmp(right.pair.matched.rule.id)
            .then(
                left.pair
                    .matched
                    .rule
                    .version
                    .cmp(&right.pair.matched.rule.version),
            )
            .then(left.pair.candidate.cmp(&right.pair.candidate))
    });
    stats.groups = groups.len();
    SemanticGrouping {
        groups,
        ungrouped,
        stats,
    }
}

/// Partition of verified pairs justified by exactly one registered rule.
struct SemanticRulePartition {
    rule: SemanticRule,
    pairs: BTreeMap<(usize, usize), VerifiedSemanticPair>,
}

impl SemanticRulePartition {
    const fn new(rule: SemanticRule) -> Self {
        Self {
            rule,
            pairs: BTreeMap::new(),
        }
    }
}

/// Normalize a semantic pair so duplicate relations have one representation.
const fn ordered_semantic_pair(pair: SemanticCandidatePair) -> SemanticCandidatePair {
    let (left, right) = ordered_usize_pair(pair.left, pair.right);
    SemanticCandidatePair { left, right }
}

/// Normalize one undirected endpoint pair.
const fn ordered_usize_pair(left: usize, right: usize) -> (usize, usize) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

/// Match two equivalent registered API pipelines without comparing API spelling.
///
/// This permits, for example, Rust `filter/map/collect` and C++
/// `copy_if/transform/push_back` only when their closed operation sequences
/// and known type categories agree. Different `BuildVariants` never match.
#[must_use]
pub fn match_registered_pipeline(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<RuleMatch> {
    match_same_variant_rule(SEQUENCE_PIPELINE_RULE, left, right)
}

/// Match two graphs against one declared rule inside a single build variant.
///
/// The caller supplies a rule from the closed registry. A declaration that
/// does not accept both graphs, or a graph from another schema or variant,
/// fails rather than being coerced into a nearby rule.
fn match_same_variant_rule(
    rule: SemanticRule,
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<RuleMatch> {
    if rule.scope != SemanticRuleScope::SameBuildVariant
        || left.schema_version != SOG_SCHEMA_VERSION
        || right.schema_version != SOG_SCHEMA_VERSION
        || left.build_variant_fingerprint != right.build_variant_fingerprint
        || !rule.pattern.accepts(left)
        || !rule.pattern.accepts(right)
    {
        return None;
    }
    let matches = match rule.matcher {
        SemanticRuleMatcher::EquivalentSequence => {
            left.nodes.len() == right.nodes.len()
                && left
                    .nodes
                    .iter()
                    .zip(&right.nodes)
                    .all(|(left, right)| compatible_nodes(left, right))
        }
        SemanticRuleMatcher::DirectConstruct {
            kind,
            fallible_kind,
            direct_propagation,
        } => {
            direct_construct_matches(left, kind, fallible_kind, direct_propagation)
                && direct_construct_matches(right, kind, fallible_kind, direct_propagation)
        }
        SemanticRuleMatcher::ResourceLifecycle => {
            resource_lifecycle_matches(left) && resource_lifecycle_matches(right)
        }
    };
    matches.then_some(RuleMatch { rule })
}

fn resource_lifecycle_matches(graph: &SemanticOperationGraph) -> bool {
    matches!(
        graph.nodes.as_slice(),
        [OperationNode {
            kind: OperationKind::AcquireResource,
            attributes: OperationAttributes {
                resource_kind: Some(acquired),
                ..
            },
        }, OperationNode {
            kind: OperationKind::ReleaseResource,
            attributes: OperationAttributes {
                resource_kind: Some(released),
                ..
            },
        }] if acquired == released
    ) && graph.edges.contains(&OperationEdge {
        from: 0,
        to: 1,
        kind: OperationEdgeKind::ResourceLifetime,
    })
}

/// Match any closed, registered SOG correspondence rule.
#[must_use]
pub fn match_registered_rule(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<RuleMatch> {
    registered_rules()
        .iter()
        .copied()
        .filter(|rule| rule.scope == SemanticRuleScope::SameBuildVariant)
        .find_map(|rule| match_same_variant_rule(rule, left, right))
}

/// Match one explicitly selected Rust-to-C++ sequence pipeline.
///
/// Unlike [`match_registered_pipeline`], this is not part of ordinary
/// BuildVariant-local detection. Its caller must first select an explicit
/// comparison domain and use [`extract_cross_language_candidates`]. Every
/// aligned operation must name the same closed API correspondence entry.
#[must_use]
pub fn match_cross_language_pipeline(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<CrossLanguageRuleMatch> {
    let rust_and_cpp = matches!(
        (left.language, right.language),
        (Language::Rust, Language::Cpp) | (Language::Cpp, Language::Rust)
    );
    if CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE.scope != SemanticRuleScope::RustCpp
        || left.schema_version != SOG_SCHEMA_VERSION
        || right.schema_version != SOG_SCHEMA_VERSION
        || !rust_and_cpp
        || left.build_variant_fingerprint == right.build_variant_fingerprint
        || left.nodes.len() != right.nodes.len()
        || !CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE.pattern.accepts(left)
        || !CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE.pattern.accepts(right)
    {
        return None;
    }
    let mut api_correspondence_ids = Vec::with_capacity(left.nodes.len());
    for (left_node, right_node) in left.nodes.iter().zip(&right.nodes) {
        if left_node.kind != right_node.kind
            || !compatible_type_tags(
                left_node.attributes.type_tag,
                right_node.attributes.type_tag,
            )
            || !compatible_fallible_kinds(
                left_node.attributes.fallible_kind,
                right_node.attributes.fallible_kind,
            )
        {
            return None;
        }
        let left_api = only_api_name(left_node)?;
        let right_api = only_api_name(right_node)?;
        let left_entry = cross_language_api_correspondence(left.language, left_api)?;
        let right_entry = cross_language_api_correspondence(right.language, right_api)?;
        let correspondence_matches = left_entry.id == right_entry.id
            && correspondence_covers(left_entry, left_node)
            && correspondence_covers(right_entry, right_node);
        if !correspondence_matches {
            return None;
        }
        api_correspondence_ids.push(left_entry.id);
    }
    Some(CrossLanguageRuleMatch {
        rule: CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
        api_correspondence_ids,
    })
}

/// Match an explicit Rust `Option` validation with its C++ `optional` counterpart.
///
/// The compiler helpers establish the standard fallible family; this rule does
/// not infer it from source-level branch spelling.
#[must_use]
pub fn match_cross_language_optional_validation(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<CrossLanguageRuleMatch> {
    let rust_and_cpp = matches!(
        (left.language, right.language),
        (Language::Rust, Language::Cpp) | (Language::Cpp, Language::Rust)
    );
    (CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE.scope == SemanticRuleScope::RustCpp
        && left.schema_version == SOG_SCHEMA_VERSION
        && right.schema_version == SOG_SCHEMA_VERSION
        && rust_and_cpp
        && left.build_variant_fingerprint != right.build_variant_fingerprint
        && is_optional_validation(left)
        && is_optional_validation(right))
    .then_some(CrossLanguageRuleMatch {
        rule: CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE,
        api_correspondence_ids: vec![OPTIONAL_VALIDATION_CORRESPONDENCE_ID],
    })
}

/// Match a Rust `Result` presence branch with the C++ `expected` counterpart.
///
/// Both helpers confirm the standard family. This stays a branch-level rule:
/// it does not infer propagation or handling from either branch body.
#[must_use]
pub fn match_cross_language_result_validation(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<CrossLanguageRuleMatch> {
    let rust_and_cpp = matches!(
        (left.language, right.language),
        (Language::Rust, Language::Cpp) | (Language::Cpp, Language::Rust)
    );
    (CROSS_LANGUAGE_RESULT_VALIDATION_RULE.scope == SemanticRuleScope::RustCpp
        && left.schema_version == SOG_SCHEMA_VERSION
        && right.schema_version == SOG_SCHEMA_VERSION
        && rust_and_cpp
        && left.build_variant_fingerprint != right.build_variant_fingerprint
        && is_result_validation(left)
        && is_result_validation(right))
    .then_some(CrossLanguageRuleMatch {
        rule: CROSS_LANGUAGE_RESULT_VALIDATION_RULE,
        api_correspondence_ids: vec![RESULT_VALIDATION_CORRESPONDENCE_ID],
    })
}

/// Match a Rust direct `Result` adapter with a C++ direct `expected` identity
/// return. Both helpers must establish the same language-neutral error/value
/// category and the exact registered propagation form.
#[must_use]
pub fn match_cross_language_result_direct_propagation(
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<CrossLanguageRuleMatch> {
    let rust_and_cpp = matches!(
        (left.language, right.language),
        (Language::Rust, Language::Cpp) | (Language::Cpp, Language::Rust)
    );
    (CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE.scope == SemanticRuleScope::RustCpp
        && left.schema_version == SOG_SCHEMA_VERSION
        && right.schema_version == SOG_SCHEMA_VERSION
        && rust_and_cpp
        && left.build_variant_fingerprint != right.build_variant_fingerprint
        && is_result_direct_propagation(left)
        && is_result_direct_propagation(right))
    .then_some(CrossLanguageRuleMatch {
        rule: CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE,
        api_correspondence_ids: vec![RESULT_DIRECT_PROPAGATION_CORRESPONDENCE_ID],
    })
}

const fn correspondence_covers(
    correspondence: &CrossLanguageApiCorrespondence,
    node: &OperationNode,
) -> bool {
    matches!(
        (correspondence.operation, node.kind),
        (OperationKind::Source, OperationKind::Source)
            | (OperationKind::Filter, OperationKind::Filter)
            | (OperationKind::Map, OperationKind::Map)
            | (OperationKind::Reduce, OperationKind::Reduce)
            | (OperationKind::Collect, OperationKind::Collect)
    )
}

fn only_api_name(node: &OperationNode) -> Option<&str> {
    (node.attributes.api_names.len() == 1)
        .then(|| node.attributes.api_names.iter().next())
        .flatten()
        .map(String::as_str)
}

fn compatible_type_tags(left: Option<TypeTag>, right: Option<TypeTag>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn compatible_fallible_kinds(left: Option<FallibleKind>, right: Option<FallibleKind>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn compatible_nodes(left: &OperationNode, right: &OperationNode) -> bool {
    left.kind == right.kind
        && compatible_type_tags(left.attributes.type_tag, right.attributes.type_tag)
        && compatible_fallible_kinds(
            left.attributes.fallible_kind,
            right.attributes.fallible_kind,
        )
}

fn direct_construct_matches(
    graph: &SemanticOperationGraph,
    kind: OperationKind,
    fallible_kind: FallibleKind,
    direct_propagation: Option<DirectPropagation>,
) -> bool {
    matches!(
        graph.nodes.as_slice(),
        [OperationNode {
            kind: node_kind,
            attributes: OperationAttributes {
                fallible_kind: node_fallible_kind,
                direct_propagation: node_direct_propagation,
                ..
            },
        }] if *node_kind == kind
            && *node_fallible_kind == Some(fallible_kind)
            && direct_propagation.is_none_or(|required| {
                *node_direct_propagation == Some(required)
            })
    )
}

fn is_optional_validation(graph: &SemanticOperationGraph) -> bool {
    OPTIONAL_VALIDATION_RULE.pattern.accepts(graph)
        && matches!(
            OPTIONAL_VALIDATION_RULE.matcher,
            SemanticRuleMatcher::DirectConstruct {
                kind,
                fallible_kind,
                direct_propagation,
            } if direct_construct_matches(graph, kind, fallible_kind, direct_propagation)
        )
}

fn is_result_validation(graph: &SemanticOperationGraph) -> bool {
    RESULT_VALIDATION_RULE.pattern.accepts(graph)
        && matches!(
            RESULT_VALIDATION_RULE.matcher,
            SemanticRuleMatcher::DirectConstruct {
                kind,
                fallible_kind,
                direct_propagation,
            } if direct_construct_matches(graph, kind, fallible_kind, direct_propagation)
        )
}

fn is_result_direct_propagation(graph: &SemanticOperationGraph) -> bool {
    CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE
        .pattern
        .accepts(graph)
        && matches!(
            CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE.matcher,
            SemanticRuleMatcher::DirectConstruct {
                kind,
                fallible_kind,
                direct_propagation,
            } if direct_construct_matches(graph, kind, fallible_kind, direct_propagation)
        )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

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
        let second = normalize_registered_apis(Language::Rust, [3; 32], reversed)
            .expect("second normalization");
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
        let same_variant = graph(Language::Cpp, [24; 32], Some(FallibleKind::Option));
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
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
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
            verified[0].1.api_correspondence_ids,
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
        let same_variant_cpp = graph(Language::Cpp, [27; 32], OperationKind::Validate);
        let cpp = graph(Language::Cpp, [28; 32], OperationKind::Validate);
        let propagation = graph(Language::Cpp, [28; 32], OperationKind::PropagateError);
        assert_eq!(
            match_registered_rule(&rust, &same_variant_cpp).map(|matched| matched.rule.id),
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
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
        assert_eq!(
            candidates.pairs,
            vec![SemanticCandidatePair { left: 0, right: 1 }]
        );
        let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].1.rule.id, "cross-language-result-validation-v1");
        assert_eq!(
            verified[0].1.api_correspondence_ids,
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
            match_cross_language_result_direct_propagation(&rust, &cpp)
                .map(|matched| matched.rule.id),
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
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
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
            verified[0].1.api_correspondence_ids,
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
        assert_eq!(registered_rules().len(), 10);
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

    #[test]
    fn registered_pipeline_rule_crosses_languages_but_not_build_variants() {
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
        let cpp = normalize_registered_apis(
            Language::Cpp,
            [4; 32],
            vec![
                OperationObservation {
                    source_offset: 1,
                    api_name: "std::copy_if".to_owned(),
                    type_tag: Some(TypeTag::Integer),
                },
                OperationObservation {
                    source_offset: 2,
                    api_name: "std::push_back".to_owned(),
                    type_tag: Some(TypeTag::Sequence),
                },
            ],
        )
        .expect("valid C++ SOG")
        .graph
        .expect("pipeline graph");
        assert_eq!(
            match_registered_pipeline(&rust, &cpp).map(|matched| matched.rule.id),
            Some("sequence-pipeline-v1")
        );
        let other = SemanticOperationGraph {
            build_variant_fingerprint: [5; 32],
            ..cpp
        };
        assert_eq!(match_registered_pipeline(&rust, &other), None);
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
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
        assert_eq!(
            candidates.pairs,
            vec![SemanticCandidatePair { left: 0, right: 1 }]
        );
        assert_eq!(candidates.stats.buckets, 1);
        let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].1.rule.id, "cross-language-sequence-pipeline-v1");
        assert_eq!(
            verified[0].1.api_correspondence_ids,
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
        assert!(
            match_cross_language_pipeline(&type_mismatched_rust, &type_mismatched_cpp).is_none()
        );

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
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
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
        SemanticOperationGraph::new(language, variant, nodes, Vec::new())
            .expect("valid pipeline graph")
    }

    fn semantic_grouping_units(count: usize) -> Vec<SemanticGroupingUnit> {
        (0..count)
            .map(|index| SemanticGroupingUnit {
                key: [u8::try_from(index).expect("small test index"); 16],
            })
            .collect()
    }

    fn verified_semantic_pair(
        left: usize,
        right: usize,
        rule: SemanticRule,
    ) -> VerifiedSemanticPair {
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
        assert_eq!(
            grouping
                .groups
                .iter()
                .map(|group| group.rule.id)
                .collect::<Vec<_>>(),
            vec![second.id, first.id]
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

    #[test]
    fn candidate_index_partitions_build_variants_and_avoids_other_sequences() {
        let graphs = vec![
            pipeline(
                Language::Rust,
                [8; 32],
                &[OperationKind::Filter, OperationKind::Collect],
            ),
            pipeline(
                Language::Cpp,
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
                Language::Cpp,
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
}
