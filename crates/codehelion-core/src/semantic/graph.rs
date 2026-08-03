use super::{BTreeSet, Deserialize, Error, Language, Serialize, TypeTag};

/// Version of the closed SOG vocabulary and normalization contract.
pub const SOG_SCHEMA_VERSION: &str = "sog-v4";

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
pub const SEMANTIC_WINDOWING_VERSION: &str = "sog-windowing-v2";

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
    /// Compiler-resolved API names used by this operation.
    pub api_names: BTreeSet<String>,
    /// Registered resource category for acquire/release operations.
    pub resource_kind: Option<String>,
    /// Standard fallible container established for a propagation or validation
    /// operation, when the helper schema retained it.
    pub fallible_kind: Option<FallibleKind>,
    /// Closed direct-propagation spelling the compiler confirmed, when any.
    pub direct_propagation: Option<DirectPropagation>,
    /// Position-free source structure retained by the Structural frontend.
    ///
    /// This keeps same-variant rules from treating different predicates or
    /// transformations as interchangeable when their compiler-resolved API
    /// sequence is otherwise identical. It is absent for graphs assembled by
    /// adapters that cannot provide a source window.
    pub structure_fingerprint: Option<[u8; 16]>,
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
