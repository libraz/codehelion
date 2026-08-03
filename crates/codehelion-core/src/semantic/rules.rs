use super::{
    CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE, CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE,
    CROSS_LANGUAGE_RESULT_VALIDATION_RULE, CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
    DirectPropagation, FallibleKind, OperationAttributes, OperationEdge, OperationEdgeKind,
    OperationKind, OperationNode, SOG_SCHEMA_VERSION, SemanticOperationGraph, TypeTag,
};

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
    /// Match a single closed compiler-confirmed API sequence. The operation
    /// kinds remain part of the rule pattern; these names prevent a generic
    /// pair of value transformations from being described as serialization.
    ExactApiSequence {
        /// One resolved API name required at each aligned operation position.
        api_names: &'static [&'static str],
    },
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

/// Serialization and deserialization are a fixed two-step value conversion
/// here, not a claim that arbitrary parsing or formatting is semantically
/// interchangeable. Rust's standard `ToString` and `str::parse` are the only
/// admitted implementation in this initial rule.
const RUST_SERIALIZATION_ROUND_TRIP_RULE: SemanticRule = SemanticRule {
    id: "rust-serialization-round-trip-v1",
    version: 1,
    confidence: 0.8,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 2,
        permitted_kinds: &[OperationKind::Map],
    },
    matcher: SemanticRuleMatcher::ExactApiSequence {
        api_names: &["rust::ToString::to_string", "rust::str::parse"],
    },
};

/// C++ records the analogous closed standard-library conversion pair. This is
/// intentionally a separate rule: source language and exact resolved APIs
/// remain evidence, rather than being erased behind a generic serialization
/// label.
const CPP_SERIALIZATION_ROUND_TRIP_RULE: SemanticRule = SemanticRule {
    id: "cpp-serialization-round-trip-v1",
    version: 1,
    confidence: 0.8,
    scope: SemanticRuleScope::SameBuildVariant,
    pattern: SemanticRulePattern {
        minimum_operations: 2,
        permitted_kinds: &[OperationKind::Map],
    },
    matcher: SemanticRuleMatcher::ExactApiSequence {
        api_names: &["std::to_string", "std::stoull"],
    },
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

pub(super) const OPTIONAL_VALIDATION_RULE: SemanticRule = SemanticRule {
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

pub(super) const RESULT_VALIDATION_RULE: SemanticRule = SemanticRule {
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

/// Rules enabled by default because each has an explicit, bounded meaning.
///
/// Cross-language entries still require the separate opt-in comparison path;
/// appearing here makes their enabled state visible and configurable beside
/// same-variant rules.
#[must_use]
pub const fn registered_rules() -> &'static [SemanticRule] {
    &[
        RUST_SERIALIZATION_ROUND_TRIP_RULE,
        CPP_SERIALIZATION_ROUND_TRIP_RULE,
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
pub(super) fn match_same_variant_rule(
    rule: SemanticRule,
    left: &SemanticOperationGraph,
    right: &SemanticOperationGraph,
) -> Option<RuleMatch> {
    if rule.scope != SemanticRuleScope::SameBuildVariant
        || left.schema_version != SOG_SCHEMA_VERSION
        || right.schema_version != SOG_SCHEMA_VERSION
        || left.language != right.language
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
                    .any(|node| node.kind != OperationKind::Map)
                && left
                    .nodes
                    .iter()
                    .zip(&right.nodes)
                    .all(|(left, right)| compatible_nodes(left, right))
        }
        SemanticRuleMatcher::ExactApiSequence { api_names } => {
            left.nodes.len() == api_names.len()
                && right.nodes.len() == api_names.len()
                && left.nodes.iter().zip(&right.nodes).zip(api_names).all(
                    |((left, right), api_name)| {
                        compatible_nodes(left, right)
                            && left.attributes.api_names.len() == 1
                            && right.attributes.api_names.len() == 1
                            && left.attributes.api_names.contains(*api_name)
                            && right.attributes.api_names.contains(*api_name)
                    },
                )
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

pub(super) fn only_api_name(node: &OperationNode) -> Option<&str> {
    (node.attributes.api_names.len() == 1)
        .then(|| node.attributes.api_names.iter().next())
        .flatten()
        .map(String::as_str)
}

pub(super) fn compatible_type_tags(left: Option<TypeTag>, right: Option<TypeTag>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

pub(super) fn compatible_fallible_kinds(
    left: Option<FallibleKind>,
    right: Option<FallibleKind>,
) -> bool {
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
        && compatible_structure_fingerprints(
            left.attributes.structure_fingerprint,
            right.attributes.structure_fingerprint,
        )
}

fn compatible_structure_fingerprints(left: Option<[u8; 16]>, right: Option<[u8; 16]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

pub(super) fn direct_construct_matches(
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
