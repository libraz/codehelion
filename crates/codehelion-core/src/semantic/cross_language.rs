use super::candidates::{SemanticCandidateConfig, SemanticCandidatePair};
use super::graph::{
    DirectPropagation, FallibleKind, OperationKind, OperationNode, SOG_SCHEMA_VERSION,
    SemanticOperationGraph,
};
use super::rules::{
    OPTIONAL_VALIDATION_RULE, RESULT_VALIDATION_RULE, SemanticRule, SemanticRuleMatcher,
    SemanticRulePattern, SemanticRuleScope, compatible_fallible_kinds, compatible_type_tags,
    direct_construct_matches, only_api_name,
};
use crate::discovery::Language;
use std::collections::BTreeMap;

/// One explicit correspondence between Rust and C++ standard-library APIs.
///
/// The strings are supplemental API evidence emitted by compiler helpers, not
/// source spellings and never stable call identifiers. A correspondence is
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

pub(super) const CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE: SemanticRule = SemanticRule {
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

pub(super) const CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE: SemanticRule = SemanticRule {
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

pub(super) const CROSS_LANGUAGE_RESULT_VALIDATION_RULE: SemanticRule = SemanticRule {
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

pub(super) const CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE: SemanticRule = SemanticRule {
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
pub(super) const OPTIONAL_VALIDATION_CORRESPONDENCE_ID: &str = "optional-presence-validation-v1";

/// Closed compiler-construct correspondence for Rust `Result::is_ok()` and
/// C++ `expected::has_value()`/`operator bool`. Both helpers resolve the
/// standard family before this rule can compare the branch.
pub(super) const RESULT_VALIDATION_CORRESPONDENCE_ID: &str = "result-expected-validation-v1";

/// Closed compiler-construct correspondence for a Rust `Result` adapter and a
/// C++ `expected` identity return. It remains distinct from the API table:
/// neither side depends on an API-call sequence.
pub(super) const RESULT_DIRECT_PROPAGATION_CORRESPONDENCE_ID: &str =
    "result-expected-direct-propagation-v1";

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

/// One verified Rust-to-C++ rule application with its closed correspondence
/// evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossLanguageRuleMatch {
    /// Rule that justified the correspondence.
    pub rule: SemanticRule,
    /// Registered API or compiler-construct correspondence identifiers used by
    /// the matched operations.
    pub correspondence_ids: Vec<&'static str>,
}

/// Extract bounded candidates for an explicit Rust-to-C++ comparison.
///
/// Ordinary semantic findings must use
/// [`extract_registered_candidates`](crate::semantic::extract_registered_candidates).
/// This function considers only graphs that carry the same caller-provided
/// comparison partition, have a Rust/C++ language pairing, and consist solely
/// of closed API correspondences or compiler-confirmed direct-loop
/// constructs. It never compares C, joins normal `BuildVariants`, or falls
/// back to matching API-name suffixes or arbitrary source syntax.
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
        let direct_loop_pipeline = is_cross_language_direct_loop(graph);
        let optional_validation = is_optional_validation(graph);
        let result_validation = is_result_validation(graph);
        let result_direct_propagation = is_result_direct_propagation(graph);
        if graph.schema_version != SOG_SCHEMA_VERSION
            || !matches!(graph.language, Language::Rust | Language::Cpp)
            || !(pipeline
                || direct_loop_pipeline
                || optional_validation
                || result_validation
                || result_direct_propagation)
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

/// Match one explicitly selected Rust-to-C++ sequence pipeline.
///
/// Unlike [`match_registered_pipeline`](crate::semantic::match_registered_pipeline), this is not part of ordinary
/// BuildVariant-local detection. Its caller must first select an explicit
/// comparison domain and use [`extract_cross_language_candidates`]. Aligned
/// operations must either name the same closed API correspondence entry or be
/// the deliberately small compiler-confirmed direct-loop construct pair.
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
    if is_cross_language_direct_loop(left)
        && is_cross_language_direct_loop(right)
        && left
            .nodes
            .iter()
            .zip(&right.nodes)
            .all(|(left_node, right_node)| left_node.kind == right_node.kind)
    {
        return Some(CrossLanguageRuleMatch {
            rule: CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
            correspondence_ids: vec![DIRECT_LOOP_SEQUENCE_CORRESPONDENCE_ID],
        });
    }

    let mut correspondence_ids = Vec::with_capacity(left.nodes.len());
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
        correspondence_ids.push(left_entry.id);
    }
    Some(CrossLanguageRuleMatch {
        rule: CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
        correspondence_ids,
    })
}

/// Closed correspondence for compiler-confirmed Rust and C++ direct loop
/// forms. It is intentionally separate from the API table: both helpers have
/// proved a standard sequence plus an unchanged loop binding, while neither
/// side is represented by an arbitrary recovered call spelling.
pub(super) const DIRECT_LOOP_SEQUENCE_CORRESPONDENCE_ID: &str = "direct-loop-sequence-v1";

/// Whether `graph` is one direct range/`for` loop form that both compiler
/// helpers recognize. A graph with an API name is deliberately excluded: that
/// stays on the API correspondence path, and a transformed call cannot borrow
/// the loop rule merely because it appears beside a construct.
fn is_cross_language_direct_loop(graph: &SemanticOperationGraph) -> bool {
    matches!(
        graph.nodes.as_slice(),
        [
            OperationNode {
                kind: OperationKind::Source,
                attributes: source,
            },
            OperationNode {
                kind: OperationKind::Collect | OperationKind::Reduce,
                attributes: operation,
            },
        ] if source.api_names.is_empty()
            && operation.api_names.is_empty()
            && source.fallible_kind.is_none()
            && operation.fallible_kind.is_none()
            && source.direct_propagation.is_none()
            && operation.direct_propagation.is_none()
            && source.resource_kind.is_none()
            && operation.resource_kind.is_none()
    )
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
        correspondence_ids: vec![OPTIONAL_VALIDATION_CORRESPONDENCE_ID],
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
        correspondence_ids: vec![RESULT_VALIDATION_CORRESPONDENCE_ID],
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
        correspondence_ids: vec![RESULT_DIRECT_PROPAGATION_CORRESPONDENCE_ID],
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
