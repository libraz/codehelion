use super::{
    BTreeMap, BTreeSet, CloneClass, Confidence, GroupingConfig, GroupingUnit, OperationKind,
    RuleMatch, SOG_SCHEMA_VERSION, SemanticOperationGraph, SemanticRule, SimilarityEdge, grouping,
    match_registered_rule, registered_rules,
};

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
