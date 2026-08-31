//! Format-neutral duplicate grouping over [`ArtifactIr`].
//!
//! Exact and normalized equality are equivalence relations, so their groups
//! are keyed directly by content rather than by a transitive similarity graph.
//! Near-match grouping is deliberately a later operation: it must use the
//! source engine's complete-linkage policy instead of union-find.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ArtifactDataSegment, ArtifactFingerprint, ArtifactIr, ArtifactSymbol};

/// The smallest data region that duplicate-data analysis reports by default.
///
/// Tiny constants occur frequently and are not useful bloat signals. Callers
/// may use [`find_duplicate_data`] with another threshold when they have a
/// format- or project-specific reason to do so.
pub const DEFAULT_MIN_DUPLICATE_DATA_BYTES: u64 = 16;

/// Maximum independent root closures considered for shared-dependency bytes.
///
/// Each root needs one reachability traversal. Above this limit the value is
/// unavailable rather than allowing a large export table to monopolize the
/// artifact worker.
const MAX_SHARED_DEPENDENCY_ROOTS: usize = 1024;

/// A model-derived estimate of a refactoring's byte impact.
///
/// Estimates may be negative when required call overhead outweighs the
/// duplicate bytes attributed to the proposed refactoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EstimatedRefactorSavingsBytes(pub i64);

/// A before/after reduction verified for one controlled refactoring.
///
/// A verified change may be negative when the controlled change grows the
/// artifact, so it cannot be represented by an unsigned observed count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerifiedSavingsBytes(pub i64);

/// Duplicate groups found in one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateReport {
    /// Groups whose machine code bytes are identical.
    pub exact: Vec<DuplicateGroup>,
    /// Groups whose version-compatible normalized instructions are identical.
    pub normalized: Vec<DuplicateGroup>,
}

/// Size categories kept separate in artifact reports.
///
/// A `None` value means the current parser evidence cannot establish the
/// category. In particular, retained and shared-dependency sizes require a
/// resolved call graph, which not every format backend can provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeClassification {
    /// Complete byte length observed directly from the input.
    pub observed_bytes: u64,
    /// Excess bytes in exact duplicate code groups.
    pub duplicated_bytes: u64,
    /// Excess bytes in code groups that are equal only after normalization,
    /// when a normalizer exists for this architecture.
    ///
    /// Kept apart from [`Self::duplicated_bytes`] rather than added to it:
    /// normalized equality is reached through a rewriting rule, so it is
    /// weaker evidence than byte equality and cannot stand in the same
    /// column. It feeds no savings value for the same reason.
    pub duplicated_bytes_normalized: Option<u64>,
    /// Bytes retained by call-graph reachability, when calculated.
    pub retained_bytes: Option<u64>,
    /// Bytes shared by several dependency closures, when calculated.
    pub shared_dependency_bytes: Option<u64>,
    /// Excess bytes in exact duplicate data groups, when regions were
    /// independently established rather than inferred from whole sections.
    pub duplicated_data_bytes: Option<u64>,
    /// A theoretical maximum from directly observed exact duplication.
    ///
    /// This is explicitly not a claim that a linker or refactoring can remove
    /// the bytes without changing behaviour or layout.
    pub upper_bound_savings_bytes: Option<u64>,
    /// A source-informed refactoring estimate, unavailable before mapping.
    pub estimated_refactor_savings_bytes: Option<EstimatedRefactorSavingsBytes>,
    /// A before/after measured reduction, unavailable for one artifact.
    pub verified_savings_bytes: Option<VerifiedSavingsBytes>,
    /// Confidence in the duplicate observation. Exact byte equality is a
    /// direct observation, while normalized equality stays separate in the
    /// duplicate report.
    pub clone_confidence: EvidenceConfidence,
    /// Confidence in a possible size reduction. This is unavailable before
    /// source mapping and a measured refactoring supply actual evidence.
    pub savings_confidence: EvidenceConfidence,
    /// Conditions and omissions that qualify the derived categories.
    pub assumptions: Vec<String>,
}

/// Evidence strength reported without turning an observation into a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceConfidence {
    /// Direct parser-observed facts establish the value.
    High,
    /// The result uses a conservative inference with known incompleteness.
    Medium,
    /// The result has substantial unresolved evidence.
    Low,
    /// The evidence necessary to calculate the value is absent.
    Unavailable,
}

/// Reachability result derived only from resolved local call edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadCodeReport {
    /// Symbols not reached from a parser-established export.
    pub symbols: Vec<ArtifactFingerprint>,
    /// Whether every relevant dispatch edge was resolved and every symbol
    /// identity was unique, which is what a reachability proof needs.
    pub definitive: bool,
    /// Why the result is conservative or unavailable.
    pub assumptions: Vec<String>,
}

/// The bytes exclusively retained by one reachable symbol's dominator region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedSize {
    /// The symbol whose removal makes the dominated region unreachable.
    pub symbol: ArtifactFingerprint,
    /// Sum of observed code sizes in its dominated region.
    pub retained_bytes: u64,
}

/// One equality class of duplicate artifact symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// Stable content identity for this group.
    pub fingerprint: ArtifactFingerprint,
    /// The byte size that could be removed if every member except the largest
    /// canonical member were safely merged. It is an observed duplicate count,
    /// not a claimed binary-size saving.
    pub duplicated_bytes: u64,
    /// Each observed occurrence. Offset distinguishes occurrences within this
    /// one artifact but never participates in the stable fingerprint.
    pub members: Vec<DuplicateMember>,
}

/// One occurrence in a [`DuplicateGroup`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateMember {
    /// Stable content fingerprint of the symbol.
    pub symbol: ArtifactFingerprint,
    /// Artifact offset for this occurrence.
    pub offset: u64,
    /// Observed symbol size in bytes.
    pub size: u64,
}

/// Find exact and normalized duplicate groups in `artifact`.
#[must_use]
pub fn find_duplicates(artifact: &ArtifactIr) -> DuplicateReport {
    let exact = groups(&artifact.symbols, |symbol| {
        Some(("exact", symbol.code.as_slice()))
    });
    let normalized = if artifact.capabilities.normalized_duplicates {
        groups(&artifact.symbols, |symbol| {
            symbol.normalized.as_ref().map(|normalized| {
                // One byte separator is unambiguous because the version gets a
                // length prefix in `group_fingerprint` below.
                (normalized.version.as_str(), normalized.bytes.as_slice())
            })
        })
    } else {
        Vec::new()
    };
    DuplicateReport { exact, normalized }
}

/// Find exact duplicate data regions at or above `min_bytes`.
///
/// Data has no normalized representation: a match here means the byte stream
/// itself is equal. Short regions are deliberately excluded before grouping.
#[must_use]
pub fn find_duplicate_data(artifact: &ArtifactIr, min_bytes: u64) -> Vec<DuplicateGroup> {
    if !artifact.capabilities.independent_data_segments {
        return Vec::new();
    }
    groups_data(&artifact.data_segments, min_bytes)
}

/// Derive the size categories supported by the currently observed IR.
#[must_use]
pub fn classify_sizes(artifact: &ArtifactIr) -> SizeClassification {
    let duplicates = find_duplicates(artifact);
    let duplicate_data = find_duplicate_data(artifact, DEFAULT_MIN_DUPLICATE_DATA_BYTES);
    classify_sizes_from_duplicates(artifact, &duplicates, &duplicate_data)
}

/// Derive size categories while reusing duplicate groups already calculated
/// for another report surface.
#[must_use]
pub fn classify_sizes_from_duplicates(
    artifact: &ArtifactIr,
    duplicates: &DuplicateReport,
    duplicate_data: &[DuplicateGroup],
) -> SizeClassification {
    let duplicated_bytes = duplicates
        .exact
        .iter()
        .map(|group| group.duplicated_bytes)
        .sum();
    let duplicated_bytes_normalized = artifact.capabilities.normalized_duplicates.then(|| {
        duplicates
            .normalized
            .iter()
            .map(|group| group.duplicated_bytes)
            .sum()
    });
    let duplicated_data_bytes = artifact.capabilities.independent_data_segments.then(|| {
        duplicate_data
            .iter()
            .map(|group| group.duplicated_bytes)
            .sum()
    });
    let mut assumptions = vec![
        "upper_bound_savings_bytes is not a guaranteed reduction".to_owned(),
        "estimated_refactor_savings_bytes needs source-artifact mapping".to_owned(),
        // Stated even when both numbers are present, because the difference
        // between them is the whole reason there are two of them.
        "duplicated_bytes counts byte-identical groups only".to_owned(),
    ];
    if duplicated_bytes_normalized.is_none() {
        assumptions.push(
            "duplicated_bytes_normalized needs a normalizer for this architecture".to_owned(),
        );
    }
    if duplicated_data_bytes.is_none() {
        assumptions
            .push("duplicated_data_bytes needs independently established data regions".to_owned());
    }
    let graph_sizes = resolved_graph(artifact);
    if graph_sizes.is_none() {
        assumptions
            .push("retained and shared dependency sizes need a resolved call graph".to_owned());
    }
    let (retained_bytes, shared_dependency_bytes) = graph_sizes.map_or((None, None), |graph| {
        let retained_bytes = graph
            .reachable
            .iter()
            .map(|symbol| graph.sizes[symbol])
            .sum();
        let mut root_reach_counts: BTreeMap<ArtifactFingerprint, u64> = BTreeMap::new();
        for root in &graph.roots {
            for symbol in reachable_from(BTreeSet::from([*root]), &graph.successors) {
                *root_reach_counts.entry(symbol).or_default() += 1;
            }
        }
        let shared_dependency_bytes = root_reach_counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(symbol, _)| graph.sizes[&symbol])
            .sum();
        (Some(retained_bytes), Some(shared_dependency_bytes))
    });
    SizeClassification {
        observed_bytes: artifact.observed_bytes,
        duplicated_bytes,
        duplicated_bytes_normalized,
        retained_bytes,
        shared_dependency_bytes,
        duplicated_data_bytes,
        upper_bound_savings_bytes: Some(duplicated_bytes),
        estimated_refactor_savings_bytes: None,
        verified_savings_bytes: None,
        clone_confidence: EvidenceConfidence::High,
        savings_confidence: EvidenceConfidence::Unavailable,
        assumptions,
    }
}

/// Find symbols not reachable from parser-established exports.
///
/// An unresolved dispatch can target any local function, so it changes the
/// result from a definitive dead-code finding into a candidate list. No
/// exports means no trustworthy root set and therefore returns no finding.
///
/// Reachability is followed over content-derived identities, so two symbols
/// built from the same bytes are one node in that graph: an unreachable copy
/// is then absorbed by an exported twin and drops out of the result. A call
/// whose endpoint matches no symbol leaves the same graph incomplete. Either
/// condition keeps the answer a candidate list and names itself among the
/// assumptions, because neither is visible in the symbol list it returns.
#[must_use]
pub fn dead_code_candidates(artifact: &ArtifactIr) -> Option<DeadCodeReport> {
    if !artifact.capabilities.call_graph {
        return None;
    }
    let mut reachable: BTreeSet<ArtifactFingerprint> = artifact
        .symbols
        .iter()
        .filter(|symbol| symbol.exported)
        .map(|symbol| symbol.fingerprint)
        .collect();
    reachable.extend(artifact.entry_points.iter().copied());
    reachable.extend(artifact.indirect_references.iter().copied());
    if reachable.is_empty() {
        return None;
    }
    loop {
        let before = reachable.len();
        for call in &artifact.calls {
            if reachable.contains(&call.caller) {
                if let Some(target) = call.target {
                    reachable.insert(target);
                }
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    let mut symbols: Vec<_> = artifact
        .symbols
        .iter()
        .map(|symbol| symbol.fingerprint)
        .filter(|fingerprint| !reachable.contains(fingerprint))
        .collect();
    symbols.sort();
    symbols.dedup();
    let mut assumptions = Vec::new();
    if artifact.calls.iter().any(|call| call.unresolved.is_some()) {
        assumptions
            .push("unresolved dispatch prevents proving unreachable symbols are dead".to_owned());
    }
    let identities: BTreeSet<_> = artifact
        .symbols
        .iter()
        .map(|symbol| symbol.fingerprint)
        .collect();
    if identities.len() != artifact.symbols.len() {
        assumptions.push(
            "two symbols share one content fingerprint, so reachability cannot separate them"
                .to_owned(),
        );
    }
    if artifact.calls.iter().any(|call| {
        !identities.contains(&call.caller)
            || call
                .target
                .is_some_and(|target| !identities.contains(&target))
    }) {
        assumptions.push(
            "a recorded call endpoint matches no symbol, so the local call graph is incomplete"
                .to_owned(),
        );
    }
    let definitive = assumptions.is_empty();
    if definitive {
        assumptions.push("all recorded call edges were resolved locally".to_owned());
    }
    Some(DeadCodeReport {
        symbols,
        definitive,
        assumptions,
    })
}

/// Calculate retained code sizes from a complete, unambiguous local call graph.
///
/// The returned regions overlap (a dominator retains its descendants too), so
/// callers must never add them together as a total saving. Ambiguous duplicate
/// fingerprints and unresolved calls are refused rather than guessed.
///
/// The immediate-dominator tree is derived with Lengauer--Tarjan. A virtual
/// root joins parser-established roots, so a symbol shared by two entry points
/// is not incorrectly retained by either one. The algorithm stores a constant
/// amount of state per reachable symbol rather than a reachability set per
/// symbol.
#[must_use]
pub fn retained_sizes(artifact: &ArtifactIr) -> Option<Vec<RetainedSize>> {
    let graph = resolved_graph(artifact)?;
    let symbols: Vec<_> = graph.reachable.iter().copied().collect();
    let index: BTreeMap<_, _> = symbols
        .iter()
        .enumerate()
        .map(|(position, symbol)| (*symbol, position + 1))
        .collect();
    let mut successors = vec![Vec::new(); symbols.len() + 1];
    successors[0] = graph.roots.iter().map(|root| index[root]).collect();
    for (caller, targets) in &graph.successors {
        if !graph.reachable.contains(caller) {
            continue;
        }
        for target in targets {
            if graph.reachable.contains(target) {
                successors[index[caller]].push(index[target]);
            }
        }
    }

    let (dfs_vertices, parents) = depth_first_tree(&successors);
    let mut dfs_index = vec![None; successors.len()];
    for (position, vertex) in dfs_vertices.iter().copied().enumerate() {
        dfs_index[vertex] = Some(position);
    }
    let mut predecessors = vec![Vec::new(); dfs_vertices.len()];
    for (vertex, edges) in successors.iter().enumerate() {
        let Some(from) = dfs_index[vertex] else {
            continue;
        };
        for target in edges {
            if let Some(to) = dfs_index[*target] {
                predecessors[to].push(from);
            }
        }
    }
    let immediate = lengauer_tarjan(&predecessors, &parents);
    let mut retained = dfs_vertices
        .iter()
        .map(|vertex| {
            if *vertex == 0 {
                0
            } else {
                graph.sizes[&symbols[*vertex - 1]]
            }
        })
        .collect::<Vec<_>>();
    for node in (1..retained.len()).rev() {
        if let Some(parent) = immediate[node] {
            retained[parent] = retained[parent].saturating_add(retained[node]);
        }
    }
    let mut result: Vec<_> = dfs_vertices
        .iter()
        .enumerate()
        .skip(1)
        .map(|(position, vertex)| RetainedSize {
            symbol: symbols[*vertex - 1],
            retained_bytes: retained[position],
        })
        .collect();
    result.sort_by(|left, right| {
        right
            .retained_bytes
            .cmp(&left.retained_bytes)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    Some(result)
}

/// Iterative DFS ordering and its parent relation, both in DFS indexes.
fn depth_first_tree(successors: &[Vec<usize>]) -> (Vec<usize>, Vec<Option<usize>>) {
    let mut vertices = vec![0];
    let mut parents = vec![None];
    let mut index = vec![None; successors.len()];
    index[0] = Some(0);
    let mut stack = vec![(0usize, 0usize)];
    while let Some((vertex, next_edge)) = stack.last_mut() {
        if *next_edge == successors[*vertex].len() {
            stack.pop();
            continue;
        }
        let target = successors[*vertex][*next_edge];
        *next_edge += 1;
        if index[target].is_some() {
            continue;
        }
        let Some(parent) = index[*vertex] else {
            continue;
        };
        index[target] = Some(vertices.len());
        vertices.push(target);
        parents.push(Some(parent));
        stack.push((target, 0));
    }
    (vertices, parents)
}

/// Immediate dominators from a DFS predecessor graph, using Lengauer--Tarjan.
fn lengauer_tarjan(predecessors: &[Vec<usize>], parents: &[Option<usize>]) -> Vec<Option<usize>> {
    let nodes = predecessors.len();
    let mut semi: Vec<_> = (0..nodes).collect();
    let mut labels: Vec<_> = (0..nodes).collect();
    let mut ancestors = vec![None; nodes];
    let mut buckets = vec![Vec::new(); nodes];
    let mut immediate = vec![None; nodes];

    for node in (1..nodes).rev() {
        for predecessor in &predecessors[node] {
            let candidate = lt_eval(*predecessor, &mut ancestors, &mut labels, &semi);
            semi[node] = semi[node].min(semi[candidate]);
        }
        buckets[semi[node]].push(node);
        let Some(parent) = parents[node] else {
            continue;
        };
        ancestors[node] = Some(parent);
        for member in std::mem::take(&mut buckets[parent]) {
            let candidate = lt_eval(member, &mut ancestors, &mut labels, &semi);
            immediate[member] = Some(if semi[candidate] < semi[member] {
                candidate
            } else {
                parent
            });
        }
    }
    for node in 1..nodes {
        let Some(parent) = immediate[node] else {
            continue;
        };
        if parent != semi[node] {
            immediate[node] = immediate[parent];
        }
    }
    immediate
}

/// Evaluate one union-find label while applying path compression.
fn lt_eval(
    node: usize,
    ancestors: &mut [Option<usize>],
    labels: &mut [usize],
    semi: &[usize],
) -> usize {
    if ancestors[node].is_none() {
        return node;
    }
    lt_compress(node, ancestors, labels, semi);
    labels[node]
}

/// Compress the union-find path used by Lengauer--Tarjan evaluation.
fn lt_compress(node: usize, ancestors: &mut [Option<usize>], labels: &mut [usize], semi: &[usize]) {
    let mut path = Vec::new();
    let mut current = node;
    while let Some(parent) = ancestors[current] {
        if ancestors[parent].is_none() {
            break;
        }
        path.push(current);
        current = parent;
    }
    for current in path.into_iter().rev() {
        let Some(parent) = ancestors[current] else {
            continue;
        };
        if semi[labels[parent]] < semi[labels[current]] {
            labels[current] = labels[parent];
        }
        ancestors[current] = ancestors[parent];
    }
}

/// Facts available only when every local graph edge and identity is sound.
struct ResolvedGraph {
    sizes: BTreeMap<ArtifactFingerprint, u64>,
    roots: BTreeSet<ArtifactFingerprint>,
    reachable: BTreeSet<ArtifactFingerprint>,
    successors: BTreeMap<ArtifactFingerprint, Vec<ArtifactFingerprint>>,
}

fn resolved_graph(artifact: &ArtifactIr) -> Option<ResolvedGraph> {
    if !artifact.capabilities.call_graph
        || artifact.calls.iter().any(|call| call.unresolved.is_some())
    {
        return None;
    }
    let mut sizes = BTreeMap::new();
    for symbol in &artifact.symbols {
        if sizes.insert(symbol.fingerprint, symbol.size).is_some() {
            return None;
        }
    }
    let roots: BTreeSet<_> = artifact
        .symbols
        .iter()
        .filter(|symbol| symbol.exported)
        .map(|symbol| symbol.fingerprint)
        .chain(artifact.entry_points.iter().copied())
        .chain(artifact.indirect_references.iter().copied())
        .collect();
    if roots.is_empty()
        || roots.len() > MAX_SHARED_DEPENDENCY_ROOTS
        || !roots.iter().all(|root| sizes.contains_key(root))
    {
        return None;
    }
    if artifact.calls.iter().any(|call| {
        !sizes.contains_key(&call.caller)
            || !call
                .target
                .is_some_and(|target| sizes.contains_key(&target))
    }) {
        return None;
    }
    let mut successors: BTreeMap<_, Vec<_>> = sizes
        .keys()
        .copied()
        .map(|symbol| (symbol, Vec::new()))
        .collect();
    for call in &artifact.calls {
        if let Some(target) = call.target {
            successors.entry(call.caller).or_default().push(target);
        }
    }
    for targets in successors.values_mut() {
        targets.sort_unstable();
        targets.dedup();
    }
    let reachable = reachable_from(roots.clone(), &successors);
    Some(ResolvedGraph {
        sizes,
        roots,
        reachable,
        successors,
    })
}

fn reachable_from(
    mut reachable: BTreeSet<ArtifactFingerprint>,
    successors: &BTreeMap<ArtifactFingerprint, Vec<ArtifactFingerprint>>,
) -> BTreeSet<ArtifactFingerprint> {
    let mut pending: Vec<_> = reachable.iter().copied().collect();
    while let Some(symbol) = pending.pop() {
        if let Some(targets) = successors.get(&symbol) {
            for target in targets {
                if reachable.insert(*target) {
                    pending.push(*target);
                }
            }
        }
    }
    reachable
}

fn groups<'a>(
    symbols: &'a [ArtifactSymbol],
    key: impl Fn(&'a ArtifactSymbol) -> Option<(&'a str, &'a [u8])>,
) -> Vec<DuplicateGroup> {
    let mut buckets: BTreeMap<(&str, &[u8]), Vec<&ArtifactSymbol>> = BTreeMap::new();
    for symbol in symbols {
        let Some((version, content)) = key(symbol) else {
            continue;
        };
        buckets.entry((version, content)).or_default().push(symbol);
    }
    let mut result: Vec<DuplicateGroup> = buckets
        .into_iter()
        // Symbols with no observed content share the empty key without sharing
        // anything: bucketing them would count aliases as a duplicate group
        // whose removable size is zero.
        .filter(|((_, content), members)| members.len() > 1 && !content.is_empty())
        .map(|((version, content), members)| group(version, content, members))
        .collect();
    result.sort_by(|left, right| {
        right
            .duplicated_bytes
            .cmp(&left.duplicated_bytes)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

fn group(version: &str, content: &[u8], symbols: Vec<&ArtifactSymbol>) -> DuplicateGroup {
    let mut members: Vec<DuplicateMember> = symbols
        .into_iter()
        .map(|symbol| DuplicateMember {
            symbol: symbol.fingerprint,
            offset: symbol.offset,
            size: symbol.size,
        })
        .collect();
    members.sort_by_key(|member| (member.offset, member.symbol));
    let total = members.iter().map(|member| member.size).sum::<u64>();
    let canonical = members.iter().map(|member| member.size).max().unwrap_or(0);
    DuplicateGroup {
        fingerprint: group_fingerprint(version, content),
        duplicated_bytes: total.saturating_sub(canonical),
        members,
    }
}

fn groups_data(segments: &[ArtifactDataSegment], min_bytes: u64) -> Vec<DuplicateGroup> {
    let mut buckets: BTreeMap<&[u8], Vec<&ArtifactDataSegment>> = BTreeMap::new();
    for segment in segments {
        if segment.bytes.len() as u64 >= min_bytes {
            buckets
                .entry(segment.bytes.as_slice())
                .or_default()
                .push(segment);
        }
    }
    let mut result: Vec<DuplicateGroup> = buckets
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|(bytes, segments)| {
            let mut members: Vec<DuplicateMember> = segments
                .into_iter()
                .map(|segment| DuplicateMember {
                    symbol: segment.fingerprint,
                    offset: segment.offset,
                    size: segment.bytes.len() as u64,
                })
                .collect();
            members.sort_by_key(|member| (member.offset, member.symbol));
            let total = members.iter().map(|member| member.size).sum::<u64>();
            let canonical = members.iter().map(|member| member.size).max().unwrap_or(0);
            DuplicateGroup {
                fingerprint: group_fingerprint("data-exact", bytes),
                duplicated_bytes: total.saturating_sub(canonical),
                members,
            }
        })
        .collect();
    result.sort_by(|left, right| {
        right
            .duplicated_bytes
            .cmp(&left.duplicated_bytes)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

fn group_fingerprint(version: &str, content: &[u8]) -> ArtifactFingerprint {
    let mut identity = Vec::new();
    identity.extend((version.len() as u64).to_le_bytes());
    identity.extend(version.as_bytes());
    identity.extend(content);
    ArtifactFingerprint::from_content("artifact-duplicate-group", &identity)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{ArtifactDataSegment, ArtifactFormat, NormalizedInstructions};
    use proptest::prelude::*;

    fn symbol(offset: u64, code: &[u8], normalized: Option<&[u8]>) -> ArtifactSymbol {
        ArtifactSymbol {
            fingerprint: ArtifactFingerprint::from_content("test-symbol", &offset.to_le_bytes()),
            name: None,
            exported: false,
            section: Some(1),
            offset,
            size: code.len() as u64,
            size_inferred: false,
            code: code.to_vec(),
            normalized: normalized.map(|bytes| NormalizedInstructions {
                version: "test-normal-v1".to_owned(),
                bytes: bytes.to_vec(),
            }),
            inline_stack: Vec::new(),
        }
    }

    #[test]
    fn exact_and_normalized_groups_are_reported_separately_and_deterministically() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.symbols = vec![
            symbol(30, &[1, 2], Some(&[9])),
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[1, 3], Some(&[9])),
            symbol(40, &[5], None),
        ];
        let duplicates = find_duplicates(&artifact);
        assert_eq!(duplicates.exact.len(), 1);
        assert_eq!(duplicates.exact[0].members.len(), 2);
        assert_eq!(duplicates.exact[0].duplicated_bytes, 2);
        assert_eq!(
            duplicates.exact[0]
                .members
                .iter()
                .map(|member| member.offset)
                .collect::<Vec<_>>(),
            vec![10, 30]
        );
        assert_eq!(duplicates.normalized.len(), 1);
        assert_eq!(duplicates.normalized[0].members.len(), 3);
        assert_eq!(duplicates.normalized[0].duplicated_bytes, 4);
        assert_eq!(find_duplicates(&artifact), duplicates);
    }

    /// Symbols with no observed content are aliases of nothing in particular,
    /// so they may not form a group of their own: a group whose members share
    /// zero bytes offers no removable size, and letting the alias count vary
    /// the group count makes every comparison report a difference of zero.
    #[test]
    fn symbols_sharing_no_observed_content_form_no_duplicate_group() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.symbols = vec![
            symbol(10, &[], Some(&[])),
            symbol(20, &[], Some(&[])),
            symbol(30, &[], Some(&[])),
        ];

        let duplicates = find_duplicates(&artifact);

        assert!(duplicates.exact.is_empty());
        assert!(duplicates.normalized.is_empty());
        assert_eq!(classify_sizes(&artifact).duplicated_bytes, 0);

        artifact.symbols.push(symbol(40, &[1, 2], Some(&[9])));
        artifact.symbols.push(symbol(50, &[1, 2], Some(&[9])));
        let with_content = find_duplicates(&artifact);

        assert_eq!(with_content.exact.len(), 1);
        assert_eq!(with_content.exact[0].members.len(), 2);
        assert_eq!(with_content.exact[0].duplicated_bytes, 2);
        assert_eq!(with_content.normalized.len(), 1);
        assert_eq!(with_content.normalized[0].members.len(), 2);

        // The same artifact without the aliases answers identically, which is
        // what keeps two builds differing only in how many zero-size aliases
        // they carry from comparing as a change.
        let mut sized_only = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        sized_only.capabilities.normalized_duplicates = true;
        sized_only.symbols = vec![
            symbol(40, &[1, 2], Some(&[9])),
            symbol(50, &[1, 2], Some(&[9])),
        ];
        assert_eq!(find_duplicates(&sized_only), with_content);
        assert_eq!(classify_sizes(&sized_only), classify_sizes(&artifact));
    }

    /// The size categories carry both duplicate totals, and the savings value
    /// stays built from the byte-identical one alone.
    ///
    /// A reader who came for size reads the categories and stops there, so a
    /// total that only appears in the duplicate listing above is a total they
    /// never see. Adding it into the upper bound instead would put an
    /// inference behind a number that says it is an observation.
    #[test]
    fn size_categories_carry_normalized_duplication_without_folding_it_into_savings() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.observed_bytes = 100;
        artifact.symbols = vec![
            symbol(30, &[1, 2], Some(&[9])),
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[1, 3], Some(&[9])),
            symbol(40, &[5], None),
        ];

        let duplicates = find_duplicates(&artifact);
        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.duplicated_bytes, duplicates.exact[0].duplicated_bytes);
        assert_eq!(
            sizes.duplicated_bytes_normalized,
            Some(duplicates.normalized[0].duplicated_bytes)
        );
        assert_eq!(
            sizes.upper_bound_savings_bytes,
            Some(sizes.duplicated_bytes),
            "the upper bound stays built from byte-identical duplication alone"
        );
        assert!(
            sizes
                .assumptions
                .iter()
                .any(|line| line == "duplicated_bytes counts byte-identical groups only"),
            "{:?}",
            sizes.assumptions
        );
    }

    /// Without a normalizer the total is absent rather than zero, and says so.
    #[test]
    fn normalized_duplication_is_unavailable_rather_than_zero_without_a_normalizer() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Elf, b"input");
        artifact.observed_bytes = 100;
        artifact.symbols = vec![
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[3, 4], Some(&[9])),
        ];

        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.duplicated_bytes_normalized, None);
        assert!(
            sizes.assumptions.iter().any(|line| line
                == "duplicated_bytes_normalized needs a normalizer for this architecture"),
            "{:?}",
            sizes.assumptions
        );
    }

    #[test]
    fn normalized_groups_are_unavailable_without_a_supported_normalizer() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Elf, b"input");
        artifact.symbols = vec![
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[3, 4], Some(&[9])),
        ];

        let duplicates = find_duplicates(&artifact);

        assert!(duplicates.exact.is_empty());
        assert!(duplicates.normalized.is_empty());
    }

    #[test]
    fn size_categories_separate_observed_data_and_unavailable_estimates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input bytes");
        artifact.capabilities.independent_data_segments = true;
        artifact.symbols = vec![symbol(10, &[1, 2, 3], None), symbol(20, &[1, 2, 3], None)];
        let bytes = vec![7; 16];
        artifact.data_segments = vec![
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"one"),
                section: None,
                offset: 100,
                bytes: bytes.clone(),
            },
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"two"),
                section: None,
                offset: 200,
                bytes,
            },
        ];
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.observed_bytes, 11);
        assert_eq!(sizes.duplicated_bytes, 3);
        assert_eq!(sizes.duplicated_data_bytes, Some(16));
        assert_eq!(sizes.upper_bound_savings_bytes, Some(3));
        assert!(sizes.estimated_refactor_savings_bytes.is_none());
        assert!(sizes.verified_savings_bytes.is_none());
        assert_eq!(sizes.clone_confidence, EvidenceConfidence::High);
        assert_eq!(sizes.savings_confidence, EvidenceConfidence::Unavailable);
        assert!(sizes.duplicated_bytes >= sizes.upper_bound_savings_bytes.unwrap_or(u64::MAX));
    }

    proptest! {
        #[test]
        fn size_categories_keep_exact_duplicate_bounds_for_disjoint_regions(
            lengths in prop::collection::vec(16_usize..128, 0..24),
        ) {
            let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"");
            artifact.capabilities.independent_data_segments = true;
            let mut offset = 0_u64;
            for (index, length) in lengths.iter().copied().enumerate() {
                let bytes = vec![u8::try_from(index).unwrap_or(u8::MAX); length];
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes: bytes.clone(),
                });
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes,
                });
                offset += length as u64;
            }
            artifact.observed_bytes = offset;
            let sizes = classify_sizes(&artifact);
            prop_assert!(sizes.duplicated_bytes <= sizes.observed_bytes);
            prop_assert!(sizes.duplicated_bytes_normalized.is_none_or(|value| value <= sizes.observed_bytes));
            prop_assert!(sizes.duplicated_data_bytes.is_some_and(|value| value <= sizes.observed_bytes));
            prop_assert_eq!(
                sizes.upper_bound_savings_bytes,
                Some(sizes.duplicated_bytes)
            );
            prop_assert!(
                sizes.estimated_refactor_savings_bytes.is_none()
                    && sizes.verified_savings_bytes.is_none()
            );
        }
    }

    #[test]
    fn unresolved_dispatch_downgrades_unreachable_symbols_to_candidates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let live = symbol(2, &[2], None);
        let dead = symbol(3, &[3], None);
        artifact.symbols = vec![entry.clone(), live.clone(), dead.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![crate::ArtifactCall {
            caller: entry.fingerprint,
            target: Some(live.fingerprint),
            unresolved: None,
        }];
        let report = dead_code_candidates(&artifact).unwrap();
        assert!(report.definitive);
        assert_eq!(report.symbols, vec![dead.fingerprint]);
        artifact.calls.push(crate::ArtifactCall {
            caller: live.fingerprint,
            target: None,
            unresolved: Some(crate::UnresolvedCall::IndirectTable),
        });
        assert!(!dead_code_candidates(&artifact).unwrap().definitive);
    }

    /// An unreachable function with a byte-identical exported twin is one node
    /// in a graph keyed by content, so it disappears into that twin. The answer
    /// stays a candidate list and says which identity question it could not
    /// answer.
    #[test]
    fn shared_symbol_identities_downgrade_reachability_to_candidates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let exported = symbol(1, &[1], None);
        let mut twin = exported.clone();
        twin.offset = 8;
        artifact.symbols = vec![exported, twin];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;

        let report = dead_code_candidates(&artifact).unwrap();

        assert!(!report.definitive);
        assert!(
            report
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("share one content fingerprint")),
            "{:?}",
            report.assumptions
        );
        assert!(
            !report
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("all recorded call edges were resolved")),
            "{:?}",
            report.assumptions
        );
    }

    /// A call endpoint that is none of the artifact's symbols leaves the local
    /// graph incomplete, and an incomplete graph proves nothing unreachable.
    #[test]
    fn a_call_endpoint_without_a_symbol_downgrades_reachability_to_candidates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let absent = symbol(99, &[9], None);
        artifact.symbols = vec![entry.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![crate::ArtifactCall {
            caller: entry.fingerprint,
            target: Some(absent.fingerprint),
            unresolved: None,
        }];

        let report = dead_code_candidates(&artifact).unwrap();

        assert!(!report.definitive);
        assert!(
            report
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("matches no symbol")),
            "{:?}",
            report.assumptions
        );
    }

    /// Without a call graph there is no reachability answer to qualify, so
    /// repeated member identities produce no report at all.
    #[test]
    fn repeated_identities_without_a_call_graph_report_no_reachability() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Archive, b"input");
        let member = symbol(1, &[1], None);
        artifact.symbols = vec![member.clone(), member];
        artifact.symbols[0].exported = true;

        assert!(dead_code_candidates(&artifact).is_none());
    }

    #[test]
    fn retained_size_uses_dominator_regions_without_summing_their_overlap() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let middle = symbol(2, &[2, 2], None);
        let leaf = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![entry.clone(), middle.clone(), leaf.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: entry.fingerprint,
                target: Some(middle.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: middle.fingerprint,
                target: Some(leaf.fingerprint),
                unresolved: None,
            },
        ];
        let retained = retained_sizes(&artifact).unwrap();
        let value = |fingerprint| {
            retained
                .iter()
                .find(|item| item.symbol == fingerprint)
                .unwrap()
                .retained_bytes
        };
        assert_eq!(value(entry.fingerprint), 6);
        assert_eq!(value(middle.fingerprint), 5);
        assert_eq!(value(leaf.fingerprint), 3);
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.retained_bytes, Some(6));
        assert_eq!(sizes.shared_dependency_bytes, Some(0));
        artifact.calls[1].unresolved = Some(crate::UnresolvedCall::IndirectTable);
        assert!(retained_sizes(&artifact).is_none());
    }

    #[test]
    fn path_compression_handles_a_deep_ancestor_chain_iteratively() {
        let nodes = 100_000_usize;
        let mut ancestors = (0..nodes)
            .map(|node| node.checked_sub(1))
            .collect::<Vec<_>>();
        let mut labels = (0..nodes).collect::<Vec<_>>();
        let semi = (0..nodes).collect::<Vec<_>>();

        lt_compress(nodes - 1, &mut ancestors, &mut labels, &semi);

        assert!(ancestors[0].is_none());
        assert_eq!(ancestors[1], Some(0));
        assert!(ancestors[2..].iter().all(|ancestor| *ancestor == Some(0)));
        assert!(labels[1..].iter().all(|label| *label == 1));
    }

    #[test]
    fn retained_size_converges_for_a_cycle() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let left = symbol(2, &[2, 2], None);
        let right = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![entry.clone(), left.clone(), right.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: entry.fingerprint,
                target: Some(left.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: left.fingerprint,
                target: Some(right.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: right.fingerprint,
                target: Some(left.fingerprint),
                unresolved: None,
            },
        ];
        let retained = retained_sizes(&artifact).unwrap();
        let value = |fingerprint| {
            retained
                .iter()
                .find(|item| item.symbol == fingerprint)
                .unwrap()
                .retained_bytes
        };
        assert_eq!(value(entry.fingerprint), 6);
        assert_eq!(value(left.fingerprint), 5);
        assert_eq!(value(right.fingerprint), 3);
    }

    #[test]
    fn retained_size_handles_a_deep_call_chain_without_quadratic_state() {
        const DEPTH: usize = 10_000;
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = (0..DEPTH)
            .map(|offset| symbol(u64::try_from(offset).unwrap(), &[1], None))
            .collect();
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = artifact
            .symbols
            .windows(2)
            .map(|pair| crate::ArtifactCall {
                caller: pair[0].fingerprint,
                target: Some(pair[1].fingerprint),
                unresolved: None,
            })
            .collect();

        let retained = retained_sizes(&artifact).unwrap();
        assert_eq!(retained.len(), DEPTH);
        let value = |fingerprint| {
            retained
                .iter()
                .find(|item| item.symbol == fingerprint)
                .unwrap()
                .retained_bytes
        };
        assert_eq!(
            value(artifact.symbols[0].fingerprint),
            u64::try_from(DEPTH).unwrap()
        );
        assert_eq!(value(artifact.symbols[DEPTH - 1].fingerprint), 1);
    }

    #[test]
    fn size_categories_keep_shared_dependencies_separate() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let left_root = symbol(1, &[1], None);
        let right_root = symbol(2, &[2, 2], None);
        let shared = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![left_root.clone(), right_root.clone(), shared.clone()];
        artifact.symbols[0].exported = true;
        artifact.symbols[1].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: left_root.fingerprint,
                target: Some(shared.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: right_root.fingerprint,
                target: Some(shared.fingerprint),
                unresolved: None,
            },
        ];
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.retained_bytes, Some(6));
        assert_eq!(sizes.shared_dependency_bytes, Some(3));
    }

    #[test]
    fn excessive_root_count_makes_shared_dependency_sizes_unavailable() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = (0..=MAX_SHARED_DEPENDENCY_ROOTS)
            .map(|offset| symbol(u64::try_from(offset).unwrap(), &[1], None))
            .collect();
        artifact
            .symbols
            .iter_mut()
            .for_each(|symbol| symbol.exported = true);
        artifact.capabilities.call_graph = true;

        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.retained_bytes, None);
        assert_eq!(sizes.shared_dependency_bytes, None);
        assert!(retained_sizes(&artifact).is_none());
    }
}
