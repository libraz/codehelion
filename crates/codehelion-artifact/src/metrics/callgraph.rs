//! One artifact's local call graph and every value derived by walking it.
//!
//! Dead code, retained sizes and shared-dependency bytes are three questions
//! about one graph and one soundness verdict, so they are answered here rather
//! than by three walks that could disagree about the same artifact.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::duplicates::{DuplicateGroup, DuplicateReport};
use super::{EvidenceConfidence, SizeClassification};
use crate::{ArtifactFingerprint, ArtifactFormat, ArtifactIr, UnresolvedCall};

/// Maximum independent root closures considered for shared-dependency bytes.
///
/// Above this limit the value is unavailable rather than reporting a number
/// that describes a whole export table instead of a shared dependency. The
/// limit withdraws that one value: retained sizes are a single traversal from
/// the joined root set and do not depend on how many roots there are.
const MAX_SHARED_DEPENDENCY_ROOTS: usize = 1024;

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

/// Find symbols not reachable from parser-established exports.
///
/// A dispatch this parser did not follow to a local symbol changes the result
/// from a definitive dead-code finding into a candidate list, whether it may
/// reach anything defined here ([`LocalDispatch::PossiblyLocal`]) or only the
/// functions the artifact made referenceable
/// ([`LocalDispatch::ThroughRecordedRoots`]). A call proved to leave the
/// artifact does not. No exports means no trustworthy root set and therefore
/// returns no finding.
///
/// Reachability is followed over content-derived identities, so two symbols
/// built from the same bytes are one node in that graph: an unreachable copy
/// is then absorbed by an exported twin and drops out of the result. A call
/// whose endpoint matches no symbol leaves the same graph incomplete. Either
/// condition keeps the answer a candidate list and names itself among the
/// assumptions, because neither is visible in the symbol list it returns.
#[must_use]
pub fn dead_code_candidates(artifact: &ArtifactIr) -> Option<DeadCodeReport> {
    CallGraph::from_ir(artifact).dead_code_candidates()
}

/// Calculate retained code sizes from a complete, unambiguous local call graph.
///
/// The returned regions overlap (a dominator retains its descendants too), so
/// callers must never add them together as a total saving. Ambiguous duplicate
/// fingerprints and dispatches that may reach a local symbol are refused
/// rather than guessed.
#[must_use]
pub fn retained_sizes(artifact: &ArtifactIr) -> Option<Vec<RetainedSize>> {
    CallGraph::from_ir(artifact).retained_sizes()
}

/// Whether one unresolved call could still denote a symbol defined here.
///
/// This is the crate's single classification of [`UnresolvedCall`]. Every
/// value that needs a sound local call graph -- dead code, retained sizes,
/// shared dependency bytes -- reads it, so a reason is classified once instead
/// of once per consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDispatch {
    /// The callee is defined outside this artifact. The local call graph is
    /// missing no edge, so this is a resolved non-edge rather than a gap.
    ProvablyExternal,
    /// The callee is one of the functions recorded in
    /// [`ArtifactIr::indirect_references`], and those are already reachability
    /// roots. Reachability stays exact while nothing is proved unreachable.
    ThroughRecordedRoots,
    /// The callee may be any symbol defined here, so the local call graph is
    /// missing an edge and cannot carry a derived size or a dead-code proof.
    PossiblyLocal,
}

/// Classify one unresolved call recorded by a `format` backend.
///
/// The container decides as much as the reason does.
/// [`UnresolvedCall::ExternalImport`] is provably external in WebAssembly,
/// where the callee index is below the imported-function count and re-entry
/// runs through exports and table elements that are roots already. The native
/// backends record the same reason for a relocation whose local symbol they
/// failed to collect, so there it leaves the graph incomplete.
#[must_use]
pub const fn local_dispatch(format: ArtifactFormat, unresolved: UnresolvedCall) -> LocalDispatch {
    match unresolved {
        UnresolvedCall::IndirectTable => LocalDispatch::ThroughRecordedRoots,
        UnresolvedCall::NativeIndirect | UnresolvedCall::MissingRelocation => {
            LocalDispatch::PossiblyLocal
        }
        UnresolvedCall::ExternalImport => match format {
            ArtifactFormat::Wasm => LocalDispatch::ProvablyExternal,
            // An archive flattens members of any native format, so it inherits
            // the native reading of this reason.
            ArtifactFormat::Elf
            | ArtifactFormat::MachO
            | ArtifactFormat::PeCoff
            | ArtifactFormat::Archive => LocalDispatch::PossiblyLocal,
        },
    }
}

/// What one walk of a local call graph could not establish.
///
/// Consumers differ in what they tolerate: dispatch bounded by recorded
/// reference roots still yields exact reachability bytes, but it is not a
/// proof that a symbol is dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphObservation {
    /// A dispatch that may reach a symbol defined here was not followed.
    UnfollowedDispatch,
    /// A dispatch is bounded only by the recorded function references, which
    /// enter the walk as roots rather than as edges.
    DispatchThroughRecordedRoots,
    /// Two symbols share one content fingerprint.
    AmbiguousIdentity,
    /// A recorded call endpoint matches no symbol.
    EndpointWithoutSymbol,
}

impl GraphObservation {
    /// Why this observation keeps a reachability answer a candidate list.
    const fn dead_code_reason(self) -> &'static str {
        match self {
            Self::UnfollowedDispatch => {
                "unresolved dispatch prevents proving unreachable symbols are dead"
            }
            Self::DispatchThroughRecordedRoots => {
                "indirect dispatch is bounded by treating every recorded function reference as a root, which does not prove an unreached symbol is dead"
            }
            Self::AmbiguousIdentity => {
                "two symbols share one content fingerprint, so reachability cannot separate them"
            }
            Self::EndpointWithoutSymbol => {
                "a recorded call endpoint matches no symbol, so the local call graph is incomplete"
            }
        }
    }

    /// Why this observation withdraws reachability-derived sizes, if it does.
    ///
    /// Reachability bounded by recorded roots is an over-approximation of the
    /// live set, which is exactly what these sizes are defined over, so it
    /// qualifies the values instead of withdrawing them.
    const fn withdrawn_size_reason(self) -> Option<&'static str> {
        match self {
            Self::UnfollowedDispatch => Some(
                "retained and shared dependency sizes need every dispatch that may reach a local symbol to be resolved",
            ),
            Self::DispatchThroughRecordedRoots => None,
            Self::AmbiguousIdentity => {
                Some("retained and shared dependency sizes need one symbol per content fingerprint")
            }
            Self::EndpointWithoutSymbol => Some(
                "retained and shared dependency sizes need every call endpoint to match a symbol",
            ),
        }
    }
}

/// One artifact's local call graph, established once for every derived value.
///
/// Dead code, retained sizes and shared-dependency bytes are three questions
/// about one graph and one soundness verdict. Answering the soundness question
/// separately per value is how two surfaces come to disagree about the same
/// artifact, so the sizes, roots, successors, reachable set and observations
/// are established here and every value reads them.
pub struct CallGraph<'a> {
    artifact: &'a ArtifactIr,
    sizes: BTreeMap<ArtifactFingerprint, u64>,
    roots: BTreeSet<ArtifactFingerprint>,
    successors: BTreeMap<ArtifactFingerprint, Vec<ArtifactFingerprint>>,
    reachable: BTreeSet<ArtifactFingerprint>,
    observations: Vec<GraphObservation>,
}

impl<'a> CallGraph<'a> {
    /// Walk `artifact` once, recording the graph and what it could not settle.
    #[must_use]
    pub fn from_ir(artifact: &'a ArtifactIr) -> Self {
        let mut sizes = BTreeMap::new();
        let mut ambiguous_identity = false;
        for symbol in &artifact.symbols {
            if sizes.insert(symbol.fingerprint, symbol.size).is_some() {
                ambiguous_identity = true;
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
        let mut successors: BTreeMap<_, Vec<_>> = sizes
            .keys()
            .copied()
            .map(|symbol| (symbol, Vec::new()))
            .collect();
        let mut unfollowed_dispatch = false;
        let mut dispatch_through_recorded_roots = false;
        let mut endpoint_without_symbol = false;
        for call in &artifact.calls {
            if !sizes.contains_key(&call.caller) {
                endpoint_without_symbol = true;
            }
            if let Some(target) = call.target {
                if !sizes.contains_key(&target) {
                    endpoint_without_symbol = true;
                }
                successors.entry(call.caller).or_default().push(target);
            }
            match call
                .unresolved
                .map(|reason| local_dispatch(artifact.format, reason))
            {
                Some(LocalDispatch::ProvablyExternal) => {}
                Some(LocalDispatch::ThroughRecordedRoots) => dispatch_through_recorded_roots = true,
                Some(LocalDispatch::PossiblyLocal) => unfollowed_dispatch = true,
                // A call that names neither a target nor a reason dropped an
                // edge. Reading that silence as resolution is what turns an
                // incomplete graph into a confident one.
                None => unfollowed_dispatch |= call.target.is_none(),
            }
        }
        for targets in successors.values_mut() {
            targets.sort_unstable();
            targets.dedup();
        }
        let mut observations = Vec::new();
        if unfollowed_dispatch {
            observations.push(GraphObservation::UnfollowedDispatch);
        }
        if dispatch_through_recorded_roots {
            observations.push(GraphObservation::DispatchThroughRecordedRoots);
        }
        if ambiguous_identity {
            observations.push(GraphObservation::AmbiguousIdentity);
        }
        if endpoint_without_symbol {
            observations.push(GraphObservation::EndpointWithoutSymbol);
        }
        let reachable = reachable_from(roots.clone(), &successors);
        Self {
            artifact,
            sizes,
            roots,
            successors,
            reachable,
            observations,
        }
    }

    /// Find symbols not reachable from parser-established roots.
    ///
    /// See [`dead_code_candidates`] for what the answer means.
    #[must_use]
    pub fn dead_code_candidates(&self) -> Option<DeadCodeReport> {
        if !self.artifact.capabilities.call_graph || self.roots.is_empty() {
            return None;
        }
        let mut symbols: Vec<_> = self
            .artifact
            .symbols
            .iter()
            .map(|symbol| symbol.fingerprint)
            .filter(|fingerprint| !self.reachable.contains(fingerprint))
            .collect();
        symbols.sort();
        symbols.dedup();
        let mut assumptions: Vec<String> = self
            .observations
            .iter()
            .map(|observation| observation.dead_code_reason().to_owned())
            .collect();
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

    /// Why reachability-derived sizes are unavailable, naming each condition.
    ///
    /// An empty answer means the walked graph carries them. Every line names a
    /// condition that actually held for this artifact, so a report never
    /// explains an absent value with a condition that did not fire.
    ///
    /// The same lines reach [`SizeClassification::assumptions`] when the sizes
    /// are withdrawn. A caller that needs to know whether sizes were withdrawn,
    /// and why, asks here rather than recognising those sentences in the
    /// assumption list.
    #[must_use]
    pub fn size_unavailability(&self) -> Vec<String> {
        if !self.artifact.capabilities.call_graph {
            return vec![
                "retained and shared dependency sizes need a backend that establishes call edges"
                    .to_owned(),
            ];
        }
        let mut reasons: Vec<String> = self
            .observations
            .iter()
            .filter_map(|observation| observation.withdrawn_size_reason())
            .map(str::to_owned)
            .collect();
        if self.roots.is_empty() {
            reasons
                .push("retained and shared dependency sizes need one established root".to_owned());
        } else if !self.roots.iter().all(|root| self.sizes.contains_key(root)) {
            reasons.push(
                "retained and shared dependency sizes need every root to match a symbol".to_owned(),
            );
        }
        reasons
    }

    /// Bytes reachable from more than one root, in one walk of the graph.
    ///
    /// Each symbol carries the identity of the single root that reached it or
    /// a mark that several did, and a symbol changes state at most twice. Its
    /// successors are therefore revisited a bounded number of times and the
    /// total work stays proportional to the graph rather than to the root
    /// count multiplied by the graph.
    fn shared_dependency_bytes(&self) -> u64 {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Reached {
            One(usize),
            Several,
        }
        let mut state: BTreeMap<ArtifactFingerprint, Reached> = BTreeMap::new();
        let mut pending: Vec<_> = self
            .roots
            .iter()
            .enumerate()
            .map(|(position, root)| (*root, Reached::One(position)))
            .collect();
        while let Some((symbol, mark)) = pending.pop() {
            let next = match (state.get(&symbol).copied(), mark) {
                (None, mark) => mark,
                (Some(Reached::Several), _) => continue,
                (Some(Reached::One(seen)), Reached::One(arriving)) if seen == arriving => continue,
                (Some(Reached::One(_)), _) => Reached::Several,
            };
            state.insert(symbol, next);
            if let Some(targets) = self.successors.get(&symbol) {
                pending.extend(targets.iter().map(|target| (*target, next)));
            }
        }
        state
            .into_iter()
            .filter(|(_, reached)| *reached == Reached::Several)
            .map(|(symbol, _)| self.sizes.get(&symbol).copied().unwrap_or_default())
            .sum()
    }

    /// Derive size categories from duplicate groups and this graph.
    ///
    /// See [`super::classify_sizes_from_duplicates`] for the category
    /// definitions.
    #[must_use]
    pub fn classify_sizes_from_duplicates(
        &self,
        duplicates: &DuplicateReport,
        duplicate_data: &[DuplicateGroup],
    ) -> SizeClassification {
        let artifact = self.artifact;
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
            assumptions.push(
                "duplicated_data_bytes needs independently established data regions".to_owned(),
            );
        }
        let unavailable = self.size_unavailability();
        let (retained_bytes, shared_dependency_bytes) = if unavailable.is_empty() {
            let retained_bytes = self
                .reachable
                .iter()
                .map(|symbol| self.sizes.get(symbol).copied().unwrap_or_default())
                .sum();
            if self
                .observations
                .contains(&GraphObservation::DispatchThroughRecordedRoots)
            {
                assumptions.push(
                    "retained and shared dependency sizes treat every recorded function reference as a root"
                        .to_owned(),
                );
            }
            let shared_dependency_bytes = if self.roots.len() > MAX_SHARED_DEPENDENCY_ROOTS {
                assumptions.push(format!(
                    "shared_dependency_bytes needs at most {MAX_SHARED_DEPENDENCY_ROOTS} roots and this artifact has {}",
                    self.roots.len()
                ));
                None
            } else {
                Some(self.shared_dependency_bytes())
            };
            (Some(retained_bytes), shared_dependency_bytes)
        } else {
            assumptions.extend(unavailable);
            (None, None)
        };
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

    /// Calculate retained code sizes from this graph.
    ///
    /// The immediate-dominator tree is derived with Lengauer--Tarjan. A virtual
    /// root joins parser-established roots, so a symbol shared by two entry
    /// points is not incorrectly retained by either one. The algorithm stores a
    /// constant amount of state per reachable symbol rather than a reachability
    /// set per symbol. The root budget that guards shared-dependency bytes does
    /// not apply: this is one traversal from the joined root set.
    #[must_use]
    pub fn retained_sizes(&self) -> Option<Vec<RetainedSize>> {
        if !self.size_unavailability().is_empty() {
            return None;
        }
        let graph = self;
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

/// Reachability from `reachable` over `successors`, visiting each edge once.
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::metrics::classify_sizes;
    use crate::metrics::tests::symbol;

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
            unresolved: Some(UnresolvedCall::IndirectTable),
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

    /// One classification of an unresolved reason answers the soundness
    /// question for every derived value. A reason that withdraws the
    /// reachability sizes must also stop the dead-code verdict from calling
    /// itself a proof; the converse is deliberately weaker, because dispatch
    /// bounded by recorded roots still yields exact bytes over those roots.
    ///
    /// A call carrying neither a target nor a reason is the shape a third
    /// party's backend can produce, and reading that silence as a resolved
    /// edge is what let one function answer "proved" while the other answered
    /// "unusable" about the same graph.
    #[test]
    fn withdrawn_sizes_and_a_dead_code_proof_never_disagree() {
        let reasons = [
            None,
            Some(UnresolvedCall::IndirectTable),
            Some(UnresolvedCall::ExternalImport),
            Some(UnresolvedCall::NativeIndirect),
            Some(UnresolvedCall::MissingRelocation),
        ];
        for format in [ArtifactFormat::Wasm, ArtifactFormat::Elf] {
            for reason in reasons {
                let mut artifact = ArtifactIr::empty(format, b"input");
                let entry = symbol(1, &[1], None);
                artifact.symbols = vec![entry.clone(), symbol(2, &[2, 2], None)];
                artifact.symbols[0].exported = true;
                artifact.capabilities.call_graph = true;
                artifact.calls = vec![crate::ArtifactCall {
                    caller: entry.fingerprint,
                    target: None,
                    unresolved: reason,
                }];

                let report = dead_code_candidates(&artifact).unwrap();
                let sizes = classify_sizes(&artifact);

                assert_eq!(
                    sizes.retained_bytes.is_none(),
                    retained_sizes(&artifact).is_none(),
                    "{format} {reason:?}"
                );
                if sizes.retained_bytes.is_none() {
                    assert!(!report.definitive, "{format} {reason:?} {report:?}");
                }
                if reason.is_none() {
                    assert!(!report.definitive, "{format} {report:?}");
                    assert_eq!(sizes.retained_bytes, None, "{format}");
                }
            }
        }
    }

    /// Reachability is one traversal whose fixpoint does not depend on the
    /// order edges happen to appear in.
    #[test]
    fn reachability_does_not_depend_on_the_order_call_edges_appear_in() {
        const DEPTH: usize = 5_000;
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = (0..DEPTH)
            .map(|offset| symbol(u64::try_from(offset).unwrap(), &[1], None))
            .collect();
        let unreached = symbol(u64::try_from(DEPTH).unwrap(), &[2, 2], None);
        artifact.symbols.push(unreached.clone());
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = artifact.symbols[..DEPTH]
            .windows(2)
            .map(|pair| crate::ArtifactCall {
                caller: pair[0].fingerprint,
                target: Some(pair[1].fingerprint),
                unresolved: None,
            })
            .collect();

        let forward = dead_code_candidates(&artifact).unwrap();
        artifact.calls.reverse();
        let reversed = dead_code_candidates(&artifact).unwrap();

        assert_eq!(forward.symbols, vec![unreached.fingerprint]);
        assert_eq!(forward.symbols, reversed.symbols);
        assert!(forward.definitive && reversed.definitive);
    }

    /// Shared-dependency bytes are one walk of the graph, not one walk per
    /// root, so an artifact whose export table fills the budget still finishes
    /// well inside the worker deadline that guards the whole report.
    #[test]
    fn shared_dependency_bytes_stay_within_the_worker_deadline_at_the_root_budget() {
        const SYMBOLS: u64 = 60_000;
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = (0..SYMBOLS)
            .map(|offset| symbol(offset, &[1], None))
            .collect();
        for symbol in artifact
            .symbols
            .iter_mut()
            .take(MAX_SHARED_DEPENDENCY_ROOTS)
        {
            symbol.exported = true;
        }
        artifact.capabilities.call_graph = true;
        // Every root reaches the same tail, which is the shape that made the
        // per-root traversal quadratic.
        artifact.calls = (0..SYMBOLS - 1)
            .map(|offset| crate::ArtifactCall {
                caller: artifact.symbols[usize::try_from(offset).unwrap()].fingerprint,
                target: Some(artifact.symbols[usize::try_from(offset).unwrap() + 1].fingerprint),
                unresolved: None,
            })
            .collect();

        let started = std::time::Instant::now();
        let sizes = classify_sizes(&artifact);
        let elapsed = started.elapsed();

        assert_eq!(sizes.retained_bytes, Some(SYMBOLS));
        // Every symbol but the first root is reached from at least two roots.
        assert_eq!(sizes.shared_dependency_bytes, Some(SYMBOLS - 1));
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "shared dependency bytes took {elapsed:?}"
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
        artifact.calls[1].unresolved = Some(UnresolvedCall::MissingRelocation);
        assert!(retained_sizes(&artifact).is_none());
    }

    /// Dispatch bounded by recorded function references keeps the reachability
    /// bytes, because those references are already roots of the same walk. It
    /// does say so, and it still refuses to call an unreached symbol dead.
    #[test]
    fn table_bounded_dispatch_keeps_retained_sizes_and_names_the_approximation() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let dispatched = symbol(2, &[2, 2], None);
        artifact.symbols = vec![entry.clone(), dispatched.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.indirect_references = vec![dispatched.fingerprint];
        artifact.calls = vec![crate::ArtifactCall {
            caller: entry.fingerprint,
            target: None,
            unresolved: Some(UnresolvedCall::IndirectTable),
        }];

        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.retained_bytes, Some(3));
        assert_eq!(sizes.shared_dependency_bytes, Some(0));
        assert!(
            sizes.assumptions.iter().any(|assumption| assumption
                .contains("treat every recorded function reference as a root")),
            "{:?}",
            sizes.assumptions
        );
        assert!(retained_sizes(&artifact).is_some());
        let dead = dead_code_candidates(&artifact).unwrap();
        assert!(!dead.definitive);
        assert!(dead.symbols.is_empty());
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

    fn artifact_with_more_roots_than_the_budget() -> ArtifactIr {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = (0..=MAX_SHARED_DEPENDENCY_ROOTS)
            .map(|offset| symbol(u64::try_from(offset).unwrap(), &[1], None))
            .collect();
        artifact
            .symbols
            .iter_mut()
            .for_each(|symbol| symbol.exported = true);
        artifact.capabilities.call_graph = true;
        artifact
    }

    #[test]
    fn excessive_root_count_makes_shared_dependency_sizes_unavailable() {
        let artifact = artifact_with_more_roots_than_the_budget();

        let sizes = classify_sizes(&artifact);

        assert_eq!(sizes.shared_dependency_bytes, None);
        assert!(
            sizes.assumptions.iter().any(|assumption| {
                assumption.contains("shared_dependency_bytes needs at most")
                    && assumption.contains(&MAX_SHARED_DEPENDENCY_ROOTS.to_string())
                    && assumption.contains(&(MAX_SHARED_DEPENDENCY_ROOTS + 1).to_string())
            }),
            "{:?}",
            sizes.assumptions
        );
    }

    /// The root budget guards one value. Retained sizes are a single traversal
    /// from the joined root set, so a large export table does not withdraw
    /// them, and no assumption may claim the call graph was the problem.
    #[test]
    fn excessive_root_count_leaves_retained_sizes_available() {
        let artifact = artifact_with_more_roots_than_the_budget();

        let sizes = classify_sizes(&artifact);

        assert_eq!(
            sizes.retained_bytes,
            Some(u64::try_from(MAX_SHARED_DEPENDENCY_ROOTS).unwrap() + 1)
        );
        assert_eq!(
            retained_sizes(&artifact).map(|retained| retained.len()),
            Some(MAX_SHARED_DEPENDENCY_ROOTS + 1)
        );
        assert!(
            !sizes
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("retained and shared dependency sizes need")),
            "{:?}",
            sizes.assumptions
        );
    }
}
