//! One artifact's local call graph and every value derived by walking it.
//!
//! Dead code, retained sizes and shared-dependency bytes are three questions
//! about one graph and one soundness verdict, so they are answered here rather
//! than by three walks that could disagree about the same artifact.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::duplicates::{DuplicateGroup, DuplicateReport};
use super::{EvidenceConfidence, SizeClassification};
use crate::ownership::{
    GLOBAL_KEY, OwnDeclaration, Ownership, is_main_spelling, is_static_initializer_spelling,
    owner_of, strips_platform_underscore,
};
use crate::{ArtifactFingerprint, ArtifactFormat, ArtifactIr, UnresolvedCall};

/// Maximum independent root closures considered for shared-dependency bytes.
///
/// Above this limit the value is unavailable rather than reporting a number
/// that describes a whole export table instead of a shared dependency. The
/// limit withdraws that one value: retained sizes are a single traversal from
/// the joined root set and do not depend on how many roots there are.
const MAX_SHARED_DEPENDENCY_ROOTS: usize = 1024;

/// Stated with every holdings answer, because absorption moves code that is
/// not named as toolchain code into the held totals.
const ABSORPTION_ASSUMPTION: &str = "unqualified functions reached only through toolchain code are counted as toolchain code, except main and static initializers";

/// Stated when indirect dispatch is bounded by the recorded references.
const RECORDED_ROOTS_ASSUMPTION: &str = "toolchain holders treat every recorded function reference as a root, so code reached through a function table is reported as shared";

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

/// Toolchain code attributed to the non-toolchain functions that hold it.
///
/// Held bytes lie inside the holder's dominator region, so they are retained
/// bytes, never a guaranteed reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainHoldings {
    /// Holders with at least one held symbol, by held bytes descending.
    pub holdings: Vec<ToolchainHolding>,
    /// Toolchain entries no single non-toolchain function dominates.
    pub shared: Vec<SharedToolchain>,
    /// Bytes of every shared toolchain symbol.
    pub shared_bytes: u64,
    /// Number of shared toolchain symbols.
    pub shared_symbols: usize,
    /// Part of `shared_bytes` counted as toolchain only by absorption.
    pub shared_absorbed_bytes: u64,
    /// Part of `shared_symbols` counted as toolchain only by absorption.
    pub shared_absorbed_symbols: usize,
    /// How the attribution was made.
    pub assumptions: Vec<String>,
}

/// Toolchain code whose nearest non-toolchain dominator is one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainHolding {
    /// The non-toolchain function holding the code.
    pub holder: ArtifactFingerprint,
    /// Bytes of the held toolchain symbols.
    pub held_bytes: u64,
    /// Number of held toolchain symbols.
    pub held_symbols: usize,
    /// Part of `held_bytes` counted as toolchain only by absorption.
    pub absorbed_bytes: u64,
    /// Part of `held_symbols` counted as toolchain only by absorption.
    pub absorbed_symbols: usize,
    /// Toolchain entries the holder immediately dominates, by held bytes
    /// descending.
    pub heads: Vec<HeldHead>,
}

/// One toolchain entry directly below a holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldHead {
    /// The entry symbol.
    pub symbol: ArtifactFingerprint,
    /// Bytes of the held symbols entered through it.
    pub held_bytes: u64,
}

/// One toolchain entry dominated only by the joined root set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedToolchain {
    /// The entry symbol.
    pub head: ArtifactFingerprint,
    /// Bytes of the shared symbols entered through it.
    pub held_bytes: u64,
    /// Whether the entry is itself a root.
    pub root: bool,
    /// Reachable symbols calling the entry directly, ascending.
    pub callers: Vec<ArtifactFingerprint>,
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

/// Immediate dominators of the reachable symbols below a virtual root.
struct DominatorTree {
    /// Reachable symbols; vertex `index + 1` is `symbols[index]` and vertex 0
    /// is the virtual root.
    symbols: Vec<ArtifactFingerprint>,
    /// Vertices in DFS preorder, starting with the virtual root.
    dfs_vertices: Vec<usize>,
    /// Immediate dominator of each DFS position, as a DFS position. A
    /// dominator always precedes the positions it dominates.
    immediate: Vec<Option<usize>>,
}

impl DominatorTree {
    /// The symbol at DFS position `position`, which must not be the root.
    fn symbol_at(&self, position: usize) -> ArtifactFingerprint {
        self.symbols[self.dfs_vertices[position] - 1]
    }
}

/// Toolchain symbols attributed to one holder or to the shared set.
#[derive(Default)]
struct HeldTally {
    bytes: u64,
    symbols: usize,
    absorbed_bytes: u64,
    absorbed_symbols: usize,
    /// Held bytes per head DFS position.
    heads: BTreeMap<usize, u64>,
}

impl HeldTally {
    fn add(&mut self, head: usize, bytes: u64, absorbed: bool) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.symbols += 1;
        if absorbed {
            self.absorbed_bytes = self.absorbed_bytes.saturating_add(bytes);
            self.absorbed_symbols += 1;
        }
        let entry = self.heads.entry(head).or_default();
        *entry = entry.saturating_add(bytes);
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
        let tree = self.dominator_tree()?;
        let mut retained = tree
            .dfs_vertices
            .iter()
            .map(|vertex| {
                if *vertex == 0 {
                    0
                } else {
                    self.sizes[&tree.symbols[*vertex - 1]]
                }
            })
            .collect::<Vec<_>>();
        for node in (1..retained.len()).rev() {
            if let Some(parent) = tree.immediate[node] {
                retained[parent] = retained[parent].saturating_add(retained[node]);
            }
        }
        let mut result: Vec<_> = (1..tree.dfs_vertices.len())
            .map(|position| RetainedSize {
                symbol: tree.symbol_at(position),
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

    /// Attribute toolchain code to the non-toolchain functions holding it.
    ///
    /// A symbol is toolchain code when its name says so, or when it is an
    /// unqualified function other than an entry or static-initializer spelling
    /// whose immediate dominator is toolchain code. Its holder is the nearest
    /// non-toolchain immediate dominator; with none below the virtual root it
    /// is shared. Available exactly when [`Self::retained_sizes`] is.
    #[must_use]
    pub fn toolchain_holdings(&self) -> Option<ToolchainHoldings> {
        let tree = self.dominator_tree()?;
        // Identities are unique whenever the tree exists.
        let names: BTreeMap<_, _> = self
            .artifact
            .symbols
            .iter()
            .map(|symbol| (symbol.fingerprint, symbol.name.as_deref()))
            .collect();
        let strip = strips_platform_underscore(self.artifact);
        let own = OwnDeclaration::default();
        let count = tree.dfs_vertices.len();
        let mut toolchain = vec![false; count];
        let mut holder = vec![None; count];
        let mut head = vec![0; count];
        let mut holders: BTreeMap<usize, HeldTally> = BTreeMap::new();
        let mut shared = HeldTally::default();
        // Preorder visits every immediate dominator before what it dominates.
        for position in 1..count {
            let symbol = tree.symbol_at(position);
            let name = names.get(&symbol).copied().flatten();
            let parent = tree.immediate[position].unwrap_or(0);
            let owner = owner_of(name, strip, &own);
            let named_toolchain = owner.ownership == Ownership::Toolchain;
            let absorbed = !named_toolchain
                && parent != 0
                && toolchain[parent]
                && owner.key == GLOBAL_KEY
                && name.is_some_and(|name| !is_entry_spelling(name, strip));
            if !named_toolchain && !absorbed {
                holder[position] = Some(position);
                continue;
            }
            toolchain[position] = true;
            holder[position] = if parent == 0 { None } else { holder[parent] };
            head[position] = if parent == 0 || !toolchain[parent] {
                position
            } else {
                head[parent]
            };
            let bytes = self.sizes.get(&symbol).copied().unwrap_or_default();
            match holder[position] {
                Some(holding) => {
                    holders
                        .entry(holding)
                        .or_default()
                        .add(head[position], bytes, absorbed);
                }
                None => shared.add(head[position], bytes, absorbed),
            }
        }

        let mut holdings: Vec<_> = holders
            .into_iter()
            .map(|(position, tally)| ToolchainHolding {
                holder: tree.symbol_at(position),
                held_bytes: tally.bytes,
                held_symbols: tally.symbols,
                absorbed_bytes: tally.absorbed_bytes,
                absorbed_symbols: tally.absorbed_symbols,
                heads: sorted_by_bytes(
                    tally
                        .heads
                        .into_iter()
                        .map(|(head, held_bytes)| HeldHead {
                            symbol: tree.symbol_at(head),
                            held_bytes,
                        })
                        .collect(),
                    |head| (head.held_bytes, head.symbol),
                ),
            })
            .collect();
        holdings = sorted_by_bytes(holdings, |holding| (holding.held_bytes, holding.holder));

        let mut assumptions = vec![ABSORPTION_ASSUMPTION.to_owned()];
        if self
            .observations
            .contains(&GraphObservation::DispatchThroughRecordedRoots)
        {
            assumptions.push(RECORDED_ROOTS_ASSUMPTION.to_owned());
        }
        Some(ToolchainHoldings {
            holdings,
            shared: self.shared_toolchain(&tree, &shared.heads),
            shared_bytes: shared.bytes,
            shared_symbols: shared.symbols,
            shared_absorbed_bytes: shared.absorbed_bytes,
            shared_absorbed_symbols: shared.absorbed_symbols,
            assumptions,
        })
    }

    /// Shared toolchain entries from held bytes per head DFS position.
    fn shared_toolchain(
        &self,
        tree: &DominatorTree,
        heads: &BTreeMap<usize, u64>,
    ) -> Vec<SharedToolchain> {
        let mut callers: BTreeMap<ArtifactFingerprint, BTreeSet<ArtifactFingerprint>> =
            BTreeMap::new();
        for (caller, targets) in &self.successors {
            if self.reachable.contains(caller) {
                // A recursive call does not reach the entry from outside.
                for target in targets.iter().filter(|target| *target != caller) {
                    callers.entry(*target).or_default().insert(*caller);
                }
            }
        }
        sorted_by_bytes(
            heads
                .iter()
                .map(|(head, held_bytes)| {
                    let symbol = tree.symbol_at(*head);
                    SharedToolchain {
                        head: symbol,
                        held_bytes: *held_bytes,
                        root: self.roots.contains(&symbol),
                        callers: callers
                            .remove(&symbol)
                            .map(|callers| callers.into_iter().collect())
                            .unwrap_or_default(),
                    }
                })
                .collect(),
            |entry| (entry.held_bytes, entry.head),
        )
    }

    /// Immediate dominators of every reachable symbol, or `None` when the
    /// graph cannot carry reachability-derived sizes.
    ///
    /// The tree is derived with Lengauer--Tarjan below a virtual root that
    /// joins the parser-established roots.
    fn dominator_tree(&self) -> Option<DominatorTree> {
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
        Some(DominatorTree {
            symbols,
            dfs_vertices,
            immediate,
        })
    }
}

/// Whether `name` is an entry or static-initializer spelling, judged after
/// the platform underscore is removed.
fn is_entry_spelling(name: &str, strip_platform_underscore: bool) -> bool {
    let name = if strip_platform_underscore {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    };
    is_main_spelling(name) || is_static_initializer_spelling(name)
}

/// `items` ordered by bytes descending, then fingerprint ascending.
fn sorted_by_bytes<T>(mut items: Vec<T>, key: impl Fn(&T) -> (u64, ArtifactFingerprint)) -> Vec<T> {
    items.sort_by(|left, right| {
        let (left_bytes, left_symbol) = key(left);
        let (right_bytes, right_symbol) = key(right);
        right_bytes
            .cmp(&left_bytes)
            .then_with(|| left_symbol.cmp(&right_symbol))
    });
    items
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
        assert!(dead.symbols.is_empty(), "symbols: {:?}", dead.symbols);
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

    /// A named code symbol of `size` bytes at `offset`.
    fn named(offset: u64, size: usize, name: Option<&str>) -> crate::ArtifactSymbol {
        let mut named = symbol(offset, &vec![0; size], None);
        named.name = name.map(str::to_owned);
        named
    }

    fn call(caller: &crate::ArtifactSymbol, target: &crate::ArtifactSymbol) -> crate::ArtifactCall {
        crate::ArtifactCall {
            caller: caller.fingerprint,
            target: Some(target.fingerprint),
            unresolved: None,
        }
    }

    /// A WASM artifact over `symbols` with the first one exported.
    fn graph_of(symbols: &[&crate::ArtifactSymbol], calls: Vec<crate::ArtifactCall>) -> ArtifactIr {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.symbols = symbols.iter().map(|symbol| (*symbol).clone()).collect();
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = calls;
        artifact
    }

    fn holdings_of(artifact: &ArtifactIr) -> ToolchainHoldings {
        CallGraph::from_ir(artifact).toolchain_holdings().unwrap()
    }

    #[test]
    fn a_toolchain_chain_is_held_by_its_nearest_non_toolchain_dominator() {
        let parse = named(1, 1, Some("my::parse"));
        let strtof = named(2, 2, Some("strtof"));
        let addtf3 = named(3, 4, Some("__addtf3"));
        let artifact = graph_of(
            &[&parse, &strtof, &addtf3],
            vec![call(&parse, &strtof), call(&strtof, &addtf3)],
        );

        let holdings = holdings_of(&artifact);

        assert_eq!(
            holdings.holdings,
            vec![ToolchainHolding {
                holder: parse.fingerprint,
                held_bytes: 6,
                held_symbols: 2,
                absorbed_bytes: 0,
                absorbed_symbols: 0,
                heads: vec![HeldHead {
                    symbol: strtof.fingerprint,
                    held_bytes: 6,
                }],
            }]
        );
        assert!(holdings.shared.is_empty(), "{:?}", holdings.shared);
        assert_eq!(holdings.shared_bytes, 0);
        assert_eq!(
            holdings.assumptions,
            vec![
                "unqualified functions reached only through toolchain code are counted as toolchain code, except main and static initializers"
                    .to_owned()
            ]
        );
    }

    /// A function without a name may be the real holder, so the search stops
    /// there instead of passing through it.
    #[test]
    fn an_unnamed_function_stops_the_search_for_a_holder() {
        let entry = named(1, 1, Some("my::entry"));
        let strtof = named(2, 2, Some("strtof"));
        let unnamed = named(3, 3, None);
        let addtf3 = named(4, 4, Some("__addtf3"));
        let artifact = graph_of(
            &[&entry, &strtof, &unnamed, &addtf3],
            vec![
                call(&entry, &strtof),
                call(&strtof, &unnamed),
                call(&unnamed, &addtf3),
            ],
        );

        let holdings = holdings_of(&artifact);

        let holders: Vec<_> = holdings
            .holdings
            .iter()
            .map(|holding| (holding.holder, holding.held_bytes, holding.held_symbols))
            .collect();
        assert_eq!(
            holders,
            vec![(unnamed.fingerprint, 4, 1), (entry.fingerprint, 2, 1)]
        );
    }

    #[test]
    fn toolchain_code_reached_from_two_callers_is_shared_with_both_callers() {
        let left = named(1, 1, Some("my::left"));
        let right = named(2, 1, Some("my::right"));
        let strtof = named(3, 2, Some("strtof"));
        let scanexp = named(4, 3, Some("scanexp"));
        let mut artifact = graph_of(
            &[&left, &right, &strtof, &scanexp],
            vec![
                call(&left, &strtof),
                call(&right, &strtof),
                call(&strtof, &scanexp),
            ],
        );
        artifact.symbols[1].exported = true;

        let holdings = holdings_of(&artifact);

        assert!(holdings.holdings.is_empty(), "{:?}", holdings.holdings);
        let mut callers = vec![left.fingerprint, right.fingerprint];
        callers.sort();
        assert_eq!(
            holdings.shared,
            vec![SharedToolchain {
                head: strtof.fingerprint,
                held_bytes: 5,
                root: false,
                callers,
            }]
        );
        assert_eq!(holdings.shared_bytes, 5);
        assert_eq!(holdings.shared_symbols, 2);
        assert_eq!(holdings.shared_absorbed_bytes, 3);
        assert_eq!(holdings.shared_absorbed_symbols, 1);
    }

    #[test]
    fn an_exported_toolchain_function_is_a_shared_root() {
        let strtof = named(1, 2, Some("strtof"));
        let addtf3 = named(2, 4, Some("__addtf3"));
        let artifact = graph_of(&[&strtof, &addtf3], vec![call(&strtof, &addtf3)]);

        let holdings = holdings_of(&artifact);

        assert!(holdings.holdings.is_empty(), "{:?}", holdings.holdings);
        assert_eq!(
            holdings.shared,
            vec![SharedToolchain {
                head: strtof.fingerprint,
                held_bytes: 6,
                root: true,
                callers: Vec::new(),
            }]
        );
        assert_eq!((holdings.shared_bytes, holdings.shared_symbols), (6, 2));
    }

    /// A recursive call is not a caller from outside the entry.
    #[test]
    fn a_self_recursive_shared_head_is_not_its_own_caller() {
        let left = named(1, 1, Some("my::left"));
        let right = named(2, 1, Some("my::right"));
        let strtof = named(3, 2, Some("strtof"));
        let mut artifact = graph_of(
            &[&left, &right, &strtof],
            vec![
                call(&left, &strtof),
                call(&right, &strtof),
                call(&strtof, &strtof),
            ],
        );
        artifact.symbols[1].exported = true;

        let holdings = holdings_of(&artifact);

        let mut callers = vec![left.fingerprint, right.fingerprint];
        callers.sort();
        assert_eq!(holdings.shared.len(), 1);
        assert_eq!(holdings.shared[0].head, strtof.fingerprint);
        assert_eq!(holdings.shared[0].callers, callers);
    }

    /// A qualified function is never absorbed, so it holds what it dominates
    /// even when toolchain code calls it.
    #[test]
    fn a_named_function_between_toolchain_calls_holds_what_it_dominates() {
        let entry = named(1, 1, Some("my::entry"));
        let qsort = named(2, 2, Some("qsort"));
        let compare = named(3, 3, Some("my::compare"));
        let memcmp = named(4, 4, Some("memcmp"));
        let artifact = graph_of(
            &[&entry, &qsort, &compare, &memcmp],
            vec![
                call(&entry, &qsort),
                call(&qsort, &compare),
                call(&compare, &memcmp),
            ],
        );

        let holdings = holdings_of(&artifact);

        let holders: Vec<_> = holdings
            .holdings
            .iter()
            .map(|holding| (holding.holder, holding.held_bytes, holding.absorbed_symbols))
            .collect();
        assert_eq!(
            holders,
            vec![(compare.fingerprint, 4, 0), (entry.fingerprint, 2, 0)]
        );
    }

    /// Entry and static-initializer spellings are always called from runtime
    /// code, so absorbing them would hide every program's own entry.
    #[test]
    fn entry_and_static_initializer_spellings_are_never_absorbed() {
        for spelling in [
            "main",
            "__original_main",
            "__main_argc_argv",
            "_GLOBAL__I_a",
        ] {
            let start = named(1, 1, Some("_start"));
            let entry = named(2, 2, Some(spelling));
            let printf = named(3, 3, Some("iprintf"));
            let artifact = graph_of(
                &[&start, &entry, &printf],
                vec![call(&start, &entry), call(&entry, &printf)],
            );

            let holdings = holdings_of(&artifact);

            assert_eq!(
                holdings.holdings,
                vec![ToolchainHolding {
                    holder: entry.fingerprint,
                    held_bytes: 3,
                    held_symbols: 1,
                    absorbed_bytes: 0,
                    absorbed_symbols: 0,
                    heads: vec![HeldHead {
                        symbol: printf.fingerprint,
                        held_bytes: 3,
                    }],
                }],
                "{spelling}"
            );
            assert_eq!(holdings.shared_bytes, 1, "{spelling}");
        }
    }

    #[test]
    fn a_holder_without_toolchain_code_is_omitted() {
        let entry = named(1, 1, Some("my::entry"));
        let helper = named(2, 2, Some("helper"));
        let artifact = graph_of(&[&entry, &helper], vec![call(&entry, &helper)]);

        let holdings = holdings_of(&artifact);

        assert!(holdings.holdings.is_empty(), "{:?}", holdings.holdings);
        assert!(holdings.shared.is_empty(), "{:?}", holdings.shared);
    }

    #[test]
    fn recorded_function_references_add_the_shared_root_note() {
        let entry = named(1, 1, Some("my::entry"));
        let dispatched = named(2, 2, Some("strtof"));
        let mut artifact = graph_of(&[&entry, &dispatched], Vec::new());
        artifact.indirect_references = vec![dispatched.fingerprint];
        artifact.calls = vec![crate::ArtifactCall {
            caller: entry.fingerprint,
            target: None,
            unresolved: Some(UnresolvedCall::IndirectTable),
        }];

        let holdings = holdings_of(&artifact);

        assert_eq!(
            holdings.assumptions,
            vec![
                "unqualified functions reached only through toolchain code are counted as toolchain code, except main and static initializers"
                    .to_owned(),
                "toolchain holders treat every recorded function reference as a root, so code reached through a function table is reported as shared"
                    .to_owned(),
            ]
        );
        assert_eq!(holdings.shared.len(), 1);
        assert!(holdings.shared[0].root);
    }

    #[test]
    fn toolchain_holdings_are_unavailable_exactly_when_retained_sizes_are() {
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
                let entry = named(1, 1, Some("my::entry"));
                artifact.symbols = vec![entry.clone(), named(2, 2, Some("strtof"))];
                artifact.symbols[0].exported = true;
                artifact.capabilities.call_graph = true;
                artifact.calls = vec![crate::ArtifactCall {
                    caller: entry.fingerprint,
                    target: None,
                    unresolved: reason,
                }];
                let graph = CallGraph::from_ir(&artifact);

                assert_eq!(
                    graph.toolchain_holdings().is_some(),
                    graph.retained_sizes().is_some(),
                    "{format} {reason:?}"
                );
            }
        }
        let mut artifact = graph_of(&[&named(1, 1, Some("strtof"))], Vec::new());
        artifact.capabilities.call_graph = false;
        assert!(CallGraph::from_ir(&artifact).toolchain_holdings().is_none());
    }

    /// The bytes a parsed module records flow through to the holder: an
    /// unqualified libc static reached only through `strtof` is absorbed, and
    /// the compiler-rt call under it stays with the same holder and head.
    #[test]
    fn a_parsed_wasm_toolchain_chain_is_held_by_its_caller() {
        use crate::ArtifactBackend;
        let mut module = vec![0, 97, 115, 109, 1, 0, 0, 0];
        module.extend([1, 4, 1, 0x60, 0, 0]);
        module.extend([3, 5, 4, 0, 0, 0, 0]);
        module.extend([7, 9, 1, 5, b'p', b'a', b'r', b's', b'e', 0, 0]);
        module.extend([
            10, 19, 4, 4, 0, 0x10, 1, 0x0b, 4, 0, 0x10, 2, 0x0b, 4, 0, 0x10, 3, 0x0b, 2, 0, 0x0b,
        ]);
        let mut names = vec![4, 0, 5];
        names.extend(b"parse");
        names.extend([1, 6]);
        names.extend(b"strtof");
        names.extend([2, 6]);
        names.extend(b"strtox");
        names.extend([3, 8]);
        names.extend(b"__addtf3");
        let mut custom = vec![4];
        custom.extend(b"name");
        custom.extend([1, u8::try_from(names.len()).unwrap()]);
        custom.extend(names);
        module.extend([0, u8::try_from(custom.len()).unwrap()]);
        module.extend(custom);
        let artifact = crate::wasm::WasmBackend.parse(&module).unwrap();
        let by_name = |name: &str| {
            artifact
                .symbols
                .iter()
                .find(|symbol| symbol.name.as_deref() == Some(name))
                .unwrap()
        };
        let size = |name: &str| by_name(name).size;
        let held = size("strtof") + size("strtox") + size("__addtf3");

        let holdings = holdings_of(&artifact);

        assert_eq!(
            holdings.holdings,
            vec![ToolchainHolding {
                holder: by_name("parse").fingerprint,
                held_bytes: held,
                held_symbols: 3,
                absorbed_bytes: size("strtox"),
                absorbed_symbols: 1,
                heads: vec![HeldHead {
                    symbol: by_name("strtof").fingerprint,
                    held_bytes: held,
                }],
            }]
        );
        assert_eq!(holdings.shared_bytes, 0);
        assert!(holdings.shared.is_empty(), "{:?}", holdings.shared);
    }

    /// Deterministic linear congruential generator, so a failure replays.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % bound
        }
    }

    /// Holdings recomputed from set-based dominance: `Dom(v)` is iterated to
    /// a fixpoint over the reachable predecessors, and holder, head and
    /// absorption are read off the immediate-dominator chain.
    #[allow(clippy::too_many_lines)] // One self-contained reference computation.
    fn holdings_from_dominator_sets(artifact: &ArtifactIr) -> ToolchainHoldings {
        use crate::ownership::{
            GLOBAL_KEY, OwnDeclaration, Ownership, is_main_spelling,
            is_static_initializer_spelling, owner_of,
        };
        let count = artifact.symbols.len() + 1;
        let mut successors = vec![Vec::new(); count];
        for (position, symbol) in artifact.symbols.iter().enumerate() {
            if symbol.exported {
                successors[0].push(position + 1);
            }
        }
        let position_of = |fingerprint: ArtifactFingerprint| {
            artifact
                .symbols
                .iter()
                .position(|symbol| symbol.fingerprint == fingerprint)
                .unwrap()
                + 1
        };
        for call in &artifact.calls {
            successors[position_of(call.caller)].push(position_of(call.target.unwrap()));
        }
        let mut reachable = vec![false; count];
        reachable[0] = true;
        let mut pending = vec![0];
        while let Some(vertex) = pending.pop() {
            for target in &successors[vertex] {
                if !reachable[*target] {
                    reachable[*target] = true;
                    pending.push(*target);
                }
            }
        }
        let mut predecessors = vec![BTreeSet::new(); count];
        for (vertex, targets) in successors.iter().enumerate() {
            if reachable[vertex] {
                for target in targets {
                    predecessors[*target].insert(vertex);
                }
            }
        }
        let live: Vec<_> = (0..count).filter(|vertex| reachable[*vertex]).collect();
        let every: BTreeSet<_> = live.iter().copied().collect();
        let mut dominators = vec![every; count];
        dominators[0] = BTreeSet::from([0]);
        let mut changed = true;
        while changed {
            changed = false;
            for vertex in live.iter().copied().skip(1) {
                let mut next = predecessors[vertex]
                    .iter()
                    .map(|predecessor| dominators[*predecessor].clone())
                    .reduce(|left, right| &left & &right)
                    .unwrap();
                next.insert(vertex);
                if next != dominators[vertex] {
                    dominators[vertex] = next;
                    changed = true;
                }
            }
        }
        let immediate = |vertex: usize| {
            dominators[vertex]
                .iter()
                .copied()
                .filter(|dominator| *dominator != vertex)
                .max_by_key(|dominator| dominators[*dominator].len())
                .unwrap()
        };
        let mut by_depth: Vec<_> = live.iter().copied().skip(1).collect();
        by_depth.sort_by_key(|vertex| dominators[*vertex].len());
        let mut toolchain = vec![false; count];
        let mut absorbed = vec![false; count];
        for vertex in by_depth.iter().copied() {
            let name = artifact.symbols[vertex - 1].name.as_deref();
            let owner = owner_of(name, false, &OwnDeclaration::default());
            let parent = immediate(vertex);
            if owner.ownership == Ownership::Toolchain {
                toolchain[vertex] = true;
            } else if owner.key == GLOBAL_KEY
                && name.is_some_and(|name| {
                    !is_main_spelling(name) && !is_static_initializer_spelling(name)
                })
                && parent != 0
                && toolchain[parent]
            {
                toolchain[vertex] = true;
                absorbed[vertex] = true;
            }
        }
        let fingerprint = |vertex: usize| artifact.symbols[vertex - 1].fingerprint;
        let size = |vertex: usize| artifact.symbols[vertex - 1].size;
        let mut holdings: BTreeMap<usize, ToolchainHolding> = BTreeMap::new();
        let mut shared: BTreeMap<usize, u64> = BTreeMap::new();
        let mut result = ToolchainHoldings {
            holdings: Vec::new(),
            shared: Vec::new(),
            shared_bytes: 0,
            shared_symbols: 0,
            shared_absorbed_bytes: 0,
            shared_absorbed_symbols: 0,
            assumptions: vec![
                "unqualified functions reached only through toolchain code are counted as toolchain code, except main and static initializers"
                    .to_owned(),
            ],
        };
        for vertex in by_depth.iter().copied().filter(|vertex| toolchain[*vertex]) {
            let mut head = vertex;
            while immediate(head) != 0 && toolchain[immediate(head)] {
                head = immediate(head);
            }
            let holder = immediate(head);
            if holder == 0 {
                *shared.entry(head).or_default() += size(vertex);
                result.shared_bytes += size(vertex);
                result.shared_symbols += 1;
                if absorbed[vertex] {
                    result.shared_absorbed_bytes += size(vertex);
                    result.shared_absorbed_symbols += 1;
                }
                continue;
            }
            let holding = holdings.entry(holder).or_insert_with(|| ToolchainHolding {
                holder: fingerprint(holder),
                held_bytes: 0,
                held_symbols: 0,
                absorbed_bytes: 0,
                absorbed_symbols: 0,
                heads: Vec::new(),
            });
            holding.held_bytes += size(vertex);
            holding.held_symbols += 1;
            if absorbed[vertex] {
                holding.absorbed_bytes += size(vertex);
                holding.absorbed_symbols += 1;
            }
            match holding
                .heads
                .iter_mut()
                .find(|entry| entry.symbol == fingerprint(head))
            {
                Some(entry) => entry.held_bytes += size(vertex),
                None => holding.heads.push(HeldHead {
                    symbol: fingerprint(head),
                    held_bytes: size(vertex),
                }),
            }
        }
        result.holdings = holdings.into_values().collect();
        for holding in &mut result.holdings {
            holding.heads.sort_by(|left, right| {
                (right.held_bytes, left.symbol).cmp(&(left.held_bytes, right.symbol))
            });
        }
        result.holdings.sort_by(|left, right| {
            (right.held_bytes, left.holder).cmp(&(left.held_bytes, right.holder))
        });
        result.shared = shared
            .into_iter()
            .map(|(head, held_bytes)| {
                let mut callers: Vec<_> = live
                    .iter()
                    .copied()
                    .skip(1)
                    .filter(|caller| *caller != head && successors[*caller].contains(&head))
                    .map(fingerprint)
                    .collect();
                callers.sort();
                callers.dedup();
                SharedToolchain {
                    head: fingerprint(head),
                    held_bytes,
                    root: artifact.symbols[head - 1].exported,
                    callers,
                }
            })
            .collect();
        result.shared.sort_by(|left, right| {
            (right.held_bytes, left.head).cmp(&(left.held_bytes, right.head))
        });
        result
    }

    #[test]
    fn holders_match_set_based_dominance_on_random_graphs() {
        const GRAPHS: usize = 200;
        let labels: [&[Option<&str>]; 5] = [
            &[Some("strtof"), Some("__addtf3"), Some("memcpy")],
            &[Some("scanexp"), Some("helper")],
            &[Some("main"), Some("__original_main"), Some("_GLOBAL__I_a")],
            &[Some("my::parse"), Some("my::Widget::draw")],
            &[None],
        ];
        let mut random = Lcg(0x5eed_c0de);
        let mut label_uses = [0usize; 5];
        let mut absorbed = 0;
        for graph in 0..GRAPHS {
            let nodes = 1 + random.below(12);
            let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
            artifact.capabilities.call_graph = true;
            for offset in 0..nodes {
                let label = usize::try_from(random.below(5)).unwrap();
                label_uses[label] += 1;
                let spellings = labels[label];
                let spelling =
                    spellings[usize::try_from(random.below(spellings.len() as u64)).unwrap()];
                let size = usize::try_from(1 + random.below(4)).unwrap();
                let mut symbol = named(offset, size, spelling);
                symbol.exported = offset == 0 || random.below(4) == 0;
                artifact.symbols.push(symbol);
            }
            for caller in 0..artifact.symbols.len() {
                for target in 0..artifact.symbols.len() {
                    if random.below(4) == 0 {
                        artifact
                            .calls
                            .push(call(&artifact.symbols[caller], &artifact.symbols[target]));
                    }
                }
            }

            let actual = CallGraph::from_ir(&artifact)
                .toolchain_holdings()
                .unwrap_or_else(|| panic!("graph {graph} has no holdings"));

            assert_eq!(
                actual,
                holdings_from_dominator_sets(&artifact),
                "graph {graph}"
            );
            for holding in &actual.holdings {
                let heads: u64 = holding.heads.iter().map(|head| head.held_bytes).sum();
                assert_eq!(holding.held_bytes, heads, "graph {graph}");
                assert!(holding.held_symbols > 0, "graph {graph}");
            }
            let shared: u64 = actual.shared.iter().map(|head| head.held_bytes).sum();
            assert_eq!(actual.shared_bytes, shared, "graph {graph}");
            absorbed += actual.shared_absorbed_symbols
                + actual
                    .holdings
                    .iter()
                    .map(|holding| holding.absorbed_symbols)
                    .sum::<usize>();
        }
        assert!(label_uses.iter().all(|uses| *uses > 0), "{label_uses:?}");
        assert!(absorbed > 0);
    }
}
