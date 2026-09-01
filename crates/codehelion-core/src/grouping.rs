//! Structural-mode clone grouping: turning verified pairs into cohesive groups.
//!
//! Type-3 similarity is *not* transitive: A resembles B and B resembles C does
//! not make A resemble C. Feeding verified pairs straight into a union-find and
//! emitting the connected components would therefore fuse a chain of drifting
//! near-clones into one incoherent group (AGENTS.md §2-9). Union-find is used
//! here for one thing only — carving the pair graph into independent components
//! so the expensive per-group work is bounded — and its components are never
//! output as groups. Every component is then refined:
//!
//! 1. a **medoid** (canonical instance) is chosen as the member with the
//!    greatest total similarity to the rest, ties broken by the smallest stable
//!    key so the choice is deterministic;
//! 2. the **medoid constraint** ejects any member too far from the medoid; the
//!    ejected members are regrouped among themselves rather than dropped;
//! 3. **complete-linkage** refinement then removes members until the weakest
//!    pair inside the group clears the cohesion floor, so every pair in a
//!    reported group — not merely every member-to-medoid edge — is similar.
//!
//! Refinement is quadratic in component size, so a component past
//! [`GroupingConfig::max_component`] is cut into pieces first and each piece
//! refined on its own. That costs recall and never soundness — the rules that
//! make a group cohesive are unchanged — and the count of components it fired
//! on is reported rather than left to be inferred from the timing.
//!
//! A pair that verification never proposed has no edge here; its similarity is
//! taken as zero, which is what makes the complete-linkage floor split a chain
//! whose ends were never compared. Singletons are not clone groups. The whole
//! module is a pure, deterministic function of its inputs: components,
//! candidate medoids under sampling, and every output collection are ordered by
//! stable key, never by discovery order.
//!
//! # What this asks of the stages above
//!
//! Reading an absent edge as a similarity of zero is the same as saying the two
//! were weighed and found apart. That holds while the stages above are complete
//! *per set*: a family they decline to propose at all is a family nothing here
//! claims anything about, and a family they propose is one every pair of which
//! they proposed. It stops holding the moment a ceiling leaves a family half
//! proposed — then a set of copies arrives looking like a set that disagrees,
//! refinement breaks it up, and the comparisons that did survive are carried
//! out one at a time as pairs no group holds both halves of. One duplication
//! comes back as many, and the report grows as the allowance shrinks.
//!
//! So a ceiling upstream of here has to cut between sets and never inside one.
//! Two have been found doing otherwise — the candidate-pair budget, which used
//! to stop in the middle of a posting list, and this module's own
//! [`GroupingConfig::max_component`], which cuts a component it cannot refine
//! whole. The first was changed to stop between posting lists; the second
//! cannot be, since cutting is the whole point of it, so it reports which
//! members it put apart ([`GroupingSet::severed_by_the_ceiling`]) and the
//! caller counts those relations rather than stating them.
//!
//! A ceiling that drops a whole set is fine and needs none of this: the
//! high-frequency posting cap drops entire lists, and lowering it onto the
//! labelled corpora only ever costs findings, never multiplies them. The
//! distinction is not how much a ceiling removes but whether what it leaves is
//! a set that was compared with itself.

use std::collections::{BTreeMap, BTreeSet};

use crate::clone_class::CloneClass;
use crate::verify::Confidence;

/// Version of the rules that decide which occurrences sit in one group.
///
/// Recorded beside every run so a later one can say whether two results were
/// grouped alike. Raising it does not move a member's content id — the same
/// code still hashes the same — but it can move a group's, because a group
/// fingerprint folds in the set of contents its members hold.
///
/// It stays at v1 until the first release tag, along with every other version
/// this build records. A second number would only describe an audit database
/// somebody still has on disk, and re-running the scan is the whole of the
/// recovery; changing medoid selection, the cohesion floors or the refinement
/// order therefore leaves this constant alone.
pub const GROUPING_VERSION: &str = "grouping-v1";

/// Tuning for grouping. Similarities are in `[0, 1]`; the defaults are
/// provisional and calibrated against the chain corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupingConfig {
    /// Smallest similarity a member may have to the medoid and stay in the
    /// group; members below it are ejected and regrouped.
    pub medoid_min_similarity: f64,
    /// Complete-linkage floor: the smallest similarity any pair inside a
    /// reported group may have. Below it the group is split.
    pub min_pairwise_similarity: f64,
    /// Component size above which medoid selection samples candidates rather
    /// than scoring every member, to avoid quadratic blow-up on huge
    /// components. The sample is deterministic and key-diverse, so repeated
    /// content cannot occupy every medoid candidate.
    pub sampling_threshold: usize,
    /// Number of candidate medoids scored when a component exceeds
    /// [`Self::sampling_threshold`].
    pub sample_size: usize,
    /// Largest component refined as one piece. A component above this is cut
    /// into key-ordered pieces, each refined on its own. Content-identical
    /// units are never separated: one equivalence class can therefore exceed
    /// this limit by itself.
    ///
    /// Refinement materializes the component's pairwise similarity matrix and
    /// orders it once, so it costs O(k² log k) time and O(k²) memory. A
    /// codebase of thousands of structurally interchangeable units — generated
    /// code, or a repository built to make the scan expensive — still produces
    /// exactly that component, which is why the ceiling exists at all
    /// (AGENTS.md §2-10, §7).
    ///
    /// Cutting costs recall, never soundness: each piece is refined by the
    /// same medoid and complete-linkage rules, so every reported group is
    /// still cohesive. What is lost is the chance that two members landing in
    /// different pieces would have grouped. The cut is by stable key, so it is
    /// deterministic, and the count of components it fired on is reported.
    /// Keeping equal-key units together prevents independently cut pieces
    /// from minting the same content-derived group and finding identifiers.
    ///
    /// Which members the cut put apart is reported too, through
    /// [`GroupingSet::severed_by_the_ceiling`]. A caller that carries out the
    /// verified relations no group expresses needs it: a relation across the
    /// cut is not one refinement weighed and declined, and carrying it out
    /// would restate the set once per crossing — at the size that makes this
    /// ceiling fire, that is the whole report.
    pub max_component: usize,
}

impl Default for GroupingConfig {
    fn default() -> Self {
        Self {
            medoid_min_similarity: 0.60,
            min_pairwise_similarity: 0.60,
            sampling_threshold: 256,
            sample_size: 32,
            // Above the sampling threshold, so a component between the two is
            // still refined whole with a sampled medoid.
            max_component: 1024,
        }
    }
}

/// One verified similarity relation between two units, as produced by
/// [`crate::verify`]. Endpoints are indices into the unit slice passed to
/// [`group`]; the pair is undirected and `a != b` is required.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SimilarityEdge {
    /// One endpoint (a unit index).
    pub a: usize,
    /// The other endpoint (a unit index).
    pub b: usize,
    /// The pair's grouping similarity, in `[0, 1]` (the verdict composite).
    pub similarity: f64,
    /// Per-dimension evidence behind `similarity`, when the verifier measured
    /// it. Generic grouping clients that have only a scalar may leave this
    /// absent; Structural mode always preserves its verifier breakdown.
    pub breakdown: Option<crate::verify::SimilarityBreakdown>,
    /// The pair's clone classification.
    pub class: CloneClass,
    /// The pair's confidence.
    pub confidence: Confidence,
}

/// A unit as seen by grouping: only its stable key matters here.
///
/// The key is used for deterministic tie-breaking and ordering. It is the
/// unit's content fingerprint bytes; grouping never interprets it beyond
/// ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupingUnit {
    /// Stable, position-free key (a content fingerprint's bytes).
    pub key: [u8; 16],
}

/// A cohesive clone group: a medoid plus the members that cleared both the
/// medoid constraint and the complete-linkage floor.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralGroup {
    /// The weakest clone class among the group's internal edges (a group is no
    /// stronger than its loosest accepted pair).
    pub clone_type: CloneClass,
    /// The weakest confidence among the group's internal edges.
    pub confidence: Confidence,
    /// The medoid: the group's canonical instance (a unit index).
    pub canonical: usize,
    /// Member unit indices, the medoid first, then the rest by ascending key.
    pub members: Vec<usize>,
    /// Similarity of each member to the medoid, parallel to [`Self::members`]
    /// (the medoid's own entry is `1.0`).
    pub medoid_similarities: Vec<f64>,
    /// The weakest pairwise similarity inside the group: its cohesion, at or
    /// above [`GroupingConfig::min_pairwise_similarity`].
    pub min_pairwise: f64,
}

/// Counters describing what grouping saw and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupingStats {
    /// Units considered (the input length).
    pub units: usize,
    /// Verified edges considered.
    pub edges: usize,
    /// Initial connected components carved by union-find.
    pub components: usize,
    /// Components too large to refine as one piece, cut into pieces of
    /// [`GroupingConfig::max_component`]. Reported because the cut can leave
    /// clones of each other in separate groups.
    pub oversized_components: usize,
    /// Groups emitted after medoid and complete-linkage refinement.
    pub groups: usize,
    /// Members ejected by the medoid constraint (and regrouped elsewhere).
    pub medoid_ejections: usize,
    /// Components whose medoid candidates were sampled rather than exhaustively
    /// scored.
    pub sampled_medoids: usize,
    /// Total distinct-content medoid candidates scored in sampled components.
    pub sampled_medoid_candidates: usize,
    /// Members removed by complete-linkage splitting.
    pub linkage_splits: usize,
    /// Members left ungrouped as singletons after refinement.
    pub singletons: usize,
    /// Pairwise similarities refinement weighed, across every component and
    /// every regrouping of the members it ejected.
    ///
    /// This is what the component ceiling exists to bound. A run that spent its
    /// time here says so with a number, rather than leaving a reader to infer
    /// it from a wall clock and a count of oversized components that can
    /// legitimately be zero.
    pub refinement_comparisons: usize,
}

/// The grouping result: refined groups plus statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupingSet {
    /// Cohesive groups, ordered by their medoid's key.
    pub groups: Vec<StructuralGroup>,
    /// Which piece each unit of a cut component landed in.
    ///
    /// Empty unless [`GroupingConfig::max_component`] fired. Units of a
    /// component small enough to refine whole are absent, because nothing
    /// about them was decided by the ceiling.
    piece_of: BTreeMap<usize, u32>,
    /// What grouping saw and did.
    pub stats: GroupingStats,
}

impl GroupingSet {
    /// Whether the component ceiling is why these two were never weighed
    /// against each other.
    ///
    /// Two units in one component that the ceiling cut into pieces, and in
    /// different pieces, were never candidates for the same group — not
    /// because refinement judged them apart but because refinement never saw
    /// them together. A caller carrying out the relations no group expresses
    /// has to tell that apart from the ones a group declined to hold, which
    /// are a fact about the code rather than about a ceiling.
    #[must_use]
    pub fn severed_by_the_ceiling(&self, a: usize, b: usize) -> bool {
        match (self.piece_of.get(&a), self.piece_of.get(&b)) {
            (Some(left), Some(right)) => left != right,
            _ => false,
        }
    }
}

/// Group verified pairs into cohesive clone groups.
///
/// The result is a pure function of the inputs: neither the edge order nor the
/// unit order (beyond what the indices name) changes the groups or their order.
#[must_use]
pub fn group(
    units: &[GroupingUnit],
    edges: &[SimilarityEdge],
    config: &GroupingConfig,
) -> GroupingSet {
    let sim = SimilarityGraph::build(units.len(), edges);
    let mut stats = GroupingStats {
        units: units.len(),
        edges: edges.len(),
        ..GroupingStats::default()
    };

    let components = connected_components(units.len(), edges);
    stats.components = components.len();

    let mut groups = Vec::new();
    // Which piece a unit landed in, recorded only where the ceiling cut, so a
    // relation the cut prevented can later be told from one refinement weighed
    // and declined.
    let mut piece_of: BTreeMap<usize, u32> = BTreeMap::new();
    let mut next_piece = 0u32;
    // Where a member sits in the table of the piece being refined. One
    // allocation for the whole run: a table per piece would cost the unit count
    // once per piece, which is the shape this module is careful not to have.
    let mut position = vec![0usize; units.len()];
    for component in &components {
        let cut = component.len() > piece_limit(config);
        for piece in refinable_pieces(component, units, config, &mut stats) {
            if cut {
                for &member in &piece {
                    piece_of.insert(member, next_piece);
                }
                next_piece += 1;
            }
            let similarities = ComponentMatrix::build(&piece, &sim, &mut position, &mut stats);
            refine_component(
                &piece,
                units,
                &similarities,
                &sim,
                config,
                &mut groups,
                &mut stats,
            );
        }
    }

    // Deterministic output order: by the medoid's key, then by group content.
    groups.sort_by(|left, right| {
        units[left.canonical]
            .key
            .cmp(&units[right.canonical].key)
            .then(left.members.len().cmp(&right.members.len()))
            .then_with(|| {
                left.members
                    .iter()
                    .map(|&member| units[member].key)
                    .cmp(right.members.iter().map(|&member| units[member].key))
            })
    });
    stats.groups = groups.len();
    GroupingSet {
        groups,
        piece_of,
        stats,
    }
}

/// Where one unit sits, and which unit declares it.
///
/// Grouping is otherwise position-free — it orders by content keys and never
/// reads a line number — so the one question that needs positions, whether a
/// group is another group seen at a smaller cut, is answered from spans passed
/// in rather than from anything grouping keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberSpan {
    /// Index of the file the unit sits in.
    pub file: usize,
    /// First source byte the unit covers.
    pub start: usize,
    /// One past the last source byte the unit covers.
    pub end: usize,
    /// The unit this one is a part of: itself where the unit is a declaration
    /// — a function, a method — and the innermost declaration around it where
    /// the unit is an expression written inside one, such as a closure.
    ///
    /// This is what separates a smaller cut of a unit from a unit that merely
    /// sits inside another: a closure is the enclosing function at a smaller
    /// extent, while a function nested in a function is a declaration of its
    /// own that could be duplicated, moved or removed without the one holding
    /// it changing at all.
    pub declaration: usize,
}

/// Mark every group a longer group already accounts for, in group order.
///
/// A duplicated stretch of code is a duplicate at more than one cut: a
/// duplicated function encloses a duplicated body, which encloses each of the
/// duplicated runs it is made of, and every level of it is proposed
/// independently. Reported apart they are one consolidation opportunity taking
/// several of the report's top slots, each entry restating the one above it.
///
/// The rule is the one the run already applies to duplicated runs — a finding
/// whose every occurrence sits inside an occurrence of a longer finding is
/// that longer finding, seen smaller — extended to whole units. It is applied
/// once, to the settled groups, so which candidate stage proposed a group
/// cannot change whether it survives.
///
/// Position alone does not settle it, for three reasons that would each leave
/// the reader with less than they had:
///
/// - a group whose members are *declarations* nested inside another group's
///   members is a duplication of its own. A helper written inside two
///   duplicated functions is duplicated code somebody can lift out on its own,
///   whatever happens to the functions holding it, so nesting only accounts
///   for a group whose members are the covering units at a smaller extent
///   ([`MemberSpan::declaration`]);
/// - a cover no longer than what it covers is not a longer cut of one
///   duplication but a second statement about the same lines, and which of two
///   such findings to keep is not a question about nesting;
/// - a verbatim group nested inside one that only matches up to renaming makes
///   the stricter claim of the two, so a cover has to classify at least as
///   strictly ([`CloneClass`] runs from exact to gapped).
///
/// `spans` is indexed by unit index, as group members are. A member no span
/// covers is never accounted for by anything, so a short slice folds nothing
/// rather than folding on missing evidence.
#[must_use]
pub fn contained_groups(groups: &[StructuralGroup], spans: &[MemberSpan]) -> Vec<bool> {
    // Widest cover first, so a group is judged against the longest thing that
    // could account for it before anything shorter is considered. Only groups
    // already settled become covers, so two groups covering each other cannot
    // remove both.
    let mut widest: Vec<usize> = (0..groups.len()).collect();
    widest.sort_by_key(|&index| std::cmp::Reverse(covered_bytes(&groups[index], spans)));

    let mut folded = vec![false; groups.len()];
    let mut settled: Vec<usize> = Vec::with_capacity(groups.len());
    for &inner in &widest {
        if settled
            .iter()
            .any(|&outer| accounts_for(&groups[outer], &groups[inner], spans))
        {
            folded[inner] = true;
        } else {
            settled.push(inner);
        }
    }
    folded
}

/// Source bytes a group's members cover, summed.
fn covered_bytes(group: &StructuralGroup, spans: &[MemberSpan]) -> usize {
    group
        .members
        .iter()
        .filter_map(|&member| spans.get(member))
        .map(|span| span.end.saturating_sub(span.start))
        .sum()
}

/// Whether `outer` reports the code `inner` reports, and more of it.
///
/// `inner` is `outer` at a smaller cut when each of its members is a piece of
/// one of `outer`'s members — the unit that declares it — and no two of them
/// are pieces of the same one. So stated, the two groups are one set of units
/// described at two extents, which is one finding; a group whose members
/// declare themselves is a set of units of its own, however deeply it sits
/// inside another.
///
/// The declaration a member names and the bytes it covers are asked together:
/// a declaration index is a claim about the tree the units came from and the
/// spans are what a reader is shown, and a fold needs both to agree.
fn accounts_for(outer: &StructuralGroup, inner: &StructuralGroup, spans: &[MemberSpan]) -> bool {
    if outer.clone_type > inner.clone_type
        || covered_bytes(outer, spans) <= covered_bytes(inner, spans)
    {
        return false;
    }
    let mut claimed: BTreeSet<usize> = BTreeSet::new();
    inner.members.iter().all(|&member| {
        spans.get(member).is_some_and(|held| {
            let declaring = held.declaration;
            outer.members.contains(&declaring)
                && claimed.insert(declaring)
                && spans.get(declaring).is_some_and(|cover| {
                    cover.file == held.file && cover.start <= held.start && held.end <= cover.end
                })
        })
    })
}

/// The largest set refinement runs on as one piece.
///
/// At least two, because a ceiling of one would cut every pair apart and leave
/// nothing that could group at all.
const fn piece_limit(config: &GroupingConfig) -> usize {
    if config.max_component > 2 {
        config.max_component
    } else {
        2
    }
}

/// Symmetric similarity lookup over the verified edges. Absent pairs read as
/// zero — units verification never compared are treated as dissimilar.
struct SimilarityGraph {
    edges: BTreeMap<(usize, usize), EdgeData>,
}

#[derive(Debug, Clone, Copy)]
struct EdgeData {
    similarity: f64,
    class: CloneClass,
    confidence: Confidence,
}

impl SimilarityGraph {
    fn build(_unit_count: usize, edges: &[SimilarityEdge]) -> Self {
        let mut map = BTreeMap::new();
        for edge in edges {
            if edge.a == edge.b {
                continue;
            }
            let key = ordered(edge.a, edge.b);
            // Keep the strongest edge if a pair is listed more than once, so
            // the result never depends on input order. Similarity alone does
            // not settle that: two listings of one pair can agree on the score
            // and differ on the class or the confidence, which is the rest of
            // what a group reads off the edge it keeps.
            let data = EdgeData {
                similarity: edge.similarity,
                class: edge.class,
                confidence: edge.confidence,
            };
            map.entry(key)
                .and_modify(|existing: &mut EdgeData| {
                    if strength(&data, existing).is_gt() {
                        *existing = data;
                    }
                })
                .or_insert(data);
        }
        Self { edges: map }
    }

    fn similarity(&self, a: usize, b: usize) -> f64 {
        #[cfg(test)]
        note_graph_query();
        if a == b {
            return 1.0;
        }
        self.edges
            .get(&ordered(a, b))
            .map_or(0.0, |data| data.similarity)
    }

    fn edge(&self, a: usize, b: usize) -> Option<EdgeData> {
        if a == b {
            return None;
        }
        self.edges.get(&ordered(a, b)).copied()
    }
}

// Similarity-graph queries made on this thread. Refinement reads one pair's
// similarity many times, and how that number grows with component size is the
// whole of the cost claim this module makes. Tests read it; nothing else does.
#[cfg(test)]
thread_local! {
    static GRAPH_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_graph_query() {
    GRAPH_QUERIES.with(|queries| queries.set(queries.get() + 1));
}

/// Take and reset the query count of the current thread.
#[cfg(test)]
fn taken_graph_queries() -> usize {
    GRAPH_QUERIES.with(|queries| queries.replace(0))
}

/// The similarity of every pair inside one refinable piece, computed once.
///
/// Refinement reads a pair's similarity while choosing a medoid, again while
/// trimming to the cohesion floor, and again at every level of the regrouping
/// of the members it ejected. Asking the keyed graph each time makes each read
/// a lookup and pays for the whole level again per level, which is what turns
/// the documented O(k² log k) into a cubic cost on a component that only sheds
/// a few members at a time. The piece's own values are held in one flat table
/// instead — the O(k²) memory [`GroupingConfig::max_component`] is already
/// sized for — so every later read is an indexed one and the graph is asked
/// once per pair.
///
/// The values are the graph's own, in the graph's own order, so what refinement
/// decides is unchanged.
struct ComponentMatrix<'a> {
    /// Position of a member in this table, indexed by unit. Only the entries
    /// of this piece's own members are meaningful.
    position: &'a [usize],
    /// Members in the table, and so its stride.
    size: usize,
    /// Row-major similarities, the diagonal reading as a unit compared with
    /// itself.
    values: Vec<f64>,
}

impl<'a> ComponentMatrix<'a> {
    fn build(
        members: &[usize],
        sim: &SimilarityGraph,
        position: &'a mut [usize],
        stats: &mut GroupingStats,
    ) -> Self {
        for (index, &member) in members.iter().enumerate() {
            position[member] = index;
        }
        let size = members.len();
        let mut values = vec![0.0; size.saturating_mul(size)];
        for (row, &left) in members.iter().enumerate() {
            values[row * size + row] = 1.0;
            for (column, &right) in members.iter().enumerate().skip(row + 1) {
                let similarity = sim.similarity(left, right);
                values[row * size + column] = similarity;
                values[column * size + row] = similarity;
            }
        }
        stats.refinement_comparisons += size * size.saturating_sub(1) / 2;
        Self {
            position,
            size,
            values,
        }
    }

    /// The similarity of two members of this piece.
    fn similarity(&self, a: usize, b: usize) -> f64 {
        self.values[self.position[a] * self.size + self.position[b]]
    }
}

/// Order two judgements of one pair from the weakest claim to the strongest:
/// by similarity, then by how exact the class is, then by confidence.
///
/// [`CloneClass`] already runs from exact to gapped, so the stronger class is
/// the lesser one. [`Confidence`] is a closed vocabulary of bands rather than a
/// scale, so the order it is read in is stated here.
fn strength(left: &EdgeData, right: &EdgeData) -> std::cmp::Ordering {
    left.similarity
        .total_cmp(&right.similarity)
        .then_with(|| right.class.cmp(&left.class))
        .then_with(|| confidence_rank(right.confidence).cmp(&confidence_rank(left.confidence)))
}

/// How far a verdict sits from the threshold, ascending: a larger rank is the
/// weaker claim.
const fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

/// Normalize an undirected endpoint pair to `(min, max)`.
const fn ordered(a: usize, b: usize) -> (usize, usize) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Carve the pair graph into connected components. This is the *only* use of
/// union-find here: its components seed the per-component refinement and are
/// never emitted as groups (a chain of near-clones is one component but many
/// groups). Members are returned sorted by key-independent index; refinement
/// re-sorts by key.
fn connected_components(unit_count: usize, edges: &[SimilarityEdge]) -> Vec<Vec<usize>> {
    let mut parent: Vec<usize> = (0..unit_count).collect();
    let mut connected = BTreeSet::new();
    for edge in edges {
        if edge.a != edge.b {
            union(&mut parent, edge.a, edge.b);
            connected.insert(edge.a);
            connected.insert(edge.b);
        }
    }
    let mut buckets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for node in connected {
        let root = find(&mut parent, node);
        buckets.entry(root).or_default().push(node);
    }
    buckets.into_values().collect()
}

const fn find(parent: &mut [usize], node: usize) -> usize {
    let mut root = node;
    while parent[root] != root {
        root = parent[root];
    }
    // Path compression.
    let mut current = node;
    while parent[current] != root {
        let next = parent[current];
        parent[current] = root;
        current = next;
    }
    root
}

const fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        // Attach the larger root under the smaller for a deterministic forest.
        if ra < rb {
            parent[rb] = ra;
        } else {
            parent[ra] = rb;
        }
    }
}

/// The pieces of a component that refinement runs on: the component itself
/// when it fits under [`GroupingConfig::max_component`], otherwise key-ordered
/// pieces. An equal-key equivalence class is atomic: splitting it would create
/// separate groups with the same content-derived identity.
fn refinable_pieces(
    component: &[usize],
    units: &[GroupingUnit],
    config: &GroupingConfig,
    stats: &mut GroupingStats,
) -> Vec<Vec<usize>> {
    let limit = piece_limit(config);
    if component.len() <= limit {
        return vec![component.to_vec()];
    }
    stats.oversized_components += 1;
    let mut ordered = component.to_vec();
    ordered.sort_by_key(|&member| units[member].key);
    let mut pieces = Vec::new();
    let mut current = Vec::new();
    let mut class_start = 0;
    while class_start < ordered.len() {
        let key = units[ordered[class_start]].key;
        let class_end = ordered[class_start..]
            .iter()
            .position(|&member| units[member].key != key)
            .map_or(ordered.len(), |offset| class_start + offset);
        let class = &ordered[class_start..class_end];
        if !current.is_empty() && current.len() + class.len() > limit {
            pieces.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(class);
        // A content class larger than the ceiling is indivisible. Emit it as
        // one oversized piece rather than minting identical groups from its
        // arbitrary sub-pieces.
        if current.len() > limit {
            pieces.push(std::mem::take(&mut current));
        }
        class_start = class_end;
    }
    if !current.is_empty() {
        pieces.push(current);
    }
    pieces
}

/// Refine one component into cohesive groups, appending them to `groups`.
///
/// Terminates because each recursion runs on a strictly smaller set: a member
/// is only ejected into `rest`, and the group built from `kept` never re-enters
/// refinement.
fn refine_component(
    component: &[usize],
    units: &[GroupingUnit],
    similarities: &ComponentMatrix<'_>,
    sim: &SimilarityGraph,
    config: &GroupingConfig,
    groups: &mut Vec<StructuralGroup>,
    stats: &mut GroupingStats,
) {
    if component.len() < 2 {
        stats.singletons += component.len();
        return;
    }

    let medoid = select_medoid(component, units, similarities, config, stats);

    // Medoid constraint: keep members close enough to the medoid, eject the
    // rest for independent regrouping.
    let mut kept = Vec::new();
    let mut rest = Vec::new();
    for &member in component {
        if member == medoid
            || similarities.similarity(member, medoid) >= config.medoid_min_similarity
        {
            kept.push(member);
        } else {
            rest.push(member);
        }
    }
    stats.medoid_ejections += rest.len();
    stats.refinement_comparisons += component.len();

    // Complete-linkage: remove members until the weakest pair clears the floor.
    complete_linkage_trim(
        medoid,
        &mut kept,
        &mut rest,
        units,
        similarities,
        config,
        stats,
    );

    if let Some(built) = build_group(medoid, &kept, units, similarities, sim) {
        groups.push(built);
    } else {
        stats.singletons += kept.len();
    }

    if !rest.is_empty() {
        // Regroup the ejected members; deterministic order for recursion. The
        // piece's table already holds their similarities, so a level costs no
        // rebuilding of what the level above already weighed.
        rest.sort_by_key(|&m| units[m].key);
        refine_component(&rest, units, similarities, sim, config, groups, stats);
    }
}

/// Choose the medoid: the member with the greatest total similarity to the
/// others, ties broken by the smallest key. On components past the sampling
/// threshold, candidates are selected evenly from distinct content keys. This
/// keeps the cost bounded without allowing one repeated content to occupy the
/// whole sample.
fn select_medoid(
    component: &[usize],
    units: &[GroupingUnit],
    similarities: &ComponentMatrix<'_>,
    config: &GroupingConfig,
    stats: &mut GroupingStats,
) -> usize {
    let mut candidates: Vec<usize> = component.to_vec();
    candidates.sort_by_key(|&m| units[m].key);
    if candidates.len() > config.sampling_threshold {
        candidates.dedup_by_key(|member| units[*member].key);
        let sample_size = config.sample_size.max(1).min(candidates.len());
        if candidates.len() > sample_size {
            let last = candidates.len() - 1;
            candidates = if sample_size == 1 {
                vec![candidates[last / 2]]
            } else {
                (0..sample_size)
                    .map(|index| candidates[index * last / (sample_size - 1)])
                    .collect()
            };
        }
        stats.sampled_medoids += 1;
        stats.sampled_medoid_candidates += candidates.len();
    }

    stats.refinement_comparisons += candidates.len() * component.len().saturating_sub(1);
    let mut best = candidates[0];
    let mut best_total = total_similarity(best, component, similarities);
    for &candidate in &candidates[1..] {
        let total = total_similarity(candidate, component, similarities);
        // Greater total wins; on a tie the smaller key wins, keeping the pick
        // deterministic without an exact float comparison.
        let better = match total.total_cmp(&best_total) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => units[candidate].key < units[best].key,
            std::cmp::Ordering::Less => false,
        };
        if better {
            best = candidate;
            best_total = total;
        }
    }
    best
}

/// Sum of a member's similarity to every other member of the set.
///
/// Summed in the set's own order, over the piece's own values, so the total a
/// candidate is judged on does not depend on where the reading came from.
fn total_similarity(member: usize, set: &[usize], similarities: &ComponentMatrix<'_>) -> f64 {
    set.iter()
        .filter(|&&other| other != member)
        .map(|&other| similarities.similarity(member, other))
        .sum()
}

/// Trim `kept` until its weakest pair reaches the complete-linkage floor,
/// moving each removed member into `rest`. The medoid is never removed. The
/// removed member of the weakest pair is the non-medoid one with the lower
/// total similarity inside `kept` (ties broken by the larger key), so the
/// choice is deterministic and progress is guaranteed.
///
/// Pair similarities do not change while a component is refined.  Sort that
/// matrix once, then discard inactive endpoints as members leave the set.
/// Totals are a row cache: removing one member subtracts its row from every
/// survivor.  The old implementation re-scanned the whole matrix and then
/// re-summed two rows for every ejection, which made this O(k³).  This keeps
/// the same decision rule in O(k² log k) time and O(k²) bounded memory.
fn complete_linkage_trim(
    medoid: usize,
    kept: &mut Vec<usize>,
    rest: &mut Vec<usize>,
    units: &[GroupingUnit],
    similarities: &ComponentMatrix<'_>,
    config: &GroupingConfig,
    stats: &mut GroupingStats,
) {
    let members = kept.clone();
    stats.refinement_comparisons += members.len() * members.len().saturating_sub(1) / 2;
    let mut active = vec![true; members.len()];
    let mut totals = vec![0.0; members.len()];
    let mut pairs = Vec::with_capacity(kept.len().saturating_mul(kept.len().saturating_sub(1)) / 2);
    for (index, &left) in members.iter().enumerate() {
        for (right_index, &right) in members.iter().enumerate().skip(index + 1) {
            let similarity = similarities.similarity(left, right);
            totals[index] += similarity;
            totals[right_index] += similarity;
            pairs.push((
                similarity,
                canonical_pair(left, right, units),
                index,
                right_index,
            ));
        }
    }
    pairs.sort_by(|left, right| {
        left.0
            .total_cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
    });
    let mut next_pair = 0;

    let mut active_count = members.len();
    while active_count >= 2 {
        while pairs
            .get(next_pair)
            .is_some_and(|(_, _, left, right)| !active[*left] || !active[*right])
        {
            next_pair += 1;
        }
        let Some(&(worst_sim, _, left, right)) = pairs.get(next_pair) else {
            break;
        };
        if worst_sim >= config.min_pairwise_similarity {
            break;
        }
        let victim = if members[left] == medoid {
            right
        } else if members[right] == medoid {
            left
        } else {
            match totals[left].total_cmp(&totals[right]) {
                std::cmp::Ordering::Less => left,
                std::cmp::Ordering::Equal
                    if units[members[left]].key >= units[members[right]].key =>
                {
                    left
                }
                std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => right,
            }
        };
        active[victim] = false;
        stats.refinement_comparisons += active_count;
        for (index, &member) in members.iter().enumerate() {
            if active[index] {
                totals[index] -= similarities.similarity(member, members[victim]);
            }
        }
        active_count -= 1;
        rest.push(members[victim]);
        stats.linkage_splits += 1;
    }
    *kept = members
        .into_iter()
        .zip(active)
        .filter_map(|(member, active)| active.then_some(member))
        .collect();
}

/// An endpoint pair ordered by the units' stable keys. This is only used for
/// deterministic tie-breaking; equal keys represent interchangeable content.
fn canonical_pair(left: usize, right: usize, units: &[GroupingUnit]) -> ([u8; 16], [u8; 16]) {
    let left_key = units[left].key;
    let right_key = units[right].key;
    if left_key <= right_key {
        (left_key, right_key)
    } else {
        (right_key, left_key)
    }
}

/// Assemble a group from a medoid and its kept members, or `None` when fewer
/// than two members remain (a singleton is not a group).
fn build_group(
    medoid: usize,
    kept: &[usize],
    units: &[GroupingUnit],
    similarities: &ComponentMatrix<'_>,
    sim: &SimilarityGraph,
) -> Option<StructuralGroup> {
    if kept.len() < 2 {
        return None;
    }
    let mut ordered_members: Vec<usize> = kept.iter().copied().filter(|&m| m != medoid).collect();
    ordered_members.sort_by_key(|&m| units[m].key);
    ordered_members.insert(0, medoid);

    let medoid_similarities: Vec<f64> = ordered_members
        .iter()
        .map(|&member| similarities.similarity(medoid, member))
        .collect();

    // Weakest class, confidence and pairwise similarity across internal edges.
    let mut clone_type = CloneClass::Type1;
    let mut confidence = Confidence::High;
    let mut min_pairwise = 1.0_f64;
    for (i, &left) in ordered_members.iter().enumerate() {
        for &right in &ordered_members[i + 1..] {
            min_pairwise = min_pairwise.min(similarities.similarity(left, right));
            if let Some(data) = sim.edge(left, right) {
                clone_type = weaker_class(clone_type, data.class);
                confidence = weaker_confidence(confidence, data.confidence);
            }
        }
    }

    Some(StructuralGroup {
        clone_type,
        confidence,
        canonical: medoid,
        members: ordered_members,
        medoid_similarities,
        min_pairwise,
    })
}

/// The looser of two classes.
///
/// [`CloneClass`] orders itself from the strongest claim to the weakest —
/// verbatim, renamed, gapped, then justified only by a registered rule — so the
/// looser of two is the greater. Deferring to that order keeps this commutative
/// and idempotent, and keeps a class this function was never told about from
/// being reported as a verbatim copy.
fn weaker_class(a: CloneClass, b: CloneClass) -> CloneClass {
    a.max(b)
}

/// The lower of two confidences.
const fn weaker_confidence(a: Confidence, b: Confidence) -> Confidence {
    match (a, b) {
        (Confidence::Low, _) | (_, Confidence::Low) => Confidence::Low,
        (Confidence::Medium, _) | (_, Confidence::Medium) => Confidence::Medium,
        _ => Confidence::High,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
