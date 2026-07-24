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
//! A pair that verification never proposed has no edge here; its similarity is
//! taken as zero, which is what makes the complete-linkage floor split a chain
//! whose ends were never compared. Singletons are not clone groups. The whole
//! module is a pure, deterministic function of its inputs: components,
//! candidate medoids under sampling, and every output collection are ordered by
//! stable key, never by discovery order.

use std::collections::BTreeMap;

use crate::verify::{Confidence, StructuralClass};

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
    /// components. The sample is deterministic (smallest keys first).
    pub sampling_threshold: usize,
    /// Number of candidate medoids scored when a component exceeds
    /// [`Self::sampling_threshold`].
    pub sample_size: usize,
}

impl Default for GroupingConfig {
    fn default() -> Self {
        Self {
            medoid_min_similarity: 0.60,
            min_pairwise_similarity: 0.60,
            sampling_threshold: 256,
            sample_size: 32,
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
    /// The pair's clone classification.
    pub class: StructuralClass,
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
    pub clone_type: StructuralClass,
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
    /// Groups emitted after medoid and complete-linkage refinement.
    pub groups: usize,
    /// Members ejected by the medoid constraint (and regrouped elsewhere).
    pub medoid_ejections: usize,
    /// Members removed by complete-linkage splitting.
    pub linkage_splits: usize,
    /// Members left ungrouped as singletons after refinement.
    pub singletons: usize,
}

/// The grouping result: refined groups plus statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupingSet {
    /// Cohesive groups, ordered by their medoid's key.
    pub groups: Vec<StructuralGroup>,
    /// What grouping saw and did.
    pub stats: GroupingStats,
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
    for component in &components {
        refine_component(component, units, &sim, config, &mut groups, &mut stats);
    }

    // Deterministic output order: by the medoid's key, then by size.
    groups.sort_by(|left, right| {
        units[left.canonical]
            .key
            .cmp(&units[right.canonical].key)
            .then(left.members.len().cmp(&right.members.len()))
    });
    stats.groups = groups.len();
    GroupingSet { groups, stats }
}

/// Symmetric similarity lookup over the verified edges. Absent pairs read as
/// zero — units verification never compared are treated as dissimilar.
struct SimilarityGraph {
    edges: BTreeMap<(usize, usize), EdgeData>,
}

#[derive(Debug, Clone, Copy)]
struct EdgeData {
    similarity: f64,
    class: StructuralClass,
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
            // the result never depends on input order.
            let data = EdgeData {
                similarity: edge.similarity,
                class: edge.class,
                confidence: edge.confidence,
            };
            map.entry(key)
                .and_modify(|existing: &mut EdgeData| {
                    if edge.similarity > existing.similarity {
                        *existing = data;
                    }
                })
                .or_insert(data);
        }
        Self { edges: map }
    }

    fn similarity(&self, a: usize, b: usize) -> f64 {
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
    for edge in edges {
        if edge.a != edge.b {
            union(&mut parent, edge.a, edge.b);
        }
    }
    let mut buckets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for node in 0..unit_count {
        let root = find(&mut parent, node);
        buckets.entry(root).or_default().push(node);
    }
    // Only components with a verified edge (size >= 2) can form a group.
    buckets.into_values().filter(|c| c.len() >= 2).collect()
}

fn find(parent: &mut [usize], node: usize) -> usize {
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

fn union(parent: &mut [usize], a: usize, b: usize) {
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

/// Refine one component into cohesive groups, appending them to `groups`.
///
/// Terminates because each recursion runs on a strictly smaller set: a member
/// is only ejected into `rest`, and the group built from `kept` never re-enters
/// refinement.
fn refine_component(
    component: &[usize],
    units: &[GroupingUnit],
    sim: &SimilarityGraph,
    config: &GroupingConfig,
    groups: &mut Vec<StructuralGroup>,
    stats: &mut GroupingStats,
) {
    if component.len() < 2 {
        stats.singletons += component.len();
        return;
    }

    let medoid = select_medoid(component, units, sim, config);

    // Medoid constraint: keep members close enough to the medoid, eject the
    // rest for independent regrouping.
    let mut kept = Vec::new();
    let mut rest = Vec::new();
    for &member in component {
        if member == medoid || sim.similarity(member, medoid) >= config.medoid_min_similarity {
            kept.push(member);
        } else {
            rest.push(member);
        }
    }
    stats.medoid_ejections += rest.len();

    // Complete-linkage: remove members until the weakest pair clears the floor.
    complete_linkage_trim(medoid, &mut kept, &mut rest, sim, config, stats);

    if let Some(built) = build_group(medoid, &kept, units, sim) {
        groups.push(built);
    } else {
        stats.singletons += kept.len();
    }

    if !rest.is_empty() {
        // Regroup the ejected members; deterministic order for recursion.
        rest.sort_by_key(|&m| units[m].key);
        refine_component(&rest, units, sim, config, groups, stats);
    }
}

/// Choose the medoid: the member with the greatest total similarity to the
/// others, ties broken by the smallest key. On components past the sampling
/// threshold only the smallest-key candidates are scored, which keeps the pick
/// deterministic while bounding the cost.
fn select_medoid(
    component: &[usize],
    units: &[GroupingUnit],
    sim: &SimilarityGraph,
    config: &GroupingConfig,
) -> usize {
    let mut candidates: Vec<usize> = component.to_vec();
    candidates.sort_by_key(|&m| units[m].key);
    if candidates.len() > config.sampling_threshold {
        candidates.truncate(config.sample_size.max(1));
    }

    let mut best = candidates[0];
    let mut best_total = total_similarity(best, component, sim);
    for &candidate in &candidates[1..] {
        let total = total_similarity(candidate, component, sim);
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
fn total_similarity(member: usize, set: &[usize], sim: &SimilarityGraph) -> f64 {
    set.iter()
        .filter(|&&other| other != member)
        .map(|&other| sim.similarity(member, other))
        .sum()
}

/// Trim `kept` until its weakest pair reaches the complete-linkage floor,
/// moving each removed member into `rest`. The medoid is never removed. The
/// removed member of the weakest pair is the non-medoid one with the lower
/// total similarity inside `kept` (ties broken by the larger key), so the
/// choice is deterministic and progress is guaranteed.
fn complete_linkage_trim(
    medoid: usize,
    kept: &mut Vec<usize>,
    rest: &mut Vec<usize>,
    sim: &SimilarityGraph,
    config: &GroupingConfig,
    stats: &mut GroupingStats,
) {
    while kept.len() >= 2 {
        let Some((weakest, worst_sim)) = weakest_pair(kept, sim) else {
            break;
        };
        if worst_sim >= config.min_pairwise_similarity {
            break;
        }
        let victim = pick_victim(medoid, weakest, kept, sim);
        kept.retain(|&m| m != victim);
        rest.push(victim);
        stats.linkage_splits += 1;
    }
}

/// The lowest-similarity pair inside `kept` and its similarity. `None` when
/// there are fewer than two members.
fn weakest_pair(kept: &[usize], sim: &SimilarityGraph) -> Option<((usize, usize), f64)> {
    let mut worst: Option<((usize, usize), f64)> = None;
    for (i, &left) in kept.iter().enumerate() {
        for &right in &kept[i + 1..] {
            let value = sim.similarity(left, right);
            match worst {
                Some((_, current)) if current <= value => {}
                _ => worst = Some(((left, right), value)),
            }
        }
    }
    worst
}

/// From the weakest pair, pick the member to remove: never the medoid,
/// otherwise the one with the lower total similarity inside `kept`, ties broken
/// by the larger index (a stable, key-independent fallback).
fn pick_victim(
    medoid: usize,
    (left, right): (usize, usize),
    kept: &[usize],
    sim: &SimilarityGraph,
) -> usize {
    if left == medoid {
        return right;
    }
    if right == medoid {
        return left;
    }
    let left_total = total_similarity(left, kept, sim);
    let right_total = total_similarity(right, kept, sim);
    // Remove the lower-total member; on a tie remove the larger index.
    match left_total.total_cmp(&right_total) {
        std::cmp::Ordering::Less => left,
        std::cmp::Ordering::Greater => right,
        std::cmp::Ordering::Equal => {
            if left > right {
                left
            } else {
                right
            }
        }
    }
}

/// Assemble a group from a medoid and its kept members, or `None` when fewer
/// than two members remain (a singleton is not a group).
fn build_group(
    medoid: usize,
    kept: &[usize],
    units: &[GroupingUnit],
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
        .map(|&member| sim.similarity(medoid, member))
        .collect();

    // Weakest class, confidence and pairwise similarity across internal edges.
    let mut clone_type = StructuralClass::Type1;
    let mut confidence = Confidence::High;
    let mut min_pairwise = 1.0_f64;
    for (i, &left) in ordered_members.iter().enumerate() {
        for &right in &ordered_members[i + 1..] {
            min_pairwise = min_pairwise.min(sim.similarity(left, right));
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

/// The looser of two classes: Type-3 is weakest, Type-1 strongest.
const fn weaker_class(a: StructuralClass, b: StructuralClass) -> StructuralClass {
    match (a, b) {
        (StructuralClass::Type3, _) | (_, StructuralClass::Type3) => StructuralClass::Type3,
        (StructuralClass::Type2, _) | (_, StructuralClass::Type2) => StructuralClass::Type2,
        _ => StructuralClass::Type1,
    }
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
mod tests {
    use super::*;

    /// Units keyed `0x00..`, `0x01..`, ... so key order matches index order.
    fn units(count: usize) -> Vec<GroupingUnit> {
        (0..count)
            .map(|i| GroupingUnit {
                key: [u8::try_from(i).unwrap(); 16],
            })
            .collect()
    }

    fn edge(a: usize, b: usize, similarity: f64) -> SimilarityEdge {
        SimilarityEdge {
            a,
            b,
            similarity,
            class: StructuralClass::Type3,
            confidence: Confidence::Medium,
        }
    }

    #[test]
    fn a_transitive_chain_does_not_fuse_into_one_group() {
        // 0-1-2-3-4, each adjacent pair strong, ends never compared. A plain
        // connected-component grouping would return one group of five; medoid +
        // complete-linkage must not, because 0 and 4 are dissimilar.
        let units = units(5);
        let edges = vec![
            edge(0, 1, 0.9),
            edge(1, 2, 0.9),
            edge(2, 3, 0.9),
            edge(3, 4, 0.9),
        ];
        let set = group(&units, &edges, &GroupingConfig::default());
        assert_eq!(set.stats.components, 1, "the chain is one component");
        assert!(
            set.groups.iter().all(|g| g.members.len() < 5),
            "no group may span the whole chain"
        );
        // Every reported group clears the cohesion floor on every internal pair.
        for reported in &set.groups {
            assert!(reported.min_pairwise >= 0.60);
        }
    }

    #[test]
    fn a_clique_is_one_group_with_a_deterministic_medoid() {
        // A fully connected trio: one cohesive group, medoid is the smallest key
        // on the total-similarity tie.
        let units = units(3);
        let edges = vec![edge(0, 1, 0.9), edge(1, 2, 0.9), edge(0, 2, 0.9)];
        let set = group(&units, &edges, &GroupingConfig::default());
        assert_eq!(set.groups.len(), 1);
        let only = &set.groups[0];
        assert_eq!(only.members.len(), 3);
        assert_eq!(only.canonical, 0);
        assert_eq!(only.members[0], 0, "medoid comes first");
    }

    #[test]
    fn a_member_far_from_the_medoid_is_ejected() {
        // 0,1,2 form a tight clique; 3 hangs off 2 weakly. 3 must not join the
        // clique's group.
        let units = units(4);
        let edges = vec![
            edge(0, 1, 0.95),
            edge(0, 2, 0.95),
            edge(1, 2, 0.95),
            edge(2, 3, 0.62),
        ];
        let set = group(&units, &edges, &GroupingConfig::default());
        let big = set
            .groups
            .iter()
            .find(|g| g.members.contains(&0))
            .expect("the clique forms a group");
        assert!(
            !big.members.contains(&3),
            "the weakly attached member stays out of the clique"
        );
    }

    #[test]
    fn union_find_components_are_not_emitted_verbatim() {
        // Two disjoint cliques: two components, two groups, and never one merged
        // group.
        let units = units(6);
        let edges = vec![
            edge(0, 1, 0.9),
            edge(1, 2, 0.9),
            edge(0, 2, 0.9),
            edge(3, 4, 0.9),
            edge(4, 5, 0.9),
            edge(3, 5, 0.9),
        ];
        let set = group(&units, &edges, &GroupingConfig::default());
        assert_eq!(set.stats.components, 2);
        assert_eq!(set.groups.len(), 2);
        assert!(set.groups.iter().all(|g| g.members.len() == 3));
    }

    #[test]
    fn a_lone_unit_is_not_a_group() {
        let units = units(2);
        // No edges: two singletons, no group.
        let set = group(&units, &[], &GroupingConfig::default());
        assert!(set.groups.is_empty());
    }

    #[test]
    fn the_group_takes_the_weakest_class_and_confidence() {
        let units = units(3);
        let edges = vec![
            SimilarityEdge {
                a: 0,
                b: 1,
                similarity: 0.95,
                class: StructuralClass::Type1,
                confidence: Confidence::High,
            },
            SimilarityEdge {
                a: 1,
                b: 2,
                similarity: 0.9,
                class: StructuralClass::Type3,
                confidence: Confidence::Low,
            },
            SimilarityEdge {
                a: 0,
                b: 2,
                similarity: 0.9,
                class: StructuralClass::Type2,
                confidence: Confidence::Medium,
            },
        ];
        let set = group(&units, &edges, &GroupingConfig::default());
        let only = &set.groups[0];
        assert_eq!(only.clone_type, StructuralClass::Type3);
        assert_eq!(only.confidence, Confidence::Low);
    }

    #[test]
    fn grouping_is_deterministic_regardless_of_edge_order() {
        let units = units(5);
        let forward = vec![
            edge(0, 1, 0.9),
            edge(1, 2, 0.9),
            edge(2, 3, 0.9),
            edge(3, 4, 0.9),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        let a = group(&units, &forward, &GroupingConfig::default());
        let b = group(&units, &reversed, &GroupingConfig::default());
        assert_eq!(a.groups, b.groups);
    }
}
