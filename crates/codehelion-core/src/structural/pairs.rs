use super::{
    BTreeMap, BTreeSet, BuildVariant, CloneClass, FileFeatures, FragmentFingerprint, GroupingSet,
    SimilarityEdge, SyntaxIrFile, Unit, VerifiedPair, candidate, control_flow,
    dominant_boilerplate_members, near_match, stable_id, verify, written_once_per_width_members,
};

/// A candidate pair that is not a statement about any one program, and so is
/// dropped before it reaches the judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotAPair {
    /// One unit encloses the other: one stretch of code seen at two levels.
    Nested,
    /// The two sit under different arms of one preprocessor conditional, so
    /// no build contains both.
    Alternatives,
    /// The two hold too different a mix of shapes to be a clone of each other,
    /// which the shape-count vectors settle without reading either tree.
    DivergentShapes,
}

/// What the candidate stages proposed, reduced to unit pairs.
pub(super) struct LiftedPairs {
    /// Distinct unit pairs for verification to judge.
    pub(super) pairs: BTreeSet<(usize, usize)>,
    /// Proposals dropped for nesting.
    pub(super) nested: usize,
    /// Proposals dropped for being alternative arms of one conditional.
    pub(super) alternatives: usize,
    /// Proposals dropped for holding too different a mix of shapes.
    pub(super) divergent: usize,
}

/// Collapse what the three candidate stages proposed into the set of distinct
/// unit pairs verification will judge, counting what was dropped on the way.
///
/// The stages describe candidates differently — a shared fragment, an
/// overlapping shingle set, a shared skeleton — and they overlap heavily on
/// real code. What verification needs is neither the evidence nor the
/// duplicates, only which two units to compare, so all three are reduced to
/// that here and deduplicated through an ordered set.
pub(super) fn lift_to_unit_pairs(
    candidate: &candidate::CandidateSet,
    near: &near_match::NearMatchSet,
    skeleton: &control_flow::ControlFlowSet,
    units: &[Unit],
    offsets: &[usize],
    feature_files: &[FileFeatures],
    max_shape_divergence: f64,
) -> LiftedPairs {
    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut nested = 0usize;
    let mut alternatives = 0usize;
    let mut divergent = 0usize;
    let places = candidate
        .pairs
        .iter()
        .map(|pair| (pair.a.file, pair.a.unit, pair.b.file, pair.b.unit))
        .chain(
            near.pairs
                .iter()
                .map(|pair| (pair.a.file, pair.a.unit, pair.b.file, pair.b.unit)),
        )
        .chain(
            skeleton
                .pairs
                .iter()
                .map(|pair| (pair.a.file, pair.a.unit, pair.b.file, pair.b.unit)),
        );
    for (file_a, unit_a, file_b, unit_b) in places {
        let proposal = Proposal {
            units,
            offsets,
            feature_files,
            max_shape_divergence,
        };
        match proposal.insert(&mut pairs, file_a, unit_a, file_b, unit_b) {
            Some(NotAPair::Nested) => nested += 1,
            Some(NotAPair::Alternatives) => alternatives += 1,
            Some(NotAPair::DivergentShapes) => divergent += 1,
            None => {}
        }
    }
    LiftedPairs {
        pairs,
        nested,
        alternatives,
        divergent,
    }
}

/// What a candidate stage proposed is judged against.
struct Proposal<'a> {
    units: &'a [Unit],
    offsets: &'a [usize],
    feature_files: &'a [FileFeatures],
    max_shape_divergence: f64,
}

impl Proposal<'_> {
    /// Insert a `(file, unit)` pair as a global, ordered unit pair, dropping
    /// self-pairs and returning why a proposal did not survive.
    fn insert(
        &self,
        pairs: &mut BTreeSet<(usize, usize)>,
        file_a: usize,
        unit_a: usize,
        file_b: usize,
        unit_b: usize,
    ) -> Option<NotAPair> {
        let a = self.offsets[file_a] + unit_a;
        let b = self.offsets[file_b] + unit_b;
        if a == b {
            return None;
        }
        if encloses(&self.units[a], &self.units[b]) {
            return Some(NotAPair::Nested);
        }
        if self.units[a].arms.excludes(&self.units[b].arms) {
            return Some(NotAPair::Alternatives);
        }
        let (vector_a, vector_b) = (
            &self.feature_files[file_a].units[unit_a].vector,
            &self.feature_files[file_b].units[unit_b].vector,
        );
        if vector_a.shape_divergence(vector_b) > self.max_shape_divergence {
            return Some(NotAPair::DivergentShapes);
        }
        pairs.insert(if a <= b { (a, b) } else { (b, a) });
        None
    }
}

/// Verified clone pairs that no reported group holds both halves of.
///
/// A group is a set whose every member is a clone of every other, which is a
/// stronger claim than any single pair makes, and it is the claim the reader
/// is given. Similarity is not transitive, so a unit can be a clone of two
/// others that are not clones of each other, and only one of those relations
/// can survive into a partition. The relation that does not survive is
/// evidence the judge accepted and the report would otherwise throw away, so
/// it is carried out separately rather than dropped: two units that are copies
/// of each other remain worth knowing about whether or not a larger set formed
/// around them.
///
/// Not every surviving verdict is such a relation. Two are returned as counts
/// rather than entries:
///
/// - a crossing whose two sides the report already relates through a group is
///   not a second fact about the code — see [`already_described`];
/// - a crossing the component ceiling severed is not a fact about the code at
///   all. Where a set was too large to refine whole it was cut, and two units
///   in different pieces were never weighed against each other. Carrying those
///   out reads as "these are copies and no group holds them", which is true of
///   the relation and false about why: nothing declined to hold them. The set
///   that made the ceiling fire is one of thousands of interchangeable units,
///   so what this spares the reader is the whole of that set restated one pair
///   at a time — the ceiling exists to keep such a repository from making the
///   scan expensive, and listing its severed pairs would move that expense
///   onto the person reading the result.
pub(super) fn unrepresented_pairs(
    edges: &[SimilarityEdge],
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
) -> (Vec<VerifiedPair>, usize, usize) {
    let mut group_of: BTreeMap<usize, usize> = BTreeMap::new();
    for (index, group) in groups.groups.iter().enumerate() {
        for &member in &group.members {
            group_of.insert(member, index);
        }
    }
    let severed = edges
        .iter()
        .filter(|edge| groups.severed_by_the_ceiling(edge.a, edge.b))
        .count();
    // Fold the surviving verdicts by the pair of contents they are about. Two
    // verdicts over the same two contents are one fact: the judge compares
    // normalized content, so where it accepted one crossing it accepts every
    // crossing of those contents, and the entries would be indistinguishable
    // anyway — their ids are composed from content alone.
    //
    // Which content that is has to be the domain the id is composed from —
    // `Unit::group_content`, so raw content for Type-1 and normalized content
    // for the rest. Folding on raw content while composing the id from
    // normalized content splits one fact into two entries that then carry the
    // same fingerprint, which is not a pair of findings but one finding
    // reported twice.
    //
    // The key is the unordered pair: which side is written first is not part
    // of the relation, and letting it in would reach the same conclusion twice
    // under two ids.
    let mut folded: BTreeMap<(FragmentFingerprint, FragmentFingerprint, CloneClass), Folded> =
        BTreeMap::new();
    for edge in edges.iter().filter(|edge| {
        !groups.severed_by_the_ceiling(edge.a, edge.b)
            && match (group_of.get(&edge.a), group_of.get(&edge.b)) {
                (Some(a), Some(b)) => a != b,
                _ => true,
            }
    }) {
        let content = |member: usize| units[member].group_content(edge.class);
        let (low, high) = if content(edge.a) <= content(edge.b) {
            (content(edge.a), content(edge.b))
        } else {
            (content(edge.b), content(edge.a))
        };
        let entry = folded
            .entry((low, high, edge.class))
            .or_insert_with(|| Folded {
                members: BTreeSet::new(),
                crossings: 0,
                similarity: edge.similarity,
                breakdown: edge.breakdown,
                confidence: edge.confidence,
                described: true,
            });
        entry.members.insert(edge.a);
        entry.members.insert(edge.b);
        entry.crossings += 1;
        // One crossing the report does not already account for is enough to
        // make the pair worth carrying: the entry stands for every crossing of
        // those two contents, and the derived ones say nothing against it.
        entry.described &= already_described(edge, &group_of, groups, units);
        // This entry asserts one relation across every occurrence of both
        // contents, so it is no stronger than its weakest accepted crossing.
        // Using the strongest crossing here made split pairs look more
        // certain than cohesive groups, which already report their minimum
        // pairwise evidence.
        if edge.similarity < entry.similarity {
            entry.similarity = edge.similarity;
            entry.breakdown = edge.breakdown;
            entry.confidence = edge.confidence;
        }
    }
    // Counted in verified pairs, not in the entries they folded into, because
    // that is what the funnel row it lands in is measured in: an entry stands
    // for every crossing of its two contents, and a coarser fold that made two
    // dropped crossings arrive as one would report the rule as removing half
    // of what it removed.
    let described: usize = folded
        .values()
        .filter(|entry| entry.described)
        .map(|entry| entry.crossings)
        .sum();

    let mut pairs: Vec<VerifiedPair> = folded
        .into_iter()
        .filter(|(_, entry)| !entry.described)
        .map(|((_low, _high, class), entry)| {
            let members: Vec<usize> = entry.members.into_iter().collect();
            // Which instance is canonical follows content, not position: the
            // members are peers, and an index would tie the anchor — and so
            // the id — to the order the tree was walked. Raw content decides
            // even though the relation is over normalized content, because it
            // is the finer of the two and orders the members the identity
            // domain holds as one.
            let canonical = members
                .iter()
                .copied()
                .min_by_key(|&member| units[member].content)
                .unwrap_or(members[0]);
            let boilerplate = dominant_boilerplate_members(&members, units);
            let width_family = written_once_per_width_members(canonical, &members, units, files);
            let identity_contents = members
                .iter()
                .map(|&member| units[member].group_content(class))
                .collect::<Vec<_>>();
            VerifiedPair {
                members,
                canonical,
                fingerprint: stable_id::structural_clone_group_fingerprint(
                    variant,
                    class,
                    &units[canonical].group_content(class),
                    &identity_contents,
                ),
                similarity: entry.similarity,
                breakdown: entry.breakdown,
                class,
                confidence: entry.confidence,
                boilerplate,
                width_family,
            }
        })
        .collect();
    // Strongest conservative evidence first, then by member indices, so the
    // order is deterministic and a pair never gains rank from one outlier.
    pairs.sort_by(|left, right| {
        right
            .similarity
            .total_cmp(&left.similarity)
            .then_with(|| left.members.cmp(&right.members))
    });
    (pairs, described, severed)
}

/// Verdicts accumulated for one pair of contents.
struct Folded {
    members: BTreeSet<usize>,
    /// Verified pairs folded in here, kept apart from the member count so
    /// that dropping this entry can be accounted for in the unit the funnel
    /// reports.
    crossings: usize,
    similarity: f64,
    breakdown: Option<verify::SimilarityBreakdown>,
    confidence: verify::Confidence,
    described: bool,
}

/// Whether a group the report already states puts the crossing's two sides in
/// the same relation, at one remove.
///
/// A unit that is a copy of something nested inside another unit is, by that
/// much, a copy of the other unit too — the smaller side matches the part of
/// the larger side that its own twin occupies. The judge sees the agreement
/// and accepts it, and the arithmetic is honest: two thirds of the tokens do
/// line up. But the report has already said both halves of it, once as the
/// group holding the two nested units and once as the group holding their
/// parents, and the crossing adds only that one of them is bigger. Carried out
/// as a pair it reads as a third duplication, at a size ratio no reader can
/// act on, so it is counted and left out.
///
/// The relation has to come from a group rather than from another pair: a
/// group is the report's strong claim, and deriving one pair from another
/// would let two crossings excuse each other.
fn already_described(
    edge: &SimilarityEdge,
    group_of: &BTreeMap<usize, usize>,
    groups: &GroupingSet,
    units: &[Unit],
) -> bool {
    let nested_peer = |side: usize, other: usize| {
        group_of
            .get(&side)
            .map(|&index| groups.groups[index].members.as_slice())
            .unwrap_or_default()
            .iter()
            .any(|&peer| peer != other && encloses(&units[peer], &units[other]))
    };
    nested_peer(edge.a, edge.b) || nested_peer(edge.b, edge.a)
}

/// Whether one of the two units contains the other.
///
/// A namespace whose only content is a class, or a function holding a single
/// closure, agrees with what it encloses on every measure there is — the two
/// are made of the same tokens. That agreement is not a copy: there is one
/// stretch of code here, described at two levels, and reporting the pair
/// claims a duplicate that nobody can remove. Containment holds within a file
/// only, so units in different files are never each other's parents.
pub(super) const fn encloses(a: &Unit, b: &Unit) -> bool {
    a.file == b.file
        && ((a.tokens.0 <= b.tokens.0 && b.tokens.1 <= a.tokens.1)
            || (b.tokens.0 <= a.tokens.0 && a.tokens.1 <= b.tokens.1))
}
