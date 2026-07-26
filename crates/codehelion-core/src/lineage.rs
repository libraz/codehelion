//! What became of each clone group between two audits.
//!
//! A scan says what a tree contains. An audit says what changed since the last
//! one looked, which is a different question and cannot be answered by
//! comparing reports line by line: a duplication that moved to another file is
//! the same finding at a new address, and a duplication whose copies drifted
//! apart is a different finding at the old one. Both are invisible to a
//! textual diff and both are the point of auditing periodically.
//!
//! # What the comparison is between
//!
//! Content, and nothing else. Every judgement here reads member content
//! fingerprints; file paths and unit names are consulted only to answer
//! whether content that stayed the same is still in the same place, and line
//! numbers are never consulted at all. A comment inserted above a clone shifts
//! every line under it and means nothing, so a state that moved on line
//! numbers would report churn on every edit and drown the states that matter.
//!
//! # Connecting a group to its past
//!
//! Group fingerprints fold in the deduplicated set of member content
//! fingerprints, so any change to what is duplicated moves the id. Equal
//! fingerprints therefore identify a group across scans directly, but unequal
//! ones say nothing about whether the two are related — which is most of the
//! interesting cases. Those are connected by how much member content the two
//! share, measured as
//!
//! ```text
//! overlap = |shared content| / min(|previous content|, |current content|)
//! ```
//!
//! rather than as a Jaccard ratio. The distinction decides the case the whole
//! mechanism exists for: when one copy of a two-member clone is edited, the
//! group keeps one of its two contents, which is a Jaccard of 1/3 — below any
//! useful threshold — and an overlap of 1/2. Divergence is exactly what an
//! audit is watching for, so the measure that can see it is the one used, with
//! Jaccard kept as a tie-break where two candidates overlap equally.
//!
//! A previous group may father several current groups (a clone group that
//! split) and a current group may descend from several previous ones (two that
//! merged); both are recorded as [`LineageEdge`]s. Each current group still
//! has exactly one *primary* parent, the one its state is judged against,
//! because a state describes a transition and a transition needs one origin.
//!
//! # What content fingerprints can and cannot show
//!
//! Two properties of the identifiers set the limits of every judgement here,
//! and both are consequences of decisions made elsewhere rather than of
//! anything in this module.
//!
//! An exact clone group holds *one* content between all of its members, since
//! that is what makes them exact copies. Editing one member therefore takes it
//! out of the group rather than changing what the group holds, and the group
//! is reported as having lost a member. Divergence is visible only where the
//! members were never byte-identical to begin with — a gapped group, whose
//! members each carry their own content.
//!
//! A member's content is hashed under the normalization its classification
//! implies: verbatim for Type-1, renamed for Type-2 and Type-3. A group
//! crossing between those two families therefore has no member content in
//! common with its past, and is reported as a resolution and a new finding
//! rather than as [`AuditState::Reclassified`] — which is reachable between
//! the two normalized classes, and whenever the member scope changes.

use std::collections::{BTreeMap, BTreeSet};

use crate::clone_class::{CloneClass, CloneScope};
use crate::stable_id::{
    CloneGroupFingerprint, FragmentFingerprint, GroupLineageId, group_lineage_id,
};

/// Least shared member content, as a fraction of the smaller group, that
/// connects a group to a previous one.
///
/// One half is the value at which a two-member clone whose copies were edited
/// apart one at a time stays connected to its past: it keeps one of its two
/// contents. Below that the two groups share less than half of the smaller
/// one, and calling them the same duplication is a guess; they are reported as
/// a resolution and a new finding, which is what the evidence supports.
pub const LINEAGE_MIN_OVERLAP: f64 = 0.5;

/// What happened to one clone group since the previous audit.
///
/// The eight states are exhaustive and mutually exclusive: every group on
/// either side of a comparison lands in exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditState {
    /// Present in both audits, with the same content in the same places.
    Unchanged,
    /// Present in this audit only, connected to nothing before it.
    New,
    /// Present in the previous audit only: the duplication is gone.
    Resolved,
    /// Connected to a previous group, with more occurrences than it had.
    Expanded,
    /// Connected to a previous group, with fewer occurrences than it had.
    Reduced,
    /// The same content as before, in a different file or unit.
    Moved,
    /// The same number of occurrences as before, but their content changed:
    /// the copies were edited while the group kept its size.
    Diverged,
    /// The clone classification or member scope changed.
    Reclassified,
}

impl AuditState {
    /// Stable lowercase identifier used in reports and storage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::New => "new",
            Self::Resolved => "resolved",
            Self::Expanded => "expanded",
            Self::Reduced => "reduced",
            Self::Moved => "moved",
            Self::Diverged => "diverged",
            Self::Reclassified => "reclassified",
        }
    }

    /// Every state, in the order reports list them: what needs attention
    /// first, what can be read as progress last.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::New,
            Self::Expanded,
            Self::Diverged,
            Self::Reclassified,
            Self::Moved,
            Self::Reduced,
            Self::Resolved,
            Self::Unchanged,
        ]
    }

    /// Whether the state describes duplication that grew or drifted, and so
    /// asks the reader to look at something.
    ///
    /// A moved clone is not here: it is the same duplication at a new address,
    /// and the address is not what an audit is about.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::New | Self::Expanded | Self::Diverged)
    }
}

/// Where one occurrence of a group's content sits, for the one question
/// position is allowed to answer: is the same content still in the same place?
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Anchor {
    /// Path of the file, relative to the scan root.
    pub file: String,
    /// Name of the enclosing unit, when the occurrence has one.
    pub unit: Option<String>,
}

/// One occurrence of a group's content, as history sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSnapshot {
    /// Content fingerprint of the matched slice.
    pub content: FragmentFingerprint,
    /// Where this occurrence sits.
    pub anchor: Anchor,
}

/// One clone group of an audited run, reduced to what history compares.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSnapshot {
    /// The group's fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Clone classification.
    pub clone_type: CloneClass,
    /// What the members are: whole units, or runs inside them.
    pub scope: CloneScope,
    /// Minimum pairwise similarity across the group.
    pub score: f64,
    /// Content fingerprint of the canonical instance, when the run recorded
    /// one. Used only to break ties between equally overlapping candidates.
    pub canonical: Option<FragmentFingerprint>,
    /// The lineage this group was already known to belong to, when the run it
    /// comes from recorded one. Absent for a run audited before lineage was
    /// recorded, in which case the history starts here.
    pub lineage: Option<GroupLineageId>,
    /// The occurrences.
    pub members: Vec<MemberSnapshot>,
}

impl GroupSnapshot {
    /// The deduplicated set of member content fingerprints — what the group
    /// fingerprint is derived from, and what lineage is measured on.
    fn contents(&self) -> BTreeSet<FragmentFingerprint> {
        self.members.iter().map(|member| member.content).collect()
    }

    /// Every occurrence's anchor, sorted, so two groups' placements compare
    /// independently of member order.
    fn anchors(&self) -> Vec<Anchor> {
        let mut anchors: Vec<Anchor> = self
            .members
            .iter()
            .map(|member| member.anchor.clone())
            .collect();
        anchors.sort();
        anchors
    }

    fn reference(&self) -> GroupRef {
        GroupRef {
            fingerprint: self.fingerprint,
            clone_type: self.clone_type,
            scope: self.scope,
            members: self.members.len(),
            score: self.score,
        }
    }
}

/// Identity and shape of one side of a transition.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GroupRef {
    /// The group's fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Clone classification.
    pub clone_type: CloneClass,
    /// What the members are.
    pub scope: CloneScope,
    /// Number of occurrences.
    pub members: usize,
    /// Minimum pairwise similarity.
    pub score: f64,
}

/// One occurrence's content staying put while its address changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Where the content was.
    pub from: Anchor,
    /// Where it is now.
    pub to: Anchor,
}

/// A connection between a previous group and a current one.
///
/// Every connection is recorded, not just the one a state was judged against,
/// so a group that split into two and two that merged into one are both
/// visible as what they are rather than as an assortment of new and resolved
/// findings.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageEdge {
    /// Fingerprint of the previous group.
    pub previous: CloneGroupFingerprint,
    /// The history the previous group belonged to. For a primary edge this is
    /// what the child inherits; for the other edges of a merge it is the
    /// history that ends here, and it has to be read from the parent rather
    /// than derived from its fingerprint, which would lose everything before
    /// the parent.
    pub previous_lineage: GroupLineageId,
    /// Fingerprint of the current group.
    pub current: CloneGroupFingerprint,
    /// Whether this is the edge the current group's state was judged against.
    /// A current group has exactly one.
    pub primary: bool,
    /// Member contents both groups hold.
    pub shared: usize,
    /// Shared content as a fraction of the smaller group.
    pub overlap: f64,
}

/// What became of one clone group, with the evidence the verdict rests on.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupHistory {
    /// The state this group is in.
    pub state: AuditState,
    /// The history this group belongs to.
    pub lineage: GroupLineageId,
    /// The group as this audit found it. Absent only for
    /// [`AuditState::Resolved`], where there is no current group.
    pub current: Option<GroupRef>,
    /// The primary parent: the previous group the state was judged against.
    /// Absent for [`AuditState::New`]; for [`AuditState::Resolved`] it is the
    /// group that went away.
    pub previous: Option<GroupRef>,
    /// Member contents the two groups hold in common.
    pub shared_content: usize,
    /// Shared content as a fraction of the smaller group; `1.0` for a group
    /// whose fingerprint did not move, `0.0` where there is no connection.
    pub overlap: f64,
    /// How many previous groups fed this one. More than one is a merge.
    pub parents: usize,
    /// How many current groups the primary parent fed. More than one is a
    /// split, and this group is one of the pieces.
    pub siblings: usize,
    /// Where content that stayed the same went, for [`AuditState::Moved`].
    /// Empty otherwise.
    pub relocations: Vec<Relocation>,
}

/// Every group of both audits, judged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditDiff {
    /// One entry per current group, plus one per previous group that nothing
    /// in this audit descends from.
    pub entries: Vec<GroupHistory>,
    /// Every connection found, primary and secondary.
    pub edges: Vec<LineageEdge>,
}

impl AuditDiff {
    /// How many entries are in `state`.
    #[must_use]
    pub fn count(&self, state: AuditState) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == state)
            .count()
    }

    /// Whether anything at all changed between the two audits.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.state == AuditState::Unchanged)
    }
}

/// One candidate connection, before the primary edges are chosen.
struct Candidate {
    previous: usize,
    shared: usize,
    overlap: f64,
    jaccard: f64,
    canonical_match: bool,
}

/// Judge every group of `current` against `previous`.
///
/// Both sides must come from runs of the same build variant; comparing across
/// variants would compare identifiers computed under different rules, and
/// every group would look new. Enforcing that is the caller's, which knows
/// where the two runs came from.
#[must_use]
pub fn diff(previous: &[GroupSnapshot], current: &[GroupSnapshot]) -> AuditDiff {
    let previous_contents: Vec<BTreeSet<FragmentFingerprint>> =
        previous.iter().map(GroupSnapshot::contents).collect();

    // Which previous groups hold a given content, so candidates are found by
    // what they share rather than by comparing every pair.
    let mut holders: BTreeMap<FragmentFingerprint, Vec<usize>> = BTreeMap::new();
    for (index, contents) in previous_contents.iter().enumerate() {
        for content in contents {
            holders.entry(*content).or_default().push(index);
        }
    }

    let mut edges: Vec<LineageEdge> = Vec::new();
    let mut primary_of: Vec<Option<Candidate>> = Vec::with_capacity(current.len());
    let mut connected: BTreeSet<usize> = BTreeSet::new();
    let mut children: BTreeMap<usize, usize> = BTreeMap::new();
    let mut parent_counts: Vec<usize> = Vec::with_capacity(current.len());

    for group in current {
        let mut candidates = candidates_for(group, previous, &previous_contents, &holders);
        // Best overlap first; ties fall to the wider agreement, then to the
        // group whose canonical instance survived, then to fingerprint order
        // so the choice never depends on input order.
        candidates.sort_by(|a, b| {
            b.overlap
                .total_cmp(&a.overlap)
                .then_with(|| b.jaccard.total_cmp(&a.jaccard))
                .then_with(|| b.canonical_match.cmp(&a.canonical_match))
                .then_with(|| {
                    previous[a.previous]
                        .fingerprint
                        .as_bytes()
                        .cmp(previous[b.previous].fingerprint.as_bytes())
                })
        });
        parent_counts.push(candidates.len());
        for (rank, candidate) in candidates.iter().enumerate() {
            connected.insert(candidate.previous);
            if rank == 0 {
                *children.entry(candidate.previous).or_default() += 1;
            }
            edges.push(LineageEdge {
                previous: previous[candidate.previous].fingerprint,
                previous_lineage: lineage_of(&previous[candidate.previous]),
                current: group.fingerprint,
                primary: rank == 0,
                shared: candidate.shared,
                overlap: candidate.overlap,
            });
        }
        primary_of.push(candidates.into_iter().next());
    }

    let mut entries: Vec<GroupHistory> = Vec::with_capacity(current.len() + previous.len());
    for ((group, primary), parents) in current.iter().zip(&primary_of).zip(&parent_counts) {
        entries.push(judge(
            group,
            primary.as_ref(),
            previous,
            &children,
            *parents,
        ));
    }
    for (index, group) in previous.iter().enumerate() {
        if !connected.contains(&index) {
            entries.push(GroupHistory {
                state: AuditState::Resolved,
                lineage: lineage_of(group),
                current: None,
                previous: Some(group.reference()),
                shared_content: 0,
                overlap: 0.0,
                parents: 0,
                siblings: 0,
                relocations: Vec::new(),
            });
        }
    }
    sort_entries(&mut entries);
    edges.sort_by(|a, b| {
        a.previous
            .as_bytes()
            .cmp(b.previous.as_bytes())
            .then_with(|| a.current.as_bytes().cmp(b.current.as_bytes()))
    });
    AuditDiff { entries, edges }
}

/// Every previous group sharing enough content with `group` to be its past.
fn candidates_for(
    group: &GroupSnapshot,
    previous: &[GroupSnapshot],
    previous_contents: &[BTreeSet<FragmentFingerprint>],
    holders: &BTreeMap<FragmentFingerprint, Vec<usize>>,
) -> Vec<Candidate> {
    let contents = group.contents();
    let mut shared_counts: BTreeMap<usize, usize> = BTreeMap::new();
    for content in &contents {
        for index in holders.get(content).into_iter().flatten() {
            *shared_counts.entry(*index).or_default() += 1;
        }
    }
    shared_counts
        .into_iter()
        .filter_map(|(index, shared)| {
            let theirs = &previous_contents[index];
            let smaller = theirs.len().min(contents.len());
            let union = theirs.len() + contents.len() - shared;
            let overlap = ratio(shared, smaller);
            if overlap < LINEAGE_MIN_OVERLAP {
                return None;
            }
            Some(Candidate {
                previous: index,
                shared,
                overlap,
                jaccard: ratio(shared, union),
                canonical_match: group.canonical.is_some()
                    && group.canonical == previous[index].canonical,
            })
        })
        .collect()
}

/// Settle one current group's state against the parent it was matched to.
fn judge(
    group: &GroupSnapshot,
    primary: Option<&Candidate>,
    previous: &[GroupSnapshot],
    children: &BTreeMap<usize, usize>,
    parents: usize,
) -> GroupHistory {
    let Some(candidate) = primary else {
        return GroupHistory {
            state: AuditState::New,
            lineage: group_lineage_id(&group.fingerprint),
            current: Some(group.reference()),
            previous: None,
            shared_content: 0,
            overlap: 0.0,
            parents: 0,
            siblings: 0,
            relocations: Vec::new(),
        };
    };
    let parent = &previous[candidate.previous];
    let state = transition(parent, group);
    GroupHistory {
        state,
        lineage: lineage_of(parent),
        current: Some(group.reference()),
        previous: Some(parent.reference()),
        shared_content: candidate.shared,
        overlap: candidate.overlap,
        parents,
        siblings: children.get(&candidate.previous).copied().unwrap_or(1),
        relocations: if state == AuditState::Moved {
            relocations(parent, group)
        } else {
            Vec::new()
        },
    }
}

/// Which of the connected states describes the step from `previous` to
/// `current`.
///
/// The order of the tests is the report's order of precedence, and it is
/// fixed: a group can satisfy several at once, and the reader is told the most
/// consequential one. A changed classification comes first because it explains
/// why the identifier moved at all and warns that comparisons across it rest
/// on less. Growth outranks shrinkage because spreading duplication is the
/// news, and both outrank divergence and relocation, which describe a group
/// that stayed the size it was. Every entry carries both sides' counts and
/// scores, so the facts the precedence did not name are still on the page.
fn transition(previous: &GroupSnapshot, current: &GroupSnapshot) -> AuditState {
    if previous.clone_type != current.clone_type || previous.scope != current.scope {
        return AuditState::Reclassified;
    }
    if current.members.len() > previous.members.len() {
        return AuditState::Expanded;
    }
    if current.members.len() < previous.members.len() {
        return AuditState::Reduced;
    }
    if previous.contents() != current.contents() {
        return AuditState::Diverged;
    }
    if previous.anchors() == current.anchors() {
        AuditState::Unchanged
    } else {
        AuditState::Moved
    }
}

/// Pair up where each content was with where it now is.
///
/// Called only when the two groups hold the same contents in the same numbers,
/// so anchors pair off within one content. Occurrences of identical content
/// have nothing to tell them apart by, so the pairing has to come from
/// somewhere else: places present on both sides are matched to themselves
/// first, and only what is left over is paired in sorted order. Without that,
/// one occurrence moving out of a group of copies reads as every occurrence
/// moving — each shunted onto the next one's address.
fn relocations(previous: &GroupSnapshot, current: &GroupSnapshot) -> Vec<Relocation> {
    let before = by_content(previous);
    let after = by_content(current);
    let mut moves = Vec::new();
    for (content, from_anchors) in before {
        let Some(to_anchors) = after.get(&content) else {
            continue;
        };
        let mut arrivals: Vec<&Anchor> = to_anchors.iter().collect();
        let mut departures = Vec::new();
        for from in from_anchors {
            match arrivals.iter().position(|to| **to == from) {
                Some(index) => {
                    arrivals.remove(index);
                }
                None => departures.push(from),
            }
        }
        for (from, to) in departures.into_iter().zip(arrivals) {
            moves.push(Relocation {
                from,
                to: to.clone(),
            });
        }
    }
    moves
}

/// A group's anchors grouped by the content sitting at them, each list sorted
/// so two groups describe one placement identically.
fn by_content(group: &GroupSnapshot) -> BTreeMap<FragmentFingerprint, Vec<Anchor>> {
    let mut map: BTreeMap<FragmentFingerprint, Vec<Anchor>> = BTreeMap::new();
    for member in &group.members {
        map.entry(member.content)
            .or_default()
            .push(member.anchor.clone());
    }
    for anchors in map.values_mut() {
        anchors.sort();
    }
    map
}

/// The history a group belongs to: the one it already carried, or a fresh one
/// starting at its own fingerprint.
fn lineage_of(group: &GroupSnapshot) -> GroupLineageId {
    group
        .lineage
        .unwrap_or_else(|| group_lineage_id(&group.fingerprint))
}

/// Report order: by state, then by whichever fingerprint the entry has, so one
/// pair of runs always yields one listing.
fn sort_entries(entries: &mut [GroupHistory]) {
    let rank = |state: AuditState| {
        AuditState::all()
            .iter()
            .position(|candidate| *candidate == state)
            .unwrap_or(usize::MAX)
    };
    entries.sort_by(|a, b| {
        rank(a.state).cmp(&rank(b.state)).then_with(|| {
            let key = |entry: &GroupHistory| {
                entry
                    .current
                    .or(entry.previous)
                    .map(|reference| *reference.fingerprint.as_bytes())
                    .unwrap_or_default()
            };
            key(a).cmp(&key(b))
        })
    });
}

/// `numerator / denominator`, answering zero for an empty denominator rather
/// than a non-number that would poison every later comparison.
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)] // group sizes are far below 2^53
    {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn content(tag: u8) -> FragmentFingerprint {
        FragmentFingerprint::from_bytes([tag; 16])
    }

    fn anchor(file: &str, unit: &str) -> Anchor {
        Anchor {
            file: file.to_string(),
            unit: Some(unit.to_string()),
        }
    }

    /// A group whose members are `(content tag, file, unit)`, fingerprinted
    /// from its tag so tests can name it.
    fn group(tag: u8, members: &[(u8, &str, &str)]) -> GroupSnapshot {
        GroupSnapshot {
            fingerprint: CloneGroupFingerprint::from_bytes([tag; 16]),
            clone_type: CloneClass::Type2,
            scope: CloneScope::Unit,
            score: 1.0,
            canonical: members.first().map(|(tag, _, _)| content(*tag)),
            lineage: None,
            members: members
                .iter()
                .map(|(tag, file, unit)| MemberSnapshot {
                    content: content(*tag),
                    anchor: anchor(file, unit),
                })
                .collect(),
        }
    }

    fn states(diff: &AuditDiff) -> Vec<AuditState> {
        diff.entries.iter().map(|entry| entry.state).collect()
    }

    #[test]
    fn a_tree_nobody_touched_reports_every_group_unchanged() {
        let before = vec![group(1, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];
        let after = before.clone();

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Unchanged]);
        assert!(diff.is_unchanged());
        assert!((diff.entries[0].overlap - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_first_audit_has_nothing_to_be_unchanged_against() {
        let after = vec![group(1, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];
        let diff = diff(&[], &after);

        assert_eq!(states(&diff), vec![AuditState::New]);
        assert!(diff.entries[0].previous.is_none());
        assert!(diff.edges.is_empty());
    }

    #[test]
    fn duplication_that_went_away_is_reported_as_resolved() {
        let before = vec![group(1, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];
        let diff = diff(&before, &[]);

        assert_eq!(states(&diff), vec![AuditState::Resolved]);
        assert!(diff.entries[0].current.is_none());
        assert_eq!(diff.entries[0].previous.map(|r| r.members), Some(2));
    }

    #[test]
    fn a_file_rename_is_a_move_and_not_a_new_finding() {
        // Identical content, identical count, one member at a new path. The
        // group fingerprint cannot see this — it is derived from content — so
        // only the anchors distinguish it from an unchanged group.
        let before = vec![group(1, &[(10, "old.rs", "one"), (10, "b.rs", "two")])];
        let after = vec![group(1, &[(10, "new.rs", "one"), (10, "b.rs", "two")])];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Moved]);
        let relocations = &diff.entries[0].relocations;
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].from.file, "old.rs");
        assert_eq!(relocations[0].to.file, "new.rs");
    }

    #[test]
    fn one_copy_moving_does_not_read_as_every_copy_moving() {
        // Three identical copies; one changes address. Pairing the anchors in
        // sorted order would shunt each onto the next one's place and report
        // three moves, all but one of them invented.
        let before = vec![group(
            1,
            &[(10, "a.rs", "one"), (10, "b.rs", "two"), (10, "z.rs", "3")],
        )];
        let after = vec![group(
            1,
            &[(10, "a.rs", "one"), (10, "b.rs", "two"), (10, "m.rs", "3")],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Moved]);
        let relocations = &diff.entries[0].relocations;
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].from.file, "z.rs");
        assert_eq!(relocations[0].to.file, "m.rs");
    }

    #[test]
    fn a_clone_that_spread_to_another_file_is_expanded() {
        let before = vec![group(1, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];
        let after = vec![group(
            2,
            &[(10, "a.rs", "one"), (10, "b.rs", "two"), (10, "c.rs", "3")],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Expanded]);
        assert_eq!(diff.entries[0].current.map(|r| r.members), Some(3));
        assert_eq!(diff.entries[0].previous.map(|r| r.members), Some(2));
    }

    #[test]
    fn another_copy_of_content_already_in_the_group_still_expands_it() {
        // The group fingerprint folds in the deduplicated content set, so a
        // third occurrence of content the group already holds leaves it
        // untouched. Reading the fingerprint alone would call this unchanged;
        // it is the case that forces occurrence counts into the comparison.
        let before = vec![group(1, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];
        let after = vec![group(
            1,
            &[(10, "a.rs", "one"), (10, "b.rs", "two"), (10, "c.rs", "3")],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Expanded]);
        assert!((diff.entries[0].overlap - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn removing_one_copy_of_three_reduces_the_group() {
        let before = vec![group(
            1,
            &[(10, "a.rs", "one"), (10, "b.rs", "two"), (10, "c.rs", "3")],
        )];
        let after = vec![group(2, &[(10, "a.rs", "one"), (10, "b.rs", "two")])];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Reduced]);
    }

    #[test]
    fn editing_one_copy_of_a_pair_keeps_the_history_and_reports_divergence() {
        // The case the overlap measure exists for: the group keeps one of its
        // two contents, a Jaccard of one third, and the two runs would look
        // unrelated under it.
        let before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let after = vec![group(2, &[(10, "a.rs", "one"), (12, "b.rs", "two")])];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Diverged]);
        assert_eq!(diff.entries[0].shared_content, 1);
        assert!((diff.entries[0].overlap - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn editing_both_copies_of_a_pair_leaves_nothing_to_connect_them_by() {
        let before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let after = vec![group(2, &[(12, "a.rs", "one"), (13, "b.rs", "two")])];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::New, AuditState::Resolved]);
    }

    #[test]
    fn a_group_whose_classification_changed_is_reported_as_reclassified() {
        let before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let mut after = before.clone();
        after[0].clone_type = CloneClass::Type3;
        after[0].fingerprint = CloneGroupFingerprint::from_bytes([2; 16]);

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Reclassified]);
    }

    #[test]
    fn a_change_of_member_scope_is_a_reclassification_too() {
        // Whole duplicated units and a duplicated stretch inside unrelated
        // units say different things about the code; the group is not the same
        // finding when that changes, even at the same size.
        let before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let mut after = before.clone();
        after[0].scope = CloneScope::Fragment;

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Reclassified]);
    }

    #[test]
    fn a_group_that_split_leaves_both_pieces_attached_to_its_history() {
        let before = vec![group(
            1,
            &[
                (10, "a.rs", "one"),
                (11, "b.rs", "two"),
                (12, "c.rs", "three"),
                (13, "d.rs", "four"),
            ],
        )];
        let after = vec![
            group(2, &[(10, "a.rs", "one"), (11, "b.rs", "two")]),
            group(3, &[(12, "c.rs", "three"), (13, "d.rs", "four")]),
        ];

        let diff = diff(&before, &after);
        assert_eq!(
            states(&diff),
            vec![AuditState::Reduced, AuditState::Reduced]
        );
        // Both pieces descend from the one group, and both say so.
        assert!(diff.entries.iter().all(|entry| entry.siblings == 2));
        let lineage = diff.entries[0].lineage;
        assert!(diff.entries.iter().all(|entry| entry.lineage == lineage));
        assert_eq!(diff.edges.len(), 2);
        assert!(diff.edges.iter().all(|edge| edge.primary));
    }

    #[test]
    fn two_groups_that_merged_are_one_group_with_two_parents() {
        let before = vec![
            group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")]),
            group(2, &[(12, "c.rs", "three"), (13, "d.rs", "four")]),
        ];
        let after = vec![group(
            3,
            &[
                (10, "a.rs", "one"),
                (11, "b.rs", "two"),
                (12, "c.rs", "three"),
                (13, "d.rs", "four"),
            ],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Expanded]);
        assert_eq!(diff.entries[0].parents, 2);
        assert_eq!(diff.edges.len(), 2);
        assert_eq!(diff.edges.iter().filter(|edge| edge.primary).count(), 1);
    }

    #[test]
    fn a_history_already_recorded_carries_forward_rather_than_restarting() {
        let origin = group_lineage_id(&CloneGroupFingerprint::from_bytes([9; 16]));
        let mut before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        before[0].lineage = Some(origin);
        let after = vec![group(
            2,
            &[(10, "a.rs", "one"), (11, "b.rs", "two"), (11, "c.rs", "3")],
        )];

        let diff = diff(&before, &after);
        assert_eq!(diff.entries[0].lineage, origin);
    }

    #[test]
    fn a_new_group_starts_its_history_at_its_own_fingerprint() {
        let after = vec![group(7, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let diff = diff(&[], &after);

        assert_eq!(
            diff.entries[0].lineage,
            group_lineage_id(&CloneGroupFingerprint::from_bytes([7; 16]))
        );
    }

    #[test]
    fn one_surviving_copy_out_of_four_is_too_thin_to_be_a_history() {
        // Below half of the smaller group the connection is dropped rather
        // than reported weakly: one content out of four surviving says the old
        // duplication is gone and a different one is here, not that the old
        // one changed.
        let before = vec![group(
            1,
            &[
                (10, "a.rs", "one"),
                (11, "b.rs", "two"),
                (12, "c.rs", "three"),
                (13, "d.rs", "four"),
            ],
        )];
        let after = vec![group(
            2,
            &[
                (10, "a.rs", "one"),
                (20, "x.rs", "x"),
                (21, "y.rs", "y"),
                (22, "z.rs", "z"),
            ],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::New, AuditState::Resolved]);
    }

    #[test]
    fn a_pairs_surviving_copy_connects_it_onward_and_says_how_thinly() {
        // Half of a two-member group is one content, the weakest connection
        // the measure can express, and the same number that keeps an edited
        // pair attached to its past. It is kept, and the entry carries how
        // little it rests on so the reader can discount it.
        let before = vec![group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")])];
        let after = vec![group(
            2,
            &[
                (10, "a.rs", "one"),
                (20, "x.rs", "x"),
                (21, "y.rs", "y"),
                (22, "z.rs", "z"),
            ],
        )];

        let diff = diff(&before, &after);
        assert_eq!(states(&diff), vec![AuditState::Expanded]);
        assert_eq!(diff.entries[0].shared_content, 1);
        assert!((diff.entries[0].overlap - LINEAGE_MIN_OVERLAP).abs() < f64::EPSILON);
    }

    #[test]
    fn the_same_two_runs_always_produce_the_same_listing() {
        let before = vec![
            group(1, &[(10, "a.rs", "one"), (11, "b.rs", "two")]),
            group(2, &[(20, "c.rs", "three"), (21, "d.rs", "four")]),
        ];
        let after = vec![
            group(3, &[(30, "e.rs", "five"), (31, "f.rs", "six")]),
            group(2, &[(20, "c.rs", "three"), (21, "d.rs", "four")]),
        ];

        let forward = diff(&before, &after);
        let reordered = diff(
            &[before[1].clone(), before[0].clone()],
            &[after[1].clone(), after[0].clone()],
        );
        assert_eq!(forward, reordered);
    }

    #[test]
    fn every_state_has_one_stable_name_and_the_listing_leads_with_the_urgent() {
        assert_eq!(AuditState::New.name(), "new");
        assert_eq!(AuditState::Reclassified.name(), "reclassified");
        assert_eq!(AuditState::all().len(), 8);
        assert_eq!(AuditState::all()[0], AuditState::New);
        assert!(AuditState::Expanded.needs_attention());
        assert!(!AuditState::Moved.needs_attention());
        assert!(!AuditState::Resolved.needs_attention());
    }
}
