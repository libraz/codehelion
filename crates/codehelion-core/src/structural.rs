//! Structural-mode analysis: the whole Type-2/Type-3 pipeline, wired end to
//! end over already-parsed IR.
//!
//! The stages each live in their own module; this one composes them into the
//! funnel the mode runs:
//!
//! 1. [`crate::features`] turns each file's IR into candidate-extraction
//!    features (statement windows, subtrees, characteristic vector, approximate
//!    CFG, API calls);
//! 2. [`crate::candidate`] seeds exact-hash fragment pairs and [`crate::near_match`]
//!    proposes near-clone unit pairs by MinHash/LSH — both over-approximate
//!    cheaply, and both are lifted here to *unit* pairs;
//! 3. [`crate::maximal`] folds the sliding-window seeds back into the maximal
//!    shared statement runs they describe, so a duplicated block is one region
//!    rather than a fan of overlapping window matches;
//! 4. [`crate::verify`] judges each distinct unit pair precisely, keeping only
//!    the ones that clear the clone threshold;
//! 5. [`crate::grouping`] turns the surviving pairs into cohesive medoid groups,
//!    so non-transitive Type-3 chains do not fuse.
//!
//! Regions and groups answer different questions and neither replaces the
//! other: a group says two whole units are copies of each other, a region says
//! one stretch of statements is shared, which happens between units that are
//! not copies at all.
//!
//! Every unit carries its raw [`UnitFingerprint`] as its stable, position-free
//! grouping key ([`crate::stable_id`]). The whole function is deterministic: the
//! unit order follows the IR walk, candidate pairs are deduplicated through an
//! ordered set, and grouping orders its own output. Nothing here executes target
//! code — it only reads IR that was already produced from source.

use std::collections::{BTreeMap, BTreeSet};

use crate::boilerplate::{self, Boilerplate};
use crate::candidate::{self, CandidateConfig, CandidateStats};
use crate::clone_class::CloneClass;
use crate::discovery::BuildVariant;
use crate::engine::LiteralNorm;
use crate::features::{self, FileFeatures};
use crate::frontend::{Lexeme, Token, UnitKind};
use crate::grouping::{
    self, GroupingConfig, GroupingSet, GroupingStats, GroupingUnit, SimilarityEdge,
};
use crate::ir::{ByteRange, IrNode, Shape, SyntaxIrFile};
use crate::maximal::{self, MaximalConfig, RegionSide, RegionStats, SharedRegion};
use crate::near_match::{self, NearMatchConfig, NearMatchStats};
use crate::stable_id::{
    self, CloneGroupFingerprint, ContentNorm, FileContext, FragmentFingerprint, UnitFingerprint,
};
use crate::test_code;
use crate::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};

/// Tuning for a whole structural run: one config per stage.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StructuralConfig {
    /// Exact-seed candidate extraction.
    pub candidate: CandidateConfig,
    /// MinHash/LSH near-match extraction.
    pub near_match: NearMatchConfig,
    /// Folding seed matches into maximal shared runs.
    pub maximal: MaximalConfig,
    /// Literal strategy the duplicated runs are confirmed under: it decides
    /// whether two runs differing only in literal values are the same run.
    pub literals: LiteralNorm,
    /// Precise verification.
    pub verify: VerifyConfig,
    /// Medoid grouping.
    pub grouping: GroupingConfig,
}

/// One analysed unit, kept so a caller can map a group's member indices back to
/// source locations. The index of a unit in [`StructuralReport::units`] is the
/// index grouping refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralUnit {
    /// Index of the file this unit belongs to (into the input slice).
    pub file: usize,
    /// What kind of unit this is; reporting only.
    pub kind: UnitKind,
    /// Source bytes the unit covers; reporting only.
    pub range: ByteRange,
    /// 1-based first line; reporting only, never an identity input.
    pub start_line: u32,
    /// 1-based last line; reporting only, never an identity input.
    pub end_line: u32,
    /// Index of the unit's first token in its file's stream.
    pub token_start: usize,
    /// Index one past the unit's last token in its file's stream.
    pub token_end: usize,
    /// The unit's declared name, when the frontend recovered one.
    pub name: Option<Lexeme>,
    /// The boilerplate shape the unit matches, when it matches one. Recorded,
    /// not acted on: a classified unit is analysed and grouped like any other.
    pub boilerplate: Option<Boilerplate>,
    /// Whether the unit is test code: marked as a test itself, or sitting
    /// inside an item that is. Recorded, not acted on, as `boilerplate` is.
    pub test_code: bool,
    /// The unit's raw content fingerprint: its stable grouping key and unit
    /// identity.
    pub fingerprint: UnitFingerprint,
    /// The unit's content fingerprint in fragment form, used as its member
    /// content id when composing a group fingerprint (a whole-unit clone is a
    /// fragment spanning the unit; keeping this as a fragment fingerprint keeps
    /// the group id forward-compatible with sub-unit members).
    pub content: FragmentFingerprint,
}

/// Reporting detail for one clone group, parallel to the group at the same
/// index in [`StructuralReport::groups`].
#[derive(Debug, Clone, PartialEq)]
pub struct GroupDetail {
    /// The group's stable, position-free fingerprint (its clone id).
    pub fingerprint: CloneGroupFingerprint,
    /// The similarity breakdown of the medoid against each member, parallel to
    /// the group's `members` (the medoid's own entry is a perfect self-match).
    pub member_breakdowns: Vec<SimilarityBreakdown>,
    /// The boilerplate shape the whole group matches, when every member
    /// matches the same one. A group whose members disagree is not boilerplate:
    /// at least one occurrence carries behaviour the others share.
    pub boilerplate: Option<Boilerplate>,
    /// Whether every member is test code. A group with even one member outside
    /// the suite is duplication between test and tested code, which is the
    /// interesting case and must not be ranked with the suite.
    pub test_code: bool,
}

/// One occurrence of a duplicated statement run, resolved against the source
/// it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionOccurrence {
    /// Index of the file this occurrence sits in.
    pub file: usize,
    /// Index of the enclosing unit in [`StructuralReport::units`].
    pub unit: usize,
    /// Source bytes the run covers; reporting only.
    pub range: ByteRange,
    /// 1-based first line; reporting only, never an identity input.
    pub start_line: u32,
    /// 1-based last line; reporting only, never an identity input.
    pub end_line: u32,
    /// Index of the run's first token in its file's stream.
    pub token_start: usize,
    /// Index one past the run's last token in its file's stream.
    pub token_end: usize,
    /// The occurrence's raw content fingerprint: its member content id.
    pub content: FragmentFingerprint,
}

/// A duplicated run of statements and every place it occurs.
///
/// Unlike a [`GroupDetail`], whose members are only *similar*, every
/// occurrence here holds the same content under the group's classification:
/// the same tokens for [`CloneClass::Type1`], the same tokens up to consistent
/// renaming for [`CloneClass::Type2`]. The enclosing units need not be clones
/// of each other — that is the point of reporting runs separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralRegion {
    /// The run's stable, position-free clone-group fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// How the occurrences match: verbatim or up to renaming.
    pub clone_type: CloneClass,
    /// Length of the run, in statements.
    pub statements: u32,
    /// Where the run occurs, at least twice, in ascending source order.
    pub occurrences: Vec<RegionOccurrence>,
}

/// Funnel counters across the whole run: how many fragments, candidate pairs
/// and verified pairs each stage saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuralStats {
    /// Files analysed.
    pub files: usize,
    /// Units across all files.
    pub units: usize,
    /// Exact-seed candidate extraction statistics.
    pub candidate: CandidateStats,
    /// Near-match extraction statistics.
    pub near_match: NearMatchStats,
    /// Maximal-region consolidation statistics.
    pub maximal: RegionStats,
    /// Duplicated runs confirmed against the source tokens.
    pub regions: usize,
    /// Occurrences dropped for holding content no other occurrence of their
    /// candidate run shared: the statement summaries agreed but the code did
    /// not.
    pub region_singletons: usize,
    /// Confirmed runs dropped because a longer run covers every one of their
    /// occurrences and claims at least as much about them.
    pub region_subsumed: usize,
    /// Distinct unit pairs handed to verification.
    pub unit_pairs: usize,
    /// Unit pairs that verification accepted as clones.
    pub verified_pairs: usize,
    /// Grouping statistics.
    pub grouping: GroupingStats,
}

/// The structural run's output: cohesive groups over [`Self::units`], plus the
/// funnel statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralReport {
    /// Analysed units; a group's member indices index this slice.
    pub units: Vec<StructuralUnit>,
    /// Cohesive clone groups.
    pub groups: GroupingSet,
    /// Duplicated statement runs, each with every place it occurs. The units
    /// involved need not be clones of each other: this is the sub-unit view of
    /// the same corpus.
    pub regions: Vec<StructuralRegion>,
    /// Reporting detail per group, parallel to `groups.groups`: stable clone id
    /// and the medoid-to-member similarity breakdowns.
    pub details: Vec<GroupDetail>,
    /// Funnel statistics.
    pub stats: StructuralStats,
}

/// One analysed unit's data, held together for verification and grouping.
struct Unit {
    file: usize,
    local: usize,
    kind: UnitKind,
    statements: Vec<crate::ir::StatementSummary>,
    fingerprint: UnitFingerprint,
    content: FragmentFingerprint,
    range: ByteRange,
    lines: (u32, u32),
    tokens: (usize, usize),
    name: Option<Lexeme>,
    boilerplate: Option<Boilerplate>,
    test_code: bool,
}

/// Run the structural pipeline over parsed IR files.
///
/// The result is a pure, deterministic function of the inputs and the build
/// variant.
#[must_use]
pub fn analyze(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> StructuralReport {
    let feature_files: Vec<FileFeatures> = files.iter().map(features::extract).collect();

    let (units, offsets) = flatten_units(files, variant);

    // Stage: candidate extraction (exact seeds + near matches), lifted to
    // distinct unit pairs.
    let candidate = candidate::generate(&feature_files, &config.candidate);
    let near = near_match::generate(&feature_files, &config.near_match);
    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    for pair in &candidate.pairs {
        insert_pair(
            &mut pairs,
            &offsets,
            pair.a.file,
            pair.a.unit,
            pair.b.file,
            pair.b.unit,
        );
    }
    for pair in &near.pairs {
        insert_pair(
            &mut pairs,
            &offsets,
            pair.a.file,
            pair.a.unit,
            pair.b.file,
            pair.b.unit,
        );
    }

    // Stage: fold the window seeds into the maximal shared runs they describe,
    // then confirm each candidate run against the tokens it actually covers.
    let candidate_regions = maximal::consolidate(&candidate.pairs, &config.maximal);
    let (mut regions, singletons) = confirm_regions(
        &candidate_regions.shared,
        files,
        &offsets,
        variant,
        config.literals,
    );
    let subsumed = drop_subsumed(&mut regions);

    // Stage: precise verification of each distinct unit pair.
    let mut edges: Vec<SimilarityEdge> = Vec::new();
    for &(a, b) in &pairs {
        let view_a = view(&units[a], files, &feature_files);
        let view_b = view(&units[b], files, &feature_files);
        let verdict = verify::verify(&view_a, &view_b, &config.verify);
        if let (Some(class), Some(confidence)) = (verdict.class, verdict.confidence) {
            edges.push(SimilarityEdge {
                a,
                b,
                similarity: verdict.breakdown.composite,
                class,
                confidence,
            });
        }
    }

    // Stage: medoid grouping over the verified pairs.
    let grouping_units: Vec<GroupingUnit> = units
        .iter()
        .map(|unit| GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect();
    let groups = grouping::group(&grouping_units, &edges, &config.grouping);

    // Per-group reporting detail: the stable clone id and the medoid-to-member
    // similarity breakdowns (re-run against the chosen medoid, deterministic).
    let details: Vec<GroupDetail> = groups
        .groups
        .iter()
        .map(|group| group_detail(group, &units, files, &feature_files, variant, config))
        .collect();

    let stats = StructuralStats {
        files: files.len(),
        units: units.len(),
        candidate: candidate.stats,
        near_match: near.stats,
        maximal: candidate_regions.stats,
        regions: regions.len(),
        region_singletons: singletons,
        region_subsumed: subsumed,
        unit_pairs: pairs.len(),
        verified_pairs: edges.len(),
        grouping: groups.stats.clone(),
    };

    let report_units = units
        .iter()
        .map(|unit| StructuralUnit {
            file: unit.file,
            kind: unit.kind,
            range: unit.range,
            start_line: unit.lines.0,
            end_line: unit.lines.1,
            token_start: unit.tokens.0,
            token_end: unit.tokens.1,
            name: unit.name.clone(),
            boilerplate: unit.boilerplate,
            test_code: unit.test_code,
            fingerprint: unit.fingerprint,
            content: unit.content,
        })
        .collect();

    StructuralReport {
        units: report_units,
        groups,
        regions,
        details,
        stats,
    }
}

/// Confirm each candidate run against the tokens it covers, and split it into
/// the classes that genuinely hold the same content.
///
/// A candidate run comes from statement-window hashes, and a statement summary
/// is its shape plus its leading token *kinds*. `let a = foo(x);` and
/// `let b = bar(y, z);` therefore summarise identically, so a candidate run is
/// a proposal about where duplication might be, not a finding. The proposal is
/// settled here by hashing the tokens themselves: occurrences that agree up to
/// consistent renaming form a [`CloneClass::Type2`] region, and one whose
/// tokens agree outright is [`CloneClass::Type1`]. An occurrence left without a
/// partner is dropped and counted — the summaries agreed, the code did not.
fn confirm_regions(
    candidates: &[SharedRegion],
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> (Vec<StructuralRegion>, usize) {
    let mut regions = Vec::new();
    let mut singletons = 0usize;
    for candidate in candidates {
        // Occurrences whose normalized content agrees are the same run up to
        // renaming; that is the coarsest claim this stage is willing to make.
        let mut classes: BTreeMap<FragmentFingerprint, Vec<RegionOccurrence>> = BTreeMap::new();
        for &side in &candidate.occurrences {
            let Some((occurrence, normalized)) =
                resolve_occurrence(side, files, offsets, variant, literals)
            else {
                singletons += 1;
                continue;
            };
            classes.entry(normalized).or_default().push(occurrence);
        }
        for occurrences in classes.into_values() {
            if occurrences.len() < 2 {
                singletons += occurrences.len();
                continue;
            }
            let contents: Vec<FragmentFingerprint> =
                occurrences.iter().map(|entry| entry.content).collect();
            // Identical raw content everywhere means the copies differ in
            // nothing but whitespace and comments.
            let clone_type = if contents.iter().all(|&content| content == contents[0]) {
                CloneClass::Type1
            } else {
                CloneClass::Type2
            };
            regions.push(StructuralRegion {
                fingerprint: stable_id::clone_group_fingerprint(variant, clone_type, &contents),
                clone_type,
                statements: candidate.statements,
                occurrences,
            });
        }
    }
    // Position-free order: two runs are told apart by content, never by where
    // they happen to sit.
    regions.sort_by(|a, b| {
        a.fingerprint
            .cmp(&b.fingerprint)
            .then_with(|| a.clone_type.name().cmp(b.clone_type.name()))
    });
    regions.dedup_by(|a, b| a.fingerprint == b.fingerprint && a.occurrences == b.occurrences);
    (regions, singletons)
}

/// Drop the runs a longer run already accounts for, returning how many went.
///
/// The window lengths overlap by construction, so one duplicated stretch
/// surfaces as a family of runs: the same eight statements confirm at length
/// eight, and their first six confirm again with whatever extra copies share
/// only those six. A run is dropped when *every* one of its occurrences sits
/// inside an occurrence of another run — the covering run reports the same
/// code in the same places, and more of it.
///
/// Coverage alone is not enough. A verbatim run nested inside a longer run
/// that only matches up to renaming makes the stronger claim of the two:
/// "these eight statements match up to renaming, and these six of them match
/// verbatim" is two facts, not one repeated. So a run is only dropped by a
/// cover that classifies at least as strictly, [`CloneClass`] ordering running
/// from exact to gapped.
fn drop_subsumed(regions: &mut Vec<StructuralRegion>) -> usize {
    let before = regions.len();
    // Widest cover first, so a run is judged against the longest thing that
    // could account for it before anything shorter is considered.
    let mut order: Vec<usize> = (0..regions.len()).collect();
    order.sort_by_key(|&index| {
        (
            std::cmp::Reverse(regions[index].statements),
            regions[index].fingerprint,
        )
    });

    let mut dropped = vec![false; regions.len()];
    for (rank, &inner) in order.iter().enumerate() {
        // Only wider runs, and among equals only those already settled, can
        // cover this one: a pair of runs covering each other must not remove
        // both.
        if order[..rank]
            .iter()
            .any(|&outer| !dropped[outer] && covers_run(&regions[outer], &regions[inner]))
        {
            dropped[inner] = true;
        }
    }
    *regions = std::mem::take(regions)
        .into_iter()
        .zip(&dropped)
        .filter_map(|(region, &drop)| (!drop).then_some(region))
        .collect();
    before - regions.len()
}

/// Whether `outer` accounts for every occurrence of `inner`.
fn covers_run(outer: &StructuralRegion, inner: &StructuralRegion) -> bool {
    if outer.fingerprint == inner.fingerprint || outer.clone_type > inner.clone_type {
        return false;
    }
    inner.occurrences.iter().all(|occurrence| {
        outer.occurrences.iter().any(|cover| {
            cover.file == occurrence.file
                && cover.range.start <= occurrence.range.start
                && occurrence.range.end <= cover.range.end
        })
    })
}

/// Resolve one candidate occurrence into its tokens, returning the reportable
/// occurrence and its normalized content fingerprint (the class key).
fn resolve_occurrence(
    side: RegionSide,
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> Option<(RegionOccurrence, FragmentFingerprint)> {
    let file = files.get(side.file)?;
    let (start, end) = token_span(&file.tokens, side.range);
    if start >= end {
        return None;
    }
    let tokens = &file.tokens[start..end];
    let context = FileContext {
        frontend_version: file.frontend_version,
        language: file.language,
    };
    let fingerprint =
        |norm| stable_id::fragment_fingerprint(variant, &context, "statement-run", tokens, norm);
    let lines = line_range(tokens);
    Some((
        RegionOccurrence {
            file: side.file,
            unit: offsets[side.file] + side.unit,
            range: side.range,
            start_line: lines.0,
            end_line: lines.1,
            token_start: start,
            token_end: end,
            content: fingerprint(ContentNorm::Raw),
        },
        fingerprint(ContentNorm::Normalized(literals)),
    ))
}

/// The half-open token index range fully inside a byte range. Tokens are in
/// source order, so both ends are found by binary search.
fn token_span(tokens: &[Token], range: ByteRange) -> (usize, usize) {
    let start = tokens.partition_point(|token| token.span.start_byte < range.start);
    let end = tokens.partition_point(|token| token.span.end_byte <= range.end);
    (start, end.max(start))
}

/// Compute one group's reporting detail: its stable clone fingerprint (anchored
/// on the medoid's content, folding the member set) and the medoid-to-member
/// similarity breakdowns.
fn group_detail(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> GroupDetail {
    let medoid_view = view(&units[group.canonical], files, feature_files);
    let member_breakdowns = group
        .members
        .iter()
        .map(|&member| {
            verify::verify(
                &medoid_view,
                &view(&units[member], files, feature_files),
                &config.verify,
            )
            .breakdown
        })
        .collect();

    let member_contents: Vec<FragmentFingerprint> =
        group.members.iter().map(|&m| units[m].content).collect();
    let fingerprint = stable_id::structural_clone_group_fingerprint(
        variant,
        group.clone_type,
        &units[group.canonical].content,
        &member_contents,
    );

    GroupDetail {
        fingerprint,
        member_breakdowns,
        boilerplate: unanimous_boilerplate(group, units),
        test_code: group.members.iter().all(|&member| units[member].test_code),
    }
}

/// The boilerplate category every member of a group shares, or `None` when
/// they do not all share one.
fn unanimous_boilerplate(group: &grouping::StructuralGroup, units: &[Unit]) -> Option<Boilerplate> {
    let mut members = group
        .members
        .iter()
        .map(|&member| units[member].boilerplate);
    let first = members.next().flatten()?;
    members
        .all(|category| category == Some(first))
        .then_some(first)
}

/// Flatten every file's units into one global list, in IR-walk order, and
/// record each file's starting offset. The unit order matches
/// [`features::extract`]'s, so a `(file, local)` index pair maps to the global
/// index `offsets[file] + local`.
fn flatten_units(files: &[SyntaxIrFile], variant: &BuildVariant) -> (Vec<Unit>, Vec<usize>) {
    let mut units = Vec::new();
    let mut offsets = Vec::with_capacity(files.len());
    for (file_index, file) in files.iter().enumerate() {
        offsets.push(units.len());
        let mut walk = UnitWalk {
            file: file_index,
            source: file,
            context: FileContext {
                frontend_version: file.frontend_version,
                language: file.language,
            },
            variant,
            local: 0,
            units: &mut units,
        };
        for root in &file.roots {
            walk.visit(root, false);
        }
    }
    (units, offsets)
}

/// A depth-first walk over one file's IR that collects its analysed units.
///
/// [`IrNode::walk`] would do for the units themselves, but a unit inherits
/// facts from the items enclosing it — a function inside a test-only module is
/// test code without carrying a marker of its own — and a flat visitor has no
/// ancestors to inherit from. The order matches [`IrNode::walk`]'s, and so
/// [`features::extract`]'s: pre-order, children in source order.
struct UnitWalk<'a> {
    file: usize,
    source: &'a SyntaxIrFile,
    context: FileContext<'a>,
    variant: &'a BuildVariant,
    local: usize,
    units: &'a mut Vec<Unit>,
}

impl UnitWalk<'_> {
    /// Visit one node, recording it when it is an analysed unit, then its
    /// children. `test_code` is what the enclosing items established.
    fn visit(&mut self, node: &IrNode, test_code: bool) {
        let end = node.token_end.min(self.source.tokens.len());
        let start = node.token_start.min(end);
        let tokens = &self.source.tokens[start..end];
        let test_code = test_code || test_code::is_marked(self.source.language, tokens);

        if let Some(kind) = unit_kind(&node.shape) {
            let fingerprint =
                stable_id::unit_fingerprint(self.variant, &self.context, tokens, ContentNorm::Raw);
            let content = stable_id::fragment_fingerprint(
                self.variant,
                &self.context,
                "unit",
                tokens,
                ContentNorm::Raw,
            );
            self.units.push(Unit {
                file: self.file,
                local: self.local,
                kind,
                statements: verify::statement_sequence(node, &self.source.tokens),
                fingerprint,
                content,
                range: node.range,
                lines: line_range(tokens),
                tokens: (start, end),
                name: node.name.clone(),
                boilerplate: boilerplate::classify(node),
                test_code,
            });
            self.local += 1;
        }

        for child in &node.children {
            self.visit(child, test_code);
        }
    }
}

/// The reportable unit kind of an IR shape, or `None` for a shape that is not
/// an analysed unit. The unit shapes here are exactly the ones
/// [`features::extract`] walks, so unit indices stay aligned.
const fn unit_kind(shape: &Shape) -> Option<UnitKind> {
    match *shape {
        Shape::Function => Some(UnitKind::Function),
        Shape::Method => Some(UnitKind::Method),
        Shape::Closure => Some(UnitKind::Closure),
        _ => None,
    }
}

/// The 1-based line range a token slice covers, following the Fast engine's
/// rule: the last token's own newlines extend its end line, so a unit ending
/// in a multi-line literal reports its true last line.
fn line_range(tokens: &[Token]) -> (u32, u32) {
    let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
        return (0, 0);
    };
    let newlines = u32::try_from(last.text.matches('\n').count()).unwrap_or(0);
    (
        first.span.start_line,
        last.span.start_line.saturating_add(newlines),
    )
}

/// Build a unit's verification view from its statements, the token stream they
/// span, and its features.
fn view<'a>(
    unit: &'a Unit,
    files: &'a [SyntaxIrFile],
    feature_files: &'a [FileFeatures],
) -> UnitView<'a> {
    UnitView {
        statements: &unit.statements,
        tokens: &files[unit.file].tokens,
        features: &feature_files[unit.file].units[unit.local],
    }
}

/// Insert a `(file, unit)` pair as a global, ordered unit pair, dropping
/// self-pairs.
fn insert_pair(
    pairs: &mut BTreeSet<(usize, usize)>,
    offsets: &[usize],
    file_a: usize,
    unit_a: usize,
    file_b: usize,
    unit_b: usize,
) {
    let a = offsets[file_a] + unit_a;
    let b = offsets[file_b] + unit_b;
    if a != b {
        pairs.insert(if a <= b { (a, b) } else { (b, a) });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CloneClass, RegionOccurrence, StructuralRegion, drop_subsumed};
    use crate::ir::ByteRange;
    use crate::stable_id::{CloneGroupFingerprint, FragmentFingerprint};

    fn occurrence(file: usize, start: usize, end: usize) -> RegionOccurrence {
        RegionOccurrence {
            file,
            unit: 0,
            range: ByteRange { start, end },
            start_line: 1,
            end_line: 2,
            token_start: start,
            token_end: end,
            content: FragmentFingerprint::from_bytes([u8::try_from(start % 251).unwrap(); 16]),
        }
    }

    fn region(
        id: u8,
        clone_type: CloneClass,
        statements: u32,
        spans: &[(usize, usize, usize)],
    ) -> StructuralRegion {
        StructuralRegion {
            fingerprint: CloneGroupFingerprint::from_bytes([id; 16]),
            clone_type,
            statements,
            occurrences: spans
                .iter()
                .map(|&(file, start, end)| occurrence(file, start, end))
                .collect(),
        }
    }

    fn ids(regions: &[StructuralRegion]) -> Vec<u8> {
        regions
            .iter()
            .map(|region| region.fingerprint.as_bytes()[0])
            .collect()
    }

    #[test]
    fn a_run_every_occurrence_of_which_sits_inside_a_longer_one_goes() {
        // The window lengths overlap, so one stretch confirms at several
        // lengths. The longest reports the same code in the same places.
        let mut regions = vec![
            region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
            region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 1);
        assert_eq!(ids(&regions), vec![2]);
    }

    #[test]
    fn a_run_with_a_copy_the_longer_one_misses_stays() {
        // The third copy shares only the shorter stretch, so the longer run
        // does not account for it and both runs carry a fact of their own.
        let mut regions = vec![
            region(
                1,
                CloneClass::Type1,
                4,
                &[(0, 20, 40), (1, 120, 140), (2, 220, 240)],
            ),
            region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 0);
        assert_eq!(ids(&regions), vec![1, 2]);
    }

    #[test]
    fn a_verbatim_run_inside_a_renamed_one_keeps_its_stronger_claim() {
        // "These eight statements match up to renaming, and these four of
        // them match verbatim" is two facts. Dropping the inner one would
        // report only the weaker.
        let mut regions = vec![
            region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
            region(2, CloneClass::Type2, 8, &[(0, 10, 60), (1, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 0);
        assert_eq!(ids(&regions), vec![1, 2]);

        // The other way round the cover claims at least as much, so it wins.
        let mut regions = vec![
            region(1, CloneClass::Type2, 4, &[(0, 20, 40), (1, 120, 140)]),
            region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 1);
        assert_eq!(ids(&regions), vec![2]);
    }

    #[test]
    fn two_runs_that_cover_each_other_do_not_both_disappear() {
        let mut regions = vec![
            region(1, CloneClass::Type1, 4, &[(0, 10, 60), (1, 110, 160)]),
            region(2, CloneClass::Type1, 4, &[(0, 10, 60), (1, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 1);
        assert_eq!(regions.len(), 1);
    }

    #[test]
    fn a_run_covered_only_in_the_wrong_file_stays() {
        // Same byte offsets, different file: coverage is per occurrence, and
        // an occurrence is a place in a file.
        let mut regions = vec![
            region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
            region(2, CloneClass::Type1, 8, &[(0, 10, 60), (2, 110, 160)]),
        ];
        assert_eq!(drop_subsumed(&mut regions), 0);
        assert_eq!(ids(&regions), vec![1, 2]);
    }

    #[test]
    fn dropping_is_independent_of_the_order_the_runs_arrive_in() {
        let build = || {
            vec![
                region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
                region(2, CloneClass::Type1, 6, &[(0, 15, 50), (1, 115, 150)]),
                region(3, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
            ]
        };
        let mut forward = build();
        drop_subsumed(&mut forward);
        let mut reversed: Vec<StructuralRegion> = build().into_iter().rev().collect();
        drop_subsumed(&mut reversed);
        assert_eq!(ids(&forward), vec![3]);
        assert_eq!(ids(&reversed), vec![3]);
    }
}
