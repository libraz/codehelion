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
use crate::conditional::ArmPath;
use crate::control_flow::{self, ControlFlowConfig, ControlFlowStats};
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
use crate::substitution;
use crate::test_code;
use crate::types::{TypeEvidence, TypeTag};
use crate::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};

/// Default largest shape-mix divergence a candidate pair may span.
///
/// Chosen to say about the shape mix what
/// [`DEFAULT_MAX_LENGTH_RATIO`](crate::near_match::DEFAULT_MAX_LENGTH_RATIO)
/// says about size: at 3.0 the two sizes alone put a pair at 0.5. Measured
/// over four projects between 39 and 480 kLOC, the most divergent pair
/// verification has ever accepted sat at 0.41, and the limit takes 15% to 36%
/// of the proposals out of verification without touching a single one of them.
///
/// Removing it entirely changes no group on any corpus this project has, which
/// is what a gate that only sheds work should do. That is also why the value
/// is not tuned against results: there are none to tune it on. What would move
/// it is a measurement of what it costs to keep, not of what it finds.
pub const DEFAULT_MAX_SHAPE_DIVERGENCE: f64 = 0.5;

/// Tuning for a whole structural run: one config per stage.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralConfig {
    /// Exact-seed candidate extraction.
    pub candidate: CandidateConfig,
    /// MinHash/LSH near-match extraction.
    pub near_match: NearMatchConfig,
    /// Control-flow skeleton extraction.
    pub control_flow: ControlFlowConfig,
    /// Folding seed matches into maximal shared runs.
    pub maximal: MaximalConfig,
    /// Literal strategy the duplicated runs are confirmed under: it decides
    /// whether two runs differing only in literal values are the same run.
    pub literals: LiteralNorm,
    /// Precise verification.
    pub verify: VerifyConfig,
    /// How far apart two units' shape mixes may be and still be worth
    /// verifying; see [`shape_divergence`](features::CharacteristicVector::shape_divergence).
    pub max_shape_divergence: f64,
    /// Medoid grouping.
    pub grouping: GroupingConfig,
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            candidate: CandidateConfig::default(),
            near_match: NearMatchConfig::default(),
            control_flow: ControlFlowConfig::default(),
            maximal: MaximalConfig::default(),
            literals: LiteralNorm::default(),
            verify: VerifyConfig::default(),
            max_shape_divergence: DEFAULT_MAX_SHAPE_DIVERGENCE,
            grouping: GroupingConfig::default(),
        }
    }
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

/// A verified clone relation between two contents that no reported group
/// could hold.
///
/// The two contents are clones of each other by the judge's own verdict; what
/// they are not is members of one set whose every pair is a clone, which is
/// what a group asserts. Similarity is not transitive, so a unit can be a
/// clone of two others that are not clones of each other, and a partition into
/// groups can keep only one of those relations. The other is evidence the
/// judge accepted, and it leaves the analysis here rather than being dropped.
///
/// The entry describes *contents*, not one pair of places. Where a codebase
/// holds eight copies of one content and eight of another, the judge reaches
/// the same verdict about all sixty-four crossings of them, and reporting
/// sixty-four entries states one fact sixty-four times — all of them under one
/// identity, because a clone id is composed from member content and two
/// entries over the same two contents cannot differ. So every unit the folded
/// verdicts touched is a member here, and there is one entry per pair of
/// contents.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPair {
    /// Every unit the folded verdicts touched, in unit-index order.
    pub members: Vec<usize>,
    /// Which member is the canonical instance. Which *content* is canonical
    /// follows content order, so it does not depend on where either was found;
    /// among the occurrences of that content the first in member order stands
    /// for it, and they are interchangeable by construction.
    pub canonical: usize,
    /// The relation's stable, position-free clone id, composed exactly as a
    /// group's is: a pair is a group of two contents, and nothing about its
    /// identity should say otherwise.
    pub fingerprint: CloneGroupFingerprint,
    /// The strongest composite similarity among the folded verdicts.
    pub similarity: f64,
    /// What the judge classified the relation as.
    pub class: CloneClass,
    /// The judge's confidence in that classification.
    pub confidence: verify::Confidence,
}

impl VerifiedPair {
    /// Whether `unit` is one of the members.
    #[must_use]
    pub fn holds(&self, unit: usize) -> bool {
        self.members.binary_search(&unit).is_ok()
    }
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
    /// Whether the group reads as one routine written once per integer width.
    ///
    /// A [`Boilerplate`] category is a judgement about one body, aggregated to
    /// the group only when every member agrees. This is not: it is a statement
    /// about how two bodies differ, which no member can carry on its own, so it
    /// sits beside the category rather than inside it.
    pub width_family: bool,
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
    /// Control-flow skeleton extraction statistics.
    pub control_flow: ControlFlowStats,
    /// Maximal-region consolidation statistics.
    pub maximal: RegionStats,
    /// Duplicated runs confirmed against the source tokens.
    pub regions: usize,
    /// Occurrences dropped for holding content no other occurrence of their
    /// candidate run shared: the statement summaries agreed but the code did
    /// not.
    pub region_singletons: usize,
    /// Occurrences dropped for covering source a kept occurrence of the same
    /// run already covers, which makes them one stretch of code rather than
    /// two instances of it.
    pub region_overlapping: usize,
    /// Occurrences dropped for continuing a kept occurrence of the same run,
    /// statement for statement, inside one block. Those tile one stretch of
    /// code, so the run is that stretch's period rather than a copy of it.
    pub region_adjoining: usize,
    /// Confirmed runs dropped because a longer run covers every one of their
    /// occurrences and claims at least as much about them.
    pub region_subsumed: usize,
    /// Longer runs made by joining confirmed runs that describe one stretch at
    /// two offsets. The parts they cover leave through `region_subsumed`.
    pub region_merged: usize,
    /// Candidate pairs dropped because one unit encloses the other.
    pub nested_pairs: usize,
    /// Candidate pairs dropped because the two units sit under different arms
    /// of one preprocessor conditional, so no build holds both.
    pub alternative_pairs: usize,
    /// Candidate pairs dropped because the two units hold too different a mix
    /// of shapes for verification to have anything to find.
    pub divergent_shape_pairs: usize,
    /// Distinct unit pairs handed to verification.
    pub unit_pairs: usize,
    /// Unit pairs that verification accepted as clones.
    pub verified_pairs: usize,
    /// Verified pairs no reported group holds both halves of.
    pub unrepresented_pairs: usize,
    /// Verified pairs left out of that carry-out because a group already
    /// relates their two sides, one of them holding a unit nested inside the
    /// other side.
    pub described_pairs: usize,
    /// Verified pairs left out because the component ceiling cut their two
    /// sides into separate pieces, so no group was ever in a position to hold
    /// both. Zero unless [`GroupingConfig::max_component`] fired.
    pub severed_pairs: usize,
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
    /// Verified clone pairs no group holds both halves of, strongest first.
    /// Real copies that a partition into groups cannot express.
    pub unrepresented: Vec<VerifiedPair>,
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
    /// The preprocessor conditionals the unit sits under, if any.
    arms: ArmPath,
}

/// What a compiler resolved about the files being analysed.
///
/// Held per file and anchored at bytes, because that is what a compiler
/// answers about: it reports the types it resolved where they were written,
/// and which unit a byte belongs to is this crate's own reading of the tree.
/// The two are matched here rather than by whoever asked the compiler, so that
/// a caller cannot attribute a type to a unit this crate never saw.
#[derive(Debug, Clone, Default)]
pub struct ResolvedTypes {
    per_file: Vec<Vec<(ByteRange, TypeTag)>>,
}

impl ResolvedTypes {
    /// Collect what was resolved in each file, indexed as the files are.
    ///
    /// A file nobody asked about contributes an empty list, which is the same
    /// to a comparison as a file whose types nobody could resolve: neither
    /// supports a claim about agreement.
    #[must_use]
    pub fn per_file(mut per_file: Vec<Vec<(ByteRange, TypeTag)>>) -> Self {
        for file in &mut per_file {
            file.sort_by_key(|(range, _)| (range.start, range.end));
        }
        Self { per_file }
    }

    /// Whether nothing was resolved anywhere.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_file.iter().all(Vec::is_empty)
    }

    /// The evidence for one unit: everything resolved within its bytes.
    ///
    /// `None` when nothing was, so that a unit no compiler spoke about is
    /// compared as one nobody measured rather than as one measured to hold no
    /// types.
    fn within(&self, unit: &Unit) -> Option<TypeEvidence> {
        let file = self.per_file.get(unit.file)?;
        let from = file.partition_point(|(range, _)| range.start < unit.range.start);
        let tags = file[from..]
            .iter()
            .take_while(|(range, _)| range.start < unit.range.end)
            .filter(|(range, _)| range.end <= unit.range.end)
            .map(|(_, tag)| *tag);
        let evidence = TypeEvidence::from_tags(tags);
        (!evidence.is_empty()).then_some(evidence)
    }
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
    analyze_resolved(files, variant, config, &ResolvedTypes::default())
}

/// [`analyze`] with what a compiler resolved about the same files.
///
/// The stages are the same ones; what changes is that the type dimension of
/// every comparison is measured instead of absent. Passing nothing resolved is
/// exactly [`analyze`], which is the modes that run no compiler.
#[must_use]
pub fn analyze_resolved(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
    resolved: &ResolvedTypes,
) -> StructuralReport {
    let feature_files: Vec<FileFeatures> = files.iter().map(features::extract).collect();

    let (units, offsets) = flatten_units(files, variant);
    let typed: Vec<Option<TypeEvidence>> = units.iter().map(|unit| resolved.within(unit)).collect();

    // Stage: candidate extraction (exact seeds, near matches and shared
    // control-flow skeletons), lifted to distinct unit pairs.
    let candidate = candidate::generate(&feature_files, &config.candidate);
    let near = near_match::generate(&feature_files, &config.near_match);
    let skeleton = control_flow::generate(&feature_files, &config.control_flow);
    let lifted = lift_to_unit_pairs(
        &candidate,
        &near,
        &skeleton,
        &units,
        &offsets,
        &feature_files,
        config.max_shape_divergence,
    );
    let pairs = lifted.pairs;

    // Stage: fold the window seeds into the maximal shared runs they describe,
    // then confirm each candidate run against the tokens it actually covers.
    let candidate_regions = maximal::consolidate(&candidate.pairs, &config.maximal);
    let (mut confirmed, mut dropped) = confirm_regions(
        &candidate_regions.shared,
        files,
        &offsets,
        variant,
        config.literals,
    );
    let merged = grow_runs(
        &mut confirmed,
        &mut dropped,
        files,
        &offsets,
        variant,
        config.literals,
    );
    let mut regions: Vec<StructuralRegion> =
        confirmed.into_iter().map(|entry| entry.region).collect();
    let subsumed = drop_subsumed(&mut regions);

    // Stage: precise verification of each distinct unit pair.
    let edges = verify_pairs(
        &pairs,
        &units,
        files,
        &feature_files,
        &typed,
        &config.verify,
    );

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
        .map(|group| {
            group_detail(
                group,
                &units,
                files,
                &feature_files,
                &typed,
                variant,
                config,
            )
        })
        .collect();

    let (unrepresented, described_pairs, severed_pairs) =
        unrepresented_pairs(&edges, &groups, &units, variant);

    let stats = StructuralStats {
        files: files.len(),
        units: units.len(),
        candidate: candidate.stats,
        near_match: near.stats,
        control_flow: skeleton.stats,
        maximal: candidate_regions.stats,
        regions: regions.len(),
        region_singletons: dropped.singletons,
        region_overlapping: dropped.overlapping,
        region_adjoining: dropped.adjoining,
        region_subsumed: subsumed,
        region_merged: merged,
        nested_pairs: lifted.nested,
        alternative_pairs: lifted.alternatives,
        divergent_shape_pairs: lifted.divergent,
        unit_pairs: pairs.len(),
        verified_pairs: edges.len(),
        unrepresented_pairs: unrepresented.len(),
        described_pairs,
        severed_pairs,
        grouping: groups.stats.clone(),
    };

    StructuralReport {
        units: reported(&units),
        groups,
        regions,
        details,
        unrepresented,
        stats,
    }
}

/// The analysed units as the report carries them: what a reader can point at,
/// without the working state the pipeline needed to get there.
fn reported(units: &[Unit]) -> Vec<StructuralUnit> {
    units
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
        .collect()
}

/// Verify every candidate unit pair, keeping the ones a verdict accepts.
///
/// A pair the verifier leaves unclassified is not an edge: grouping works over
/// accepted pairs only.
fn verify_pairs(
    pairs: &BTreeSet<(usize, usize)>,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    typed: &[Option<TypeEvidence>],
    config: &VerifyConfig,
) -> Vec<SimilarityEdge> {
    let mut edges: Vec<SimilarityEdge> = Vec::new();
    for &(a, b) in pairs {
        let view_a = view(a, units, files, feature_files, typed);
        let view_b = view(b, units, files, feature_files, typed);
        let verdict = verify::verify(&view_a, &view_b, config);
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
    edges
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
///
/// Occurrences that hold the same content and cover the same source are also
/// settled here: see [`distinct`] for why they arrive and why this is the stage
/// that can tell them apart.
fn confirm_regions(
    candidates: &[SharedRegion],
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> (Vec<Confirmed>, Dropped) {
    let mut regions = Vec::new();
    let mut dropped = Dropped::default();
    for candidate in candidates {
        // Occurrences whose normalized content agrees are the same run up to
        // renaming; that is the coarsest claim this stage is willing to make.
        let mut classes: BTreeMap<FragmentFingerprint, Vec<(RegionOccurrence, RegionSide)>> =
            BTreeMap::new();
        for &side in &candidate.occurrences {
            let Some((occurrence, normalized)) =
                resolve_occurrence(side, files, offsets, variant, literals)
            else {
                dropped.singletons += 1;
                continue;
            };
            classes
                .entry(normalized)
                .or_default()
                .push((occurrence, side));
        }
        for class in classes.into_values() {
            let class = distinct(class, &mut dropped);
            if class.len() < 2 {
                dropped.singletons += class.len();
                continue;
            }
            let (occurrences, sides): (Vec<RegionOccurrence>, Vec<RegionSide>) =
                class.into_iter().unzip();
            let contents: Vec<FragmentFingerprint> =
                occurrences.iter().map(|entry| entry.content).collect();
            // Identical raw content everywhere means the copies differ in
            // nothing but whitespace and comments.
            let clone_type = if contents.iter().all(|&content| content == contents[0]) {
                CloneClass::Type1
            } else {
                CloneClass::Type2
            };
            regions.push(Confirmed {
                region: StructuralRegion {
                    fingerprint: stable_id::clone_group_fingerprint(variant, clone_type, &contents),
                    clone_type,
                    statements: candidate.statements,
                    occurrences,
                },
                sides,
            });
        }
    }
    // Position-free order: two runs are told apart by content, never by where
    // they happen to sit.
    regions.sort_by(|a, b| {
        a.region
            .fingerprint
            .cmp(&b.region.fingerprint)
            .then_with(|| a.region.clone_type.name().cmp(b.region.clone_type.name()))
    });
    regions.dedup_by(|a, b| {
        a.region.fingerprint == b.region.fingerprint && a.region.occurrences == b.region.occurrences
    });
    (regions, dropped)
}

/// What confirmation set aside, by reason.
///
/// Kept apart rather than summed because the three say different things about
/// the detector: a singleton is a summary that promised more than the code
/// delivered, while the other two are one stretch of code arriving as several
/// occurrences of itself.
#[derive(Debug, Clone, Copy, Default)]
struct Dropped {
    /// Occurrences left without a partner holding the same content.
    singletons: usize,
    /// Occurrences covering source a kept occurrence already covers.
    overlapping: usize,
    /// Occurrences continuing a kept occurrence, statement for statement.
    adjoining: usize,
}

/// Keep one occurrence per stretch of source, dropping any that overlaps or
/// continues one already kept.
///
/// A candidate set is the transitive closure over pairwise matches, so two
/// occurrences that overlap each other can still arrive together by way of a
/// third they both match — even though the pairwise stage rejects an
/// overlapping pair as one stretch of code rather than two. That rejection has
/// to hold here too, or a run of interchangeable statements comes back as a
/// clone of itself: every shifted window of the run matches every other, and
/// each window arrives as its own occurrence.
///
/// This is the stage that can decide it. Overlapping occurrences reach it only
/// once they are known to hold the same content, so dropping one really does
/// leave the same code behind. Deciding it earlier, on statement summaries
/// alone, discards whichever overlapping window happens to sit first — which is
/// not always the one that holds the shared content.
///
/// Occurrences that merely continue one another are the same case seen from
/// one step further along: a run whose every window matches the next tiles its
/// block instead of overlapping inside it. Neither describes two sites, so
/// neither survives — see [`maximal::adjoins`].
///
/// A class left with one occurrence is not a duplication and is dropped by the
/// caller. `class` must be in occurrence order, which makes the survivor of an
/// overlapping cluster its first member rather than an artefact of match order.
fn distinct(
    class: Vec<(RegionOccurrence, RegionSide)>,
    dropped: &mut Dropped,
) -> Vec<(RegionOccurrence, RegionSide)> {
    let mut kept: Vec<(RegionOccurrence, RegionSide)> = Vec::with_capacity(class.len());
    for entry in class {
        if kept.iter().any(|(_, other)| {
            other.file == entry.1.file && maximal::intersects(other.range, entry.1.range)
        }) {
            dropped.overlapping += 1;
            continue;
        }
        if kept
            .iter()
            .any(|(_, other)| maximal::adjoins(other, &entry.1))
        {
            dropped.adjoining += 1;
            continue;
        }
        kept.push(entry);
    }
    kept
}

/// Join the confirmed runs that describe one stretch at several offsets,
/// confirm the joins in turn, and return how many longer runs that produced.
///
/// Confirmation is what makes the joins possible, so it has to run first: an
/// occurrence's extent is part of its identity while the runs are still
/// candidates, and only once the occurrences that do not hold the content are
/// gone does a family of runs turn out to be one stretch.
///
/// One sweep is enough. [`merge_adjacent`] grows each chain to its maximum in
/// a single pass, so a second round would have nothing left to reach; joining
/// pair by pair and repeating would instead emit every intermediate length,
/// which on a long repetitive block is quadratically many candidates to
/// confirm.
fn grow_runs(
    confirmed: &mut Vec<Confirmed>,
    dropped: &mut Dropped,
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> usize {
    let candidates = merge_adjacent(confirmed);
    if candidates.is_empty() {
        return 0;
    }
    let (grown, again) = confirm_regions(&candidates, files, offsets, variant, literals);
    dropped.singletons += again.singletons;
    dropped.overlapping += again.overlapping;
    dropped.adjoining += again.adjoining;
    let before = confirmed.len();
    confirmed.extend(grown);
    confirmed.sort_by_key(|entry| entry.region.fingerprint);
    confirmed.dedup_by(|a, b| {
        a.region.fingerprint == b.region.fingerprint && a.region.occurrences == b.region.occurrences
    });
    confirmed.len() - before
}

/// A confirmed run together with the candidate sides it was confirmed from.
///
/// The sides carry the statement indices [`merge_adjacent`] needs and the
/// report does not, so they travel beside the region rather than inside it.
struct Confirmed {
    region: StructuralRegion,
    sides: Vec<RegionSide>,
}

/// Candidate runs made by joining confirmed runs that continue one another.
///
/// The window fold already joins seeds that touch, but it works on candidate
/// occurrence sets, and an occurrence's extent is part of its identity there:
/// a stretch shared six statements deep with one neighbour and four with
/// another is two sets, deliberately, because merging them would credit the
/// second neighbour with statements it does not have. Confirmation then drops
/// whichever occurrences do not really hold the content — and once the short
/// neighbour is gone, what is left of the two sets is one run reported twice,
/// at two offsets, with the same occurrences.
///
/// Joining them is sound for the same reason the fold is: runs at one
/// alignment that overlap or touch compose into their union, every statement
/// of which is covered by one of them at the same relative position. Nothing
/// is assumed about the join — the result goes back through confirmation like
/// any other candidate, and the parts it covers are dropped afterwards by
/// [`drop_subsumed`], which keeps a part making a stricter claim than the
/// whole.
///
/// Runs are grown in one sweep per alignment rather than pair by pair. Pairing
/// every run with every other would emit each intermediate length as its own
/// candidate, and a long repetitive block has quadratically many of those; the
/// sweep emits only the maximal run each chain reaches, which is the only one
/// that survives [`drop_subsumed`] anyway.
fn merge_adjacent(confirmed: &[Confirmed]) -> Vec<SharedRegion> {
    // Runs join only if their occurrences sit in the same places and hold the
    // same offsets relative to one another, so that is the bucket key: within
    // one bucket the runs differ in nothing but where the chain starts.
    let mut alignments: BTreeMap<Alignment, Vec<&Confirmed>> = BTreeMap::new();
    for entry in confirmed {
        let Some(alignment) = alignment_of(entry) else {
            continue;
        };
        alignments.entry(alignment).or_default().push(entry);
    }

    let mut joined = Vec::new();
    for mut runs in alignments.into_values() {
        runs.sort_by_key(|entry| entry.sides[0].run.start);
        let mut chain: Option<Chain> = None;
        for run in runs {
            let touches = chain
                .as_ref()
                .is_some_and(|grown| run.sides[0].run.start <= grown.sides[0].run.end());
            match chain.as_mut() {
                Some(grown) if touches => grown.absorb(&run.sides),
                _ => {
                    if let Some(region) = chain.take().and_then(Chain::finish) {
                        joined.push(region);
                    }
                    chain = Some(Chain::starting_at(&run.sides));
                }
            }
        }
        if let Some(region) = chain.and_then(Chain::finish) {
            joined.push(region);
        }
    }
    joined.sort_unstable();
    joined.dedup();
    joined
}

/// A run of runs, grown along one alignment.
struct Chain {
    /// The union so far, one entry per occurrence.
    sides: Vec<RegionSide>,
    /// The longest single run the chain has absorbed. The union is only worth
    /// proposing when it is longer than this: a chain of one says nothing new,
    /// and a run wholly inside another is containment, which
    /// [`drop_subsumed`] settles without a fresh confirmation.
    longest: u32,
}

impl Chain {
    fn starting_at(sides: &[RegionSide]) -> Self {
        Self {
            sides: sides.to_vec(),
            longest: sides.first().map_or(0, |side| side.run.length),
        }
    }

    fn absorb(&mut self, sides: &[RegionSide]) {
        for (grown, part) in self.sides.iter_mut().zip(sides) {
            grown.run.length = part.run.end().max(grown.run.end()) - grown.run.start;
            grown.range.start = grown.range.start.min(part.range.start);
            grown.range.end = grown.range.end.max(part.range.end);
        }
        self.longest = self
            .longest
            .max(sides.first().map_or(0, |side| side.run.length));
    }

    /// Whether growing the chain has made two of its occurrences reach into
    /// each other. Repetitive code matches a shifted copy of itself, and a
    /// long enough union of those matches runs into its own other end: that is
    /// one stretch of source, not two instances of anything. The fold has the
    /// same guard for the same reason.
    fn overlaps_itself(&self) -> bool {
        self.sides.iter().enumerate().any(|(index, here)| {
            self.sides[index + 1..].iter().any(|there| {
                here.file == there.file && maximal::intersects(here.range, there.range)
            })
        })
    }

    fn finish(mut self) -> Option<SharedRegion> {
        let statements = self.sides.first()?.run.length;
        if statements <= self.longest {
            return None;
        }
        if self.overlaps_itself() {
            return None;
        }
        self.sides.sort_unstable();
        Some(SharedRegion {
            occurrences: self.sides,
            statements,
        })
    }
}

/// How a run's occurrences sit relative to one another: where each is, and how
/// far it starts from the first. Two runs with the same alignment describe the
/// same stretch at different offsets along it.
type Alignment = Vec<(usize, usize, u32, i64)>;

/// A run's alignment, or `None` when it has no occurrences to align.
fn alignment_of(entry: &Confirmed) -> Option<Alignment> {
    let anchor = i64::from(entry.sides.first()?.run.start);
    Some(
        entry
            .sides
            .iter()
            .map(|side| {
                (
                    side.file,
                    side.unit,
                    side.run.block,
                    i64::from(side.run.start) - anchor,
                )
            })
            .collect(),
    )
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
    typed: &[Option<TypeEvidence>],
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> GroupDetail {
    let medoid_view = view(group.canonical, units, files, feature_files, typed);
    let member_breakdowns = group
        .members
        .iter()
        .map(|&member| {
            verify::verify(
                &medoid_view,
                &view(member, units, files, feature_files, typed),
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
        width_family: written_once_per_width(group, units, files),
    }
}

/// Whether every member differs from the medoid by one integer width and
/// nothing else.
///
/// Asked of each member against the medoid rather than of one pair, because the
/// answer decides what the whole group is. A family written for four widths
/// gives four different swaps against the same medoid and each is one, which is
/// the point; a group where one member is a real copy and another a width
/// variant is not a family and must not read as one.
///
/// A group whose members are the same text answers no. Nothing was substituted,
/// so nothing says the two were written per width — that is a plain copy.
fn written_once_per_width(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> bool {
    let medoid = unit_tokens(&units[group.canonical], files);
    let mut compared = 0usize;
    for &member in &group.members {
        if member == group.canonical {
            continue;
        }
        compared += 1;
        let alike = substitution::witness(medoid, unit_tokens(&units[member], files))
            .is_some_and(|witness| witness.written_once_per_width());
        if !alike {
            return false;
        }
    }
    compared > 0
}

/// The tokens one unit covers, in its file's stream.
fn unit_tokens<'a>(unit: &Unit, files: &'a [SyntaxIrFile]) -> &'a [Token] {
    &files[unit.file].tokens[unit.tokens.0..unit.tokens.1]
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
    // Conditional identifiers run across the whole corpus rather than per
    // file, so that two files' conditionals can never be taken for one.
    let mut next_conditional = 0u32;
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
            next_conditional: &mut next_conditional,
            units: &mut units,
        };
        // A file the tree declares as a test module starts marked: the
        // attribute saying so is on the declaration, which is in some other
        // file, so nothing in this one would carry it.
        for root in &file.roots {
            walk.visit(root, file.test_module, &ArmPath::default());
        }
    }
    (units, offsets)
}

/// A depth-first walk over one file's IR that collects its analysed units.
///
/// [`IrNode::walk`] would do for the units themselves, but a unit inherits
/// facts from the items enclosing it — a function inside a test-only module is
/// test code without carrying a marker of its own, and one inside a `#ifdef`
/// belongs to that arm — and a flat visitor has no ancestors to inherit from.
/// The order matches [`IrNode::walk`]'s, and so [`features::extract`]'s:
/// pre-order, children in source order.
struct UnitWalk<'a> {
    file: usize,
    source: &'a SyntaxIrFile,
    context: FileContext<'a>,
    variant: &'a BuildVariant,
    local: usize,
    /// Hands out conditional identifiers; shared across every file in a run.
    next_conditional: &'a mut u32,
    units: &'a mut Vec<Unit>,
}

impl UnitWalk<'_> {
    /// Visit one node, recording it when it is an analysed unit, then its
    /// children. `test_code` and `arms` are what the enclosing items
    /// established.
    fn visit(&mut self, node: &IrNode, test_code: bool, arms: &ArmPath) {
        let end = node.token_end.min(self.source.tokens.len());
        let start = node.token_start.min(end);
        let tokens = &self.source.tokens[start..end];
        let test_code = test_code || test_code::is_marked(self.source.language, tokens);
        // Only a conditional's own node allocates a path; everything else
        // keeps the one it was handed. A conditional the parser stumbled
        // inside is entered but believed nothing of: see [`crate::conditional`]
        // for why an invented arm costs more than a missed one.
        let descended = arms.descend(node, self.next_conditional);
        let arms = descended.as_ref().unwrap_or(arms);

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
                arms: arms.clone(),
            });
            self.local += 1;
        }

        for child in &node.children {
            self.visit(child, test_code, arms);
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
    index: usize,
    units: &'a [Unit],
    files: &'a [SyntaxIrFile],
    feature_files: &'a [FileFeatures],
    typed: &'a [Option<TypeEvidence>],
) -> UnitView<'a> {
    let unit = &units[index];
    UnitView {
        statements: &unit.statements,
        tokens: &files[unit.file].tokens,
        features: &feature_files[unit.file].units[unit.local],
        // Absent unless a compiler resolved types inside this unit's bytes.
        types: typed.get(index).and_then(Option::as_ref),
    }
}

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
struct LiftedPairs {
    /// Distinct unit pairs for verification to judge.
    pairs: BTreeSet<(usize, usize)>,
    /// Proposals dropped for nesting.
    nested: usize,
    /// Proposals dropped for being alternative arms of one conditional.
    alternatives: usize,
    /// Proposals dropped for holding too different a mix of shapes.
    divergent: usize,
}

/// Collapse what the three candidate stages proposed into the set of distinct
/// unit pairs verification will judge, counting what was dropped on the way.
///
/// The stages describe candidates differently — a shared fragment, an
/// overlapping shingle set, a shared skeleton — and they overlap heavily on
/// real code. What verification needs is neither the evidence nor the
/// duplicates, only which two units to compare, so all three are reduced to
/// that here and deduplicated through an ordered set.
fn lift_to_unit_pairs(
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
fn unrepresented_pairs(
    edges: &[SimilarityEdge],
    groups: &GroupingSet,
    units: &[Unit],
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
    let mut folded: BTreeMap<(FragmentFingerprint, FragmentFingerprint, CloneClass), Folded> =
        BTreeMap::new();
    for edge in edges.iter().filter(|edge| {
        !groups.severed_by_the_ceiling(edge.a, edge.b)
            && match (group_of.get(&edge.a), group_of.get(&edge.b)) {
                (Some(a), Some(b)) => a != b,
                _ => true,
            }
    }) {
        // Which content is canonical follows content, not position: the two
        // are peers, and an index would make the id depend on walk order.
        let (canonical, other) = if units[edge.a].content <= units[edge.b].content {
            (edge.a, edge.b)
        } else {
            (edge.b, edge.a)
        };
        let entry = folded
            .entry((units[canonical].content, units[other].content, edge.class))
            .or_insert_with(|| Folded {
                members: BTreeSet::new(),
                similarity: edge.similarity,
                confidence: edge.confidence,
                described: true,
            });
        entry.members.insert(edge.a);
        entry.members.insert(edge.b);
        // One crossing the report does not already account for is enough to
        // make the pair worth carrying: the entry stands for every crossing of
        // those two contents, and the derived ones say nothing against it.
        entry.described &= already_described(edge, &group_of, groups, units);
        // The reported evidence is the strongest crossing the judge accepted;
        // the weaker ones say the same thing about the same two contents.
        if edge.similarity > entry.similarity {
            entry.similarity = edge.similarity;
            entry.confidence = edge.confidence;
        }
    }
    let described = folded.values().filter(|entry| entry.described).count();

    let mut pairs: Vec<VerifiedPair> = folded
        .into_iter()
        .filter(|(_, entry)| !entry.described)
        .map(|((canonical_content, other_content, class), entry)| {
            let members: Vec<usize> = entry.members.into_iter().collect();
            // Any occurrence of the canonical content stands for it; the first
            // in member order is the deterministic choice.
            let canonical = members
                .iter()
                .copied()
                .find(|&member| units[member].content == canonical_content)
                .unwrap_or(members[0]);
            VerifiedPair {
                members,
                canonical,
                fingerprint: stable_id::structural_clone_group_fingerprint(
                    variant,
                    class,
                    &canonical_content,
                    &[canonical_content, other_content],
                ),
                similarity: entry.similarity,
                class,
                confidence: entry.confidence,
            }
        })
        .collect();
    // Strongest first, then by member indices, so the order is deterministic
    // and the reader meets the best evidence first.
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
    similarity: f64,
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
const fn encloses(a: &Unit, b: &Unit) -> bool {
    a.file == b.file
        && ((a.tokens.0 <= b.tokens.0 && b.tokens.1 <= a.tokens.1)
            || (b.tokens.0 <= a.tokens.0 && a.tokens.1 <= b.tokens.1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CloneClass, Confirmed, RegionOccurrence, RegionSide, ResolvedTypes, StructuralRegion, Unit,
        drop_subsumed, merge_adjacent,
    };
    use crate::candidate::StatementRun;
    use crate::conditional::ArmPath;
    use crate::frontend::UnitKind;
    use crate::ir::ByteRange;
    use crate::stable_id::{CloneGroupFingerprint, FragmentFingerprint, UnitFingerprint};
    use crate::types::TypeTag;

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

    fn unit_at(file: usize, start: usize, end: usize) -> Unit {
        Unit {
            file,
            local: 0,
            kind: UnitKind::Function,
            statements: Vec::new(),
            fingerprint: UnitFingerprint::from_bytes([0; 16]),
            content: FragmentFingerprint::from_bytes([0; 16]),
            range: ByteRange { start, end },
            lines: (1, 2),
            tokens: (0, 0),
            name: None,
            boilerplate: None,
            test_code: false,
            arms: ArmPath::default(),
        }
    }

    fn at(start: usize, end: usize, tag: TypeTag) -> (ByteRange, TypeTag) {
        (ByteRange { start, end }, tag)
    }

    /// A compiler answers about bytes; which unit those bytes are in is this
    /// crate's reading of the tree, and the two are matched here.
    #[test]
    fn a_type_resolved_inside_a_unit_is_evidence_about_that_unit() {
        let resolved = ResolvedTypes::per_file(vec![vec![
            at(30, 33, TypeTag::Integer),
            at(10, 16, TypeTag::Text),
            at(90, 93, TypeTag::Integer),
        ]]);
        let evidence = resolved
            .within(&unit_at(0, 0, 40))
            .expect("two types were resolved inside it");
        assert_eq!(evidence.len(), 2);
        // The one at 90 belongs to whatever holds byte 90, not to this unit.
        let other = resolved
            .within(&unit_at(0, 80, 100))
            .expect("one type was resolved inside it");
        assert_eq!(other.len(), 1);
    }

    /// A unit nobody resolved anything in is compared as one nobody measured,
    /// not as one measured to hold no types: the second would let a pair no
    /// compiler spoke about claim the dimension's full weight.
    #[test]
    fn a_unit_no_compiler_spoke_about_has_no_evidence_rather_than_empty_evidence() {
        let resolved = ResolvedTypes::per_file(vec![vec![at(10, 16, TypeTag::Text)]]);
        assert!(resolved.within(&unit_at(0, 40, 80)).is_none());
        // A file nobody asked about at all.
        assert!(resolved.within(&unit_at(1, 0, 40)).is_none());
        assert!(
            ResolvedTypes::default()
                .within(&unit_at(0, 0, 40))
                .is_none()
        );
    }

    /// A range that starts in one unit and ends outside it describes neither,
    /// so it is counted for neither.
    #[test]
    fn a_type_reaching_past_a_unit_is_not_counted_inside_it() {
        let resolved = ResolvedTypes::per_file(vec![vec![at(30, 60, TypeTag::Sequence)]]);
        assert!(resolved.within(&unit_at(0, 0, 40)).is_none());
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

    /// A confirmed run at one alignment: `spans` gives each occurrence's file
    /// and the statement it starts at, all in one block.
    fn confirmed(id: u8, statements: u32, spans: &[(usize, u32)]) -> Confirmed {
        let sides: Vec<RegionSide> = spans
            .iter()
            .map(|&(file, start)| RegionSide {
                file,
                unit: 0,
                run: StatementRun {
                    block: 0,
                    start,
                    length: statements,
                },
                // Ten bytes a statement, so ranges follow the run.
                range: ByteRange {
                    start: (start as usize) * 10,
                    end: (start as usize + statements as usize) * 10,
                },
            })
            .collect();
        let occurrences = sides
            .iter()
            .map(|side| occurrence(side.file, side.range.start, side.range.end))
            .collect();
        Confirmed {
            region: StructuralRegion {
                fingerprint: CloneGroupFingerprint::from_bytes([id; 16]),
                clone_type: CloneClass::Type1,
                statements,
                occurrences,
            },
            sides,
        }
    }

    #[test]
    fn two_runs_describing_one_stretch_at_two_offsets_join() {
        // Statements 2..7 in one file match 1..6 in another, and 3..8 match
        // 2..7. That is one six-statement stretch, reported twice.
        let confirmed = vec![
            confirmed(1, 5, &[(0, 2), (1, 1)]),
            confirmed(2, 5, &[(0, 3), (1, 2)]),
        ];
        let joined = merge_adjacent(&confirmed);
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].statements, 6);
        let starts: Vec<u32> = joined[0]
            .occurrences
            .iter()
            .map(|side| side.run.start)
            .collect();
        assert_eq!(starts, vec![2, 1]);
        assert_eq!(
            joined[0].occurrences[0].range,
            ByteRange { start: 20, end: 80 }
        );
    }

    #[test]
    fn runs_too_far_apart_to_touch_are_two_duplications() {
        // A gap of statements neither run covers: joining would claim the
        // statements in between match, which nothing checked.
        let confirmed = vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(2, 4, &[(0, 9), (1, 9)]),
        ];
        assert_eq!(merge_adjacent(&confirmed), vec![]);
    }

    #[test]
    fn runs_that_shift_by_different_amounts_do_not_join() {
        // One side advances by one statement and the other by three, so the
        // two runs are not one stretch seen twice.
        let confirmed = vec![
            confirmed(1, 5, &[(0, 2), (1, 2)]),
            confirmed(2, 5, &[(0, 3), (1, 5)]),
        ];
        assert_eq!(merge_adjacent(&confirmed), vec![]);
    }

    #[test]
    fn runs_with_different_occurrence_counts_do_not_join() {
        // The shorter run has a third copy, which the join would silently
        // credit with statements it does not hold.
        let confirmed = vec![
            confirmed(1, 5, &[(0, 2), (1, 1)]),
            confirmed(2, 5, &[(0, 3), (1, 2), (2, 4)]),
        ];
        assert_eq!(merge_adjacent(&confirmed), vec![]);
    }

    #[test]
    fn runs_starting_together_are_left_to_containment() {
        let confirmed = vec![
            confirmed(1, 4, &[(0, 2), (1, 1)]),
            confirmed(2, 6, &[(0, 2), (1, 1)]),
        ];
        assert_eq!(merge_adjacent(&confirmed), vec![]);
    }

    #[test]
    fn joining_does_not_depend_on_the_order_the_runs_arrive_in() {
        let build = || {
            vec![
                confirmed(1, 5, &[(0, 2), (1, 1)]),
                confirmed(2, 5, &[(0, 3), (1, 2)]),
                confirmed(3, 5, &[(0, 4), (1, 3)]),
            ]
        };
        let forward = merge_adjacent(&build());
        let reversed: Vec<Confirmed> = build().into_iter().rev().collect();
        assert_eq!(forward, merge_adjacent(&reversed));
        assert!(!forward.is_empty());
    }
}
