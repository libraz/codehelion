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
//! 3. [`crate::verify`] judges each distinct unit pair precisely, keeping only
//!    the ones that clear the clone threshold;
//! 4. [`crate::grouping`] turns the surviving pairs into cohesive medoid groups,
//!    so non-transitive Type-3 chains do not fuse.
//!
//! Every unit carries its raw [`UnitFingerprint`] as its stable, position-free
//! grouping key ([`crate::stable_id`]). The whole function is deterministic: the
//! unit order follows the IR walk, candidate pairs are deduplicated through an
//! ordered set, and grouping orders its own output. Nothing here executes target
//! code — it only reads IR that was already produced from source.

use std::collections::BTreeSet;

use crate::candidate::{self, CandidateConfig, CandidateStats};
use crate::discovery::BuildVariant;
use crate::features::{self, FileFeatures};
use crate::frontend::{Lexeme, Token, UnitKind};
use crate::grouping::{
    self, GroupingConfig, GroupingSet, GroupingStats, GroupingUnit, SimilarityEdge,
};
use crate::ir::{ByteRange, Shape, SyntaxIrFile};
use crate::near_match::{self, NearMatchConfig, NearMatchStats};
use crate::stable_id::{
    self, CloneGroupFingerprint, ContentNorm, FileContext, FragmentFingerprint, UnitFingerprint,
};
use crate::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};

/// Tuning for a whole structural run: one config per stage.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StructuralConfig {
    /// Exact-seed candidate extraction.
    pub candidate: CandidateConfig,
    /// MinHash/LSH near-match extraction.
    pub near_match: NearMatchConfig,
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

    // Stage: precise verification of each distinct unit pair.
    let mut edges: Vec<SimilarityEdge> = Vec::new();
    for &(a, b) in &pairs {
        let view_a = view(&units[a], &feature_files);
        let view_b = view(&units[b], &feature_files);
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
        .map(|group| group_detail(group, &units, &feature_files, variant, config))
        .collect();

    let stats = StructuralStats {
        files: files.len(),
        units: units.len(),
        candidate: candidate.stats,
        near_match: near.stats,
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
            fingerprint: unit.fingerprint,
            content: unit.content,
        })
        .collect();

    StructuralReport {
        units: report_units,
        groups,
        details,
        stats,
    }
}

/// Compute one group's reporting detail: its stable clone fingerprint (anchored
/// on the medoid's content, folding the member set) and the medoid-to-member
/// similarity breakdowns.
fn group_detail(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    feature_files: &[FileFeatures],
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> GroupDetail {
    let medoid_view = view(&units[group.canonical], feature_files);
    let member_breakdowns = group
        .members
        .iter()
        .map(|&member| {
            verify::verify(
                &medoid_view,
                &view(&units[member], feature_files),
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
    }
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
        let context = FileContext {
            frontend_version: file.frontend_version,
            language: file.language,
        };
        let mut local = 0usize;
        file.walk(&mut |node| {
            let Some(kind) = unit_kind(&node.shape) else {
                return;
            };
            let statements = verify::statement_sequence(node, &file.tokens);
            let end = node.token_end.min(file.tokens.len());
            let start = node.token_start.min(end);
            let tokens = &file.tokens[start..end];
            let fingerprint =
                stable_id::unit_fingerprint(variant, &context, tokens, ContentNorm::Raw);
            let content_fp = stable_id::fragment_fingerprint(
                variant,
                &context,
                "unit",
                tokens,
                ContentNorm::Raw,
            );
            units.push(Unit {
                file: file_index,
                local,
                kind,
                statements,
                fingerprint,
                content: content_fp,
                range: node.range,
                lines: line_range(tokens),
                tokens: (start, end),
                name: node.name.clone(),
            });
            local += 1;
        });
    }
    (units, offsets)
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

/// Build a unit's verification view from its statements and its features.
fn view<'a>(unit: &'a Unit, feature_files: &'a [FileFeatures]) -> UnitView<'a> {
    UnitView {
        statements: &unit.statements,
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
