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
use crate::frontend::Lexeme;
use crate::grouping::{
    self, GroupingConfig, GroupingSet, GroupingStats, GroupingUnit, SimilarityEdge,
};
use crate::ir::{ByteRange, Shape, SyntaxIrFile};
use crate::near_match::{self, NearMatchConfig, NearMatchStats};
use crate::stable_id::{self, ContentNorm, FileContext, UnitFingerprint};
use crate::verify::{self, UnitView, VerifyConfig};

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
    /// Source bytes the unit covers; reporting only.
    pub range: ByteRange,
    /// The unit's declared name, when the frontend recovered one.
    pub name: Option<Lexeme>,
    /// The unit's raw content fingerprint: its stable grouping key.
    pub fingerprint: UnitFingerprint,
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
    /// Funnel statistics.
    pub stats: StructuralStats,
}

/// One analysed unit's data, held together for verification and grouping.
struct Unit {
    file: usize,
    local: usize,
    statements: Vec<crate::ir::StatementSummary>,
    fingerprint: UnitFingerprint,
    range: ByteRange,
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
            range: unit.range,
            name: unit.name.clone(),
            fingerprint: unit.fingerprint,
        })
        .collect();

    StructuralReport {
        units: report_units,
        groups,
        stats,
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
            if matches!(node.shape, Shape::Function | Shape::Method | Shape::Closure) {
                let statements = verify::statement_sequence(node, &file.tokens);
                let end = node.token_end.min(file.tokens.len());
                let start = node.token_start.min(end);
                let fingerprint = stable_id::unit_fingerprint(
                    variant,
                    &context,
                    &file.tokens[start..end],
                    ContentNorm::Raw,
                );
                units.push(Unit {
                    file: file_index,
                    local,
                    statements,
                    fingerprint,
                    range: node.range,
                    name: node.name.clone(),
                });
                local += 1;
            }
        });
    }
    (units, offsets)
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
