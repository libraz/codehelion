use super::Unit;
use super::evidence::UnitEvidence;
use super::model::{BodyMateriality, GroupDetail, SourceTokenSpan, StructuralConfig};
use super::units::view;
use crate::boilerplate::Boilerplate;
use crate::discovery::BuildVariant;
use crate::features::{self, FileFeatures};
use crate::frontend::{Lexeme, Token, TokenKind};
use crate::grouping::{self, SimilarityEdge};
use crate::ir::SyntaxIrFile;
use crate::stable_id::{self, CloneGroupFingerprint, FragmentFingerprint};
use crate::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};
use crate::{substitution, test_code};
use std::collections::{BTreeMap, BTreeSet};

/// The verified pair evidence, addressable by unordered endpoint pair.
///
/// Grouping already weighed every pair inside a group against the same
/// verdicts, so reporting reads them back instead of measuring them again:
/// re-verifying is a statement alignment per pair, which is quadratic in group
/// size and would dominate a tree of interchangeable units (AGENTS.md §2-10).
/// A pair listed more than once collapses to its strongest verdict, the rule
/// grouping applied when it built its own similarity lookup, so both stages
/// read one pair the same way.
pub(super) struct PairEvidence<'a> {
    edges: &'a [SimilarityEdge],
    /// Endpoint pairs in `(low, high, edge index)` form, ordered by endpoints.
    index: Vec<(usize, usize, usize)>,
}

impl<'a> PairEvidence<'a> {
    /// Index verified edges for lookup. Endpoints are unit indices, as in
    /// [`SimilarityEdge`].
    pub(super) fn index(edges: &'a [SimilarityEdge]) -> Self {
        let mut index: Vec<(usize, usize, usize)> = edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| edge.a != edge.b)
            .map(|(position, edge)| {
                let (low, high) = if edge.a <= edge.b {
                    (edge.a, edge.b)
                } else {
                    (edge.b, edge.a)
                };
                (low, high, position)
            })
            .collect();
        index.sort_by(|left, right| {
            (left.0, left.1).cmp(&(right.0, right.1)).then_with(|| {
                edges[right.2]
                    .similarity
                    .total_cmp(&edges[left.2].similarity)
            })
        });
        // The strongest listing of a pair sorts first, so dropping the later
        // duplicates keeps it.
        index.dedup_by(|left, right| (left.0, left.1) == (right.0, right.1));
        Self { edges, index }
    }

    /// The verdict recorded for a pair, or `None` for a pair no edge names.
    fn edge(&self, a: usize, b: usize) -> Option<&SimilarityEdge> {
        let key = if a <= b { (a, b) } else { (b, a) };
        self.index
            .binary_search_by(|probe| (probe.0, probe.1).cmp(&key))
            .ok()
            .map(|position| &self.edges[self.index[position].2])
    }

    /// A pair's grouping similarity. An absent pair reads as zero, which is
    /// how grouping itself reads one.
    fn similarity(&self, a: usize, b: usize) -> f64 {
        self.edge(a, b).map_or(0.0, |edge| edge.similarity)
    }

    /// A pair's per-dimension evidence, when the verifier's own breakdown
    /// travelled with the edge.
    fn breakdown(&self, a: usize, b: usize) -> Option<SimilarityBreakdown> {
        self.edge(a, b).and_then(|edge| edge.breakdown)
    }
}

/// Verify one pair for its breakdown alone.
///
/// Reporting reaches for this only where no verified edge can answer: a unit
/// against itself, or a pair whose edge carried a bare similarity.
fn measure(a: &UnitView<'_>, b: &UnitView<'_>, config: &VerifyConfig) -> SimilarityBreakdown {
    #[cfg(test)]
    verifier_calls::record();
    verify::verify(a, b, config).breakdown
}

/// Compute one group's reporting detail: its stable clone fingerprint (anchored
/// on the medoid's content, folding the member set) and the medoid-to-member
/// similarity breakdowns.
///
/// The similarity evidence comes from the verified edges grouping settled the
/// group with, so the detail costs a lookup per pair rather than an alignment.
/// The medoid's own entry has no pair to read — a unit is not an edge against
/// itself — so a group whose edges carry their breakdowns is one verifier call.
#[allow(
    clippy::too_many_arguments,
    reason = "one group's detail is read from the whole analysed corpus"
)]
pub(super) fn group_detail(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    pairs: &PairEvidence<'_>,
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> GroupDetail {
    let medoid_view = view(group.canonical, units, files, feature_files, evidence);
    let member_breakdowns = group
        .members
        .iter()
        .map(|&member| {
            if member == group.canonical {
                return measure(&medoid_view, &medoid_view, &config.verify);
            }
            pairs.breakdown(group.canonical, member).unwrap_or_else(|| {
                measure(
                    &medoid_view,
                    &view(member, units, files, feature_files, evidence),
                    &config.verify,
                )
            })
        })
        .collect();
    let cohesion_breakdown = weakest_pair(group, pairs).map_or_else(
        // Grouping emits only multi-member groups. Preserve a total report
        // function for a malformed externally-constructed group as well:
        // its medoid's self-comparison is the only available evidence.
        || measure(&medoid_view, &medoid_view, &config.verify),
        |(a, b)| {
            pairs.breakdown(a, b).unwrap_or_else(|| {
                measure(
                    &view(a, units, files, feature_files, evidence),
                    &view(b, units, files, feature_files, evidence),
                    &config.verify,
                )
            })
        },
    );

    let fingerprint = group_fingerprint(group, units, variant);

    GroupDetail {
        fingerprint,
        member_breakdowns,
        cohesion_breakdown,
        identifier_jaccard: group_identifier_jaccard(group, units, files),
        body_materiality: group_body_materiality(group, units, feature_files),
        boilerplate: dominant_boilerplate(group, units),
        test_code: group.members.iter().all(|&member| units[member].test_code),
        test_code_evidence: test_code::aggregate_evidence(
            group
                .members
                .iter()
                .map(|&member| units[member].test_code_evidence),
        ),
        width_family: written_once_per_width(group, units, files),
    }
}

/// The group's weakest internal pair: the one whose similarity is
/// `min_pairwise`, and whose evidence is therefore what establishes it.
///
/// Ties keep the pair the member order reaches first, and an absent pair reads
/// as zero, so the pair named here is the one grouping's own minimum settled
/// on. `None` only for a group holding fewer than two members, which grouping
/// does not emit.
fn weakest_pair(
    group: &grouping::StructuralGroup,
    pairs: &PairEvidence<'_>,
) -> Option<(usize, usize)> {
    let mut weakest: Option<((usize, usize), f64)> = None;
    for (position, &a) in group.members.iter().enumerate() {
        for &b in &group.members[position + 1..] {
            let similarity = pairs.similarity(a, b);
            let lower = weakest.is_none_or(|(_, lowest)| {
                similarity.total_cmp(&lowest) == std::cmp::Ordering::Less
            });
            if lower {
                weakest = Some(((a, b), similarity));
            }
        }
    }
    weakest.map(|(pair, _)| pair)
}

/// Compose a structural group id from the content domain its class promises.
///
/// Type-1 identity is exact source content. Type-2 and Type-3 identity is
/// identifier-normalized content so a consistent rename does not turn an
/// otherwise unchanged clone relation into a new baseline finding.
pub(super) fn group_fingerprint(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    variant: &BuildVariant,
) -> CloneGroupFingerprint {
    let member_contents: Vec<FragmentFingerprint> = group
        .members
        .iter()
        .map(|&member| units[member].group_content(group.clone_type))
        .collect();
    stable_id::structural_clone_group_fingerprint(
        variant,
        group.clone_type,
        &units[group.canonical].group_content(group.clone_type),
        &member_contents,
    )
}

/// Material work that exists in every member rather than just the medoid.
pub(super) fn group_body_materiality(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    feature_files: &[FileFeatures],
) -> BodyMateriality {
    let members: Vec<&features::UnitFeatures> = group
        .members
        .iter()
        .map(|&member| {
            let unit = &units[member];
            &feature_files[unit.file].units[unit.local]
        })
        .collect();
    BodyMateriality {
        has_loop: members
            .iter()
            .all(|features| features.cfg.max_loop_depth > 0),
        has_dynamic_allocation: members
            .iter()
            .all(|features| features.api.names.iter().any(is_allocation_api)),
        call_count: members
            .iter()
            .map(|features| u64::try_from(features.api.names.len()).unwrap_or(u64::MAX))
            .min()
            .unwrap_or(0),
    }
}

/// Allocation APIs recognised without a compiler backend.
///
/// The lexical frontend intentionally recognises only explicit, portable
/// allocator names. An unfamiliar wrapper is absence of evidence, not a
/// guess that the call allocates.
pub(super) fn is_allocation_api(name: &Lexeme) -> bool {
    matches!(
        name.as_str(),
        "aligned_alloc"
            | "calloc"
            | "make_shared"
            | "make_unique"
            | "malloc"
            | "realloc"
            | "reserve"
            | "reserve_exact"
            | "try_reserve"
            | "try_reserve_exact"
            | "with_capacity"
            | "with_capacity_and_hasher"
    )
}

/// The weakest raw identifier-set agreement between a canonical span and its
/// corresponding spans, or `None` where there was nothing to agree about.
///
/// This is reporting and triage evidence only. In particular, a duplicated
/// run may have exact normalized content while this value is low because its
/// names differ; the value is a proxy for whether a shared refactoring target
/// may exist, not a similarity measurement and never an input to detection or
/// grouping.
///
/// A comparison where neither span holds an identifier is absent rather than
/// perfect: a duplicated literal table names nothing, and reporting a 1.00 for
/// it would let the strongest possible reading of this evidence rest on none of
/// it. Comparisons that were measurable still decide the value.
#[must_use]
pub fn span_identifier_jaccard(
    files: &[SyntaxIrFile],
    canonical: SourceTokenSpan,
    corresponding: impl IntoIterator<Item = SourceTokenSpan>,
) -> Option<f64> {
    let canonical = identifier_set(files, canonical);
    corresponding
        .into_iter()
        .filter_map(|span| set_jaccard(&canonical, &identifier_set(files, span)))
        .min_by(f64::total_cmp)
}

/// The weakest identifier-set agreement between a canonical unit and its
/// group members.
fn group_identifier_jaccard(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> Option<f64> {
    span_identifier_jaccard(
        files,
        unit_token_span(&units[group.canonical]),
        group
            .members
            .iter()
            .filter(|&&member| member != group.canonical)
            .map(|&member| unit_token_span(&units[member])),
    )
}

const fn unit_token_span(unit: &Unit) -> SourceTokenSpan {
    SourceTokenSpan::new(unit.file, unit.tokens.0, unit.tokens.1)
}

fn identifier_set(files: &[SyntaxIrFile], span: SourceTokenSpan) -> BTreeSet<&str> {
    let tokens = files
        .get(span.file)
        .and_then(|file| file.tokens.get(span.token_start..span.token_end))
        .unwrap_or(&[]);
    tokens
        .iter()
        .filter(|token| matches!(token.kind, TokenKind::Identifier))
        .map(|token| token.text.as_str())
        .collect()
}

/// The agreement of two identifier sets, or `None` where neither side holds an
/// identifier and there is therefore nothing the ratio could be about.
#[allow(clippy::cast_precision_loss)]
pub(super) fn set_jaccard(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> Option<f64> {
    let union = left.union(right).count();
    if union == 0 {
        return None;
    }
    // One set entry requires one input token; discovery's file-size ceiling
    // bounds this far below the integer range where a report ratio loses a
    // meaningful displayed digit.
    Some(left.intersection(right).count() as f64 / union as f64)
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
pub(super) fn written_once_per_width(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> bool {
    written_once_per_width_members(group.canonical, &group.members, units, files)
}

/// The pair counterpart of [`written_once_per_width`].
pub(super) fn written_once_per_width_members(
    canonical: usize,
    members: &[usize],
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> bool {
    let medoid = unit_tokens(&units[canonical], files);
    let mut compared = 0usize;
    for &member in members {
        if member == canonical {
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

/// The category that covers at least four fifths of one cohesive group.
///
/// Clone grouping permits structurally similar bodies to differ in a small
/// number of details. Requiring unanimity therefore let a single exceptional
/// body erase the useful classification of a large predicate family. The
/// threshold is intentionally strict: a two-member pair still needs both
/// members to agree, while a high-instance group can retain a few explicitly
/// visible exceptions.
pub(super) fn dominant_boilerplate(
    group: &grouping::StructuralGroup,
    units: &[Unit],
) -> Option<Boilerplate> {
    dominant_boilerplate_members(&group.members, units)
}

/// The pair counterpart of [`dominant_boilerplate`].
pub(super) fn dominant_boilerplate_members(
    members: &[usize],
    units: &[Unit],
) -> Option<Boilerplate> {
    let mut counts = BTreeMap::new();
    for &member in members {
        if let Some(category) = units[member].boilerplate {
            *counts.entry(category).or_insert(0usize) += 1;
        }
    }
    let (category, count) = counts
        .into_iter()
        .max_by_key(|(category, count)| (*count, *category))?;
    (count.saturating_mul(5) >= members.len().saturating_mul(4)).then_some(category)
}

/// How many pairs reporting has measured itself on this thread.
///
/// The per-group ceiling on that work is a property the crate's own tests hold
/// this module to; nothing a caller sees observes it.
#[cfg(test)]
pub(super) mod verifier_calls {
    use std::cell::Cell;

    thread_local! {
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    /// Start counting again from zero.
    pub(in crate::structural) fn reset() {
        COUNT.with(|count| count.set(0));
    }

    /// Measurements counted since the last reset.
    pub(in crate::structural) fn count() -> usize {
        COUNT.with(Cell::get)
    }

    /// Count one measurement.
    pub(super) fn record() {
        COUNT.with(|count| count.set(count.get().saturating_add(1)));
    }
}
