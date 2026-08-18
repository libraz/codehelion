//! Bounded post-grouping search for incomplete local mirrors.
//!
//! Primary grouping is complete before this module runs. The similarity
//! channel remains file-scoped: a sibling is an ungrouped unit in a file that
//! already hosts a member of an established group. The signature channel is
//! scoped instead to the opaque directory partitions occupied by group
//! members. Both channels compare only to the group's medoid, never emit a
//! primary edge, and never edit a group, so neither can turn a local
//! incomplete copy into transitive group membership.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use super::pairs::encloses;
use super::{
    DirectoryPartition, FileFeatures, GroupSiblings, GroupingSet, SiblingBasis, SiblingSweepStats,
    SignatureSiblingSweepStats, StructuralConfig, StructuralSibling, SyntaxIrFile, Unit,
    UnitEvidence, unit_meets_minimum, verify, view,
};
use crate::clone_class::CloneClass;
use crate::grouping::StructuralGroup;
use crate::ir::SignatureKey;
use crate::stable_id::UnitFingerprint;
use crate::verify::Confidence;

/// Sweep ungrouped units beside established groups for incomplete mirrors.
///
/// This compatibility wrapper preserves the old private test helper's return
/// shape and deliberately disables the signature channel.
#[cfg(test)]
pub(super) fn sweep_siblings(
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    config: &StructuralConfig,
) -> (Vec<GroupSiblings>, SiblingSweepStats) {
    let (siblings, stats, _) =
        sweep_siblings_with_context(groups, units, files, feature_files, evidence, config, false);
    (siblings, stats)
}

/// Run both independent sibling channels and merge overlapping entries.
pub(super) fn sweep_siblings_with_context(
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    config: &StructuralConfig,
    signature_context: bool,
) -> (
    Vec<GroupSiblings>,
    SiblingSweepStats,
    SignatureSiblingSweepStats,
) {
    let (mut similarity, similarity_stats) =
        sweep_similarity_siblings(groups, units, files, feature_files, evidence, config);
    let (signature, signature_stats) = if signature_context {
        sweep_signature_siblings(
            groups,
            units,
            files,
            feature_files,
            evidence,
            config,
            &similarity,
        )
    } else {
        (Vec::new(), SignatureSiblingSweepStats::default())
    };
    merge_sibling_channels(&mut similarity, signature, units);
    (similarity, similarity_stats, signature_stats)
}

/// Sweep the existing file-scoped verifier-similarity channel.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded sweep keeps its ordered caps and accounting together for auditability"
)]
fn sweep_similarity_siblings(
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    config: &StructuralConfig,
) -> (Vec<GroupSiblings>, SiblingSweepStats) {
    let verify_config = &config.verify;
    let sibling_config = &config.siblings;
    let mut stats = SiblingSweepStats::default();
    let grouped: BTreeSet<usize> = groups
        .groups
        .iter()
        .flat_map(|group| group.members.iter().copied())
        .collect();
    let mut ungrouped_by_file: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, unit) in units.iter().enumerate() {
        if !grouped.contains(&index) {
            ungrouped_by_file.entry(unit.file).or_default().push(index);
        }
    }
    for candidates in ungrouped_by_file.values_mut() {
        candidates.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
    }

    // Form the file-scoped work lists before spending the budget. This makes
    // every dropped count exact while comparison work itself remains bounded.
    let candidate_lists: Vec<Vec<usize>> = groups
        .groups
        .iter()
        .map(|group| {
            let files: BTreeSet<usize> = group
                .members
                .iter()
                .map(|&member| units[member].file)
                .collect();
            files
                .into_iter()
                .flat_map(|file| ungrouped_by_file.get(&file).into_iter().flatten().copied())
                .filter(|&candidate| {
                    sibling_candidate_allowed(
                        group.canonical,
                        candidate,
                        units,
                        feature_files,
                        config,
                    )
                })
                .collect()
        })
        .collect();
    stats.groups_considered = groups.groups.len();
    stats.eligible_candidates = candidate_lists.iter().map(Vec::len).sum();

    let relaxed_threshold = (verify_config.type3_min_composite
        - sibling_config
            .similarity_delta
            .clamp(0.0, verify_config.type3_min_composite))
    .max(0.0);
    let mut accepted = 0usize;
    let mut out = Vec::new();
    'groups: for (group_index, (group, group_candidates)) in
        groups.groups.iter().zip(&candidate_lists).enumerate()
    {
        let mut siblings = Vec::new();
        for (position, &unit) in group_candidates.iter().enumerate() {
            if accepted >= sibling_config.total_cap {
                stats.total_cap_dropped = stats.total_cap_dropped.saturating_add(
                    group_candidates.len().saturating_sub(position)
                        + candidate_lists[group_index + 1..]
                            .iter()
                            .map(Vec::len)
                            .sum::<usize>(),
                );
                break 'groups;
            }
            if siblings.len() >= sibling_config.per_group_cap {
                stats.per_group_cap_dropped = stats
                    .per_group_cap_dropped
                    .saturating_add(group_candidates.len().saturating_sub(position));
                break;
            }
            if stats.candidates_examined >= sibling_config.candidate_budget {
                break 'groups;
            }
            let canonical = view(group.canonical, units, files, feature_files, evidence);
            let sibling = view(unit, units, files, feature_files, evidence);
            let verdict = verify::verify(&canonical, &sibling, verify_config);
            stats.candidates_examined += 1;
            if verdict.breakdown.composite < relaxed_threshold {
                continue;
            }
            let (clone_type, confidence) = sibling_classification(
                verdict.class,
                verdict.confidence,
                verdict.breakdown.composite,
                verify_config.type3_min_composite,
            );
            siblings.push(StructuralSibling {
                unit,
                clone_type,
                confidence,
                breakdown: verdict.breakdown,
                basis: SiblingBasis::Similarity,
                signature: None,
                signature_units: None,
            });
            accepted += 1;
            stats.accepted += 1;
        }
        if !siblings.is_empty() {
            out.push(GroupSiblings {
                group: group_index,
                siblings,
            });
        }
    }
    stats.candidate_budget_dropped = stats
        .eligible_candidates
        .saturating_sub(stats.candidates_examined)
        .saturating_sub(stats.per_group_cap_dropped)
        .saturating_sub(stats.total_cap_dropped);
    (out, stats)
}

/// Sweep exact normalized signatures within the directory partitions occupied
/// by each established group. This channel never uses the verifier's
/// threshold to decide acceptance; the verifier is evidence only.
#[allow(
    clippy::too_many_lines,
    reason = "the independent signature sweep keeps its index, guards, caps, and accounting together"
)]
fn sweep_signature_siblings(
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    config: &StructuralConfig,
    existing_similarity: &[GroupSiblings],
) -> (Vec<GroupSiblings>, SignatureSiblingSweepStats) {
    let mut stats = SignatureSiblingSweepStats {
        groups_considered: groups.groups.len(),
        ..SignatureSiblingSweepStats::default()
    };
    let grouped: BTreeSet<usize> = groups
        .groups
        .iter()
        .flat_map(|group| group.members.iter().copied())
        .collect();
    // How many units share each signature, counted over every unit in the
    // tree including grouped ones. Counting only ungrouped units would loosen
    // the sharing limit as grouping succeeds, which is backwards: a signature
    // held by a whole callback layer stays common however much of that layer
    // primary grouping already explains.
    let mut units_per_signature: BTreeMap<SignatureKey, usize> = BTreeMap::new();
    for data in units {
        if let Some(signature) = data.signature.as_ref() {
            *units_per_signature.entry(signature.key).or_default() += 1;
        }
    }
    let max_shared = config.signature_siblings.max_units_per_signature;
    let mut index: BTreeMap<(SignatureKey, DirectoryPartition), Vec<usize>> = BTreeMap::new();
    // Excluded keys keep their posting sizes but not their members: the sweep
    // must be able to say how much the sharing limit removed without paying
    // the memory the limit exists to avoid.
    let mut excluded: BTreeMap<(SignatureKey, DirectoryPartition), usize> = BTreeMap::new();
    let mut excluded_keys: BTreeSet<SignatureKey> = BTreeSet::new();
    for (unit, data) in units.iter().enumerate() {
        if grouped.contains(&unit) {
            continue;
        }
        let (Some(signature), Some(directory)) = (data.signature.as_ref(), data.directory) else {
            continue;
        };
        let shared = units_per_signature
            .get(&signature.key)
            .copied()
            .unwrap_or_default();
        if shared > max_shared {
            excluded_keys.insert(signature.key);
            *excluded.entry((signature.key, directory)).or_default() += 1;
            stats.largest_skipped_signature_units =
                stats.largest_skipped_signature_units.max(shared);
            continue;
        }
        index
            .entry((signature.key, directory))
            .or_default()
            .push(unit);
    }
    stats.common_signatures_skipped = excluded_keys.len();
    stats.common_signature_dropped = groups
        .groups
        .iter()
        .map(|group| {
            group_posting_total(group, units, |key, directory| {
                excluded.get(&(key, directory)).copied().unwrap_or_default()
            })
        })
        .sum();
    for candidates in index.values_mut() {
        candidates.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
    }

    // Keep only one posting index over ungrouped units. Group-specific
    // candidates are traversed below with a bounded k-way cursor; no
    // group-by-posting `Vec<Vec<usize>>` is materialized.
    let group_candidate_counts: Vec<usize> = groups
        .groups
        .iter()
        .map(|group| {
            group_posting_total(group, units, |key, directory| {
                index.get(&(key, directory)).map_or(0, Vec::len)
            })
        })
        .collect();
    stats.eligible_candidates = group_candidate_counts.iter().sum();

    // Every candidate offered to one group carries that group's medoid
    // signature, so the number of units sharing it is uniform inside a group
    // and decides only which groups reach the shared caps first. Rarer
    // signatures go first, then the existing deterministic group order, so a
    // cap truncates the least informative offers.
    let mut order: Vec<usize> = (0..groups.groups.len()).collect();
    order.sort_by_key(|&group_index| {
        (
            shared_signature_units(&groups.groups[group_index], units, &units_per_signature),
            group_index,
        )
    });
    let mut remaining_after = vec![0usize; order.len()];
    let mut tail = 0usize;
    for (position, &group_index) in order.iter().enumerate().rev() {
        remaining_after[position] = tail;
        tail += group_candidate_counts[group_index];
    }

    let mut accepted = 0usize;
    let mut out = Vec::new();
    'groups: for (position, &group_index) in order.iter().enumerate() {
        let group = &groups.groups[group_index];
        let shared = shared_signature_units(group, units, &units_per_signature);
        let mut candidates = signature_candidate_stream(group, units, &index);
        let mut remaining = group_candidate_counts[group_index];
        let mut siblings = Vec::new();
        // Similarity output is emitted in primary group order. Keep the
        // signature channel's existing-breakdown lookup logarithmic in the
        // number of similarity groups rather than scanning that output for
        // every signature candidate.
        let existing_group = existing_similarity
            .binary_search_by_key(&group_index, |existing| existing.group)
            .ok()
            .and_then(|index| existing_similarity.get(index));
        loop {
            if accepted >= config.signature_siblings.total_cap {
                stats.total_cap_dropped = stats
                    .total_cap_dropped
                    .saturating_add(remaining + remaining_after[position]);
                if !siblings.is_empty() {
                    out.push(GroupSiblings {
                        group: group_index,
                        siblings,
                    });
                }
                break 'groups;
            }
            if siblings.len() >= config.signature_siblings.per_group_cap {
                stats.per_group_cap_dropped = stats.per_group_cap_dropped.saturating_add(remaining);
                break;
            }
            if stats.candidates_examined >= config.signature_siblings.candidate_budget {
                stats.candidate_budget_dropped = stats
                    .candidate_budget_dropped
                    .saturating_add(remaining + remaining_after[position]);
                if !siblings.is_empty() {
                    out.push(GroupSiblings {
                        group: group_index,
                        siblings,
                    });
                }
                break 'groups;
            }
            let Some(unit) = candidates.next() else {
                break;
            };
            remaining = remaining.saturating_sub(1);
            stats.candidates_examined += 1;
            let Some(signature) = units[group.canonical].signature.as_ref() else {
                continue;
            };
            if units[unit]
                .signature
                .as_ref()
                .is_none_or(|candidate_signature| {
                    candidate_signature.normalized != signature.normalized
                })
                || !signature_sibling_candidate_allowed(group.canonical, unit, units, config)
            {
                continue;
            }
            let breakdown = existing_group
                .and_then(|existing| {
                    existing
                        .siblings
                        .iter()
                        .find(|sibling| sibling.unit == unit)
                        .map(|sibling| sibling.breakdown)
                })
                .unwrap_or_else(|| {
                    let canonical_view =
                        view(group.canonical, units, files, feature_files, evidence);
                    let candidate_view = view(unit, units, files, feature_files, evidence);
                    verify::verify(&canonical_view, &candidate_view, &config.verify).breakdown
                });
            siblings.push(StructuralSibling {
                unit,
                clone_type: CloneClass::Type3,
                confidence: Confidence::Low,
                breakdown,
                basis: SiblingBasis::Signature,
                signature: Some(signature.normalized.clone()),
                signature_units: Some(shared),
            });
            accepted += 1;
            stats.accepted += 1;
        }
        if !siblings.is_empty() {
            out.push(GroupSiblings {
                group: group_index,
                siblings,
            });
        }
    }
    // Groups were visited rarest signature first; the channel's output stays
    // in primary group order, as the merge step expects.
    out.sort_by_key(|group| group.group);
    (out, stats)
}

/// How many units in the tree share one group medoid's signature. Zero when
/// the medoid has no signature, which is also how such a group sorts first:
/// it offers no signature candidates at all.
fn shared_signature_units(
    group: &StructuralGroup,
    units: &[Unit],
    units_per_signature: &BTreeMap<SignatureKey, usize>,
) -> usize {
    units[group.canonical]
        .signature
        .as_ref()
        .and_then(|signature| units_per_signature.get(&signature.key))
        .copied()
        .unwrap_or_default()
}

/// Total the postings one group would traverse, without copying them: the
/// medoid's signature key in each directory its members occupy. The caller
/// supplies the posting size, so the same walk serves both the retained index
/// and the postings the sharing limit excluded. The total is the denominator
/// for exact cap/drop accounting; per-unit safety guards are applied while the
/// stream is consumed.
fn group_posting_total(
    group: &StructuralGroup,
    units: &[Unit],
    mut posting_size: impl FnMut(SignatureKey, DirectoryPartition) -> usize,
) -> usize {
    let Some(signature) = units[group.canonical].signature.as_ref() else {
        return 0;
    };
    group
        .members
        .iter()
        .filter_map(|&member| units[member].directory)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|directory| posting_size(signature.key, directory))
        .sum()
}

/// A deterministic, bounded-memory merge over the posting lists occupied by
/// one group's medoid signature and member directories.
struct SignatureCandidateStream<'a> {
    units: &'a [Unit],
    postings: Vec<&'a [usize]>,
    heap: BinaryHeap<Reverse<(UnitFingerprint, usize, usize, usize)>>,
}

impl Iterator for SignatureCandidateStream<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((_, unit, posting, position)) = self.heap.pop()?;
        let next_position = position.saturating_add(1);
        if let Some(&next_unit) = self.postings[posting].get(next_position) {
            self.heap.push(Reverse((
                self.units[next_unit].fingerprint,
                next_unit,
                posting,
                next_position,
            )));
        }
        Some(unit)
    }
}

fn signature_candidate_stream<'a>(
    group: &StructuralGroup,
    units: &'a [Unit],
    index: &'a BTreeMap<(SignatureKey, DirectoryPartition), Vec<usize>>,
) -> SignatureCandidateStream<'a> {
    let signature = units[group.canonical].signature.as_ref();
    let directories: BTreeSet<DirectoryPartition> = group
        .members
        .iter()
        .filter_map(|&member| units[member].directory)
        .collect();
    let postings: Vec<&[usize]> = signature
        .into_iter()
        .flat_map(|signature| {
            directories
                .iter()
                .filter_map(|&directory| index.get(&(signature.key, directory)))
                .map(Vec::as_slice)
        })
        .collect();
    let heap = postings
        .iter()
        .enumerate()
        .filter_map(|(posting, candidates)| {
            candidates
                .first()
                .map(|&unit| Reverse((units[unit].fingerprint, unit, posting, 0)))
        })
        .collect();
    SignatureCandidateStream {
        units,
        postings,
        heap,
    }
}

/// Merge the channels by owning group and candidate unit. An exact signature
/// hit wins over a similarity hit for the same pair, while all output remains
/// ordered by the unit's stable fingerprint.
fn merge_sibling_channels(
    similarity: &mut Vec<GroupSiblings>,
    signature: Vec<GroupSiblings>,
    units: &[Unit],
) {
    for signature_group in signature {
        let Some(existing_group) = similarity
            .iter_mut()
            .find(|group| group.group == signature_group.group)
        else {
            similarity.push(signature_group);
            continue;
        };
        for signature_sibling in signature_group.siblings {
            if let Some(existing) = existing_group
                .siblings
                .iter_mut()
                .find(|sibling| sibling.unit == signature_sibling.unit)
            {
                *existing = signature_sibling;
            } else {
                existing_group.siblings.push(signature_sibling);
            }
        }
    }
    similarity.sort_by_key(|group| group.group);
    for group in similarity {
        group.siblings.sort_by(|left, right| {
            units[left.unit]
                .fingerprint
                .cmp(&units[right.unit].fingerprint)
                .then(left.unit.cmp(&right.unit))
        });
    }
}

/// Whether a sibling candidate satisfies every guard used before primary
/// pair verification.
fn sibling_candidate_allowed(
    canonical: usize,
    candidate: usize,
    units: &[Unit],
    feature_files: &[FileFeatures],
    config: &StructuralConfig,
) -> bool {
    let canonical = &units[canonical];
    let candidate = &units[candidate];
    if !unit_meets_minimum(canonical, config.min_clone_tokens)
        || !unit_meets_minimum(candidate, config.min_clone_tokens)
        || encloses(canonical, candidate)
        || canonical.arms.excludes(&candidate.arms)
    {
        return false;
    }
    let canonical_vector = &feature_files[canonical.file].units[canonical.local].vector;
    let candidate_vector = &feature_files[candidate.file].units[candidate.local].vector;
    canonical_vector.shape_divergence(candidate_vector) <= config.max_shape_divergence
}

/// Whether a signature sibling candidate satisfies the safety guards that do
/// not judge body similarity. Exact signatures are deliberately allowed to
/// cross the ordinary shape-divergence gate: that gate is a similarity
/// proposal filter, while this channel's candidate selection is the exact
/// signature key itself and verifier evidence is never thresholded.
fn signature_sibling_candidate_allowed(
    canonical: usize,
    candidate: usize,
    units: &[Unit],
    config: &StructuralConfig,
) -> bool {
    let canonical = &units[canonical];
    let candidate = &units[candidate];
    unit_meets_minimum(canonical, config.min_clone_tokens)
        && unit_meets_minimum(candidate, config.min_clone_tokens)
        && !encloses(canonical, candidate)
        && !canonical.arms.excludes(&candidate.arms)
}

/// Apply the sibling contract to a verifier result.
///
/// Exact structural agreement can classify a pair before the composite
/// threshold is consulted. That classification remains useful, but below the
/// ordinary Type-3 floor it cannot carry medium or high confidence.
fn sibling_classification(
    class: Option<CloneClass>,
    confidence: Option<Confidence>,
    composite: f64,
    type3_min_composite: f64,
) -> (CloneClass, Confidence) {
    let (class, mut confidence) = match (class, confidence) {
        (Some(class), Some(confidence)) => (class, confidence),
        _ => (CloneClass::Type3, Confidence::Low),
    };
    if composite < type3_min_composite {
        confidence = Confidence::Low;
    }
    (class, confidence)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::conditional::{ArmTracker, StaticCondition};
    use crate::discovery::{BuildVariant, Language, LanguageSelection};
    use crate::engine::LiteralNorm;
    use crate::features;
    use crate::frontend::{SourceSpan, Token, TokenKind};
    use crate::grouping::{self, GroupingConfig, GroupingUnit, SimilarityEdge};
    use crate::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, Signature};
    use crate::structural::{
        DirectoryPartition, ResolvedTypes, SiblingBasis, SiblingConfig, SignatureSiblingConfig,
        flatten_units, flatten_units_with_context, unit_evidence,
    };

    fn variant() -> BuildVariant {
        BuildVariant::structural(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            Language::Rust,
        )
    }

    fn file(names: &[&str]) -> SyntaxIrFile {
        let tokens = names
            .iter()
            .enumerate()
            .map(|(index, name)| Token {
                kind: TokenKind::Identifier,
                text: (*name).into(),
                span: SourceSpan {
                    start_byte: index,
                    end_byte: index + 1,
                    start_line: 1,
                    start_column: u32::try_from(index + 1).unwrap_or(u32::MAX),
                },
            })
            .collect();
        let roots = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let range = ByteRange {
                    start: index,
                    end: index + 1,
                };
                IrNode {
                    shape: Shape::Function,
                    name: Some((*name).into()),
                    token_start: index,
                    token_end: index + 1,
                    range,
                    children: vec![IrNode {
                        shape: Shape::Block,
                        name: None,
                        token_start: index,
                        token_end: index + 1,
                        range,
                        children: vec![IrNode {
                            shape: Shape::Return,
                            name: None,
                            token_start: index,
                            token_end: index + 1,
                            range,
                            children: Vec::new(),
                        }],
                    }],
                }
            })
            .collect();
        SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens,
            signatures: Vec::new(),
            roots,
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
            test_module: false,
        }
    }

    fn inputs() -> (
        Vec<Unit>,
        Vec<SyntaxIrFile>,
        Vec<FileFeatures>,
        UnitEvidence,
        GroupingSet,
    ) {
        // File 0 has a primary member and three ungrouped local candidates.
        // File 1 supplies the other primary member; file 2 is deliberately
        // outside the group's host files and must never enter the sweep.
        let files = vec![
            file(&["anchor", "zeta", "alpha", "middle"]),
            file(&["peer"]),
            file(&["outside"]),
        ];
        let feature_files = files.iter().map(features::extract).collect();
        let (units, _) = flatten_units(
            &files,
            &variant(),
            LiteralNorm::Full,
            &ResolvedTypes::default(),
        );
        let evidence = unit_evidence(&units, &ResolvedTypes::default());
        let grouping_units = units
            .iter()
            .map(|unit| GroupingUnit {
                key: *unit.fingerprint.as_bytes(),
            })
            .collect::<Vec<_>>();
        let groups = grouping::group(
            &grouping_units,
            &[SimilarityEdge {
                a: 0,
                b: 4,
                similarity: 1.0,
                breakdown: None,
                class: CloneClass::Type1,
                confidence: Confidence::High,
            }],
            &GroupingConfig::default(),
        );
        (units, files, feature_files, evidence, groups)
    }

    fn config() -> StructuralConfig {
        StructuralConfig {
            min_clone_tokens: 1,
            ..StructuralConfig::default()
        }
    }

    fn signature_inputs() -> (
        Vec<Unit>,
        Vec<SyntaxIrFile>,
        Vec<FileFeatures>,
        UnitEvidence,
        GroupingSet,
    ) {
        let (original_units, mut files, feature_files, _original_evidence, groups) = inputs();
        let signature = Signature::new(Language::Rust, "rust|params=[]|return=()");
        for (file_index, file) in files.iter_mut().enumerate() {
            let roots_with_signatures = match file_index {
                0 => &[0, 1, 2][..],
                1 | 2 => &[0][..],
                _ => &[][..],
            };
            file.signatures = roots_with_signatures
                .iter()
                .map(|&root| (file.roots[root].range, signature.clone()))
                .collect();
        }
        let partitions = [
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(1),
        ];
        let (units, _) = flatten_units_with_context(
            &files,
            &variant(),
            LiteralNorm::Full,
            &ResolvedTypes::default(),
            Some(&partitions),
        );
        for (original, contextual) in original_units.iter().zip(&units) {
            assert_eq!(contextual.fingerprint, original.fingerprint);
            assert_eq!(contextual.content, original.content);
            assert_eq!(contextual.normalized_content, original.normalized_content);
            assert_eq!(contextual.statements, original.statements);
        }
        let evidence = unit_evidence(&units, &ResolvedTypes::default());
        (units, files, feature_files, evidence, groups)
    }

    /// Two primary groups in two directories, each with one signature of its
    /// own and ungrouped units beside it: one signature is shared by four
    /// units of the tree, the other by three.
    fn two_signature_inputs() -> (
        Vec<Unit>,
        Vec<SyntaxIrFile>,
        Vec<FileFeatures>,
        UnitEvidence,
        GroupingSet,
    ) {
        let mut files = vec![
            file(&["wide_anchor", "wide_first", "wide_second"]),
            file(&["wide_peer"]),
            file(&["rare_anchor", "rare_spare"]),
            file(&["rare_peer"]),
        ];
        let wide = Signature::new(Language::Rust, "rust|params=[wide]|return=()");
        let rare = Signature::new(Language::Rust, "rust|params=[rare]|return=()");
        for (file_index, file) in files.iter_mut().enumerate() {
            let signature = if file_index < 2 { &wide } else { &rare };
            file.signatures = file
                .roots
                .iter()
                .map(|root| (root.range, signature.clone()))
                .collect();
        }
        let feature_files = files.iter().map(features::extract).collect();
        let partitions = [
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(1),
            DirectoryPartition::new(1),
        ];
        let (units, _) = flatten_units_with_context(
            &files,
            &variant(),
            LiteralNorm::Full,
            &ResolvedTypes::default(),
            Some(&partitions),
        );
        let evidence = unit_evidence(&units, &ResolvedTypes::default());
        let grouping_units = units
            .iter()
            .map(|unit| GroupingUnit {
                key: *unit.fingerprint.as_bytes(),
            })
            .collect::<Vec<_>>();
        let edge = |a: usize, b: usize| SimilarityEdge {
            a,
            b,
            similarity: 1.0,
            breakdown: None,
            class: CloneClass::Type1,
            confidence: Confidence::High,
        };
        let groups = grouping::group(
            &grouping_units,
            &[edge(0, 3), edge(4, 6)],
            &GroupingConfig::default(),
        );
        (units, files, feature_files, evidence, groups)
    }

    /// Copy a unit's analysed data. `Unit` is deliberately not `Clone`, so a
    /// test that needs a second unit spells the copy out.
    fn duplicate(unit: &Unit) -> Unit {
        Unit {
            file: unit.file,
            local: unit.local,
            kind: unit.kind,
            statements: unit.statements.clone(),
            fingerprint: unit.fingerprint,
            content: unit.content,
            normalized_content: unit.normalized_content,
            signature: unit.signature.clone(),
            directory: unit.directory,
            range: unit.range,
            lines: unit.lines,
            tokens: unit.tokens,
            name: unit.name.clone(),
            boilerplate: unit.boilerplate,
            test_code: unit.test_code,
            test_code_evidence: unit.test_code_evidence,
            arms: unit.arms.clone(),
        }
    }

    /// Add units that carry one unit's signature but no directory context, so
    /// they raise how widely the tree shares that signature without offering
    /// themselves as candidates.
    fn widen_signature(units: &mut Vec<Unit>, source: usize, extra: usize) {
        for _ in 0..extra {
            let mut copy = duplicate(&units[source]);
            copy.directory = None;
            units.push(copy);
        }
    }

    #[test]
    fn a_signature_shared_by_more_units_than_the_limit_offers_no_siblings() {
        let (units, files, feature_files, evidence, groups) = signature_inputs();
        let mut gated = config();
        // Five units of the tree share the one signature in this fixture.
        gated.signature_siblings.max_units_per_signature = 4;
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &gated,
            &[],
        );
        assert!(siblings.is_empty());
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.eligible_candidates, 0);
        assert_eq!(stats.candidates_examined, 0);
        assert_eq!(stats.common_signatures_skipped, 1);
        assert_eq!(stats.largest_skipped_signature_units, 5);
        assert_eq!(stats.common_signature_dropped, 2);
    }

    #[test]
    fn the_share_count_covers_grouped_units_so_the_limit_cannot_loosen() {
        let (units, files, feature_files, evidence, groups) = signature_inputs();
        let ungrouped_with_signature = units
            .iter()
            .enumerate()
            .filter(|(index, unit)| {
                unit.signature.is_some()
                    && !groups
                        .groups
                        .iter()
                        .any(|group| group.members.contains(index))
            })
            .count();
        assert_eq!(ungrouped_with_signature, 3);

        // A limit of four can only exclude this signature if the two units
        // primary grouping already holds are counted as sharing it too.
        let mut gated = config();
        gated.signature_siblings.max_units_per_signature = 4;
        let (_, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &gated,
            &[],
        );
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.largest_skipped_signature_units, 5);
    }

    #[test]
    fn a_signature_within_the_limit_keeps_its_siblings_and_names_the_share_count() {
        let (units, files, feature_files, evidence, groups) = signature_inputs();
        let mut allowed = config();
        allowed.signature_siblings.max_units_per_signature = 5;
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &allowed,
            &[],
        );
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.common_signatures_skipped, 0);
        assert_eq!(stats.largest_skipped_signature_units, 0);
        assert_eq!(stats.common_signature_dropped, 0);
        for sibling in siblings.iter().flat_map(|group| &group.siblings) {
            assert_eq!(sibling.basis, SiblingBasis::Signature);
            assert_eq!(sibling.signature_units, Some(5));
            assert_eq!(
                sibling.confidence,
                Confidence::Low,
                "rarity travels as a number, never as a stronger confidence band"
            );
        }

        // The limit is the caller's, and one unit lower turns the same input
        // into no siblings at all.
        let mut refused = config();
        refused.signature_siblings.max_units_per_signature = 4;
        let (refused_siblings, refused_stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &refused,
            &[],
        );
        assert!(refused_siblings.is_empty());
        assert_eq!(refused_stats.accepted, 0);
    }

    #[test]
    fn the_sharing_limit_and_the_caps_are_counted_in_separate_fields() {
        let (units, files, feature_files, evidence, groups) = two_signature_inputs();
        let mut limited = config();
        // Four units share the first signature and three share the second, so
        // the limit excludes one key and leaves the other to the caps.
        limited.signature_siblings = SignatureSiblingConfig {
            max_units_per_signature: 3,
            candidate_budget: 10,
            per_group_cap: 0,
            total_cap: 10,
        };
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &limited,
            &[],
        );
        assert!(siblings.is_empty());
        assert_eq!(stats.common_signatures_skipped, 1);
        assert_eq!(stats.largest_skipped_signature_units, 4);
        assert_eq!(stats.common_signature_dropped, 2);
        assert_eq!(stats.eligible_candidates, 1);
        assert_eq!(stats.per_group_cap_dropped, 1);
        assert_eq!(stats.candidate_budget_dropped, 0);
        assert_eq!(stats.total_cap_dropped, 0);
    }

    #[test]
    fn signature_siblings_reaching_a_shared_cap_are_the_rarest_signatures_first() {
        let (units, files, feature_files, evidence, groups) = two_signature_inputs();
        let mut capped = config();
        capped.signature_siblings = SignatureSiblingConfig {
            max_units_per_signature: 8,
            candidate_budget: 10,
            per_group_cap: 8,
            total_cap: 1,
        };
        // The group whose signature four units share owns the lower group
        // index, so only the share count can put the rarer one first.
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &capped,
            &[],
        );
        assert_eq!(stats.eligible_candidates, 3);
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.total_cap_dropped, 2);
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].group, 1);
        assert_eq!(siblings[0].siblings[0].unit, 5);
        assert_eq!(siblings[0].siblings[0].signature_units, Some(3));

        // Widen the second signature past the first, and the survivor flips.
        let (mut widened_units, files, feature_files, _, groups) = two_signature_inputs();
        widen_signature(&mut widened_units, 5, 3);
        let evidence = unit_evidence(&widened_units, &ResolvedTypes::default());
        let (widened, widened_stats) = sweep_signature_siblings(
            &groups,
            &widened_units,
            &files,
            &feature_files,
            &evidence,
            &capped,
            &[],
        );
        assert_eq!(widened_stats.accepted, 1);
        assert_eq!(widened_stats.total_cap_dropped, 2);
        assert_eq!(widened.len(), 1);
        assert_eq!(widened[0].group, 0);
        assert_eq!(widened[0].siblings[0].signature_units, Some(4));
    }

    #[test]
    fn signature_channel_finds_same_directory_ungrouped_units_and_wins_overlap() {
        let (units, files, feature_files, evidence, groups) = signature_inputs();
        let (similarity_only, _, _) = sweep_siblings_with_context(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
            false,
        );
        let (siblings, similarity_stats, signature_stats) = sweep_siblings_with_context(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
            true,
        );
        let group = siblings.iter().find(|group| group.group == 0).unwrap();
        let candidate = group
            .siblings
            .iter()
            .find(|sibling| sibling.unit == 1)
            .unwrap();
        assert_eq!(candidate.basis, SiblingBasis::Signature);
        assert_eq!(candidate.clone_type, CloneClass::Type3);
        assert_eq!(candidate.confidence, Confidence::Low);
        assert!(candidate.signature.is_some());
        assert_eq!(
            candidate.breakdown,
            similarity_only[0]
                .siblings
                .iter()
                .find(|sibling| sibling.unit == 1)
                .expect("overlapping similarity sibling")
                .breakdown,
            "overlap reuses the existing verifier breakdown"
        );
        assert_eq!(signature_stats.accepted, 2);
        assert_eq!(similarity_stats.accepted, 3);
        assert!(group.siblings.iter().any(|sibling| sibling.unit == 2));
        assert_eq!(
            group
                .siblings
                .iter()
                .find(|sibling| sibling.unit == 3)
                .map(|sibling| sibling.basis),
            Some(SiblingBasis::Similarity)
        );
    }

    #[test]
    fn signature_channel_is_directory_scoped_and_legacy_wrapper_disables_it() {
        let (mut units, files, feature_files, evidence, groups) = signature_inputs();
        units[1].directory = Some(DirectoryPartition::new(2));
        let (signature, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
            &[],
        );
        assert_eq!(stats.accepted, 1);
        assert!(
            !signature
                .iter()
                .flat_map(|group| &group.siblings)
                .any(|sibling| sibling.unit == 1)
        );

        let (legacy, _) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
        );
        assert!(
            legacy
                .iter()
                .flat_map(|group| &group.siblings)
                .all(|sibling| sibling.basis == SiblingBasis::Similarity)
        );
    }

    #[test]
    fn signature_channel_ignores_verifier_threshold_and_missing_signatures() {
        let (mut units, files, mut feature_files, evidence, groups) = signature_inputs();
        units[2].signature = None;
        feature_files[0].units[1].vector.counts.fill(0);
        feature_files[0].units[1].vector.node_count = 1;
        let mut high_threshold = config();
        high_threshold.verify.type3_min_composite = 1.1;
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &high_threshold,
            &[],
        );
        assert_eq!(stats.accepted, 1);
        let sibling = &siblings[0].siblings[0];
        assert_eq!(sibling.basis, SiblingBasis::Signature);
        assert_eq!(sibling.clone_type, CloneClass::Type3);
        assert_eq!(sibling.confidence, Confidence::Low);
    }

    #[test]
    fn signature_caps_are_independent_and_report_exact_drops() {
        let (units, files, feature_files, evidence, groups) = signature_inputs();
        let mut signature_limited = config();
        signature_limited.siblings = SiblingConfig {
            similarity_delta: 0.10,
            candidate_budget: 0,
            per_group_cap: 0,
            total_cap: 0,
        };
        signature_limited.signature_siblings = SignatureSiblingConfig {
            max_units_per_signature: 8,
            candidate_budget: 10,
            per_group_cap: 1,
            total_cap: 10,
        };
        let (siblings, similarity_stats, signature_stats) = sweep_siblings_with_context(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &signature_limited,
            true,
        );
        assert_eq!(similarity_stats.candidates_examined, 0);
        assert_eq!(signature_stats.eligible_candidates, 2);
        assert_eq!(signature_stats.candidates_examined, 1);
        assert_eq!(signature_stats.accepted, 1);
        assert_eq!(signature_stats.candidate_budget_dropped, 0);
        assert_eq!(signature_stats.per_group_cap_dropped, 1);
        assert_eq!(signature_stats.total_cap_dropped, 0);
        assert_eq!(siblings[0].siblings.len(), 1);

        let mut budget_limited = config();
        budget_limited.signature_siblings = SignatureSiblingConfig {
            max_units_per_signature: 8,
            candidate_budget: 1,
            per_group_cap: 10,
            total_cap: 10,
        };
        let (_, budget_stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &budget_limited,
            &[],
        );
        assert_eq!(budget_stats.eligible_candidates, 2);
        assert_eq!(budget_stats.candidates_examined, 1);
        assert_eq!(budget_stats.candidate_budget_dropped, 1);
        assert_eq!(budget_stats.per_group_cap_dropped, 0);
        assert_eq!(budget_stats.total_cap_dropped, 0);

        let mut total_limited = config();
        total_limited.signature_siblings = SignatureSiblingConfig {
            max_units_per_signature: 8,
            candidate_budget: 10,
            per_group_cap: 10,
            total_cap: 1,
        };
        let (_, total_stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &total_limited,
            &[],
        );
        assert_eq!(total_stats.eligible_candidates, 2);
        assert_eq!(total_stats.candidates_examined, 1);
        assert_eq!(total_stats.candidate_budget_dropped, 0);
        assert_eq!(total_stats.per_group_cap_dropped, 0);
        assert_eq!(total_stats.total_cap_dropped, 1);
    }

    #[test]
    fn high_frequency_signature_posting_stops_at_budget_without_group_materialization() {
        const POSTING_SIZE: usize = 4_096;
        let (mut units, files, feature_files, evidence, groups) = signature_inputs();
        let prototype = duplicate(&units[1]);
        for index in 0..POSTING_SIZE {
            let mut unit = duplicate(&prototype);
            let mut fingerprint = [0_u8; 16];
            fingerprint[..8]
                .copy_from_slice(&u64::try_from(index + 10).unwrap_or(u64::MAX).to_le_bytes());
            unit.fingerprint = UnitFingerprint::from_bytes(fingerprint);
            units.push(unit);
        }
        let mut limited = config();
        limited.signature_siblings = SignatureSiblingConfig {
            // This case is about the budget alone, so the sharing limit is
            // put out of the way rather than allowed to empty the posting.
            max_units_per_signature: usize::MAX,
            candidate_budget: 3,
            per_group_cap: POSTING_SIZE + 2,
            total_cap: POSTING_SIZE + 2,
        };
        let (siblings, stats) = sweep_signature_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &limited,
            &[],
        );
        let eligible = POSTING_SIZE + 2;
        assert_eq!(stats.eligible_candidates, eligible);
        assert_eq!(stats.candidates_examined, 3);
        assert_eq!(stats.accepted, 3);
        assert_eq!(stats.candidate_budget_dropped, eligible - 3);
        assert_eq!(stats.per_group_cap_dropped, 0);
        assert_eq!(stats.total_cap_dropped, 0);
        assert_eq!(siblings[0].siblings.len(), 3);
    }

    #[test]
    fn mismatched_directory_context_is_ignored_without_changing_identity() {
        let (legacy, files, _, _, _) = inputs();
        let (contextual, _) = flatten_units_with_context(
            &files,
            &variant(),
            LiteralNorm::Full,
            &ResolvedTypes::default(),
            Some(&[DirectoryPartition::new(7)]),
        );
        assert_eq!(contextual.len(), legacy.len());
        for (old, new) in legacy.iter().zip(&contextual) {
            assert_eq!(new.directory, None);
            assert_eq!(new.signature, old.signature);
            assert_eq!(new.fingerprint, old.fingerprint);
            assert_eq!(new.content, old.content);
            assert_eq!(new.normalized_content, old.normalized_content);
            assert_eq!(new.statements, old.statements);
        }
    }

    #[test]
    fn sibling_candidates_reuse_every_primary_pair_guard() {
        let (mut units, _files, mut feature_files, _evidence, _groups) = inputs();
        let default = config();
        assert!(sibling_candidate_allowed(
            0,
            1,
            &units,
            &feature_files,
            &default
        ));

        units[1].tokens = units[0].tokens;
        assert!(!sibling_candidate_allowed(
            0,
            1,
            &units,
            &feature_files,
            &default
        ));
        units[1].tokens = (1, 2);

        let mut minimum = default.clone();
        minimum.min_clone_tokens = 2;
        assert!(!sibling_candidate_allowed(
            0,
            1,
            &units,
            &feature_files,
            &minimum
        ));

        let mut tracker = ArmTracker::default();
        tracker.begin(StaticCondition::Unknown);
        units[0].arms = tracker.current();
        tracker.next_arm(StaticCondition::Unknown);
        units[1].arms = tracker.current();
        assert!(!sibling_candidate_allowed(
            0,
            1,
            &units,
            &feature_files,
            &default
        ));
        units[0].arms = crate::conditional::ArmPath::default();
        units[1].arms = crate::conditional::ArmPath::default();

        feature_files[0].units[1].vector.counts.fill(0);
        feature_files[0].units[1].vector.node_count = 1;
        assert!(!sibling_candidate_allowed(
            0,
            1,
            &units,
            &feature_files,
            &default
        ));
    }

    #[test]
    fn sweep_is_file_scoped_and_orders_siblings_by_fingerprint() {
        let (units, files, feature_files, evidence, groups) = inputs();
        let (siblings, stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
        );

        let mut expected = vec![1, 2, 3];
        expected.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
        assert_eq!(siblings.len(), 1);
        assert_eq!(
            siblings[0]
                .siblings
                .iter()
                .map(|sibling| sibling.unit)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(!siblings[0].siblings.iter().any(|sibling| sibling.unit == 5));
        assert_eq!(stats.eligible_candidates, 3);
        assert_eq!(stats.candidates_examined, 3);
        assert_eq!(stats.accepted, 3);
        assert_eq!(groups.groups[0].members.len(), 2);

        let (again, again_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &config(),
        );
        assert_eq!(again, siblings);
        assert_eq!(again_stats, stats);
    }

    #[test]
    fn sweep_caps_bound_comparisons_and_retained_siblings() {
        let (units, files, feature_files, evidence, groups) = inputs();
        let mut ordered = vec![1, 2, 3];
        ordered.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
        let expected_first = ordered.remove(0);

        let mut per_group_config = config();
        per_group_config.siblings = SiblingConfig {
            similarity_delta: 0.10,
            candidate_budget: 10,
            per_group_cap: 1,
            total_cap: 10,
        };
        let (per_group, per_group_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &per_group_config,
        );
        assert_eq!(per_group[0].siblings[0].unit, expected_first);
        assert_eq!(per_group_stats.candidates_examined, 1);
        assert_eq!(per_group_stats.per_group_cap_dropped, 2);

        let mut total_config = config();
        total_config.siblings = SiblingConfig {
            similarity_delta: 0.10,
            candidate_budget: 10,
            per_group_cap: 8,
            total_cap: 1,
        };
        let (_, total_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &total_config,
        );
        assert_eq!(total_stats.candidates_examined, 1);
        assert_eq!(total_stats.total_cap_dropped, 2);

        let mut budget_config = config();
        budget_config.siblings = SiblingConfig {
            similarity_delta: 0.10,
            candidate_budget: 1,
            per_group_cap: 8,
            total_cap: 10,
        };
        let (_, budget_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &budget_config,
        );
        assert_eq!(budget_stats.candidates_examined, 1);
        assert_eq!(budget_stats.candidate_budget_dropped, 2);
    }

    #[test]
    fn exact_structure_below_the_normal_threshold_is_low_confidence() {
        assert_eq!(
            sibling_classification(Some(CloneClass::Type2), Some(Confidence::High), 0.69, 0.70,),
            (CloneClass::Type2, Confidence::Low)
        );
        assert_eq!(
            sibling_classification(Some(CloneClass::Type2), Some(Confidence::High), 0.70, 0.70,),
            (CloneClass::Type2, Confidence::High)
        );
    }
}
