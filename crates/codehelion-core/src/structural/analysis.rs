use super::Unit;
use super::evidence::{
    ResolvedTypes, UnitEvidence, token_count_meets_minimum, unit_evidence, unit_meets_minimum,
};
use super::model::{
    DirectoryPartition, GroupDetail, GroupSiblings, StructuralConfig, StructuralNearMiss,
    StructuralReport, StructuralStats, StructuralUnit,
};
use super::pairs::{lift_to_unit_pairs, unrepresented_pairs};
use super::regions::{confirm_regions, drop_subsumed, fold_by_content, grow_runs};
use super::reporting::PairEvidence;
use super::reporting::group_detail;
use super::siblings::sweep_siblings_with_context;
use super::units::{flatten_units_with_context, view};
use crate::discovery::BuildVariant;
use crate::features::{self, FileFeatures};
use crate::frontend::UnitKind;
use crate::grouping::{self, GroupingSet, GroupingUnit, SimilarityEdge};
use crate::ir::SyntaxIrFile;
use crate::verify::{self, VerifyConfig};
use crate::{candidate, control_flow, maximal, near_match};
use std::collections::{BTreeMap, BTreeSet};

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
    analyze_resolved_inner(files, variant, config, &ResolvedTypes::default(), None)
}

/// Run the structural pipeline with caller-owned opaque directory partitions.
///
/// The partitions enable only the supplementary signature sibling channel.
/// They are never interpreted as paths and never participate in fingerprints,
/// feature extraction, primary grouping, or the existing file-scoped sibling
/// sweep. If their length differs from `files.len()`, the signature channel is
/// disabled for the whole run rather than guessing which partition belongs to
/// any file.
#[must_use]
pub fn analyze_with_context(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
    directory_partitions: &[DirectoryPartition],
) -> StructuralReport {
    analyze_resolved_inner(
        files,
        variant,
        config,
        &ResolvedTypes::default(),
        Some(directory_partitions),
    )
}

/// [`analyze`] with what a compiler resolved about the same files.
///
/// The stages are the same ones; what changes is that the type dimension of
/// every comparison is measured instead of absent. Passing nothing resolved is
/// exactly [`analyze`], which is the modes that run no compiler.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the structural pipeline deliberately keeps its ordered stages together"
)]
pub fn analyze_resolved(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
    resolved: &ResolvedTypes,
) -> StructuralReport {
    analyze_resolved_inner(files, variant, config, resolved, None)
}

/// [`analyze_resolved`] with caller-owned opaque directory partitions.
///
/// If the partition slice length differs from `files.len()`, the signature
/// channel is disabled for the whole run rather than guessing file identity.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the structural pipeline deliberately keeps its ordered stages together"
)]
pub fn analyze_resolved_with_context(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
    resolved: &ResolvedTypes,
    directory_partitions: &[DirectoryPartition],
) -> StructuralReport {
    analyze_resolved_inner(files, variant, config, resolved, Some(directory_partitions))
}

#[allow(
    clippy::too_many_lines,
    reason = "the structural pipeline deliberately keeps its ordered stages together"
)]
fn analyze_resolved_inner(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    config: &StructuralConfig,
    resolved: &ResolvedTypes,
    directory_partitions: Option<&[DirectoryPartition]>,
) -> StructuralReport {
    let feature_files: Vec<FileFeatures> = files.iter().map(features::extract).collect();

    let (units, index) = flatten_units_with_context(
        files,
        variant,
        config.literals,
        resolved,
        directory_partitions,
    );
    let evidence = unit_evidence(&units, resolved);

    // Stage: candidate extraction (exact seeds, near matches and shared
    // control-flow skeletons), lifted to distinct unit pairs.
    let candidate = candidate::generate(&feature_files, &config.candidate);
    let near = near_match::generate(&feature_files, &config.near_match);
    let skeleton = control_flow::generate(&feature_files, &config.control_flow);
    // A diagnostic naming a walk position that produced no unit describes
    // nothing a reader could look at, so it is not carried out.
    let near_misses = near
        .near_misses
        .iter()
        .filter_map(|near_miss| {
            Some(StructuralNearMiss {
                a: index.global(near_miss.a.file, near_miss.a.unit)?,
                b: index.global(near_miss.b.file, near_miss.b.unit)?,
                estimated_jaccard: near_miss.estimated_jaccard,
            })
        })
        .collect();
    let lifted = lift_to_unit_pairs(
        &candidate,
        &near,
        &skeleton,
        &units,
        &index,
        &feature_files,
        config.max_shape_divergence,
    );
    let mut pairs = lifted.pairs;
    let candidate_pairs = pairs.len();
    pairs.retain(|&(left, right)| {
        unit_meets_minimum(&units[left], config.min_clone_tokens)
            && unit_meets_minimum(&units[right], config.min_clone_tokens)
    });
    let below_min_clone_token_pairs = candidate_pairs.saturating_sub(pairs.len());

    // Stage: fold the window seeds into the maximal shared runs they describe,
    // then confirm each candidate run against the tokens it actually covers.
    let candidate_regions = maximal::consolidate(&candidate.pairs, &config.maximal);
    let (mut confirmed, mut dropped) = confirm_regions(
        &candidate_regions.shared,
        files,
        &index,
        variant,
        config.literals,
    );
    let merged = grow_runs(
        &mut confirmed,
        &mut dropped,
        files,
        &index,
        variant,
        config.literals,
    );
    let (mut regions, folded) = fold_by_content(confirmed, &mut dropped);
    let subsumed = drop_subsumed(&mut regions);
    let confirmed_regions = regions.len();
    regions.retain(|region| {
        region.occurrences.iter().all(|occurrence| {
            token_count_meets_minimum(
                occurrence.token_end.saturating_sub(occurrence.token_start),
                config.min_clone_tokens,
            )
        })
    });
    let below_min_clone_token_regions = confirmed_regions.saturating_sub(regions.len());

    // Stage: precise verification of each distinct unit pair.
    let verification = verify_pairs(
        &pairs,
        &units,
        files,
        &feature_files,
        &evidence,
        &config.verify,
        config.verification_budget,
    );
    // The precise verifier has consumed the lifted candidates. Keeping this
    // potentially large set alive through grouping and reporting needlessly
    // raises the scan's peak memory.
    drop(pairs);
    let edges = verification.edges;

    // Stage: medoid grouping over the verified pairs.
    let grouping_units: Vec<GroupingUnit> = units
        .iter()
        .map(|unit| GroupingUnit {
            // The component ceiling must not cut a content-equivalence class
            // into several groups: structural group identity uses normalized
            // content for non-Type-1 findings, and raw keys would therefore
            // mint duplicate fingerprints after a cut.
            key: *unit.normalized_content.as_bytes(),
        })
        .collect();
    let groups = grouping::group(&grouping_units, &edges, &config.grouping);

    // Per-group reporting detail: the stable clone id and the medoid-to-member
    // similarity breakdowns, read back from the verified edges grouping
    // settled each group with rather than measured a second time.
    let details: Vec<GroupDetail> = {
        let pair_evidence = PairEvidence::index(&edges);
        groups
            .groups
            .iter()
            .map(|group| {
                group_detail(
                    group,
                    &units,
                    files,
                    &feature_files,
                    &evidence,
                    &pair_evidence,
                    variant,
                    config,
                )
            })
            .collect()
    };

    let (unrepresented, described_pairs, severed_pairs) =
        unrepresented_pairs(&edges, &groups, &units, files, variant);
    // This is intentionally after primary grouping and unrepresented-pair
    // carry-out. It only inspects ungrouped units and cannot add an edge or a
    // member to `groups`.
    let (siblings, sibling_stats, signature_sibling_stats) = sweep_siblings_with_context(
        &groups,
        &units,
        files,
        &feature_files,
        &evidence,
        config,
        directory_partitions.is_some_and(|partitions| partitions.len() == files.len()),
    );

    // Stage: one duplication, one finding. A duplicated function is also a
    // duplicated body and a duplicated run, and each level is proposed on its
    // own, so the containment among the settled findings is decided here —
    // once, after every stage has had its say and before anything is reported
    // or recorded. Deciding it per stage would let the next stage put the
    // nested cut back.
    //
    // It runs after the carry-out of unrepresented pairs and after the sibling
    // sweep on purpose: both ask which units a group already accounts for, and
    // asking them about a group folded for nesting would return the nested cut
    // as a pair or a sibling instead.
    let mut groups = groups;
    let mut details = details;
    let mut siblings = siblings;
    let subsumed_groups = fold_contained_groups(&mut groups, &mut details, &mut siblings, &units);

    let stats = StructuralStats {
        files: files.len(),
        units: units.len(),
        candidate: candidate.stats,
        near_match: near.stats,
        control_flow: skeleton.stats,
        maximal: candidate_regions.stats,
        regions: regions.len(),
        region_occurrences: regions
            .iter()
            .map(|region| region.occurrences.len())
            .sum::<usize>(),
        region_singletons: dropped.singletons,
        region_unresolved: dropped.unresolved,
        region_overlapping: dropped.overlapping,
        region_adjoining: dropped.adjoining,
        region_subsumed: subsumed + subsumed_groups,
        region_merged: merged,
        region_folded: folded,
        below_min_clone_token_regions,
        nested_pairs: lifted.nested,
        alternative_pairs: lifted.alternatives,
        divergent_shape_pairs: lifted.divergent,
        below_min_clone_token_pairs,
        unit_pairs: candidate_pairs.saturating_sub(below_min_clone_token_pairs),
        verification_budget_dropped: verification.dropped,
        verified_pairs: edges.len(),
        unrepresented_pairs: unrepresented.len(),
        described_pairs,
        severed_pairs,
        grouping: groups.stats.clone(),
        siblings: sibling_stats,
        signature_siblings: signature_sibling_stats,
    };

    StructuralReport {
        units: reported(&units),
        groups,
        regions,
        details,
        unrepresented,
        siblings,
        near_misses,
        stats,
    }
}

/// Fold every group a longer group already accounts for, returning how many
/// went.
///
/// The rule itself is [`grouping::contained_groups`]; what happens here is
/// that everything naming a group keeps naming the same group. Details are
/// parallel to the groups, and a sibling names its owning group by index, so
/// the survivors are renumbered rather than left pointing at whatever moved
/// into their place. A sibling whose owning group is gone is a sibling of
/// nothing and goes with it.
fn fold_contained_groups(
    groups: &mut GroupingSet,
    details: &mut Vec<GroupDetail>,
    siblings: &mut Vec<GroupSiblings>,
    units: &[Unit],
) -> usize {
    let spans = member_spans(units);
    let folded = grouping::contained_groups(&groups.groups, &spans);
    let subsumed = folded.iter().filter(|&&folded| folded).count();
    if subsumed == 0 {
        return 0;
    }

    let mut moved_to: Vec<Option<usize>> = Vec::with_capacity(folded.len());
    let mut kept = 0;
    for &folded in &folded {
        moved_to.push((!folded).then(|| {
            kept += 1;
            kept - 1
        }));
    }
    groups.groups = std::mem::take(&mut groups.groups)
        .into_iter()
        .zip(&folded)
        .filter_map(|(group, &folded)| (!folded).then_some(group))
        .collect();
    *details = std::mem::take(details)
        .into_iter()
        .zip(&folded)
        .filter_map(|(detail, &folded)| (!folded).then_some(detail))
        .collect();
    *siblings = std::mem::take(siblings)
        .into_iter()
        .filter_map(|entry| {
            let group = moved_to.get(entry.group).copied().flatten()?;
            Some(GroupSiblings { group, ..entry })
        })
        .collect();
    subsumed
}

/// Where each unit sits and which unit declares it, indexed by unit.
///
/// Units arrive in walk order — pre-order, children in source order, one file
/// after another — so the units enclosing one are exactly the ones still open
/// when it is reached, and a stack of those answers the question in one pass.
///
/// A closure is written inside a declaration and is that declaration at a
/// smaller extent, so it names the innermost declaration around it. Everything
/// else declares itself: a function nested in a function is a function, and
/// the fold has to be able to tell that from a body seen smaller.
fn member_spans(units: &[Unit]) -> Vec<grouping::MemberSpan> {
    let mut spans: Vec<grouping::MemberSpan> = Vec::with_capacity(units.len());
    let mut open: Vec<usize> = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        while open
            .last()
            .is_some_and(|&enclosing| !encloses(&units[enclosing], unit))
        {
            open.pop();
        }
        // A closure the walk found outside every declaration — a top-level
        // lambda, or one whose enclosing item the frontend could not read — is
        // nothing's smaller extent, so it stands for itself.
        let declaration = if declares_itself(unit.kind) {
            index
        } else {
            open.last()
                .map_or(index, |&enclosing| spans[enclosing].declaration)
        };
        spans.push(grouping::MemberSpan {
            file: unit.file,
            start: unit.range.start,
            end: unit.range.end,
            declaration,
        });
        open.push(index);
    }
    spans
}

/// Whether a unit is a declaration in its own right rather than an expression
/// written inside one.
///
/// Matched exhaustively: a kind added later has to say which of the two it is,
/// because reading it as a declaration keeps a finding a reader may not need
/// and reading it as an expression removes one they do.
const fn declares_itself(kind: UnitKind) -> bool {
    match kind {
        UnitKind::Function | UnitKind::Method | UnitKind::Impl | UnitKind::Record => true,
        UnitKind::Closure => false,
    }
}

/// Whether one unit's bytes lie inside another's.
const fn encloses(outer: &Unit, inner: &Unit) -> bool {
    outer.file == inner.file
        && outer.range.start <= inner.range.start
        && inner.range.end <= outer.range.end
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
            test_code_evidence: unit.test_code_evidence,
            fingerprint: unit.fingerprint,
            content: unit.content,
            normalized_content: unit.normalized_content,
        })
        .collect()
}

/// Verify every candidate unit pair, keeping the ones a verdict accepts.
///
/// A pair the verifier leaves unclassified is not an edge: grouping works over
/// accepted pairs only.
struct VerificationSet {
    /// Candidate pairs the verifier accepted.
    edges: Vec<SimilarityEdge>,
    /// Candidate pairs the resource ceiling intentionally left unexamined.
    dropped: usize,
}

fn verify_pairs(
    pairs: &BTreeSet<(usize, usize)>,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    config: &VerifyConfig,
    budget: usize,
) -> VerificationSet {
    let mut edges: Vec<SimilarityEdge> = Vec::new();
    let (selected, dropped) = verification_components(pairs, budget);
    for (a, b) in selected {
        let view_a = view(a, units, files, feature_files, evidence);
        let view_b = view(b, units, files, feature_files, evidence);
        let verdict = verify::verify(&view_a, &view_b, config);
        if let (Some(class), Some(confidence)) = (verdict.class, verdict.confidence) {
            edges.push(SimilarityEdge {
                a,
                b,
                similarity: verdict.breakdown.composite,
                breakdown: Some(verdict.breakdown),
                class,
                confidence,
            });
        }
    }
    VerificationSet { edges, dropped }
}

/// Select complete candidate components for verification under `budget`.
///
/// A candidate set is read a fixed number of times whatever it is shaped like:
/// the traversal that decides which component a unit belongs to labels it at
/// the same time, and the pairs are then counted and placed by that label. The
/// alternative — asking each component which of the candidate pairs are its own
/// — multiplies the candidate count by the number of independent duplicate
/// families the repository has, which is largest exactly where this ceiling
/// exists to help (AGENTS.md §2-10). A component the budget cannot afford costs
/// no scan of its own either.
///
/// Components keep the order of their smallest member and their pairs the order
/// of `pairs`, which is the order a per-component rescan produced.
fn verification_components(
    pairs: &BTreeSet<(usize, usize)>,
    budget: usize,
) -> (Vec<(usize, usize)>, usize) {
    let mut adjacent = BTreeMap::<usize, Vec<usize>>::new();
    for &(a, b) in pairs {
        adjacent.entry(a).or_default().push(b);
        adjacent.entry(b).or_default().push(a);
    }
    let mut component_of = BTreeMap::<usize, usize>::new();
    let mut components = 0;
    for &root in adjacent.keys() {
        if component_of.contains_key(&root) {
            continue;
        }
        component_of.insert(root, components);
        let mut stack = vec![root];
        while let Some(member) = stack.pop() {
            for &next in &adjacent[&member] {
                if component_of.insert(next, components).is_none() {
                    stack.push(next);
                }
            }
        }
        components += 1;
    }

    // How many pairs each component holds, so the allowance is settled before
    // anything is copied.
    let mut held = vec![0usize; components];
    for &(a, _) in pairs {
        note_pair_scan();
        if let Some(&component) = component_of.get(&a) {
            held[component] += 1;
        }
    }

    let mut remaining = budget;
    let mut dropped = 0;
    let mut placed = 0;
    // Where each admitted component's pairs start in the selection, in root
    // order; `None` for the ones the allowance did not cover.
    let mut start_of: Vec<Option<usize>> = Vec::with_capacity(components);
    for &count in &held {
        if count > remaining {
            dropped += count;
            start_of.push(None);
            continue;
        }
        remaining -= count;
        start_of.push(Some(placed));
        placed += count;
    }

    let mut selected = vec![(0usize, 0usize); placed];
    let mut cursor = vec![0usize; components];
    for &(a, b) in pairs {
        note_pair_scan();
        let Some(&component) = component_of.get(&a) else {
            continue;
        };
        if let Some(start) = start_of[component] {
            selected[start + cursor[component]] = (a, b);
            cursor[component] += 1;
        }
    }
    (selected, dropped)
}

// Candidate pairs read while sorting them into components, counted on this
// thread. The cost this partition must not have is one that grows with the
// number of independent families as well as with the candidate count, and that
// is a count rather than a duration. Tests read it; nothing else does.
#[cfg(test)]
thread_local! {
    static PAIR_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_pair_scan() {
    PAIR_SCANS.with(|scans| scans.set(scans.get() + 1));
}

/// Take and reset the current thread's scan count.
#[cfg(test)]
fn taken_pair_scans() -> usize {
    PAIR_SCANS.with(std::cell::Cell::take)
}

#[cfg(not(test))]
const fn note_pair_scan() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_budget_never_cuts_through_a_connected_candidate_family() {
        let pairs = BTreeSet::from([(0, 1), (1, 2), (3, 4)]);
        let (selected, dropped) = verification_components(&pairs, 1);

        assert_eq!(selected, vec![(3, 4)]);
        assert_eq!(dropped, 2);
    }

    /// The per-component rescan this selection replaced, kept as an oracle: the
    /// way the pairs of one component are found may change, the set that is
    /// selected and the order it arrives in may not.
    fn rescanning_components(
        pairs: &BTreeSet<(usize, usize)>,
        budget: usize,
    ) -> (Vec<(usize, usize)>, usize) {
        let mut adjacent = BTreeMap::<usize, Vec<usize>>::new();
        for &(a, b) in pairs {
            adjacent.entry(a).or_default().push(b);
            adjacent.entry(b).or_default().push(a);
        }
        let mut visited = BTreeSet::new();
        let mut remaining = budget;
        let mut dropped = 0;
        let mut selected = Vec::new();
        for &root in adjacent.keys() {
            if !visited.insert(root) {
                continue;
            }
            let mut stack = vec![root];
            let mut members = BTreeSet::from([root]);
            while let Some(member) = stack.pop() {
                for &next in &adjacent[&member] {
                    if visited.insert(next) {
                        members.insert(next);
                        stack.push(next);
                    }
                }
            }
            let component: Vec<(usize, usize)> = pairs
                .iter()
                .copied()
                .filter(|(a, b)| members.contains(a) && members.contains(b))
                .collect();
            if component.len() > remaining {
                dropped += component.len();
                continue;
            }
            remaining -= component.len();
            selected.extend(component);
        }
        (selected, dropped)
    }

    #[test]
    fn component_selection_is_the_one_the_per_component_rescan_made() {
        // Deterministic shapes with chains, hubs, isolated pairs and repeated
        // endpoints, under allowances that admit all, some and none of them.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        for case in 0..24_u64 {
            let span = 8 + case * 3;
            let mut pairs = BTreeSet::new();
            for _ in 0..64 {
                let a = usize::try_from(next() % span).unwrap_or(0);
                let b = usize::try_from(next() % span).unwrap_or(0);
                if a != b {
                    pairs.insert((a.min(b), a.max(b)));
                }
            }
            for budget in [0, 1, 3, 7, 16, 64, usize::MAX] {
                assert_eq!(
                    verification_components(&pairs, budget),
                    rescanning_components(&pairs, budget),
                    "case {case} under a budget of {budget}"
                );
            }
        }
    }

    #[test]
    fn sorting_candidates_into_components_does_not_multiply_by_their_number() {
        // Twenty thousand two-node families: the shape where a component-by-
        // component rescan reads the whole candidate set once per family.
        const COMPONENTS: usize = 20_000;
        let pairs: BTreeSet<(usize, usize)> = (0..COMPONENTS)
            .map(|component| (component * 2, component * 2 + 1))
            .collect();

        let _ = taken_pair_scans();
        let (selected, dropped) = verification_components(&pairs, usize::MAX);
        let scans = taken_pair_scans();

        assert_eq!(selected.len(), pairs.len());
        assert_eq!(dropped, 0);
        assert!(
            scans <= 4 * pairs.len(),
            "{scans} reads of {} candidate pairs across {COMPONENTS} components",
            pairs.len()
        );

        // The same candidate count in one family costs the same reads, so the
        // number of families is not a multiplier on the work.
        let one_family: BTreeSet<(usize, usize)> =
            (0..pairs.len()).map(|node| (0, node + 1)).collect();
        let _ = taken_pair_scans();
        let (selected, _) = verification_components(&one_family, usize::MAX);
        let family_scans = taken_pair_scans();

        assert_eq!(selected.len(), one_family.len());
        assert_eq!(scans, family_scans);
    }

    #[test]
    fn a_component_the_allowance_cannot_afford_costs_no_scan_of_its_own() {
        // Two families, one of them refused: the refusal is settled from the
        // counts, so the reads do not grow with what was refused.
        let mut pairs = BTreeSet::from([(0, 1)]);
        for node in 2..2_000 {
            pairs.insert((2, node));
        }

        let _ = taken_pair_scans();
        let (selected, dropped) = verification_components(&pairs, 1);
        let scans = taken_pair_scans();

        assert_eq!(selected, vec![(0, 1)]);
        assert_eq!(dropped, pairs.len() - 1);
        assert!(scans <= 4 * pairs.len(), "{scans} reads");
    }
}
