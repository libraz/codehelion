use super::{
    BTreeSet, BuildVariant, FileFeatures, GroupDetail, GroupingUnit, ResolvedTypes, SimilarityEdge,
    StructuralConfig, StructuralNearMiss, StructuralRegion, StructuralReport, StructuralStats,
    StructuralUnit, SyntaxIrFile, Unit, UnitEvidence, VerifyConfig, candidate, confirm_regions,
    control_flow, drop_subsumed, features, flatten_units, group_detail, grouping, grow_runs,
    lift_to_unit_pairs, maximal, near_match, sweep_siblings, token_count_meets_minimum,
    unit_evidence, unit_meets_minimum, unrepresented_pairs, verify, view,
};

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
    let feature_files: Vec<FileFeatures> = files.iter().map(features::extract).collect();

    let (units, offsets) = flatten_units(files, variant);
    let evidence = unit_evidence(&units, resolved);

    // Stage: candidate extraction (exact seeds, near matches and shared
    // control-flow skeletons), lifted to distinct unit pairs.
    let candidate = candidate::generate(&feature_files, &config.candidate);
    let near = near_match::generate(&feature_files, &config.near_match);
    let skeleton = control_flow::generate(&feature_files, &config.control_flow);
    let near_misses = near
        .near_misses
        .iter()
        .map(|near_miss| StructuralNearMiss {
            a: offsets[near_miss.a.file] + near_miss.a.unit,
            b: offsets[near_miss.b.file] + near_miss.b.unit,
            estimated_jaccard: near_miss.estimated_jaccard,
        })
        .collect();
    let lifted = lift_to_unit_pairs(
        &candidate,
        &near,
        &skeleton,
        &units,
        &offsets,
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
    let edges = verification.edges;

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
                &evidence,
                variant,
                config,
            )
        })
        .collect();

    let (unrepresented, described_pairs, severed_pairs) =
        unrepresented_pairs(&edges, &groups, &units, files, variant);
    // This is intentionally after primary grouping and unrepresented-pair
    // carry-out. It only inspects ungrouped units and cannot add an edge or a
    // member to `groups`.
    let (siblings, sibling_stats) = sweep_siblings(
        &groups,
        &units,
        files,
        &feature_files,
        &evidence,
        &config.verify,
        &config.siblings,
    );

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
        below_min_clone_token_regions,
        nested_pairs: lifted.nested,
        alternative_pairs: lifted.alternatives,
        divergent_shape_pairs: lifted.divergent,
        below_min_clone_token_pairs,
        unit_pairs: pairs.len(),
        verification_budget_dropped: verification.dropped,
        verified_pairs: edges.len(),
        unrepresented_pairs: unrepresented.len(),
        described_pairs,
        severed_pairs,
        grouping: groups.stats.clone(),
        siblings: sibling_stats,
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
    for &(a, b) in pairs.iter().take(budget) {
        let view_a = view(a, units, files, feature_files, evidence);
        let view_b = view(b, units, files, feature_files, evidence);
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
    VerificationSet {
        edges,
        dropped: pairs.len().saturating_sub(budget),
    }
}
