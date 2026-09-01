//! The one place a run's statistics become the funnel a report prints.
//!
//! A scan narrows: everything the sources hold goes in and a few findings come
//! out. The funnel is how a reader tells a tree with little duplication from a
//! run whose filters threw the evidence away, which only works while every
//! counter a stage keeps is either shown or deliberately not shown.
//!
//! Both modes are assembled here, and each assembles from an exhaustive
//! destructuring with no rest pattern — the same discipline
//! [`crate::scan::runtime::stage_limits`] applies to the ceilings going the
//! other way. A statistic added to either stats type stops this module
//! compiling until somebody has given it a stage, or has bound it with the
//! reason it belongs to no report surface. Two mode-specific builders sitting
//! in two pipelines is how a counter came to be computed on every run and
//! shown on none.
//!
//! The drop causes are named through [`report::FunnelCause`] rather than
//! spelled, so the vocabulary a producer writes is the vocabulary the
//! truncation and note predicates read back.

use codehelion_core::engine::EngineStats;
use codehelion_core::structural::StructuralStats;

use crate::report::{self, FunnelCause};

/// Counts arrive as `usize` and are reported as `u64`.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The Fast pipeline's pass counts, stage by stage: a winnowed fingerprint
/// index, the seed pairs its posting lists propose, the fragments the
/// identifier-normalized pass cuts from those seeds, the pairs that pass
/// proposes in turn, and the pairs that survive verification.
///
/// Both pairing stages carry their own budget accounting, because both hold
/// their own allowance.
pub(super) fn fast(stats: &EngineStats, groups: usize) -> Vec<report::FunnelStage> {
    // Exhaustively destructured on purpose: a counter added to the engine
    // stops this compiling until it has been given a stage or bound below with
    // the reason it has none.
    let EngineStats {
        // Reported as the summary's analysed-file count, which is the same
        // population read off the files that were lexed. A funnel row would
        // be that number a second time, under a second name.
        files: _,
        tokens,
        raw_fingerprints,
        raw_distinct,
        stop_fingerprints,
        stop_postings,
        fragments,
        control_headers_over_limit,
        bodies_over_nesting_limit,
        fragment_classes,
        class_cap_dropped,
        seed_candidates,
        raw_pairs_available,
        fragment_candidates,
        fragment_pairs_available,
        pairs,
        restated_pairs,
        hash_collisions,
        // Not a count of anything: the summary states outright whether the
        // allowance ran out, and each pairing stage below says how much of its
        // own search that cost.
        pair_budget_exhausted: _,
        conditional_pairs,
        subsumed_groups,
    } = stats;
    vec![
        report::FunnelStage::new("tokens", as_u64(*tokens)),
        report::FunnelStage::new("fingerprints", as_u64(*raw_fingerprints)),
        report::FunnelStage::new(
            "indexed values",
            as_u64(raw_distinct.saturating_sub(*stop_fingerprints)),
        )
        .dropping(FunnelCause::OversharedValues, as_u64(*stop_fingerprints))
        .dropping(FunnelCause::OversharedPostings, as_u64(*stop_postings)),
        report::FunnelStage::new("seed pairs", as_u64(*seed_candidates)).dropping(
            FunnelCause::PairBudget,
            as_u64(raw_pairs_available.saturating_sub(*seed_candidates)),
        ),
        // The nesting ceiling is stated beside the header one because both
        // describe blocks the cut never reached, and a fragment count with an
        // unexplained shortfall reads as a tree with nothing in it.
        report::FunnelStage::new("fragments", as_u64(*fragments))
            .dropping(
                FunnelCause::ControlHeaderLimit,
                as_u64(*control_headers_over_limit),
            )
            .dropping(
                FunnelCause::NestingLimit,
                as_u64(*bodies_over_nesting_limit),
            ),
        report::FunnelStage::new("fragment classes", as_u64(*fragment_classes))
            .dropping(FunnelCause::ClassCap, as_u64(*class_cap_dropped))
            .dropping(FunnelCause::HashCollision, as_u64(*hash_collisions)),
        // The two passes hold separate allowances, so each says separately how
        // much of its own search it got through. One combined figure would let
        // a pass that stopped early hide behind one that finished.
        report::FunnelStage::new("fragment pairs", as_u64(*fragment_candidates)).dropping(
            FunnelCause::PairBudget,
            as_u64(fragment_pairs_available.saturating_sub(*fragment_candidates)),
        ),
        // A restatement is a pair the run found and then declined to state
        // twice, so it is a drop of this stage rather than an internal detail:
        // without it the verified count is short of the pairs the two passes
        // proposed and nothing on the report says why.
        report::FunnelStage::new("verified pairs", as_u64(*pairs))
            .dropping(FunnelCause::ConditionalArms, as_u64(*conditional_pairs))
            .dropping(
                FunnelCause::AWiderPairSaysItAlready,
                as_u64(*restated_pairs),
            ),
        report::FunnelStage::new("clone groups", as_u64(groups))
            .dropping(FunnelCause::Subsumed, as_u64(*subsumed_groups)),
    ]
}

/// The structural pipeline's pass counts, stage by stage.
///
/// The run forks after candidate extraction: whole units go to verification
/// and grouping, while the statement windows that seeded the candidates are
/// folded back into the maximal runs they describe and confirmed against the
/// tokens they cover. The confirmed-run counts therefore continue the seed
/// line, not the verified-pair line.
#[allow(
    clippy::too_many_lines,
    reason = "the report deliberately presents the entire cross-mode funnel in one ordered definition"
)]
pub(super) fn structural(inputs: &StructuralFunnel<'_>) -> Vec<report::FunnelStage> {
    // Exhaustively destructured on purpose, for the reason `fast` above is.
    let StructuralStats {
        // Reported as the summary's analysed-file count; the structural-files
        // stage below counts the same files against the depth ceiling.
        files: _,
        units,
        candidate,
        near_match,
        control_flow,
        maximal,
        regions,
        region_occurrences,
        region_singletons,
        region_unresolved,
        region_overlapping,
        region_adjoining,
        region_subsumed,
        region_merged,
        region_folded,
        below_min_clone_token_regions,
        nested_pairs,
        alternative_pairs,
        divergent_shape_pairs,
        below_min_clone_token_pairs,
        unit_pairs,
        verification_budget_dropped,
        verified_pairs,
        unrepresented_pairs,
        described_pairs,
        severed_pairs,
        grouping,
        siblings,
        signature_siblings,
    } = inputs.stats;
    let mut stages = vec![
        report::FunnelStage::new(
            "structural files",
            inputs
                .parsed_files
                .saturating_sub(inputs.depth_truncated_files),
        )
        .dropping(FunnelCause::DepthLimit, inputs.depth_truncated_files),
        report::FunnelStage::new("units", as_u64(*units)),
        report::FunnelStage::new("indexed fragments", as_u64(candidate.fragments))
            .dropping(
                FunnelCause::OversharedValues,
                as_u64(candidate.stop_fingerprints),
            )
            .dropping(
                FunnelCause::OversharedPostings,
                as_u64(candidate.stop_postings),
            ),
        report::FunnelStage::new("exact seed pairs", as_u64(candidate.candidate_pairs)).dropping(
            FunnelCause::PairBudget,
            as_u64(
                candidate
                    .available_pairs
                    .saturating_sub(candidate.candidate_pairs),
            ),
        ),
        report::FunnelStage::new("near-match pairs", as_u64(near_match.candidate_pairs))
            .dropping(
                FunnelCause::TooFewShingles,
                as_u64(near_match.skipped_small),
            )
            .dropping(
                FunnelCause::SignedUnitLimit,
                as_u64(near_match.signed_limit_dropped),
            )
            .dropping(FunnelCause::CrowdedBucket, as_u64(near_match.stop_buckets))
            .dropping(FunnelCause::PairBudget, as_u64(near_match.budget_dropped))
            .dropping(
                FunnelCause::LengthRatio,
                as_u64(near_match.filtered_by_size),
            )
            .dropping(
                FunnelCause::EstimatedJaccard,
                as_u64(near_match.filtered_by_jaccard),
            ),
        // This is a diagnostic side stream, not another candidate stage: it
        // is deliberately limited to size-compatible proposals that already
        // fell through the primary estimate gate.
        report::FunnelStage::new(
            "near-match near misses",
            as_u64(near_match.near_misses_retained),
        )
        .dropping(
            FunnelCause::RetentionCap,
            as_u64(near_match.near_miss_cap_dropped),
        ),
        report::FunnelStage::new("sibling entries", as_u64(siblings.accepted))
            .dropping(
                FunnelCause::SiblingCandidateBudget,
                as_u64(siblings.candidate_budget_dropped),
            )
            .dropping(
                FunnelCause::SiblingPerGroupCap,
                as_u64(siblings.per_group_cap_dropped),
            )
            .dropping(
                FunnelCause::SiblingTotalCap,
                as_u64(siblings.total_cap_dropped),
            ),
        report::FunnelStage::new(
            "signature sibling entries",
            as_u64(signature_siblings.accepted),
        )
        .dropping(
            FunnelCause::SignatureSiblingCandidateBudget,
            as_u64(signature_siblings.candidate_budget_dropped),
        )
        .dropping(
            FunnelCause::SignatureSiblingPerGroupCap,
            as_u64(signature_siblings.per_group_cap_dropped),
        )
        .dropping(
            FunnelCause::SignatureSiblingTotalCap,
            as_u64(signature_siblings.total_cap_dropped),
        )
        // Kept apart from the three caps above: a reader who cannot tell a
        // candidate the sharing limit removed from one a cap dropped cannot
        // tell which of the two to move.
        .dropping(
            FunnelCause::SignatureSharedByTooManyUnits,
            as_u64(signature_siblings.common_signature_dropped),
        ),
        report::FunnelStage::new("control-flow pairs", as_u64(control_flow.candidate_pairs))
            .dropping(
                FunnelCause::SkeletonTooSmall,
                as_u64(control_flow.skipped_shallow),
            )
            .dropping(
                FunnelCause::OversharedSkeletons,
                as_u64(control_flow.stop_skeletons),
            )
            .dropping(
                FunnelCause::OversharedSkeletonPostings,
                as_u64(control_flow.stop_postings),
            )
            .dropping(FunnelCause::PairBudget, as_u64(control_flow.budget_dropped))
            .dropping(
                FunnelCause::LengthRatio,
                as_u64(control_flow.filtered_by_size),
            ),
        report::FunnelStage::new("unit pairs", as_u64(*unit_pairs))
            .dropping(FunnelCause::Nested, as_u64(*nested_pairs))
            .dropping(FunnelCause::ConditionalArms, as_u64(*alternative_pairs))
            .dropping(FunnelCause::DivergentShapes, as_u64(*divergent_shape_pairs))
            .dropping(
                FunnelCause::BelowMinCloneTokens,
                as_u64(*below_min_clone_token_pairs),
            ),
        report::FunnelStage::new("verified pairs", as_u64(*verified_pairs))
            .dropping(
                FunnelCause::VerificationBudget,
                as_u64(*verification_budget_dropped),
            )
            .dropping(FunnelCause::NoGroupHoldsBoth, as_u64(*unrepresented_pairs))
            .dropping(FunnelCause::AGroupSaysItAlready, as_u64(*described_pairs))
            .dropping(FunnelCause::TheCeilingCutTheSet, as_u64(*severed_pairs)),
        report::FunnelStage::new("components", as_u64(grouping.components)),
        // This stage counts units, not groups: a medoid ejection or
        // complete-linkage split only moves a unit into a later refinement
        // pass, so neither is a permanent funnel drop. Every unit ends in one
        // emitted group or as one final singleton.
        report::FunnelStage::new(
            "grouped units",
            as_u64(grouping.units.saturating_sub(grouping.singletons)),
        )
        .dropping(FunnelCause::LeftAlone, as_u64(grouping.singletons)),
        report::FunnelStage::new(
            "run seeds",
            as_u64(maximal.seeds.saturating_sub(maximal.divergent_extent)),
        )
        .dropping(
            FunnelCause::DivergentExtent,
            as_u64(maximal.divergent_extent),
        ),
        report::FunnelStage::new("folded runs", as_u64(maximal.regions))
            .dropping(FunnelCause::BelowMinimum, as_u64(maximal.below_minimum))
            .dropping(
                FunnelCause::SelfOverlapping,
                as_u64(maximal.self_overlapping),
            )
            .dropping(FunnelCause::Contained, as_u64(maximal.absorbed)),
        report::FunnelStage::new("duplicated runs", as_u64(maximal.shared)),
        report::FunnelStage::new("joined runs", as_u64(*region_merged)),
        // Runs, and only runs: what this row passes on and what it drops are
        // both whole duplicated runs, so the two can be read against each
        // other.
        report::FunnelStage::new("confirmed runs", as_u64(*regions))
            .dropping(FunnelCause::SameContent, as_u64(*region_folded))
            .dropping(FunnelCause::Subsumed, as_u64(*region_subsumed))
            .dropping(
                FunnelCause::BelowMinCloneTokens,
                as_u64(*below_min_clone_token_regions),
            ),
        // The reasons confirmation sets an occurrence aside are about single
        // occurrences, so they are stated where the value is occurrences too.
        // Against a count of runs they would be a ratio of two different
        // things, and a run holding four occurrences would let the drops
        // exceed it.
        report::FunnelStage::new("run occurrences", as_u64(*region_occurrences))
            .dropping(FunnelCause::UnsharedContent, as_u64(*region_singletons))
            // Kept apart from `unshared_content`: an occurrence whose tokens
            // were never established did not disagree with anything, and
            // reading the two as one reason points an investigation at the
            // content comparison instead of at the range that named no tokens.
            .dropping(
                FunnelCause::UnresolvedOccurrence,
                as_u64(*region_unresolved),
            )
            .dropping(
                FunnelCause::OverlappingOccurrence,
                as_u64(*region_overlapping),
            )
            .dropping(FunnelCause::AdjoiningOccurrence, as_u64(*region_adjoining)),
    ];
    // A stage a mode never reaches is absent from its funnel rather than
    // measured at zero: a run that asked no compiler about anything has no
    // answer about registered-rule duplication, and a reader who found a zero
    // there would take it for one.
    if !inputs.compiler_ran {
        return stages;
    }
    stages.extend(semantic_stages(&inputs.semantic));
    stages
}

/// Everything the compiler-backed half of a run narrowed, in run order.
fn semantic_stages(semantic: &SemanticFunnel) -> Vec<report::FunnelStage> {
    // Exhaustively destructured for the reason the two builders above are.
    let SemanticFunnel {
        registered_observations,
        excluded_observations,
        graphs,
        ineligible_graphs,
        units_without_registered_operations,
        units_no_registered_rule_claimed,
        buckets,
        oversized_buckets,
        pairs_emitted,
        pairs_budget_dropped,
        verified_pairs,
        disabled_pairs,
        grouped_pairs,
        invalid_pairs,
        duplicate_pairs,
        declined_pairs,
        ceiling_severed_pairs,
        groups,
        pairs,
    } = *semantic;
    vec![
        report::FunnelStage::new(
            "semantic API observations",
            as_u64(registered_observations).saturating_add(as_u64(excluded_observations)),
        )
        .dropping(
            FunnelCause::OutsideRegisteredVocabulary,
            as_u64(excluded_observations),
        ),
        // The denominator is every parser-owned unit normalization looked at:
        // the graphs the extractor was presented with, plus the units that
        // reached it with no graph to present. What passed is what the
        // extractor found eligible, so the ineligible graphs are a drop rather
        // than part of the value they are subtracted from.
        report::FunnelStage::new(
            "semantic graphs",
            as_u64(graphs.saturating_sub(ineligible_graphs)),
        )
        .dropping(FunnelCause::Ineligible, as_u64(ineligible_graphs))
        .dropping(
            FunnelCause::NoRegisteredOperations,
            as_u64(units_without_registered_operations),
        )
        .dropping(
            FunnelCause::NoRegisteredRuleMatched,
            as_u64(units_no_registered_rule_claimed),
        ),
        // A member ceiling discards buckets, not a known number of pairs:
        // omitted oversized buckets never enumerate their quadratic pair set.
        // Keep that unit explicit so a bucket count cannot read as a pair
        // count in the next stage.
        report::FunnelStage::new(
            "semantic candidate buckets",
            as_u64(buckets.saturating_sub(oversized_buckets)),
        )
        .dropping(FunnelCause::BucketMemberCap, as_u64(oversized_buckets)),
        report::FunnelStage::new("semantic candidate pairs", as_u64(pairs_emitted))
            .dropping(FunnelCause::PairBudget, as_u64(pairs_budget_dropped)),
        // What a verified pair passes on to is grouping, so the pairs a
        // disabled rule kept out of it are not among them. Grouping counts the
        // same population from the other side, in
        // `SemanticGroupingStats::considered_pairs`.
        report::FunnelStage::new(
            "semantic verified pairs",
            as_u64(verified_pairs.saturating_sub(disabled_pairs)),
        )
        .dropping(FunnelCause::RuleDisabled, as_u64(disabled_pairs)),
        // Grouping is where a pair either reaches a group or does not, so the
        // reasons it reached none are stated here rather than on the pair
        // findings below, which are those same pairs written out. A pair
        // refinement weighed and declined is a fact about the code; one the
        // component ceiling severed is a fact about the ceiling, and the two
        // are named apart so neither is counted twice.
        report::FunnelStage::new(
            "semantic pairs represented by groups",
            as_u64(grouped_pairs),
        )
        .dropping(FunnelCause::InvalidGroupingInput, as_u64(invalid_pairs))
        .dropping(FunnelCause::DuplicateRelation, as_u64(duplicate_pairs))
        .dropping(FunnelCause::NoGroupHoldsBoth, as_u64(declined_pairs))
        .dropping(
            FunnelCause::TheCeilingCutTheSet,
            as_u64(ceiling_severed_pairs),
        ),
        report::FunnelStage::new("restricted semantic groups", as_u64(groups)),
        report::FunnelStage::new("restricted semantic pairs", as_u64(pairs)),
    ]
}

/// What the compiler-backed half of a run narrowed, as plain counts.
///
/// The detection record itself is private to the structural pipeline, so its
/// numbers are handed over rather than read here. Keeping the counts in one
/// struct still leaves every semantic stage defined in this module, beside the
/// two syntactic funnels, rather than growing a third builder elsewhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SemanticFunnel {
    /// API observations inside the registered vocabulary.
    pub(super) registered_observations: usize,
    /// API observations outside it.
    pub(super) excluded_observations: usize,
    /// Unit graphs the extractor was presented with.
    pub(super) graphs: usize,
    /// How many of those it found ineligible.
    pub(super) ineligible_graphs: usize,
    /// Units holding no registered operation.
    pub(super) units_without_registered_operations: usize,
    /// Units no registered rule claimed.
    pub(super) units_no_registered_rule_claimed: usize,
    /// Candidate buckets built.
    pub(super) buckets: usize,
    /// How many of those exceeded the member ceiling.
    pub(super) oversized_buckets: usize,
    /// Candidate pairs emitted.
    pub(super) pairs_emitted: usize,
    /// Candidate pairs the allowance left unemitted.
    pub(super) pairs_budget_dropped: usize,
    /// Pairs verification accepted.
    pub(super) verified_pairs: usize,
    /// How many of those a disabled rule kept out of grouping.
    pub(super) disabled_pairs: usize,
    /// Verified pairs a reported group holds both halves of.
    pub(super) grouped_pairs: usize,
    /// Grouping input that did not describe a pair of units.
    pub(super) invalid_pairs: usize,
    /// Relations grouping had already been given.
    pub(super) duplicate_pairs: usize,
    /// Pairs refinement weighed and declined.
    pub(super) declined_pairs: usize,
    /// Pairs the component ceiling cut apart.
    pub(super) ceiling_severed_pairs: usize,
    /// Restricted semantic groups reported.
    pub(super) groups: usize,
    /// Restricted semantic pairs reported.
    pub(super) pairs: usize,
}

/// What the Structural funnel is assembled from beyond the core statistics.
pub(super) struct StructuralFunnel<'a> {
    /// What the structural analysis counted.
    pub(super) stats: &'a StructuralStats,
    /// The compiler-backed half of the run, read only when one ran.
    pub(super) semantic: SemanticFunnel,
    /// Files handed to the structural frontends.
    pub(super) parsed_files: u64,
    /// How many of them stopped at the parser's depth ceiling.
    pub(super) depth_truncated_files: u64,
    /// Whether this run asked a compiler anything, which decides whether the
    /// semantic stages exist at all.
    pub(super) compiler_ran: bool,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
