//! Conversion of structural analysis results into public report models.

use super::{
    BTreeMap, BTreeSet, CloneScope, DiscoveryReport, GroupDetail, LiteralNorm, REGION_SIMILARITY,
    Report, ReportInputs, Result, SemanticDetection, SemanticUnitGraph, StructuralGroup,
    StructuralRegion, StructuralUnit, SummaryRow, VerifiedPair, WEIGHT_VERSION,
    aggregate_test_code_evidence, as_u64, engine, region_identifier_jaccard,
    region_test_code_evidence, report, semantic_group_member_fingerprints, semantic_member_ranks,
    semantic_scope, shared, stable_id, structural, unit_token_span,
};
use codehelion_core::boilerplate::BOILERPLATE_VERSION;
use codehelion_core::discovery::NORMALIZATION_VERSION;
use codehelion_core::features::FEATURE_SCHEMA_VERSION;
use codehelion_core::grouping::GROUPING_VERSION;
use codehelion_core::maximal::MAXIMAL_VERSION;
use codehelion_core::semantic::{
    SEMANTIC_CANDIDATE_INDEX_VERSION, SEMANTIC_RULE_REGISTRY_VERSION, SEMANTIC_WINDOWING_VERSION,
    SOG_SCHEMA_VERSION,
};
use codehelion_core::stable_id::{ContentNorm, FP_SCHEMA_VERSION, UnitFingerprint};
use codehelion_core::substitution::SUBSTITUTION_VERSION;
use codehelion_core::test_code::TEST_CODE_VERSION;
use codehelion_core::verify::SimilarityBreakdown;
use codehelion_store::snapshot::UnparsedRow;

use crate::scan::{RunInfoInputs, common_run_info, display_path, file_counts, guardrails_row};

pub(super) fn build_groups(inputs: &ReportInputs<'_>) -> Result<report::NormalizedGroups> {
    let mut entries: Vec<report::Group> = (0..inputs.analysis.groups.groups.len())
        .map(|index| build_group(inputs, index))
        // A run carries no boilerplate classification: the classifier reads
        // whole units, so no run is ever ranked down for its shape. Where it
        // sits is another matter — a run duplicated across a suite is the
        // suite's repetition as much as a duplicated test function is.
        .chain((0..inputs.regions.reported.len()).map(|index| build_region(inputs, index)))
        // A pair no group could hold says less per finding than a group does
        // — two members rather than a set — and there are more of them than
        // there are groups, so the policy ranks them down by default rather
        // than letting them crowd the top of the report.
        .chain(
            (0..inputs.analysis.unrepresented.len()).map(|index| build_split_pair(inputs, index)),
        )
        .chain((0..inputs.semantic_groups.len()).map(|index| build_semantic_group(inputs, index)))
        .chain((0..inputs.semantic_pairs.len()).map(|index| build_semantic_pair(inputs, index)))
        .collect();
    report::order(&mut entries, inputs.suppression, inputs.sort);
    report::normalize_identities(entries)
}

/// Turn one verified semantic relation left outside every cohesive group into
/// a split-pair restricted semantic finding.
fn build_semantic_pair(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let pair = &inputs.semantic_pairs[index];
    let members = [&pair.canonical, &pair.corresponding];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        pair.rule.id,
        pair.rule.version,
        &semantic_group_member_fingerprints(members, inputs.analysis),
    );
    let test_code_evidence =
        aggregate_test_code_evidence(inputs.analysis, members.iter().map(|member| member.unit));
    let member_ranks = semantic_member_ranks(members.iter().copied());
    let canonical_unit = &inputs.analysis.units[pair.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let entropy_bits = engine::content_entropy_bits(canonical_tokens, inputs.literals);
    let node_mappings = (0..pair.canonical.graph.nodes.len())
        .filter_map(|index| {
            let index = u32::try_from(index).ok()?;
            Some(report::SemanticNodeMapping {
                corresponding_member: 1,
                canonical: index,
                corresponding: index,
            })
        })
        .collect();
    let mut assembled = shared::report_group(shared::ReportGroupCore {
        fingerprint: fingerprint.to_hex(),
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        scope: semantic_scope(members.iter().copied(), inputs.analysis),
        statements: None,
        confidence: pair.semantic_confidence,
        entropy_bits,
        members: members
            .iter()
            .enumerate()
            .map(|(position, member)| {
                let unit = &inputs.analysis.units[member.unit];
                let file = &inputs.files[unit.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &fingerprint,
                        Some(&unit.fingerprint),
                        member_ranks[position],
                    )
                    .to_hex(),
                    content: member.content.to_hex(),
                    file: display_path(&file.relative_path),
                    language: file.language.name().to_string(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                    unit: unit.name.as_deref().map(ToString::to_string),
                    boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                    tokens: u64::try_from(member.token_count).unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    });
    assembled.test_code = test_code_evidence.is_some();
    assembled.test_code_evidence = test_code_evidence;
    assembled.split_pair = true;
    assembled.suppressed = inputs.finding_suppression(
        entropy_bits,
        canonical_tokens.len(),
        inputs.semantic_pair_suppressed[index],
    );
    assembled.semantic = Some(report::SemanticEvidence {
        schema_version: pair.canonical.graph.schema_version.clone(),
        rules: vec![report::SemanticRuleEvidence {
            id: pair.rule.id.to_string(),
            version: pair.rule.version,
            confidence: pair.rule.confidence,
        }],
        graphs: vec![
            pair.canonical.graph.clone(),
            pair.corresponding.graph.clone(),
        ],
        node_mappings,
    });
    let mut group = report::ranked(assembled, &inputs.weights, inputs.min_clone_tokens);
    group.priority.semantic_confidence = Some(pair.semantic_confidence);
    group
}

/// Turn one complete-linkage semantic group into a restricted semantic
/// finding. Each mapping names the corresponding member explicitly so a
/// multi-member group remains explainable after it leaves the scan process.
fn build_semantic_group(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let semantic_group = &inputs.semantic_groups[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        semantic_group.rule.id,
        semantic_group.rule.version,
        &semantic_group_member_fingerprints(semantic_group.members.iter(), inputs.analysis),
    );
    let test_code_evidence = aggregate_test_code_evidence(
        inputs.analysis,
        semantic_group.members.iter().map(|member| member.unit),
    );
    let node_mappings = semantic_node_mappings(&semantic_group.canonical, &semantic_group.members);
    let member_ranks = semantic_member_ranks(semantic_group.members.iter());
    let canonical_unit = &inputs.analysis.units[semantic_group.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let entropy_bits = engine::content_entropy_bits(canonical_tokens, inputs.literals);
    let mut assembled = shared::report_group(shared::ReportGroupCore {
        fingerprint: fingerprint.to_hex(),
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        scope: semantic_scope(semantic_group.members.iter(), inputs.analysis),
        statements: None,
        confidence: semantic_group.semantic_confidence,
        entropy_bits,
        members: semantic_group
            .members
            .iter()
            .enumerate()
            .map(|(position, member)| {
                let unit = &inputs.analysis.units[member.unit];
                let file = &inputs.files[unit.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &fingerprint,
                        Some(&unit.fingerprint),
                        member_ranks[position],
                    )
                    .to_hex(),
                    content: member.content.to_hex(),
                    file: display_path(&file.relative_path),
                    language: file.language.name().to_string(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                    unit: unit.name.as_ref().map(ToString::to_string),
                    boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                    tokens: u64::try_from(member.token_count).unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    });
    assembled.test_code = test_code_evidence.is_some();
    assembled.test_code_evidence = test_code_evidence;
    assembled.suppressed = inputs.finding_suppression(
        entropy_bits,
        canonical_tokens.len(),
        inputs.semantic_group_suppressed[index],
    );
    assembled.semantic = Some(report::SemanticEvidence {
        schema_version: semantic_group.canonical.graph.schema_version.clone(),
        rules: vec![report::SemanticRuleEvidence {
            id: semantic_group.rule.id.to_string(),
            version: semantic_group.rule.version,
            confidence: semantic_group.rule.confidence,
        }],
        graphs: semantic_group
            .members
            .iter()
            .map(|member| member.graph.clone())
            .collect(),
        node_mappings,
    });
    let mut group = report::ranked(assembled, &inputs.weights, inputs.min_clone_tokens);
    group.priority.semantic_confidence = Some(semantic_group.semantic_confidence);
    group
}

/// Produce explicit canonical-to-member node mappings for an entire cohesive
/// group. Rules admitted to grouping retain aligned fixed SOG sequences.
fn semantic_node_mappings(
    canonical: &SemanticUnitGraph,
    members: &[SemanticUnitGraph],
) -> Vec<report::SemanticNodeMapping> {
    members
        .iter()
        .enumerate()
        .skip(1)
        .flat_map(|(member, corresponding)| {
            (0..canonical
                .graph
                .nodes
                .len()
                .min(corresponding.graph.nodes.len()))
                .filter_map(move |node| {
                    let node = u32::try_from(node).ok()?;
                    Some(report::SemanticNodeMapping {
                        corresponding_member: u32::try_from(member).ok()?,
                        canonical: node,
                        corresponding: node,
                    })
                })
        })
        .collect()
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
pub(super) fn funnel(
    stats: &structural::StructuralStats,
    semantic: &SemanticDetection,
    parsed_files: u64,
    depth_truncated_files: u64,
) -> Vec<report::FunnelStage> {
    let near = &stats.near_match;
    let grouping = &stats.grouping;
    let maximal = &stats.maximal;
    let mut stages = vec![
        report::FunnelStage::new(
            "structural files",
            parsed_files.saturating_sub(depth_truncated_files),
        )
        .dropping("depth_limit", depth_truncated_files),
        report::FunnelStage::new("units", as_u64(stats.units)),
        report::FunnelStage::new("indexed fragments", as_u64(stats.candidate.fragments))
            .dropping("high_frequency", as_u64(stats.candidate.stop_fingerprints))
            .dropping(
                "high_frequency_postings",
                as_u64(stats.candidate.stop_postings),
            ),
        report::FunnelStage::new("exact seed pairs", as_u64(stats.candidate.candidate_pairs))
            .dropping(
                "pair_budget",
                as_u64(
                    stats
                        .candidate
                        .available_pairs
                        .saturating_sub(stats.candidate.candidate_pairs),
                ),
            ),
        report::FunnelStage::new("near-match pairs", as_u64(near.candidate_pairs))
            .dropping("too_few_shingles", as_u64(near.skipped_small))
            .dropping("signed_unit_limit", as_u64(near.signed_limit_dropped))
            .dropping("crowded_bucket", as_u64(near.stop_buckets))
            .dropping("pair_budget", as_u64(near.budget_dropped))
            .dropping("length_ratio", as_u64(near.filtered_by_size))
            .dropping("estimated_jaccard", as_u64(near.filtered_by_jaccard)),
        // This is a diagnostic side stream, not another candidate stage: it
        // is deliberately limited to size-compatible proposals that already
        // fell through the primary estimate gate.
        report::FunnelStage::new("near-match near misses", as_u64(near.near_misses_retained))
            .dropping("retention_cap", as_u64(near.near_miss_cap_dropped)),
        report::FunnelStage::new("sibling entries", as_u64(stats.siblings.accepted))
            .dropping(
                "sibling_candidate_budget",
                as_u64(stats.siblings.candidate_budget_dropped),
            )
            .dropping(
                "sibling_per_group_cap",
                as_u64(stats.siblings.per_group_cap_dropped),
            )
            .dropping(
                "sibling_total_cap",
                as_u64(stats.siblings.total_cap_dropped),
            ),
        report::FunnelStage::new(
            "signature sibling entries",
            as_u64(stats.signature_siblings.accepted),
        )
        .dropping(
            "signature_sibling_candidate_budget",
            as_u64(stats.signature_siblings.candidate_budget_dropped),
        )
        .dropping(
            "signature_sibling_per_group_cap",
            as_u64(stats.signature_siblings.per_group_cap_dropped),
        )
        .dropping(
            "signature_sibling_total_cap",
            as_u64(stats.signature_siblings.total_cap_dropped),
        ),
        report::FunnelStage::new(
            "control-flow pairs",
            as_u64(stats.control_flow.candidate_pairs),
        )
        .dropping(
            "skeleton_too_small",
            as_u64(stats.control_flow.skipped_shallow),
        )
        .dropping("common_skeleton", as_u64(stats.control_flow.stop_skeletons))
        .dropping(
            "common_skeleton_postings",
            as_u64(stats.control_flow.stop_postings),
        )
        .dropping("pair_budget", as_u64(stats.control_flow.budget_dropped))
        .dropping("length_ratio", as_u64(stats.control_flow.filtered_by_size)),
        report::FunnelStage::new("unit pairs", as_u64(stats.unit_pairs))
            .dropping("nested", as_u64(stats.nested_pairs))
            .dropping("conditional_arms", as_u64(stats.alternative_pairs))
            .dropping("divergent_shapes", as_u64(stats.divergent_shape_pairs))
            .dropping(
                "below_min_clone_tokens",
                as_u64(stats.below_min_clone_token_pairs),
            ),
        report::FunnelStage::new("verified pairs", as_u64(stats.verified_pairs))
            .dropping(
                "verification_budget",
                as_u64(stats.verification_budget_dropped),
            )
            .dropping("no_group_holds_both", as_u64(stats.unrepresented_pairs))
            .dropping("a_group_says_it_already", as_u64(stats.described_pairs))
            .dropping("the_ceiling_cut_the_set", as_u64(stats.severed_pairs)),
        report::FunnelStage::new("components", as_u64(grouping.components)),
        // This stage counts units, not groups: a medoid ejection or
        // complete-linkage split only moves a unit into a later refinement
        // pass, so neither is a permanent funnel drop. Every unit ends in one
        // emitted group or as one final singleton.
        report::FunnelStage::new(
            "grouped units",
            as_u64(grouping.units.saturating_sub(grouping.singletons)),
        )
        .dropping("left_alone", as_u64(grouping.singletons)),
        report::FunnelStage::new(
            "run seeds",
            as_u64(maximal.seeds.saturating_sub(maximal.divergent_extent)),
        )
        .dropping("divergent_extent", as_u64(maximal.divergent_extent)),
        report::FunnelStage::new("folded runs", as_u64(maximal.regions))
            .dropping("below_minimum", as_u64(maximal.below_minimum))
            .dropping("self_overlapping", as_u64(maximal.self_overlapping))
            .dropping("contained", as_u64(maximal.absorbed)),
        report::FunnelStage::new("duplicated runs", as_u64(maximal.shared)),
        report::FunnelStage::new("joined runs", as_u64(stats.region_merged)),
        report::FunnelStage::new("confirmed runs", as_u64(stats.regions))
            .dropping("unshared_content", as_u64(stats.region_singletons))
            .dropping("overlapping_occurrence", as_u64(stats.region_overlapping))
            .dropping("adjoining_occurrence", as_u64(stats.region_adjoining))
            .dropping("same_content", as_u64(stats.region_folded))
            .dropping("subsumed", as_u64(stats.region_subsumed))
            .dropping(
                "below_min_clone_tokens",
                as_u64(stats.below_min_clone_token_regions),
            ),
    ];
    let candidates = &semantic.candidates;
    stages.extend([
        report::FunnelStage::new(
            "semantic API observations",
            as_u64(semantic.registered_observations)
                .saturating_add(as_u64(semantic.excluded_observations)),
        )
        .dropping(
            "outside_registered_vocabulary",
            as_u64(semantic.excluded_observations),
        ),
        // `candidates.graphs` already excludes short windows, while
        // `unrepresentable_units` never produced a graph at all. The stage
        // starts from the parser-owned inputs so its drops share one
        // denominator instead of subtracting unrelated populations.
        report::FunnelStage::new(
            "semantic graphs",
            as_u64(
                semantic
                    .units
                    .len()
                    .saturating_add(semantic.unrepresentable_units),
            ),
        )
        .dropping("ineligible", as_u64(candidates.ineligible_graphs))
        .dropping(
            "no_registered_operations",
            as_u64(semantic.unrepresentable_units),
        ),
        // A member ceiling discards buckets, not a known number of pairs:
        // omitted oversized buckets never enumerate their quadratic pair set.
        // Keep that unit explicit so a bucket count cannot read as a pair
        // count in the next stage.
        report::FunnelStage::new(
            "semantic candidate buckets",
            as_u64(
                candidates
                    .buckets
                    .saturating_sub(candidates.oversized_buckets),
            ),
        )
        .dropping("bucket_member_cap", as_u64(candidates.oversized_buckets)),
        report::FunnelStage::new("semantic candidate pairs", as_u64(candidates.pairs_emitted))
            .dropping("pair_budget", as_u64(candidates.pairs_budget_dropped)),
        report::FunnelStage::new("semantic verified pairs", as_u64(semantic.verified_pairs))
            .dropping("rule_disabled", as_u64(semantic.disabled_pairs)),
        report::FunnelStage::new(
            "semantic pairs represented by groups",
            as_u64(semantic.grouping.grouped_pairs),
        ),
        report::FunnelStage::new("restricted semantic groups", as_u64(semantic.groups.len()))
            .dropping(
                "invalid_grouping_input",
                as_u64(semantic.grouping.invalid_pairs),
            ),
        report::FunnelStage::new("restricted semantic pairs", as_u64(semantic.pairs.len()))
            .dropping(
                "no_group_holds_both",
                as_u64(semantic.grouping.ungrouped_pairs),
            )
            .dropping(
                "the_ceiling_cut_the_set",
                as_u64(semantic.grouping.ceiling_severed_pairs),
            ),
    ]);
    stages
}

/// Assemble the report model both output formats render from.
pub(super) fn build_report(
    inputs: &ReportInputs<'_>,
    run_id: Option<i64>,
    stored: &SummaryRow,
    groups: Vec<report::Group>,
) -> Report {
    let mut report = shared::report(
        common_run_info(RunInfoInputs {
            root: inputs.root,
            db_path: inputs.db_path,
            configuration: inputs.configuration,
            run_id,
            started_at: inputs.started_at,
            finished_at: inputs.finished_at,
            variant: inputs.variant,
            detector_versions: detector_versions(
                inputs.literals,
                inputs.entropy_ratio_floor,
                inputs.compiler_answers,
            )
            .into_iter()
            .map(|(component, version)| report::DetectorVersion { component, version })
            .collect(),
            weights: &inputs.weights,
        }),
        stored,
        groups,
        inputs.variant.mode.name(),
    );
    report.siblings = build_siblings(inputs);
    report.near_misses = build_near_misses(inputs);
    report.order_supplemental();
    report
}

/// Convert bounded core near-match diagnostics into the run-scoped public
/// shape. They do not become groups, siblings, or finding identities.
fn build_near_misses(inputs: &ReportInputs<'_>) -> Vec<report::NearMiss> {
    inputs
        .analysis
        .near_misses
        .iter()
        .enumerate()
        .map(|(index, near_miss)| report::NearMiss {
            estimated_jaccard: near_miss.estimated_jaccard,
            left: near_miss_unit(inputs, near_miss.a),
            right: near_miss_unit(inputs, near_miss.b),
            suppressed: inputs.near_miss_suppressed[index].map(|rule| inputs.suppression(rule)),
        })
        .collect()
}

/// Render one near-miss side without borrowing primary-member semantics.
fn near_miss_unit(inputs: &ReportInputs<'_>, index: usize) -> report::NearMissUnit {
    let unit = &inputs.analysis.units[index];
    let file = &inputs.files[unit.file];
    report::NearMissUnit {
        unit_fingerprint: unit.fingerprint.to_hex(),
        language: file.language.name().to_string(),
        file: display_path(&file.relative_path),
        start_line: unit.start_line,
        end_line: unit.end_line,
        unit: unit.name.as_deref().map(ToString::to_string),
        tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start)).unwrap_or(u64::MAX),
    }
}

/// Convert core-owned sibling findings into the additive public report shape.
/// They stay keyed by their owning primary group rather than becoming ranked
/// standalone findings.
fn build_siblings(inputs: &ReportInputs<'_>) -> Vec<report::GroupSiblings> {
    inputs
        .analysis
        .siblings
        .iter()
        .enumerate()
        .filter_map(|(owner_index, siblings)| {
            let detail = inputs.analysis.details.get(siblings.group)?;
            let group = inputs.analysis.groups.groups.get(siblings.group)?;
            let ranks = ranks_after(
                member_hosts(&inputs.analysis.units, &group.members),
                siblings
                    .siblings
                    .iter()
                    .map(|sibling| inputs.analysis.units[sibling.unit].fingerprint),
            );
            Some(report::GroupSiblings {
                group_fingerprint: detail.fingerprint.to_hex(),
                siblings: siblings
                    .siblings
                    .iter()
                    .zip(ranks)
                    .enumerate()
                    .map(|(sibling_index, (sibling, rank))| {
                        let unit = &inputs.analysis.units[sibling.unit];
                        let file = &inputs.files[unit.file];
                        report::Sibling {
                            clone_type: sibling.clone_type.name().to_string(),
                            confidence_band: sibling.confidence.name().to_string(),
                            basis: sibling.basis.name().to_string(),
                            signature: sibling.signature.clone(),
                            similarity: report::SiblingSimilarity {
                                weight_version: WEIGHT_VERSION.to_string(),
                                lexical: sibling.breakdown.lexical,
                                structural: sibling.breakdown.structural,
                                control_flow: sibling.breakdown.control_flow,
                                type_similarity: sibling.breakdown.type_similarity,
                                api: sibling.breakdown.api,
                                composite: sibling.breakdown.composite,
                            },
                            member: report::Member {
                                finding_id: stable_id::finding_id(
                                    &detail.fingerprint,
                                    Some(&unit.fingerprint),
                                    rank,
                                )
                                .to_hex(),
                                content: unit.content.to_hex(),
                                file: display_path(&file.relative_path),
                                language: file.language.name().to_string(),
                                start_line: unit.start_line,
                                end_line: unit.end_line,
                                unit: unit.name.as_deref().map(ToString::to_string),
                                boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                                tokens: u64::try_from(
                                    unit.token_end.saturating_sub(unit.token_start),
                                )
                                .unwrap_or(u64::MAX),
                                canonical: false,
                            },
                            suppressed: inputs.sibling_suppressed[owner_index][sibling_index]
                                .map(|rule| inputs.suppression(rule)),
                        }
                    })
                    .collect(),
            })
        })
        .collect()
}

/// What the run reported about itself beyond the groups it found, in the shape
/// the audit database stores.
///
/// Built before the snapshot is written and read back out of it by
/// [`build_summary`], so the recorded run and the printed report carry one set
/// of numbers rather than two derivations that happen to agree.
pub(super) fn summary_row(
    inputs: &ReportInputs<'_>,
    shared_discovery: Option<&DiscoveryReport>,
    baseline_digest: Option<String>,
    guardrails: Option<&report::Guardrails>,
) -> SummaryRow {
    let stats = &inputs.analysis.stats;
    let tokens = as_u64(inputs.irs.iter().map(|ir| ir.tokens.len()).sum::<usize>());
    let unparsed = report::UnparsedCounts::new(
        inputs.files.iter().map(|file| file.unaccounted_tokens),
        tokens,
    );
    let exclusions = discovery_exclusions(shared_discovery, inputs.glob_excluded);
    shared::summary(shared::SummaryInputs {
        analyzed_files: file_counts(inputs.files.iter().map(|file| file.language)),
        lines: inputs.files.iter().map(|file| file.lines).sum(),
        tokens,
        lexer_diagnostics: as_u64(inputs.files.iter().map(|file| file.diagnostics).sum()),
        unparsed: Some(UnparsedRow {
            files: unparsed.files,
            tokens: unparsed.tokens,
        }),
        excluded_generated: exclusions.generated,
        excluded_by_glob: exclusions.by_glob,
        excluded_too_large: exclusions.too_large,
        excluded_binary: exclusions.binary,
        excluded_unreadable: exclusions.unreadable + inputs.unreadable,
        excluded_symlinks: exclusions.symlinks,
        excluded_walk_errors: exclusions.walk_errors,
        excluded_timed_out: inputs.timed_out,
        excluded_language: exclusions.language_excluded,
        excluded_symlink_files: exclusions.symlink_files,
        excluded_symlink_directories: exclusions.symlink_directories,
        guardrails: guardrails.map(guardrails_row),
        excluded_skipped: exclusions.skipped + inputs.unreadable + inputs.timed_out,
        folded_runs: as_u64(inputs.regions.folded),
        subsumed_runs: as_u64(stats.region_subsumed),
        split_components: as_u64(stats.grouping.oversized_components),
        // Any candidate stage exhausting its budget makes the result
        // potentially incomplete.
        pair_budget_exhausted: stats.candidate.budget_exhausted
            || stats.near_match.budget_exhausted
            || stats.control_flow.budget_exhausted
            || stats.verification_budget_dropped > 0
            || inputs.semantic_detection.candidates.pairs_budget_dropped > 0,
        baseline_digest,
        funnel: funnel(
            stats,
            inputs.semantic_detection,
            as_u64(inputs.files.len()),
            as_u64(
                inputs
                    .files
                    .iter()
                    .filter(|file| file.depth_truncated)
                    .count(),
            ),
        ),
        unused_suppressions: inputs.unused_suppressions(),
    })
}

/// Discovery exclusions shared by an invocation rather than tied to a parsed
/// build-variant partition.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DiscoveryExclusions {
    pub(super) generated: u64,
    pub(super) by_glob: u64,
    pub(super) too_large: u64,
    pub(super) binary: u64,
    pub(super) unreadable: u64,
    pub(super) symlinks: u64,
    pub(super) walk_errors: u64,
    pub(super) language_excluded: u64,
    pub(super) symlink_files: u64,
    pub(super) symlink_directories: u64,
    pub(super) skipped: u64,
}

/// Attribute discovery work to the sole partition that records it.
///
/// Semantic partitions are separate programs, but discovery precedes their
/// selection. Giving its counts to each program would make a reader who sums
/// the partition summaries believe files were excluded more than once.
pub(super) fn discovery_exclusions(
    discovery: Option<&DiscoveryReport>,
    glob_excluded: usize,
) -> DiscoveryExclusions {
    discovery.map_or_else(DiscoveryExclusions::default, |discovery| {
        DiscoveryExclusions {
            generated: as_u64(discovery.suppressed_generated.len()),
            by_glob: as_u64(glob_excluded),
            too_large: discovery.skipped.too_large,
            binary: discovery.skipped.binary,
            unreadable: discovery.skipped.unreadable,
            symlinks: discovery.skipped.symlinks,
            walk_errors: discovery.skipped.walk_errors,
            language_excluded: discovery.skipped.language_excluded,
            symlink_files: discovery.skipped.symlink_files,
            symlink_directories: discovery.skipped.symlink_directories,
            skipped: discovery.skipped.total(),
        }
    })
}

/// One group of the report model, with its similarity evidence and its
/// suppression cause resolved.
fn build_group(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.analysis.groups.groups[index];
    let detail = &inputs.analysis.details[index];
    let canonical_unit = &inputs.analysis.units[group.canonical];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let entropy_bits = engine::content_entropy_bits(canonical_tokens, inputs.literals);
    let mut assembled = shared::report_group(shared::ReportGroupCore {
        fingerprint: detail.fingerprint.to_hex(),
        clone_type: group.clone_type,
        scope: CloneScope::Unit,
        statements: None,
        confidence: group.min_pairwise,
        entropy_bits,
        members: group
            .members
            .iter()
            .zip(ranks_within_host(member_hosts(
                &inputs.analysis.units,
                &group.members,
            )))
            .enumerate()
            .map(|(position, (&member, rank))| {
                let unit = &inputs.analysis.units[member];
                let file = &inputs.files[unit.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &detail.fingerprint,
                        Some(&unit.fingerprint),
                        rank,
                    )
                    .to_hex(),
                    content: unit.content.to_hex(),
                    file: display_path(&file.relative_path),
                    language: file.language.name().to_string(),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    unit: unit.name.as_deref().map(ToString::to_string),
                    boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                    tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start))
                        .unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    });
    assembled.similarity = Some(similarity(group, detail));
    assembled.identifier_jaccard = Some(detail.identifier_jaccard);
    assembled.body_materiality = Some(report::BodyMateriality {
        has_loop: detail.body_materiality.has_loop,
        has_dynamic_allocation: detail.body_materiality.has_dynamic_allocation,
        call_count: detail.body_materiality.call_count,
    });
    assembled.boilerplate = detail
        .boilerplate
        .map(|category| category.name().to_string());
    assembled.test_code = detail.test_code;
    assembled.test_code_evidence = detail.test_code_evidence;
    assembled.width_family = detail.width_family;
    assembled.suppressed = inputs.finding_suppression(
        entropy_bits,
        canonical_tokens.len(),
        inputs.group_suppressed[index],
    );
    report::ranked(assembled, &inputs.weights, inputs.min_clone_tokens)
}

/// A split pair's occurrences with the canonical instance first.
///
/// [`VerifiedPair::members`] is in unit-index order and has to stay that way —
/// membership is answered by binary search over it — while a group lists its
/// canonical instance first and the audit database records whichever it was
/// handed first as the canonical one. Ordering here is what keeps the report
/// and the recorded rows saying the same thing about the same pair.
pub(super) fn pair_members(pair: &VerifiedPair) -> Vec<usize> {
    let mut members = vec![pair.canonical];
    members.extend(pair.members.iter().filter(|&&m| m != pair.canonical));
    members
}

/// Raw identifier agreement between a split pair's canonical unit and every
/// corresponding unit.
///
/// A split pair is a verified clone relation, but its raw names are only
/// triage evidence for a possible shared refactoring target. They do not
/// establish similarity and cannot affect detection or grouping.
pub(super) fn split_pair_identifier_jaccard(inputs: &ReportInputs<'_>, pair: &VerifiedPair) -> f64 {
    structural::span_identifier_jaccard(
        inputs.irs,
        unit_token_span(&inputs.analysis.units[pair.canonical]),
        pair.members
            .iter()
            .filter(|&&member| member != pair.canonical)
            .map(|&member| unit_token_span(&inputs.analysis.units[member])),
    )
}

/// One verified clone relation that no group could hold, as a report entry.
///
/// It is shaped exactly like a group, because that is what it is: a set whose
/// every member is a copy of every other. What sets it apart is that its
/// members appear in other findings too, which `split_pair` says outright.
/// Where the same two contents recur across the tree the entry carries every
/// occurrence of both, since that is one relation observed many times rather
/// than many relations.
fn build_split_pair(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let pair = &inputs.analysis.unrepresented[index];
    let members = &pair_members(pair);
    let test_code_evidence = aggregate_test_code_evidence(inputs.analysis, members.iter().copied());
    let canonical_unit = &inputs.analysis.units[pair.canonical];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let entropy_bits = engine::content_entropy_bits(canonical_tokens, inputs.literals);
    let mut assembled = shared::report_group(shared::ReportGroupCore {
        fingerprint: pair.fingerprint.to_hex(),
        clone_type: pair.class,
        scope: CloneScope::Unit,
        statements: None,
        confidence: pair.similarity,
        entropy_bits,
        members: members
            .iter()
            .zip(ranks_within_host(member_hosts(
                &inputs.analysis.units,
                members,
            )))
            .enumerate()
            .map(|(position, (&member, rank))| {
                let unit = &inputs.analysis.units[member];
                let file = &inputs.files[unit.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &pair.fingerprint,
                        Some(&unit.fingerprint),
                        rank,
                    )
                    .to_hex(),
                    content: unit.content.to_hex(),
                    file: display_path(&file.relative_path),
                    language: file.language.name().to_string(),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    unit: unit.name.as_deref().map(ToString::to_string),
                    boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                    tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start))
                        .unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    });
    assembled.identifier_jaccard = Some(split_pair_identifier_jaccard(inputs, pair));
    assembled.similarity = pair.breakdown.map(|breakdown| report::Similarity {
        weight_version: WEIGHT_VERSION.to_string(),
        lexical: breakdown.lexical,
        structural: breakdown.structural,
        control_flow: breakdown.control_flow,
        type_similarity: breakdown.type_similarity,
        api: breakdown.api,
        composite: breakdown.composite,
        min_pairwise: pair.similarity,
        confidence_band: Some(pair.confidence.name().to_string()),
    });
    assembled.boilerplate = pair.boilerplate.map(|shape| shape.name().to_string());
    assembled.test_code = test_code_evidence.is_some();
    assembled.test_code_evidence = test_code_evidence;
    assembled.width_family = pair.width_family;
    assembled.suppressed = inputs.finding_suppression(
        entropy_bits,
        canonical_tokens.len(),
        inputs.pair_suppressed[index],
    );
    assembled.split_pair = true;
    report::ranked(assembled, &inputs.weights, inputs.min_clone_tokens)
}

/// One duplicated run as a report entry.
///
/// The occurrences are runs of statements, so each is anchored at its own line
/// span and names the unit it sits in; the units themselves are usually not
/// clones of each other, which is the whole point of reporting the run.
fn build_region(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = ranks_within_host(occurrence_hosts(&inputs.analysis.units, region));
    let test_code_evidence = region_test_code_evidence(inputs.analysis, region);
    let canonical = &region.occurrences[0];
    let tokens = &inputs.irs[canonical.file].tokens;
    let end = canonical.token_end.min(tokens.len());
    let entropy_bits =
        engine::content_entropy_bits(&tokens[canonical.token_start..end], inputs.literals);
    let mut assembled = shared::report_group(shared::ReportGroupCore {
        fingerprint: region.fingerprint.to_hex(),
        clone_type: region.clone_type,
        scope: CloneScope::Fragment,
        statements: Some(u64::from(region.statements)),
        confidence: REGION_SIMILARITY,
        entropy_bits,
        members: region
            .occurrences
            .iter()
            .zip(&ranks)
            .enumerate()
            .map(|(position, (occurrence, &rank))| {
                let unit = &inputs.analysis.units[occurrence.unit];
                let file = &inputs.files[occurrence.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &region.fingerprint,
                        Some(&unit.fingerprint),
                        rank,
                    )
                    .to_hex(),
                    content: occurrence.content.to_hex(),
                    file: display_path(&file.relative_path),
                    language: file.language.name().to_string(),
                    start_line: occurrence.start_line,
                    end_line: occurrence.end_line,
                    unit: unit.name.as_deref().map(ToString::to_string),
                    boilerplate: None,
                    tokens: u64::try_from(
                        occurrence.token_end.saturating_sub(occurrence.token_start),
                    )
                    .unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    });
    assembled.identifier_jaccard = Some(region_identifier_jaccard(inputs, region));
    assembled.test_code = test_code_evidence.is_some();
    assembled.test_code_evidence = test_code_evidence;
    assembled.suppressed = inputs.finding_suppression(
        entropy_bits,
        end.saturating_sub(canonical.token_start),
        inputs.region_suppressed[index],
    );
    report::ranked(assembled, &inputs.weights, inputs.min_clone_tokens)
}

/// Rank of each occurrence within its host, in occurrence order.
///
/// A finding is told apart from its siblings by its host's fingerprint plus
/// its rank within that host, so the rank has to count per *fingerprint* and
/// not per host: a unit fingerprint is raw content, so the same function
/// copied unchanged into eight files carries one fingerprint across all eight,
/// and counting per host would hand all eight occurrences rank zero and one
/// identifier between them. Counting per fingerprint also keeps the case the
/// rank was introduced for — one run duplicated twice inside a single unit —
/// since those two share a host and therefore a fingerprint.
pub(super) fn ranks_within_host(hosts: impl IntoIterator<Item = UnitFingerprint>) -> Vec<u32> {
    ranks_after(std::iter::empty(), hosts)
}

/// Rank later occurrences after the ones already emitted for the same group.
///
/// A sibling can have byte-identical content to a primary member when a
/// candidate ceiling leaves that otherwise matching unit out of the primary
/// group. Its host fingerprint then matches a primary member's fingerprint,
/// so its rank must continue after the primary occurrences to keep the
/// group's finding identifiers unique.
pub(super) fn ranks_after(
    existing: impl IntoIterator<Item = UnitFingerprint>,
    later: impl IntoIterator<Item = UnitFingerprint>,
) -> Vec<u32> {
    let mut next: BTreeMap<UnitFingerprint, u32> = BTreeMap::new();
    for host in existing {
        let slot = next.entry(host).or_insert(0);
        *slot = slot.saturating_add(1);
    }
    later
        .into_iter()
        .map(|host| {
            let slot = next.entry(host).or_insert(0);
            let rank = *slot;
            *slot = slot.saturating_add(1);
            rank
        })
        .collect()
}

/// The host fingerprints of a group's members, in member order.
pub(super) fn member_hosts<'a>(
    units: &'a [StructuralUnit],
    members: &'a [usize],
) -> impl Iterator<Item = UnitFingerprint> + 'a {
    members.iter().map(|&member| units[member].fingerprint)
}

/// The host fingerprints of a duplicated run's occurrences, in occurrence
/// order.
pub(super) fn occurrence_hosts<'a>(
    units: &'a [StructuralUnit],
    region: &'a StructuralRegion,
) -> impl Iterator<Item = UnitFingerprint> + 'a {
    region
        .occurrences
        .iter()
        .map(|occurrence| units[occurrence.unit].fingerprint)
}

/// A group's reported similarity: the medoid-to-member breakdown of its
/// *weakest* member, paired with the group's cohesion.
///
/// The breakdown of the pair that establishes the group's cohesion.
///
/// Every value remains a real measurement of a real pair. In particular this
/// is not necessarily the medoid-to-member comparison with the lowest score:
/// complete linkage can be constrained by two non-canonical members.
pub(super) const fn weakest_breakdown(detail: &GroupDetail) -> &SimilarityBreakdown {
    &detail.cohesion_breakdown
}

fn similarity(group: &StructuralGroup, detail: &GroupDetail) -> report::Similarity {
    let breakdown = weakest_breakdown(detail);
    report::Similarity {
        weight_version: WEIGHT_VERSION.to_string(),
        lexical: breakdown.lexical,
        structural: breakdown.structural,
        control_flow: breakdown.control_flow,
        type_similarity: breakdown.type_similarity,
        api: breakdown.api,
        composite: breakdown.composite,
        min_pairwise: group.min_pairwise,
        confidence_band: Some(group.confidence.name().to_string()),
    }
}

/// The `(component, version)` pairs recorded with every Structural/Semantic
/// snapshot. The frontend versions are the structural parsers', which is what
/// the fingerprints were derived under; an answering compiler additionally
/// qualifies the public set with each distinct IR schema it actually emitted.
///
/// What a difference in any of them costs a recorded result is weighed by
/// [`codehelion_core::compat`] rather than assumed from being listed: the
/// grouping rules and the ranking recipe are here because they can be seen in
/// a result, not because they move an identifier.
pub(super) fn detector_versions(
    literals: LiteralNorm,
    entropy_ratio_floor: f64,
    answers: Option<&crate::semantic::Answers>,
) -> Vec<(String, String)> {
    let mut versions = vec![
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        (
            "literals".to_string(),
            ContentNorm::Normalized(literals).label().to_string(),
        ),
        ("grouping".to_string(), GROUPING_VERSION.to_string()),
        ("maximal".to_string(), MAXIMAL_VERSION.to_string()),
        ("substitution".to_string(), SUBSTITUTION_VERSION.to_string()),
        (
            "normalization".to_string(),
            NORMALIZATION_VERSION.to_string(),
        ),
        ("features".to_string(), FEATURE_SCHEMA_VERSION.to_string()),
        ("verify-weights".to_string(), WEIGHT_VERSION.to_string()),
        ("boilerplate".to_string(), BOILERPLATE_VERSION.to_string()),
        ("test-code".to_string(), TEST_CODE_VERSION.to_string()),
        (
            "entropy-ratio".to_string(),
            format!("entropy-ratio-v1:{entropy_ratio_floor:.6}"),
        ),
        ("sog-schema".to_string(), SOG_SCHEMA_VERSION.to_string()),
        (
            "semantic-candidate-index".to_string(),
            SEMANTIC_CANDIDATE_INDEX_VERSION.to_string(),
        ),
        (
            "semantic-windowing".to_string(),
            SEMANTIC_WINDOWING_VERSION.to_string(),
        ),
        (
            "semantic-rule-registry".to_string(),
            SEMANTIC_RULE_REGISTRY_VERSION.to_string(),
        ),
        (
            "frontend.rust".to_string(),
            codehelion_frontend_rust::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.c".to_string(),
            codehelion_frontend_c::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.cpp".to_string(),
            codehelion_frontend_cpp::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
    ];
    let compiler_ir_versions: BTreeSet<String> = answers
        .into_iter()
        .flat_map(|answers| answers.per_source.iter())
        .filter_map(|answer| match answer {
            crate::semantic::Answer::Analyzed { ir, .. } => Some(ir.schema_version.clone()),
            crate::semantic::Answer::Unavailable { .. }
            | crate::semantic::Answer::NotAsked { .. } => None,
        })
        .collect();
    versions.extend(compiler_ir_versions.into_iter().map(|version| {
        (
            codehelion_store::compiler::IR_SCHEMA_COMPONENT.to_string(),
            version,
        )
    }));
    versions.sort_unstable();
    versions
}
