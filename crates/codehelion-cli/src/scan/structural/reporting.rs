//! Conversion of structural analysis results into public report models.

use super::REGION_SIMILARITY;
use super::inputs::ReportInputs;
use super::model::{SemanticDetection, SemanticUnitGraph};
use super::semantic_analysis::{
    semantic_group_member_fingerprints, semantic_member_ranks, semantic_scope,
};
use super::suppression::{
    aggregate_test_code_evidence, region_identifier_jaccard, region_test_code_evidence,
    unit_token_span,
};
use crate::report::{self, Report};
use crate::scan::build::as_u64;
use crate::scan::shared;
use anyhow::Result;
use codehelion_core::boilerplate::BOILERPLATE_VERSION;
use codehelion_core::clone_class::CloneScope;
use codehelion_core::config::Stage;
use codehelion_core::discovery::DiscoveryReport;
use codehelion_core::discovery::{AnalysisMode, NORMALIZATION_VERSION};
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::features::FEATURE_SCHEMA_VERSION;
use codehelion_core::grouping::GROUPING_VERSION;
use codehelion_core::grouping::StructuralGroup;
use codehelion_core::maximal::MAXIMAL_VERSION;
use codehelion_core::semantic::{
    SEMANTIC_CANDIDATE_INDEX_VERSION, SEMANTIC_RULE_REGISTRY_VERSION, SEMANTIC_WINDOWING_VERSION,
    SOG_SCHEMA_VERSION,
};
use codehelion_core::stable_id;
use codehelion_core::stable_id::{ContentNorm, FP_SCHEMA_VERSION, UnitFingerprint};
use codehelion_core::structural::{
    self, GroupDetail, StructuralRegion, StructuralUnit, VerifiedPair,
};
use codehelion_core::substitution::SUBSTITUTION_VERSION;
use codehelion_core::test_code::TEST_CODE_VERSION;
use codehelion_core::verify::SimilarityBreakdown;
use codehelion_core::verify::WEIGHT_VERSION;
use codehelion_store::snapshot::SummaryRow;
use codehelion_store::snapshot::UnparsedRow;
use std::collections::{BTreeMap, BTreeSet};

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
        members: semantic_members(inputs, &fingerprint, members.iter().copied()),
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
        members: semantic_members(inputs, &fingerprint, semantic_group.members.iter()),
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

/// The occurrences of one unit-scoped finding, as the report lists them.
///
/// A group and a split pair list their members identically because a member is
/// the same thing in both: a whole unit the run holds to be a copy of the
/// others. Only what established the set differs, and that is said elsewhere.
fn unit_members(
    inputs: &ReportInputs<'_>,
    fingerprint: &stable_id::CloneGroupFingerprint,
    members: &[usize],
) -> Vec<report::Member> {
    members
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
                    fingerprint,
                    stable_id::OccurrenceScope::Unit(&unit.fingerprint),
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
        .collect()
}

/// The occurrences of one restricted-semantic finding, as the report lists
/// them.
///
/// A semantic window is anchored to its own span rather than to its host
/// unit's, so it carries its own lines and token count while the unit around
/// it supplies the name and the shape. The canonical member is first, which is
/// how both a verified pair and a cohesive group arrive here.
fn semantic_members<'a>(
    inputs: &ReportInputs<'_>,
    fingerprint: &stable_id::CloneGroupFingerprint,
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
) -> Vec<report::Member> {
    let members: Vec<&SemanticUnitGraph> = members.into_iter().collect();
    members
        .iter()
        .zip(semantic_member_ranks(members.iter().copied()))
        .enumerate()
        .map(|(position, (member, rank))| {
            let unit = &inputs.analysis.units[member.unit];
            let file = &inputs.files[unit.file];
            report::Member {
                finding_id: stable_id::finding_id(
                    fingerprint,
                    stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                    rank,
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
        .collect()
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
            replay_database: inputs.replay_database,
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
                            signature_units: sibling
                                .signature_units
                                .map(|units| u64::try_from(units).unwrap_or(u64::MAX)),
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
                                    stable_id::OccurrenceScope::Unit(&unit.fingerprint),
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
        excluded_oversized_metadata: exclusions.oversized_metadata,
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
        common_signatures_skipped: as_u64(stats.signature_siblings.common_signatures_skipped),
        largest_skipped_signature_units: as_u64(
            stats.signature_siblings.largest_skipped_signature_units,
        ),
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
            inputs.variant.mode,
        ),
        unused_suppressions: inputs.unused_suppressions(),
    })
}

/// This pipeline's funnel, assembled where every mode's is.
///
/// The stages themselves live in [`crate::scan::funnel`], which holds each
/// mode's statistics to an exhaustive destructuring so a counter cannot be
/// added without being given a place in a report. What is left here is the
/// part that cannot move: the semantic record is private to this pipeline, so
/// its counts are read locally and handed over.
pub(super) fn funnel(
    stats: &structural::StructuralStats,
    semantic: &SemanticDetection,
    parsed_files: u64,
    depth_truncated_files: u64,
    mode: AnalysisMode,
) -> Vec<report::FunnelStage> {
    crate::scan::funnel::structural(&crate::scan::funnel::StructuralFunnel {
        stats,
        semantic: semantic_funnel(semantic),
        parsed_files,
        depth_truncated_files,
        compiler_ran: Stage::Compiler.runs_in(mode),
    })
}

/// The compiler-backed counts the shared funnel builder needs.
///
/// The detection record is private to this pipeline, so its numbers are read
/// here and the stages they become are still defined in one place.
const fn semantic_funnel(semantic: &SemanticDetection) -> crate::scan::funnel::SemanticFunnel {
    let candidates = &semantic.candidates;
    crate::scan::funnel::SemanticFunnel {
        registered_observations: semantic.registered_observations,
        excluded_observations: semantic.excluded_observations,
        graphs: candidates.graphs,
        ineligible_graphs: candidates.ineligible_graphs,
        units_without_registered_operations: semantic.units_without_registered_operations,
        units_no_registered_rule_claimed: semantic.units_no_registered_rule_claimed,
        buckets: candidates.buckets,
        oversized_buckets: candidates.oversized_buckets,
        pairs_emitted: candidates.pairs_emitted,
        pairs_budget_dropped: candidates.pairs_budget_dropped,
        verified_pairs: semantic.verified_pairs,
        disabled_pairs: semantic.disabled_pairs,
        grouped_pairs: semantic.grouping.grouped_pairs,
        invalid_pairs: semantic.grouping.invalid_pairs,
        duplicate_pairs: semantic.grouping.duplicate_pairs,
        declined_pairs: semantic.grouping.declined_pairs(),
        ceiling_severed_pairs: semantic.grouping.ceiling_severed_pairs,
        groups: semantic.groups.len(),
        pairs: semantic.pairs.len(),
    }
}

/// Discovery exclusions shared by an invocation rather than tied to a parsed
/// build-variant partition.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DiscoveryExclusions {
    pub(super) generated: u64,
    pub(super) by_glob: u64,
    pub(super) too_large: u64,
    pub(super) oversized_metadata: u64,
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
            oversized_metadata: discovery.skipped.oversized_metadata,
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
        members: unit_members(inputs, &detail.fingerprint, &group.members),
    });
    assembled.similarity = Some(similarity(group, detail));
    assembled.identifier_jaccard = detail.identifier_jaccard;
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
/// corresponding unit, absent where neither side named an identifier.
///
/// A split pair is a verified clone relation, but its raw names are only
/// triage evidence for a possible shared refactoring target. They do not
/// establish similarity and cannot affect detection or grouping.
pub(super) fn split_pair_identifier_jaccard(
    inputs: &ReportInputs<'_>,
    pair: &VerifiedPair,
) -> Option<f64> {
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
        members: unit_members(inputs, &pair.fingerprint, members),
    });
    assembled.identifier_jaccard = split_pair_identifier_jaccard(inputs, pair);
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
                        stable_id::OccurrenceScope::Unit(&unit.fingerprint),
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
    assembled.identifier_jaccard = region_identifier_jaccard(inputs, region);
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
