//! Store rows for the structural finding families and for what a compiler
//! managed to say about the tree.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use codehelion_core::clone_class::CloneScope;
use codehelion_core::engine;
use codehelion_core::grouping::StructuralGroup;
use codehelion_core::stable_id::{self, CloneGroupFingerprint};
use codehelion_core::structural::GroupDetail;
use codehelion_core::verify::WEIGHT_VERSION;
use codehelion_store::compiler::{self as store_compiler, CompilerHelperRow, CompilerOutcome};
use codehelion_store::snapshot::{
    GroupRow, MemberRow, NearMissRow, PriorityRow, SiblingGroupRow, SiblingRow,
    SimilarityBreakdownRow,
};

use crate::report;
use crate::scan::shared;
use crate::scan::structural::reporting::{
    member_hosts, occurrence_hosts, pair_members, ranks_after, ranks_within_host,
    split_pair_identifier_jaccard, weakest_breakdown,
};
use crate::scan::structural::{
    REGION_SIMILARITY, ReportInputs, aggregate_test_code_evidence, region_identifier_jaccard,
    region_test_code_evidence,
};
use crate::semantic;

/// Convert bounded LSH diagnostics to the store's run-scoped representation.
/// They deliberately carry no group or finding identity.
pub(super) fn near_miss_rows(
    inputs: &ReportInputs<'_>,
    host_index: &BTreeMap<usize, usize>,
) -> Result<Vec<NearMissRow>> {
    inputs
        .analysis
        .near_misses
        .iter()
        .enumerate()
        .map(|(index, near_miss)| {
            let left = *host_index.get(&near_miss.a).with_context(|| {
                format!(
                    "near-miss source unit {} is missing from the snapshot",
                    near_miss.a
                )
            })?;
            let right = *host_index.get(&near_miss.b).with_context(|| {
                format!(
                    "near-miss source unit {} is missing from the snapshot",
                    near_miss.b
                )
            })?;
            Ok(NearMissRow {
                left,
                right,
                estimated_jaccard: near_miss.estimated_jaccard,
                suppressed_by: inputs.near_miss_suppressed[index],
            })
        })
        .collect()
}

/// Convert core sibling evidence to the store's dedicated, non-membership
/// table rows. Group fingerprints keep the attachment stable across replay.
pub(super) fn sibling_rows(
    inputs: &ReportInputs<'_>,
    host_index: &BTreeMap<usize, usize>,
) -> Result<Vec<SiblingGroupRow>> {
    inputs
        .analysis
        .siblings
        .iter()
        .enumerate()
        .map(|(owner_index, siblings)| {
            let detail = inputs
                .analysis
                .details
                .get(siblings.group)
                .with_context(|| format!("missing detail for sibling group {}", siblings.group))?;
            let group = inputs
                .analysis
                .groups
                .groups
                .get(siblings.group)
                .with_context(|| {
                    format!("missing primary group for siblings {}", siblings.group)
                })?;
            let ranks = ranks_after(
                member_hosts(&inputs.analysis.units, &group.members),
                siblings
                    .siblings
                    .iter()
                    .map(|sibling| inputs.analysis.units[sibling.unit].fingerprint),
            );
            let siblings = siblings
                .siblings
                .iter()
                .zip(ranks)
                .enumerate()
                .map(|(sibling_index, (sibling, rank))| {
                    let unit = &inputs.analysis.units[sibling.unit];
                    let snapshot_unit = host_index.get(&sibling.unit).with_context(|| {
                        format!(
                            "sibling source unit {} is missing from the snapshot",
                            sibling.unit
                        )
                    })?;
                    Ok(SiblingRow {
                        unit: *snapshot_unit,
                        content: unit.content,
                        finding: stable_id::finding_id(
                            &detail.fingerprint,
                            stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                            rank,
                        ),
                        basis: sibling.basis,
                        signature: sibling.signature.clone(),
                        signature_units: sibling.signature_units,
                        clone_type: sibling.clone_type,
                        confidence: sibling.confidence,
                        similarity: SimilarityBreakdownRow {
                            weight_version: WEIGHT_VERSION.to_string(),
                            lexical: sibling.breakdown.lexical,
                            structural: sibling.breakdown.structural,
                            control_flow: sibling.breakdown.control_flow,
                            type_similarity: sibling.breakdown.type_similarity,
                            api: sibling.breakdown.api,
                            composite: sibling.breakdown.composite,
                            min_pairwise: sibling.breakdown.composite,
                            confidence_band: sibling.confidence,
                        },
                        boilerplate: unit.boilerplate,
                        suppressed_by: inputs.sibling_suppressed[owner_index][sibling_index],
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(SiblingGroupRow {
                group: detail.fingerprint,
                siblings,
            })
        })
        .collect()
}

/// What a compiler said about the tree, as the snapshot records it.
///
/// Every source gets a row, including the ones nobody was asked about. The
/// helper column is what tells those apart from the ones a helper was given
/// and could not answer: a row naming no helper was ruled out before any was
/// asked, and its reason says which of the two gaps it was. Leaving them out
/// instead would make the three outcomes recoverable only by subtracting the
/// rows from the file list, and a run reporting itself has no business
/// deriving what it knew outright.
pub(super) fn compiler_rows(
    asked: &semantic::Answers,
) -> (Vec<CompilerHelperRow>, Vec<store_compiler::CompilerUnitRow>) {
    let helpers: Vec<CompilerHelperRow> = asked
        .helpers
        .iter()
        .map(|helper| CompilerHelperRow {
            identity: helper.identity.clone(),
            restarts: Some(helper.restarts),
        })
        .collect();
    let units = asked
        .per_source
        .iter()
        .map(|answer| match answer {
            semantic::Answer::Analyzed { helper, ir } => store_compiler::CompilerUnitRow {
                helper: Some(*helper),
                outcome: CompilerOutcome::Analyzed(ir.clone()),
            },
            semantic::Answer::Unavailable {
                helper,
                unit,
                reason,
                diagnostics,
            } => store_compiler::CompilerUnitRow {
                helper: *helper,
                outcome: CompilerOutcome::Unavailable {
                    unit: unit.clone(),
                    reason: *reason,
                    diagnostic: (!diagnostics.is_empty()).then(|| diagnostics.join(" / ")),
                },
            },
            semantic::Answer::NotAsked { unit, reason } => store_compiler::CompilerUnitRow {
                helper: None,
                outcome: CompilerOutcome::Unavailable {
                    unit: unit.clone(),
                    reason: *reason,
                    diagnostic: None,
                },
            },
        })
        .collect();
    (helpers, units)
}

/// The recorded occurrences of one unit-scoped finding, ranked within their
/// hosts.
///
/// The rank is what tells two occurrences apart when their enclosing units
/// share a fingerprint, and a group and a split pair record it the same way
/// because a member is the same thing in both: a whole unit the run holds to
/// be a copy of the others.
fn unit_member_rows(
    inputs: &ReportInputs<'_>,
    host_index: &BTreeMap<usize, usize>,
    fingerprint: &CloneGroupFingerprint,
    members: &[usize],
) -> Vec<MemberRow> {
    members
        .iter()
        .zip(ranks_within_host(member_hosts(
            &inputs.analysis.units,
            members,
        )))
        .map(|(&member, rank)| {
            let unit = &inputs.analysis.units[member];
            let file = &inputs.files[unit.file];
            MemberRow {
                content: unit.content,
                finding: stable_id::finding_id(
                    fingerprint,
                    stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                    rank,
                ),
                language: file.language,
                host_unit: Some(host_index[&member]),
                boilerplate: unit.boilerplate,
                file_path: file.relative_path.clone(),
                start_line: unit.start_line,
                end_line: unit.end_line,
                token_count: unit.token_end.saturating_sub(unit.token_start),
            }
        })
        .collect()
}

/// One duplicated-unit group as a store row, with its occurrences.
///
/// The rank is what tells two occurrences of one group apart when their
/// enclosing units share a fingerprint, which is every verbatim copy: without
/// it the whole group would be recorded under the canonical instance's
/// identifier and `explain` could answer about none of the others.
pub(super) fn unit_group_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let group = &inputs.analysis.groups.groups[index];
    let detail = &inputs.analysis.details[index];
    let medoid = &inputs.analysis.units[group.canonical];
    let medoid_tokens = inputs.unit_tokens(medoid);
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint: detail.fingerprint,
        clone_type: group.clone_type,
        scope: CloneScope::Unit,
        statements: None,
        score: group.min_pairwise,
        entropy_bits: engine::content_entropy_bits(medoid_tokens, inputs.literals),
        suppressed_by: inputs.group_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &detail.fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &detail.fingerprint.to_hex())?,
        members: unit_member_rows(inputs, host_index, &detail.fingerprint, &group.members),
    });
    row.test_code = detail.test_code;
    row.test_code_evidence = detail.test_code_evidence;
    row.boilerplate = detail.boilerplate;
    row.width_family = detail.width_family;
    row.similarity = Some(breakdown_row(group, detail));
    row.identifier_jaccard = detail.identifier_jaccard;
    row.has_loop = Some(detail.body_materiality.has_loop);
    row.has_dynamic_allocation = Some(detail.body_materiality.has_dynamic_allocation);
    row.call_count = Some(detail.body_materiality.call_count);
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, medoid_tokens.len());
    Ok(row)
}

/// The ranking the report gave one entry, by its fingerprint.
///
/// An entry the report never ranked is a disagreement between what a run shows
/// and what it records, which is exactly the thing this arrangement exists to
/// prevent — so it fails the scan rather than storing a placeholder that would
/// read as a finding nobody thought was worth anything.
pub(super) fn recorded_ranking(
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
    fingerprint: &str,
) -> Result<PriorityRow> {
    ranking.get(fingerprint).map_or_else(
        || bail!("group {fingerprint} was recorded without being ranked"),
        |(priority, _)| Ok(crate::scan::priority_row(priority)),
    )
}

pub(super) fn recorded_ranked_down(
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
    fingerprint: &str,
) -> Result<bool> {
    ranking.get(fingerprint).map_or_else(
        || bail!("group {fingerprint} was recorded without a presentation policy"),
        |(_, ranked_down)| Ok(*ranked_down),
    )
}

/// One duplicated run as a store row. Its entropy is measured over the
/// canonical occurrence's own tokens, not its host unit's: the run is the
/// content the group is about.
/// One verified pair no group could hold, as a recorded group of two.
pub(super) fn split_pair_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let pair = &inputs.analysis.unrepresented[index];
    let canonical = &inputs.analysis.units[pair.canonical];
    let canonical_tokens = inputs.unit_tokens(canonical);
    let test_code_evidence =
        aggregate_test_code_evidence(inputs.analysis, pair.members.iter().copied());
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint: pair.fingerprint,
        clone_type: pair.class,
        scope: CloneScope::Unit,
        statements: None,
        score: pair.similarity,
        entropy_bits: engine::content_entropy_bits(canonical_tokens, inputs.literals),
        suppressed_by: inputs.pair_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &pair.fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &pair.fingerprint.to_hex())?,
        members: unit_member_rows(inputs, host_index, &pair.fingerprint, &pair_members(pair)),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.split_pair = true;
    row.boilerplate = pair.boilerplate;
    row.similarity = pair.breakdown.map(|breakdown| SimilarityBreakdownRow {
        weight_version: WEIGHT_VERSION.to_string(),
        lexical: breakdown.lexical,
        structural: breakdown.structural,
        control_flow: breakdown.control_flow,
        type_similarity: breakdown.type_similarity,
        api: breakdown.api,
        composite: breakdown.composite,
        min_pairwise: pair.similarity,
        confidence_band: pair.confidence,
    });
    row.identifier_jaccard = split_pair_identifier_jaccard(inputs, pair);
    row.width_family = pair.width_family;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical_tokens.len());
    Ok(row)
}

pub(super) fn region_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = ranks_within_host(occurrence_hosts(&inputs.analysis.units, region));
    let test_code_evidence = region_test_code_evidence(inputs.analysis, region);
    let canonical = region
        .occurrences
        .first()
        .map_or_else(Vec::new, |occurrence| {
            inputs.region_tokens(occurrence).to_vec()
        });
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint: region.fingerprint,
        clone_type: region.clone_type,
        scope: CloneScope::Fragment,
        statements: Some(region.statements),
        score: REGION_SIMILARITY,
        entropy_bits: engine::content_entropy_bits(&canonical, inputs.literals),
        suppressed_by: inputs.region_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &region.fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &region.fingerprint.to_hex())?,
        members: region
            .occurrences
            .iter()
            .zip(&ranks)
            .map(|(occurrence, &rank)| {
                let unit = &inputs.analysis.units[occurrence.unit];
                let file = &inputs.files[occurrence.file];
                MemberRow {
                    content: occurrence.content,
                    finding: stable_id::finding_id(
                        &region.fingerprint,
                        stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                        rank,
                    ),
                    language: file.language,
                    host_unit: Some(host_index[&occurrence.unit]),
                    boilerplate: None,
                    file_path: file.relative_path.clone(),
                    start_line: occurrence.start_line,
                    end_line: occurrence.end_line,
                    token_count: occurrence.token_end.saturating_sub(occurrence.token_start),
                }
            })
            .collect(),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical.len());
    row.identifier_jaccard = region_identifier_jaccard(inputs, region);
    Ok(row)
}

/// The persisted form of a group's similarity evidence.
fn breakdown_row(group: &StructuralGroup, detail: &GroupDetail) -> SimilarityBreakdownRow {
    let breakdown = weakest_breakdown(detail);
    SimilarityBreakdownRow {
        weight_version: WEIGHT_VERSION.to_string(),
        lexical: breakdown.lexical,
        structural: breakdown.structural,
        control_flow: breakdown.control_flow,
        type_similarity: breakdown.type_similarity,
        api: breakdown.api,
        composite: breakdown.composite,
        min_pairwise: group.min_pairwise,
        confidence_band: group.confidence,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use codehelion_core::discovery::Language;
    use codehelion_helper::ir::{CompilerIr, Unavailability, UnitRef};
    use codehelion_helper::protocol::{Capability, HelperIdentity};
    use codehelion_store::snapshot::{Snapshot, SummaryRow};

    use super::compiler_rows;

    /// One unit of every outcome, from a run where a helper died before it
    /// could say who it was.
    ///
    /// Two backends were installed: one answered and is in the run's helper
    /// list, the other fell over before its handshake and is in nobody's, so
    /// the unit it failed on names no helper at all.
    fn answers_from_a_run_whose_helper_died() -> crate::semantic::Answers {
        let unit = |file: &str| UnitRef {
            unit: "crate".to_string(),
            file: file.to_string(),
            variant: "target=host".to_string(),
        };
        crate::semantic::Answers {
            helpers: vec![crate::semantic::Answered {
                identity: HelperIdentity {
                    name: "codehelion-backend-rust".to_string(),
                    version: "0.1.0".to_string(),
                    protocol: 2,
                    toolchains: vec!["1.98.0".to_string()],
                    capabilities: vec![Capability::Types],
                    executes: Vec::new(),
                },
                restarts: 1,
            }],
            per_source: vec![
                crate::semantic::Answer::Analyzed {
                    helper: 0,
                    ir: Box::new(CompilerIr::empty(unit("src/answered.rs"))),
                },
                crate::semantic::Answer::Unavailable {
                    helper: None,
                    unit: unit("src/crashed.rs"),
                    reason: Unavailability::HelperDied,
                    diagnostics: vec!["the helper stopped before answering".to_string()],
                },
                crate::semantic::Answer::NotAsked {
                    unit: unit("vendor/blob.c"),
                    reason: Unavailability::NotSupported,
                },
            ],
        }
    }

    /// What a run says about itself and what a later `report --run` says about
    /// it are one claim read twice, so a helper that died has to be a helper
    /// that died in both. The record has only the reason to go on — a helper
    /// that never introduced itself leaves no row to name — and reading the
    /// gap in the helper column instead turns the diagnosis into its opposite
    /// on the only path that replays a finished run.
    #[test]
    fn a_dead_helper_reads_back_as_the_split_the_run_reported() {
        let asked = answers_from_a_run_whose_helper_died();
        let live = crate::scan::structural::coverage(&asked);
        let (helpers, units) = compiler_rows(&asked);

        let directory = tempfile::tempdir().expect("a directory for the audit database");
        let mut store = codehelion_store::Store::open(&directory.path().join("audit.db"))
            .expect("a database on disk");
        let variant = codehelion_core::discovery::BuildVariant::fast(
            codehelion_core::discovery::LanguageSelection::default(),
            Language::Rust,
        );
        let run = store
            .record_snapshot(&Snapshot {
                root_path: "/work",
                tool_version: "0.0.0",
                config_hash: "cfg-hash",
                config_source: "defaults",
                config_path: None,
                started_at: "2026-01-01T00:00:00Z",
                finished_at: "2026-01-01T00:00:01Z",
                variant: &variant,
                min_clone_tokens: 20,
                detector_versions: &[],
                suppressions: Vec::new(),
                units: Vec::new(),
                groups: Vec::new(),
                sibling_groups: Vec::new(),
                near_misses: Vec::new(),
                files: Vec::new(),
                compiler_helpers: helpers,
                compiler_units: units,
                summary: SummaryRow::default(),
            })
            .expect("a recorded run");
        let stored = store
            .run_compiler_coverage(run)
            .expect("the recorded coverage")
            .expect("a compiler was asked about this run");
        let replayed = crate::report_command::restored_compiler_coverage(stored);

        assert_eq!(live.answered, 1);
        assert_eq!(live.not_asked, 1);
        assert_eq!(live.unavailable["helper_died"], 1);
        // The unasked file is named by the reason it went unasked about, in
        // both readings: a total the reader cannot attribute is what the
        // by-reason breakdown exists to prevent.
        assert_eq!(live.not_asked_reasons["not_supported"], 1);
        assert_eq!(replayed.answered, live.answered);
        assert_eq!(replayed.not_asked, live.not_asked);
        assert_eq!(replayed.not_asked_reasons, live.not_asked_reasons);
        assert_eq!(replayed.unavailable, live.unavailable);
        assert_eq!(replayed.diagnostics, live.diagnostics);
        assert_eq!(replayed.restarts, live.restarts);
    }
}
