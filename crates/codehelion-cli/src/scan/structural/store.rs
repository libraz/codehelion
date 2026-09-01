//! Persistence of structural and semantic scan snapshots.

use super::reporting::{
    detector_versions, member_hosts, occurrence_hosts, pair_members, ranks_after,
    ranks_within_host, split_pair_identifier_jaccard, weakest_breakdown,
};
use super::{
    BTreeMap, BTreeSet, CloneScope, CompilerHelperRow, CompilerOutcome, Config, Context, FileRow,
    GroupDetail, GroupRow, MemberRow, NearMissRow, PriorityRow, REGION_SIMILARITY, ReportInputs,
    Result, SemanticEvidenceRow, SemanticNodeMappingRow, SemanticOperationGraphRow,
    SemanticUnitGraph, SiblingGroupRow, SiblingRow, SimilarityBreakdownRow, Snapshot,
    StructuralGroup, SummaryRow, UnitRow, WEIGHT_VERSION, aggregate_test_code_evidence, bail,
    engine, literal_norm, open_store, path_key, region_identifier_jaccard,
    region_test_code_evidence, report, semantic, semantic_group_member_fingerprints,
    semantic_member_ranks, semantic_scope, shared, stable_id, store_compiler,
};
use crate::scan::reuse_config_hash;
use crate::scan::store::ReuseProfile;
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::ContentHash;
use codehelion_core::discovery::Language;
use codehelion_core::frontend::UnitKind;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, GroupLineageId, UnitFingerprint,
};
use codehelion_core::test_code::TestCodeEvidence;
use codehelion_core::verify::Confidence;
use codehelion_store::snapshot::{AuditState, StagedSnapshotPart};

type SnapshotRows = (Vec<UnitRow>, Vec<GroupRow>, BTreeMap<usize, usize>);

pub(super) struct RecordResult {
    pub run_id: i64,
    pub reused: bool,
    pub changes: Option<report::TreeChanges>,
    pub staged: Option<StagedSnapshotPart>,
    /// The key this snapshot was recorded under. A later reuse decision about
    /// the same invocation reads it back rather than rebuilding the recipe,
    /// which is how the two could describe different runs.
    pub reuse_key: ContentHash,
}

pub(super) fn record(
    cfg: &Config,
    inputs: &ReportInputs<'_>,
    ranked: &[report::Group],
    files: Vec<FileRow>,
    summary: &SummaryRow,
    asked: Option<&semantic::Answers>,
    completed: bool,
) -> Result<RecordResult> {
    let (units, groups, host_index) = snapshot_rows(inputs, ranked)?;
    let mut store = open_store(inputs.db_path)?;
    let config_hash = reuse_config_hash(
        cfg,
        ReuseProfile {
            untrusted: inputs.untrusted,
            siblings_by_signature: inputs.siblings_by_signature,
            rules: &inputs.rules.rows,
            presentation: inputs.suppression,
        },
    )?;
    let mut detector_versions = detector_versions(
        literal_norm(cfg.literal_normalization),
        cfg.entropy_ratio_floor,
        asked,
    );
    // Kept for historical report rendering only; baseline compatibility and
    // the public detector list deliberately exclude presentation weights.
    detector_versions.push(("ranking".to_string(), cfg.priority.weights().recipe()));
    let root_path = path_key(inputs.root);
    let current_tree = file_tree(&files);
    let compatible = store.latest_compatible_run(
        &root_path,
        config_hash.as_str(),
        &inputs.variant.fingerprint(),
    )?;
    let compatible = compatible.map(|run| run.id);
    let changes = compatible
        .map(|previous_id| {
            store
                .run_tree(previous_id)
                .map(|previous_tree| tree_changes(previous_id, &previous_tree, &current_tree))
        })
        .transpose()?;
    if completed
        && inputs.reuse_allowed
        && let Some(previous_id) = compatible
        && store
            .run_summary_row(previous_id)?
            .is_some_and(|stored| stored.baseline_digest == summary.baseline_digest)
        && changes.as_ref().is_some_and(tree_unchanged)
    {
        store.activate_suppressions(&inputs.rules.rows)?;
        return Ok(RecordResult {
            run_id: previous_id,
            reused: true,
            changes,
            staged: None,
            reuse_key: config_hash,
        });
    }
    let (compiler_helpers, compiler_units) = asked.map_or_else(
        // No compiler was asked anything: this mode reads source and nothing
        // else, and an empty list is the whole truth about it.
        || (Vec::new(), Vec::new()),
        compiler_rows,
    );
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
        config_source: &inputs.configuration.source,
        config_path: inputs.configuration.path.as_deref(),
        started_at: inputs.started_at,
        finished_at: inputs.finished_at,
        variant: inputs.variant,
        min_clone_tokens: cfg.min_clone_tokens,
        detector_versions: &detector_versions,
        suppressions: inputs.rules.rows.clone(),
        files,
        units,
        groups,
        sibling_groups: sibling_rows(inputs, &host_index)?,
        near_misses: near_miss_rows(inputs, &host_index)?,
        compiler_helpers,
        compiler_units,
        summary: summary.clone(),
    };
    let (run_id, staged) = if completed {
        let run_id = store.record_snapshot_with_predecessor(&snapshot, compatible)?;
        (run_id, None)
    } else {
        let staged = store
            .record_snapshot_part_staged(&snapshot)?
            .with_predecessor(compatible);
        let run_id = staged.run_id();
        (run_id, Some(staged))
    };
    Ok(RecordResult {
        run_id,
        reused: false,
        changes,
        staged,
        reuse_key: config_hash,
    })
}

fn file_tree(files: &[FileRow]) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|file| (file.relative_path.clone(), file.content_hash.clone()))
        .collect()
}

const fn tree_unchanged(changes: &report::TreeChanges) -> bool {
    changes.modified == 0 && changes.added == 0 && changes.removed == 0
}

fn tree_changes(
    since_run_id: i64,
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> report::TreeChanges {
    let modified = after
        .iter()
        .filter(|(path, hash)| before.get(*path).is_some_and(|old| old != *hash))
        .count();
    let added = after
        .keys()
        .filter(|path| !before.contains_key(*path))
        .count();
    let removed = before
        .keys()
        .filter(|path| !after.contains_key(*path))
        .count();
    let unchanged = after
        .iter()
        .filter(|(path, hash)| before.get(*path) == Some(*hash))
        .count();
    report::TreeChanges {
        since_run_id,
        modified: u64::try_from(modified).unwrap_or(u64::MAX),
        added: u64::try_from(added).unwrap_or(u64::MAX),
        removed: u64::try_from(removed).unwrap_or(u64::MAX),
        unchanged: u64::try_from(unchanged).unwrap_or(u64::MAX),
    }
}

/// Convert bounded LSH diagnostics to the store's run-scoped representation.
/// They deliberately carry no group or finding identity.
fn near_miss_rows(
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
fn sibling_rows(
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
fn compiler_rows(
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

/// Turn the analysis into store rows. Every unit that hosts a member is
/// written once, even when it appears in several groups. A unit-scope
/// member's host is the unit it *is*; a duplicated run's host is the unit it
/// sits inside, which is a different unit for each occurrence and usually not
/// a clone of the others.
#[allow(
    clippy::too_many_lines,
    reason = "all persisted structural finding families share one host-index transaction boundary"
)]
fn snapshot_rows(inputs: &ReportInputs<'_>, ranked: &[report::Group]) -> Result<SnapshotRows> {
    // The ranking is looked up by fingerprint rather than by position: the
    // report interleaves duplicated units, duplicated runs and the pairs no
    // group could hold into one order, and the store keeps them apart.
    let ranking: BTreeMap<&str, (&report::Priority, bool)> = ranked
        .iter()
        .map(|group| {
            (
                group.fingerprint.as_str(),
                (
                    &group.priority,
                    report::ranks_down(group, inputs.suppression),
                ),
            )
        })
        .collect();
    let mut host_index: BTreeMap<usize, usize> = BTreeMap::new();
    for group in &inputs.analysis.groups.groups {
        for &member in &group.members {
            host_index.entry(member).or_insert(0);
        }
    }
    // Siblings are intentionally not primary members, but their source
    // units must still be persisted so the dedicated sibling table can refer
    // to a valid local snapshot row on replay.
    for siblings in &inputs.analysis.siblings {
        for sibling in &siblings.siblings {
            host_index.entry(sibling.unit).or_insert(0);
        }
    }
    // Near misses are not findings, but both sides still need durable source
    // anchors for `report --run` to reconstruct the diagnostic faithfully.
    for near_miss in &inputs.analysis.near_misses {
        host_index.entry(near_miss.a).or_insert(0);
        host_index.entry(near_miss.b).or_insert(0);
    }
    for &index in &inputs.regions.reported {
        for occurrence in &inputs.analysis.regions[index].occurrences {
            host_index.entry(occurrence.unit).or_insert(0);
        }
    }
    // A pair no group could hold reaches units no group holds, so its members
    // need recording as much as a group's do.
    for pair in &inputs.analysis.unrepresented {
        for &member in &pair.members {
            host_index.entry(member).or_insert(0);
        }
    }
    for pair in inputs.semantic_pairs {
        host_index.entry(pair.canonical.unit).or_insert(0);
        host_index.entry(pair.corresponding.unit).or_insert(0);
    }
    for group in inputs.semantic_groups {
        for member in &group.members {
            host_index.entry(member.unit).or_insert(0);
        }
    }
    let mut units = Vec::with_capacity(host_index.len());
    for (row, (unit_index, slot)) in host_index.iter_mut().enumerate() {
        *slot = row;
        let unit = &inputs.analysis.units[*unit_index];
        let file = &inputs.files[unit.file];
        units.push(UnitRow {
            fingerprint: unit.fingerprint,
            language: file.language,
            kind: unit.kind,
            name: unit.name.as_deref().map(ToString::to_string),
            file_path: file.relative_path.clone(),
            start_line: unit.start_line,
            end_line: unit.end_line,
            token_count: unit.token_end.saturating_sub(unit.token_start),
        });
    }

    let regions = (0..inputs.regions.reported.len())
        .map(|index| region_row(inputs, index, &host_index, &ranking))
        .collect::<Result<Vec<_>>>()?;
    let split_pairs = (0..inputs.analysis.unrepresented.len())
        .map(|index| split_pair_row(inputs, index, &host_index, &ranking))
        .collect::<Result<Vec<_>>>()?;
    let semantic_pairs = (0..inputs.semantic_pairs.len())
        .map(|index| semantic_pair_row(inputs, index, &host_index, &ranking))
        .collect::<Result<Vec<_>>>()?;
    let semantic_groups = (0..inputs.semantic_groups.len())
        .map(|index| semantic_group_row(inputs, index, &host_index, &ranking))
        .collect::<Result<Vec<_>>>()?;
    let mut groups = (0..inputs.analysis.groups.groups.len())
        .map(|index| unit_group_row(inputs, index, &host_index, &ranking))
        .chain(regions.into_iter().map(Ok))
        .chain(split_pairs.into_iter().map(Ok))
        .chain(semantic_groups.into_iter().map(Ok))
        .chain(semantic_pairs.into_iter().map(Ok))
        .collect::<Result<Vec<_>>>()?;
    groups = collapse_stored_group_rows(groups, &units)?;
    for group in &mut groups {
        collapse_stored_member_rows(group, &units)?;
    }
    // `build_groups` has already rejected unequal payloads for one stable
    // group id and counted exact duplicate groups. Keep the durable view on
    // that same identity decision so the store cannot see a second copy of a
    // report group or finding assembled from another evidence family.
    let report_members: BTreeMap<String, BTreeSet<String>> = ranked
        .iter()
        .map(|group| {
            (
                group.fingerprint.clone(),
                group
                    .members
                    .iter()
                    .map(|member| member.finding_id.clone())
                    .collect(),
            )
        })
        .collect();
    let mut emitted = BTreeSet::new();
    groups = groups
        .into_iter()
        .filter_map(|mut group| {
            let fingerprint = group.fingerprint.to_hex();
            let members = report_members.get(&fingerprint)?;
            if !emitted.insert(fingerprint) {
                return None;
            }
            let mut emitted_findings = BTreeSet::new();
            group.members.retain(|member| {
                members.contains(&member.finding.to_hex())
                    && emitted_findings.insert(member.finding)
            });
            Some(group)
        })
        .collect();
    Ok((units, groups, host_index))
}

/// IEEE-754 identity payload for one persisted measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredFloatBits(u64);

impl From<f64> for StoredFloatBits {
    fn from(value: f64) -> Self {
        Self(value.to_bits())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredLineageParentDescriptor {
    fingerprint: CloneGroupFingerprint,
    lineage: GroupLineageId,
    primary: bool,
    shared_content: u64,
    overlap: StoredFloatBits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredHistoryDescriptor {
    state: AuditState,
    lineage: GroupLineageId,
    parents: Vec<StoredLineageParentDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredPriorityDescriptor {
    clone_confidence: StoredFloatBits,
    maintenance_risk: StoredFloatBits,
    refactoring_difficulty: StoredFloatBits,
    final_priority: StoredFloatBits,
    semantic_confidence: Option<StoredFloatBits>,
    source_artifact_confidence: Option<StoredFloatBits>,
    savings_confidence: Option<StoredFloatBits>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSimilarityDescriptor {
    weight_version: String,
    lexical: StoredFloatBits,
    structural: StoredFloatBits,
    control_flow: Option<StoredFloatBits>,
    type_similarity: Option<StoredFloatBits>,
    api: Option<StoredFloatBits>,
    composite: StoredFloatBits,
    min_pairwise: StoredFloatBits,
    confidence_band: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSemanticGraphDescriptor {
    schema_version: String,
    graph_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSemanticDescriptor {
    schema_version: String,
    rule_id: String,
    rule_version: u32,
    rule_confidence: StoredFloatBits,
    graphs: Vec<StoredSemanticGraphDescriptor>,
    node_mappings: Vec<SemanticNodeMappingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredMemberDescriptor {
    content: FragmentFingerprint,
    finding: FindingId,
    language: Language,
    host_unit: Option<StoredUnitDescriptor>,
    boilerplate: Option<Boilerplate>,
    file_path: String,
    start_line: u32,
    end_line: u32,
    token_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredUnitDescriptor {
    fingerprint: UnitFingerprint,
    language: Language,
    kind: UnitKind,
    name: Option<String>,
    file_path: String,
    start_line: u32,
    end_line: u32,
    token_count: usize,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the identity payload mirrors independent durable group fields"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredGroupDescriptor {
    history: StoredHistoryDescriptor,
    clone_type: CloneClass,
    member_scope: CloneScope,
    test_code: bool,
    test_code_evidence: Option<TestCodeEvidence>,
    split_pair: bool,
    score: StoredFloatBits,
    entropy_bits: StoredFloatBits,
    suppress_reason: Option<String>,
    boilerplate: Option<Boilerplate>,
    identifier_jaccard: Option<StoredFloatBits>,
    has_loop: Option<bool>,
    has_dynamic_allocation: Option<bool>,
    call_count: Option<u64>,
    width_family: bool,
    ranked_down: bool,
    statements: Option<u32>,
    suppressed_by: Option<usize>,
    priority: StoredPriorityDescriptor,
    similarity: Option<StoredSimilarityDescriptor>,
    semantic: Option<StoredSemanticDescriptor>,
    members: Vec<StoredMemberDescriptor>,
}

fn stored_unit_descriptor(unit: &UnitRow) -> StoredUnitDescriptor {
    StoredUnitDescriptor {
        fingerprint: unit.fingerprint,
        language: unit.language,
        kind: unit.kind,
        name: unit.name.clone(),
        file_path: unit.file_path.clone(),
        start_line: unit.start_line,
        end_line: unit.end_line,
        token_count: unit.token_count,
    }
}

fn stored_member_descriptor(
    member: &MemberRow,
    units: &[UnitRow],
) -> Result<StoredMemberDescriptor> {
    let host_unit = member
        .host_unit
        .map(|index| {
            units.get(index).map(stored_unit_descriptor).ok_or_else(|| {
                anyhow::anyhow!(
                    "stable stored finding identity {} references out-of-range host unit {}",
                    member.finding,
                    index
                )
            })
        })
        .transpose()?;
    Ok(StoredMemberDescriptor {
        content: member.content,
        finding: member.finding,
        language: member.language,
        host_unit,
        boilerplate: member.boilerplate,
        file_path: member.file_path.clone(),
        start_line: member.start_line,
        end_line: member.end_line,
        token_count: member.token_count,
    })
}

fn stored_group_descriptor(group: &GroupRow, units: &[UnitRow]) -> Result<StoredGroupDescriptor> {
    Ok(StoredGroupDescriptor {
        history: StoredHistoryDescriptor {
            state: group.history.state,
            lineage: group.history.lineage,
            parents: group
                .history
                .parents
                .iter()
                .map(|parent| StoredLineageParentDescriptor {
                    fingerprint: parent.fingerprint,
                    lineage: parent.lineage,
                    primary: parent.primary,
                    shared_content: parent.shared_content,
                    overlap: StoredFloatBits::from(parent.overlap),
                })
                .collect(),
        },
        clone_type: group.clone_type,
        member_scope: group.member_scope,
        test_code: group.test_code,
        test_code_evidence: group.test_code_evidence,
        split_pair: group.split_pair,
        score: StoredFloatBits::from(group.score),
        entropy_bits: StoredFloatBits::from(group.entropy_bits),
        suppress_reason: group.suppress_reason.clone(),
        boilerplate: group.boilerplate,
        identifier_jaccard: group.identifier_jaccard.map(StoredFloatBits::from),
        has_loop: group.has_loop,
        has_dynamic_allocation: group.has_dynamic_allocation,
        call_count: group.call_count,
        width_family: group.width_family,
        ranked_down: group.ranked_down,
        statements: group.statements,
        suppressed_by: group.suppressed_by,
        priority: StoredPriorityDescriptor {
            clone_confidence: StoredFloatBits::from(group.priority.clone_confidence),
            maintenance_risk: StoredFloatBits::from(group.priority.maintenance_risk),
            refactoring_difficulty: StoredFloatBits::from(group.priority.refactoring_difficulty),
            final_priority: StoredFloatBits::from(group.priority.final_priority),
            semantic_confidence: group
                .priority
                .semantic_confidence
                .map(StoredFloatBits::from),
            source_artifact_confidence: group
                .priority
                .source_artifact_confidence
                .map(StoredFloatBits::from),
            savings_confidence: group.priority.savings_confidence.map(StoredFloatBits::from),
        },
        similarity: group
            .similarity
            .as_ref()
            .map(|similarity| StoredSimilarityDescriptor {
                weight_version: similarity.weight_version.clone(),
                lexical: StoredFloatBits::from(similarity.lexical),
                structural: StoredFloatBits::from(similarity.structural),
                control_flow: similarity.control_flow.map(StoredFloatBits::from),
                type_similarity: similarity.type_similarity.map(StoredFloatBits::from),
                api: similarity.api.map(StoredFloatBits::from),
                composite: StoredFloatBits::from(similarity.composite),
                min_pairwise: StoredFloatBits::from(similarity.min_pairwise),
                confidence_band: similarity.confidence_band,
            }),
        semantic: group
            .semantic
            .as_ref()
            .map(|semantic| StoredSemanticDescriptor {
                schema_version: semantic.schema_version.clone(),
                rule_id: semantic.rule_id.clone(),
                rule_version: semantic.rule_version,
                rule_confidence: StoredFloatBits::from(semantic.rule_confidence),
                graphs: semantic
                    .graphs
                    .iter()
                    .map(|graph| StoredSemanticGraphDescriptor {
                        schema_version: graph.schema_version.clone(),
                        graph_json: graph.graph_json.clone(),
                    })
                    .collect(),
                node_mappings: semantic.node_mappings.clone(),
            }),
        members: group
            .members
            .iter()
            .map(|member| stored_member_descriptor(member, units))
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Collapse raw durable group rows using a typed descriptor that includes
/// every persisted field. Equal identifiers with unequal measurements remain
/// an invariant error; no debug rendering or position-based tie-breaker is
/// involved.
fn collapse_stored_group_rows(groups: Vec<GroupRow>, units: &[UnitRow]) -> Result<Vec<GroupRow>> {
    let descriptors = groups
        .iter()
        .map(|group| {
            stored_group_descriptor(group, units).map(|descriptor| (group.fingerprint, descriptor))
        })
        .collect::<Result<Vec<_>>>()?;
    let collapsed = codehelion_core::identity::collapse_exact(&descriptors).map_err(|error| {
        anyhow::anyhow!(
            "stable stored clone-group identity {} has unequal durable payloads",
            error.identity
        )
    })?;
    let retained = collapsed.retained.into_iter().collect::<BTreeSet<_>>();
    Ok(groups
        .into_iter()
        .enumerate()
        .filter_map(|(index, group)| retained.contains(&index).then_some(group))
        .collect())
}

/// Collapse exact duplicate members inside one durable group, rejecting
/// storage-only differences for a reused finding identity.
fn collapse_stored_member_rows(group: &mut GroupRow, units: &[UnitRow]) -> Result<()> {
    let descriptors = group
        .members
        .iter()
        .map(|member| {
            stored_member_descriptor(member, units).map(|descriptor| (member.finding, descriptor))
        })
        .collect::<Result<Vec<_>>>()?;
    let collapsed = codehelion_core::identity::collapse_exact(&descriptors).map_err(|error| {
        anyhow::anyhow!(
            "stable stored finding identity {} has unequal durable payloads",
            error.identity
        )
    })?;
    let retained = collapsed.retained.into_iter().collect::<BTreeSet<_>>();
    group.members = std::mem::take(&mut group.members)
        .into_iter()
        .enumerate()
        .filter_map(|(index, member)| retained.contains(&index).then_some(member))
        .collect();
    Ok(())
}

/// Store one restricted semantic pair with its normalized graphs and rule
/// evidence. It remains a pair for the same non-transitivity reason the
/// report names with `split_pair`.
fn semantic_pair_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
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
    let graph_json = members
        .iter()
        .map(|member| {
            serde_json::to_string(&member.graph).with_context(|| {
                format!(
                    "serializing normalized SOG for {}",
                    inputs.files[inputs.analysis.units[member.unit].file].relative_path
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let node_mappings = (0..pair.canonical.graph.nodes.len())
        .filter_map(|index| {
            let index = u32::try_from(index).ok()?;
            Some(SemanticNodeMappingRow {
                corresponding_member: 1,
                canonical: index,
                corresponding: index,
            })
        })
        .collect();
    let canonical_unit = &inputs.analysis.units[pair.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: CloneClass::RestrictedSemantic,
        scope: semantic_scope(members.iter().copied(), inputs.analysis),
        statements: None,
        score: pair.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(canonical_tokens, inputs.literals),
        suppressed_by: inputs.semantic_pair_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        members: members
            .iter()
            .enumerate()
            .map(|(position, member)| {
                let unit = &inputs.analysis.units[member.unit];
                let file = &inputs.files[unit.file];
                MemberRow {
                    content: member.content,
                    finding: stable_id::finding_id(
                        &fingerprint,
                        stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                        member_ranks[position],
                    ),
                    language: file.language,
                    host_unit: Some(host_index[&member.unit]),
                    boilerplate: unit.boilerplate,
                    file_path: file.relative_path.clone(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                    token_count: member.token_count,
                }
            })
            .collect(),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.split_pair = true;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical_tokens.len());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: pair.canonical.graph.schema_version.clone(),
        rule_id: pair.rule.id.to_string(),
        rule_version: pair.rule.version,
        rule_confidence: pair.rule.confidence,
        graphs: graph_json
            .into_iter()
            .map(|graph_json| SemanticOperationGraphRow {
                schema_version: pair.canonical.graph.schema_version.clone(),
                graph_json,
            })
            .collect(),
        node_mappings,
    });
    Ok(row)
}

/// Store one cohesive restricted-semantic group with member-qualified SOG
/// node correspondences.
fn semantic_group_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
) -> Result<GroupRow> {
    let group = &inputs.semantic_groups[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        group.rule.id,
        group.rule.version,
        &semantic_group_member_fingerprints(group.members.iter(), inputs.analysis),
    );
    let test_code_evidence = aggregate_test_code_evidence(
        inputs.analysis,
        group.members.iter().map(|member| member.unit),
    );
    let graph_json = group
        .members
        .iter()
        .map(|member| {
            serde_json::to_string(&member.graph).with_context(|| {
                format!(
                    "serializing normalized SOG for {}",
                    inputs.files[inputs.analysis.units[member.unit].file].relative_path
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let node_mappings = semantic_store_node_mappings(&group.canonical, &group.members);
    let member_ranks = semantic_member_ranks(group.members.iter());
    let canonical_unit = &inputs.analysis.units[group.canonical.unit];
    let canonical_tokens = inputs.unit_tokens(canonical_unit);
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: CloneClass::RestrictedSemantic,
        scope: semantic_scope(group.members.iter(), inputs.analysis),
        statements: None,
        score: group.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(canonical_tokens, inputs.literals),
        suppressed_by: inputs.semantic_group_suppressed[index],
        ranked_down: recorded_ranked_down(ranking, &fingerprint.to_hex())?,
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        members: group
            .members
            .iter()
            .enumerate()
            .map(|(position, member)| {
                let unit = &inputs.analysis.units[member.unit];
                let file = &inputs.files[unit.file];
                MemberRow {
                    content: member.content,
                    finding: stable_id::finding_id(
                        &fingerprint,
                        stable_id::OccurrenceScope::Unit(&unit.fingerprint),
                        member_ranks[position],
                    ),
                    language: file.language,
                    host_unit: Some(host_index[&member.unit]),
                    boilerplate: unit.boilerplate,
                    file_path: file.relative_path.clone(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                    token_count: member.token_count,
                }
            })
            .collect(),
    });
    row.test_code = test_code_evidence.is_some();
    row.test_code_evidence = test_code_evidence;
    row.suppress_reason = inputs.entropy_suppress_reason(row.entropy_bits, canonical_tokens.len());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: group.canonical.graph.schema_version.clone(),
        rule_id: group.rule.id.to_string(),
        rule_version: group.rule.version,
        rule_confidence: group.rule.confidence,
        graphs: graph_json
            .into_iter()
            .map(|graph_json| SemanticOperationGraphRow {
                schema_version: group.canonical.graph.schema_version.clone(),
                graph_json,
            })
            .collect(),
        node_mappings,
    });
    Ok(row)
}

/// Store canonical node correspondences once for each non-canonical member.
fn semantic_store_node_mappings(
    canonical: &SemanticUnitGraph,
    members: &[SemanticUnitGraph],
) -> Vec<SemanticNodeMappingRow> {
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
                    Some(SemanticNodeMappingRow {
                        corresponding_member: u32::try_from(member).ok()?,
                        canonical: node,
                        corresponding: node,
                    })
                })
        })
        .collect()
}

/// One duplicated-unit group as a store row, with its occurrences.
///
/// The rank is what tells two occurrences of one group apart when their
/// enclosing units share a fingerprint, which is every verbatim copy: without
/// it the whole group would be recorded under the canonical instance's
/// identifier and `explain` could answer about none of the others.
fn unit_group_row(
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
        members: group
            .members
            .iter()
            .zip(ranks_within_host(member_hosts(
                &inputs.analysis.units,
                &group.members,
            )))
            .map(|(&member, rank)| {
                let unit = &inputs.analysis.units[member];
                let file = &inputs.files[unit.file];
                MemberRow {
                    content: unit.content,
                    finding: stable_id::finding_id(
                        &detail.fingerprint,
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
            .collect(),
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
fn recorded_ranking(
    ranking: &BTreeMap<&str, (&report::Priority, bool)>,
    fingerprint: &str,
) -> Result<PriorityRow> {
    ranking.get(fingerprint).map_or_else(
        || bail!("group {fingerprint} was recorded without being ranked"),
        |(priority, _)| Ok(crate::scan::priority_row(priority)),
    )
}

fn recorded_ranked_down(
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
fn split_pair_row(
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
        members: pair_members(pair)
            .iter()
            .zip(ranks_within_host(member_hosts(
                &inputs.analysis.units,
                &pair_members(pair),
            )))
            .map(|(&member, rank)| {
                let unit = &inputs.analysis.units[member];
                let file = &inputs.files[unit.file];
                MemberRow {
                    content: unit.content,
                    finding: stable_id::finding_id(
                        &pair.fingerprint,
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
            .collect(),
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

fn region_row(
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
    use codehelion_core::clone_class::{CloneClass, CloneScope};
    use codehelion_core::discovery::Language;
    use codehelion_core::frontend::UnitKind;
    use codehelion_core::stable_id::{
        CloneGroupFingerprint, FindingId, FragmentFingerprint, UnitFingerprint,
    };

    use super::{
        MemberRow, PriorityRow, UnitRow, collapse_stored_group_rows, collapse_stored_member_rows,
        shared, stored_unit_descriptor,
    };

    fn group(score: f64) -> codehelion_store::snapshot::GroupRow {
        group_with_members(score, Vec::new())
    }

    fn group_with_members(
        score: f64,
        members: Vec<MemberRow>,
    ) -> codehelion_store::snapshot::GroupRow {
        shared::stored_group(shared::StoredGroupCore {
            fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            clone_type: CloneClass::Type1,
            scope: CloneScope::Unit,
            statements: None,
            score,
            entropy_bits: 1.0,
            suppressed_by: None,
            ranked_down: false,
            priority: PriorityRow {
                clone_confidence: 1.0,
                maintenance_risk: 0.0,
                refactoring_difficulty: 0.0,
                final_priority: 1.0,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            members,
        })
    }

    fn units_with_same_semantics() -> Vec<UnitRow> {
        vec![unit("src/unit.rs"), unit("src/unit.rs")]
    }

    fn units_with_different_semantics() -> Vec<UnitRow> {
        vec![unit("src/first.rs"), unit("src/second.rs")]
    }

    fn unit(file_path: &str) -> UnitRow {
        UnitRow {
            fingerprint: UnitFingerprint::from_bytes([4; 16]),
            language: Language::Rust,
            kind: UnitKind::Function,
            name: Some("unit".to_string()),
            file_path: file_path.to_string(),
            start_line: 1,
            end_line: 10,
            token_count: 20,
        }
    }

    fn member(file_path: &str) -> MemberRow {
        member_at(file_path, Some(0))
    }

    fn member_at(file_path: &str, host_unit: Option<usize>) -> MemberRow {
        MemberRow {
            content: FragmentFingerprint::from_bytes([8; 16]),
            finding: FindingId::from_bytes([9; 16]),
            language: Language::Rust,
            host_unit,
            boilerplate: None,
            file_path: file_path.to_string(),
            start_line: 4,
            end_line: 8,
            token_count: 12,
        }
    }

    #[test]
    fn exact_duplicate_stored_groups_collapse_once() {
        let rows = collapse_stored_group_rows(vec![group(1.0), group(1.0)], &[])
            .expect("exact duplicate durable rows should collapse");
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn unequal_durable_payload_for_one_group_identity_is_an_error() {
        let error = collapse_stored_group_rows(vec![group(1.0), group(2.0)], &[])
            .expect_err("storage-only payload differences must not be hidden");
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn exact_duplicate_stored_members_with_same_host_semantics_collapse_once() {
        let units = units_with_same_semantics();
        let mut row = group_with_members(
            1.0,
            vec![
                member_at("src/a.rs", Some(0)),
                member_at("src/a.rs", Some(1)),
            ],
        );
        collapse_stored_member_rows(&mut row, &units)
            .expect("exact duplicate members should collapse");
        assert_eq!(row.members.len(), 1);
    }

    #[test]
    fn unequal_durable_payload_for_one_finding_identity_is_an_error() {
        let mut row = group_with_members(1.0, vec![member("src/a.rs"), member("src/b.rs")]);
        let error = collapse_stored_member_rows(&mut row, &units_with_same_semantics())
            .expect_err("storage-only member differences must not be hidden");
        assert!(error.to_string().contains("stable stored finding identity"));
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn stored_unit_descriptor_keeps_durable_semantics() {
        let units = units_with_different_semantics();
        assert_ne!(
            stored_unit_descriptor(&units[0]),
            stored_unit_descriptor(&units[1]),
            "distinct resolved units must not compare equal through an ordinal"
        );
    }

    #[test]
    fn unequal_resolved_host_semantics_for_one_finding_is_an_error() {
        let units = units_with_different_semantics();
        let mut row = group_with_members(
            1.0,
            vec![
                member_at("src/a.rs", Some(0)),
                member_at("src/a.rs", Some(1)),
            ],
        );
        let error = collapse_stored_member_rows(&mut row, &units)
            .expect_err("different resolved host units must not be hidden");
        assert!(error.to_string().contains("stable stored finding identity"));
        assert!(error.to_string().contains("unequal durable payloads"));
    }

    #[test]
    fn out_of_range_host_unit_is_an_explicit_finding_identity_error() {
        let mut row = group_with_members(1.0, vec![member_at("src/a.rs", Some(9))]);
        let error = collapse_stored_member_rows(&mut row, &units_with_same_semantics())
            .expect_err("an invalid host-unit ordinal must not be silently accepted");
        let message = error.to_string();
        assert!(message.contains(&FindingId::from_bytes([9; 16]).to_string()));
        assert!(message.contains("out-of-range host unit 9"));
    }
}
