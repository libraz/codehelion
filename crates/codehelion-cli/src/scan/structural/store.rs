//! Persistence of structural and semantic scan snapshots.

use super::reporting::{
    detector_versions, member_hosts, occurrence_hosts, pair_members, ranks_within_host,
    split_pair_identifier_jaccard, weakest_breakdown,
};
use super::{
    BTreeMap, CloneScope, CompilerHelperRow, CompilerOutcome, Config, ContentHash, Context,
    FeatureRow, FileRow, GroupDetail, GroupRow, MemberRow, NearMissRow, PriorityRow,
    REGION_SIMILARITY, ReportInputs, Result, SemanticEvidenceRow, SemanticNodeMappingRow,
    SemanticOperationGraphRow, SemanticUnitGraph, SiblingGroupRow, SiblingRow,
    SimilarityBreakdownRow, Snapshot, StructuralGroup, SummaryRow, UnitRow, WEIGHT_VERSION,
    aggregate_test_code_evidence, bail, engine, features, literal_norm, local_unit_indices,
    open_store, region_identifier_jaccard, region_test_code_evidence, report, semantic,
    semantic_member_ranks, semantic_scope, shared, stable_id, store_compiler,
};

type SnapshotRows = (
    Vec<UnitRow>,
    Vec<GroupRow>,
    Vec<FeatureRow>,
    BTreeMap<usize, usize>,
);

pub(super) fn record(
    cfg: &Config,
    inputs: &ReportInputs<'_>,
    ranked: &[report::Group],
    files: Vec<FileRow>,
    summary: &SummaryRow,
    asked: Option<&semantic::Answers>,
    completed: bool,
) -> Result<i64> {
    let (units, groups, features, host_index) = snapshot_rows(inputs, ranked)?;
    let mut store = open_store(inputs.db_path)?;
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let mut detector_versions = detector_versions(literal_norm(cfg.literal_normalization));
    // Kept for historical report rendering only; baseline compatibility and
    // the public detector list deliberately exclude presentation weights.
    detector_versions.push(("ranking".to_string(), cfg.priority.weights().recipe()));
    let root_path = inputs.root.to_string_lossy();
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
        features,
        compiler_helpers,
        compiler_units,
        summary: summary.clone(),
    };
    if completed {
        store.record_snapshot(&snapshot).map_err(Into::into)
    } else {
        store.record_snapshot_part(&snapshot).map_err(Into::into)
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
        .map(|near_miss| {
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
        .map(|siblings| {
            let detail = inputs
                .analysis
                .details
                .get(siblings.group)
                .with_context(|| format!("missing detail for sibling group {}", siblings.group))?;
            let siblings = siblings
                .siblings
                .iter()
                .map(|sibling| {
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
                            Some(&unit.fingerprint),
                            0,
                        ),
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
            } => store_compiler::CompilerUnitRow {
                helper: *helper,
                outcome: CompilerOutcome::Unavailable {
                    unit: unit.clone(),
                    reason: *reason,
                },
            },
            semantic::Answer::NotAsked { unit, reason } => store_compiler::CompilerUnitRow {
                helper: None,
                outcome: CompilerOutcome::Unavailable {
                    unit: unit.clone(),
                    reason: *reason,
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
fn snapshot_rows(inputs: &ReportInputs<'_>, ranked: &[report::Group]) -> Result<SnapshotRows> {
    // The ranking is looked up by fingerprint rather than by position: the
    // report interleaves duplicated units, duplicated runs and the pairs no
    // group could hold into one order, and the store keeps them apart.
    let ranking: BTreeMap<&str, &report::Priority> = ranked
        .iter()
        .map(|group| (group.fingerprint.as_str(), &group.priority))
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
    let groups = (0..inputs.analysis.groups.groups.len())
        .map(|index| unit_group_row(inputs, index, &host_index, &ranking))
        .chain(regions.into_iter().map(Ok))
        .chain(split_pairs.into_iter().map(Ok))
        .chain(semantic_groups.into_iter().map(Ok))
        .chain(semantic_pairs.into_iter().map(Ok))
        .collect::<Result<Vec<_>>>()?;
    let feature_files = inputs.irs.iter().map(features::extract).collect::<Vec<_>>();
    let local_units = local_unit_indices(inputs.analysis);
    let features = host_index
        .iter()
        .map(|(&unit_index, &host_unit)| {
            let unit = &inputs.analysis.units[unit_index];
            let local_index = local_units[unit_index];
            let file_features = feature_files.get(unit.file).with_context(|| {
                format!("missing candidate features for source file {}", unit.file)
            })?;
            let unit_features = file_features.units.get(local_index).with_context(|| {
                format!(
                    "candidate features and structural units diverged for source file {} at unit {local_index}",
                    unit.file
                )
            })?;
            Ok(FeatureRow::from_unit(host_unit, unit_features))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((units, groups, features, host_index))
}

/// Store one restricted semantic pair with its normalized graphs and rule
/// evidence. It remains a pair for the same non-transitivity reason the
/// report names with `split_pair`.
fn semantic_pair_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, &report::Priority>,
) -> Result<GroupRow> {
    let pair = &inputs.semantic_pairs[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        pair.rule.id,
        pair.rule.version,
        &[pair.canonical.content, pair.corresponding.content],
    );
    let members = [&pair.canonical, &pair.corresponding];
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
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        scope: semantic_scope(members.iter().copied(), inputs.analysis),
        statements: None,
        score: pair.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(
            inputs.unit_tokens(canonical_unit),
            inputs.literals,
        ),
        suppressed_by: inputs.semantic_pair_suppressed[index],
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
                        Some(&unit.fingerprint),
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
    row.suppress_reason =
        inputs.semantic_pair_suppressed[index].map(|rule| inputs.rules.rows[rule].pattern.clone());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: pair.canonical.graph.schema_version.clone(),
        rule_id: pair.rule.id.to_string(),
        rule_version: pair.rule.version,
        rule_confidence: pair.semantic_confidence,
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
    ranking: &BTreeMap<&str, &report::Priority>,
) -> Result<GroupRow> {
    let group = &inputs.semantic_groups[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        group.rule.id,
        group.rule.version,
        &group
            .members
            .iter()
            .map(|member| member.content)
            .collect::<Vec<_>>(),
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
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint,
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        scope: semantic_scope(group.members.iter(), inputs.analysis),
        statements: None,
        score: group.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(
            inputs.unit_tokens(canonical_unit),
            inputs.literals,
        ),
        suppressed_by: inputs.semantic_group_suppressed[index],
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
                        Some(&unit.fingerprint),
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
    row.suppress_reason =
        inputs.semantic_group_suppressed[index].map(|rule| inputs.rules.rows[rule].pattern.clone());
    row.semantic = Some(SemanticEvidenceRow {
        schema_version: group.canonical.graph.schema_version.clone(),
        rule_id: group.rule.id.to_string(),
        rule_version: group.rule.version,
        rule_confidence: group.semantic_confidence,
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
    ranking: &BTreeMap<&str, &report::Priority>,
) -> Result<GroupRow> {
    let group = &inputs.analysis.groups.groups[index];
    let detail = &inputs.analysis.details[index];
    let medoid = &inputs.analysis.units[group.canonical];
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint: detail.fingerprint,
        clone_type: group.clone_type,
        scope: CloneScope::Unit,
        statements: None,
        score: group.min_pairwise,
        entropy_bits: engine::content_entropy_bits(inputs.unit_tokens(medoid), inputs.literals),
        suppressed_by: inputs.group_suppressed[index],
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
                        Some(&unit.fingerprint),
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
    row.identifier_jaccard = Some(detail.identifier_jaccard);
    row.has_loop = Some(detail.body_materiality.has_loop);
    row.has_dynamic_allocation = Some(detail.body_materiality.has_dynamic_allocation);
    row.call_count = Some(detail.body_materiality.call_count);
    Ok(row)
}

/// The ranking the report gave one entry, by its fingerprint.
///
/// An entry the report never ranked is a disagreement between what a run shows
/// and what it records, which is exactly the thing this arrangement exists to
/// prevent — so it fails the scan rather than storing a placeholder that would
/// read as a finding nobody thought was worth anything.
fn recorded_ranking(
    ranking: &BTreeMap<&str, &report::Priority>,
    fingerprint: &str,
) -> Result<PriorityRow> {
    ranking.get(fingerprint).map_or_else(
        || bail!("group {fingerprint} was recorded without being ranked"),
        |priority| Ok(crate::scan::priority_row(priority)),
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
    ranking: &BTreeMap<&str, &report::Priority>,
) -> Result<GroupRow> {
    let pair = &inputs.analysis.unrepresented[index];
    let canonical = &inputs.analysis.units[pair.canonical];
    let test_code_evidence =
        aggregate_test_code_evidence(inputs.analysis, pair.members.iter().copied());
    let mut row = shared::stored_group(shared::StoredGroupCore {
        fingerprint: pair.fingerprint,
        clone_type: pair.class,
        scope: CloneScope::Unit,
        statements: None,
        score: pair.similarity,
        entropy_bits: engine::content_entropy_bits(inputs.unit_tokens(canonical), inputs.literals),
        suppressed_by: inputs.pair_suppressed[index],
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
                        Some(&unit.fingerprint),
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
    row.identifier_jaccard = Some(split_pair_identifier_jaccard(inputs, pair));
    row.width_family = pair.width_family;
    Ok(row)
}

fn region_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, &report::Priority>,
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
                        Some(&unit.fingerprint),
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
    row.identifier_jaccard = Some(region_identifier_jaccard(inputs, region));
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
