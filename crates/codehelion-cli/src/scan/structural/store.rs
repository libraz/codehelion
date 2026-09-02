//! Persistence of structural and semantic scan snapshots.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use codehelion_core::discovery::ContentHash;
use codehelion_store::snapshot::{
    FileRow, GroupRow, Snapshot, StagedSnapshotPart, SummaryRow, UnitRow,
};

use crate::config::Config;
use crate::report;
use crate::scan::shared;
use crate::scan::store::ReuseProfile;
use crate::scan::structural::ReportInputs;
use crate::scan::structural::reporting::detector_versions;
use crate::scan::{literal_norm, open_store, path_key, reuse_config_hash};
use crate::semantic::Answers;

mod collapse;
mod rows;
mod semantic;

use collapse::{collapse_stored_group_rows, collapse_stored_member_rows};
use rows::{
    compiler_rows, near_miss_rows, region_row, sibling_rows, split_pair_row, unit_group_row,
};
use semantic::{semantic_group_row, semantic_pair_row};

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
    asked: Option<&Answers>,
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
    let current_tree = shared::file_tree(&files);
    let compatible = store.latest_compatible_run(
        &root_path,
        config_hash.as_str(),
        &inputs.variant.fingerprint(),
    )?;
    let compatible = compatible.map(|run| run.id);
    let changes = compatible
        .map(|previous_id| {
            store.run_tree(previous_id).map(|previous_tree| {
                shared::tree_changes(previous_id, &previous_tree, &current_tree)
            })
        })
        .transpose()?;
    if completed
        && inputs.reuse_allowed
        && let Some(previous_id) = compatible
        && store
            .run_summary_row(previous_id)?
            .is_some_and(|stored| stored.baseline_digest == summary.baseline_digest)
        && changes.as_ref().is_some_and(shared::tree_unchanged)
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
