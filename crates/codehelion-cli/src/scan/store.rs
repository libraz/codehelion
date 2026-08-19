//! Fast-scan snapshot row construction and persistence.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares store helpers across scan modes"
)]

use super::{
    BTreeMap, BuildInputs, BuildVariant, Config, ContentHash, ContentNorm, Context, EngineReport,
    FP_SCHEMA_VERSION, FileContext, FileRow, GroupIds, GroupRow, LexedSource, LiteralNorm,
    MemberRow, NORMALIZATION_VERSION, Path, Result, Snapshot, SourceUnit, Store, SummaryRow,
    UnitRow, build_group, engine, fast_group_scope, literal_norm, path_key, priority_row, report,
    shared, stable_id,
};

/// The tree a scan read, as rows to record beside its findings.
///
/// Every discovered file is here, including the ones that yielded no unit: a
/// later scan compares trees, and a file missing from the record is one it
/// would call newly added.
pub(crate) fn file_rows(units: &[SourceUnit]) -> Vec<FileRow> {
    units
        .iter()
        .map(|unit| FileRow {
            relative_path: path_key(&unit.relative_path),
            content_hash: unit.content_hash.as_str().to_string(),
            language: unit.language,
            byte_len: unit.byte_len,
        })
        .collect()
}

/// Hash the effective detector configuration and the reuse profile.
///
/// The profile is part of reuse compatibility even though it is not a
/// detector setting serialized by `Config`: an untrusted scan is subject to a
/// different execution contract from a trusted one. Keeping this recipe in
/// one place prevents the Fast, Structural, and Semantic paths from selecting
/// different predecessors for the same invocation.
pub(crate) fn reuse_config_hash(
    cfg: &Config,
    untrusted: bool,
    siblings_by_signature: bool,
) -> Result<ContentHash> {
    let config_text = format!(
        "{}\nreuse-profile-v2:untrusted={};siblings-by-signature={}",
        cfg.to_toml()?,
        untrusted,
        siblings_by_signature,
    );
    Ok(ContentHash::of(config_text.as_bytes()))
}

/// Rank every Fast entry without touching the audit database.
pub(super) fn rank_groups(
    inputs: &BuildInputs<'_>,
    summary: &mut SummaryRow,
) -> Result<Vec<report::Group>> {
    let raw_ranked: Vec<report::Group> = (0..inputs.report.groups.len())
        .map(|index| build_group(inputs, index))
        .collect();
    let normalized = report::normalize_identities(raw_ranked)?;
    report::append_stored_identity_stage(
        &mut summary.funnel,
        normalized.groups.len(),
        normalized.identity_collapsed,
    );
    // The report model carries the retained groups; persistence reconstructs
    // source positions by their stable group fingerprints after presentation
    // ordering, so no second copy of non-Clone report values is required.
    Ok(normalized.groups)
}

/// Persist already-ranked Fast findings and fill in what recording decided:
/// the run id and what became of duplication since the previous run.
pub(super) fn record_ranked(
    inputs: &mut BuildInputs<'_>,
    cfg: &Config,
    contexts: &[FileContext<'_>],
    files: Vec<FileRow>,
    summary: &SummaryRow,
    ranked: &[report::Group],
) -> Result<()> {
    let variant = &inputs.discovered.build_variant;
    let source_indices: Vec<usize> = ranked
        .iter()
        .map(|group| {
            inputs
                .ids
                .iter()
                .position(|ids| ids.fingerprint.to_hex() == group.fingerprint)
                .with_context(|| {
                    format!(
                        "ranked Fast group {} is missing from the engine identity report",
                        group.fingerprint
                    )
                })
        })
        .collect::<Result<_>>()?;
    let (units, groups) = snapshot_rows(
        inputs.lexed,
        contexts,
        variant,
        inputs.report,
        inputs.ids,
        inputs.group_suppressed,
        ranked,
        &source_indices,
        &cfg.suppression,
    );
    let mut store = open_store(inputs.db_path)?;
    let config_hash = reuse_config_hash(cfg, inputs.untrusted, false)?;
    let mut detector_versions = detector_versions(
        literal_norm(cfg.literal_normalization),
        cfg.entropy_ratio_floor,
    );
    // Ranking is persisted beside the run so `report --run` can render the
    // historical ordering. It is intentionally excluded from the public
    // detector contract and baseline compatibility: changing presentation
    // cannot invalidate a judgement about detected duplication.
    detector_versions.push(("ranking".to_string(), cfg.priority.weights().recipe()));
    let root_path = path_key(inputs.root);
    let current_tree = file_tree(&files);
    let predecessor =
        store.latest_compatible_run(&root_path, config_hash.as_str(), &variant.fingerprint())?;
    if let Some(previous) = predecessor.as_ref() {
        let previous_tree = store.run_tree(previous.id)?;
        inputs.changes = Some(tree_changes(previous.id, &previous_tree, &current_tree));
        if inputs.reuse_allowed
            && store
                .run_summary_row(previous.id)?
                .is_some_and(|stored| stored.baseline_digest == summary.baseline_digest)
            && previous_tree == current_tree
        {
            store.activate_suppressions(&inputs.rules.rows)?;
            inputs.run_id = Some(previous.id);
            inputs.reused = true;
            return Ok(());
        }
    }
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
        config_source: &inputs.configuration.source,
        config_path: inputs.configuration.path.as_deref(),
        started_at: inputs.started_at,
        finished_at: inputs.finished_at,
        variant,
        min_clone_tokens: cfg.min_clone_tokens,
        detector_versions: &detector_versions,
        suppressions: inputs.rules.rows.clone(),
        units,
        groups,
        sibling_groups: Vec::new(),
        near_misses: Vec::new(),
        files,
        // No compiler was asked anything: this mode reads source and nothing
        // else, and an empty list is the whole truth about it.
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: summary.clone(),
    };
    let run_id = store
        .record_snapshot_with_predecessor(&snapshot, predecessor.as_ref().map(|run| run.id))?;
    inputs.run_id = Some(run_id);
    Ok(())
}

fn file_tree(files: &[FileRow]) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|file| (file.relative_path.clone(), file.content_hash.clone()))
        .collect()
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

/// Open the current store, creating its parent directory when needed.
pub(crate) fn open_store(path: &Path) -> Result<Store> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    Store::open(path).with_context(|| database_open_context(path))
}

/// Open a recorded database for reading, refusing an unsupported schema with
/// the same way out a recording command offers.
///
/// # Errors
///
/// Returns whatever opening the database returns.
pub(crate) fn open_recorded_store(path: &Path) -> Result<Store> {
    Store::open_existing(path).with_context(|| database_open_context(path))
}

/// What to say about `path` when opening it fails.
///
/// The way out is spelled out only when there is one to spell: this build has
/// a naming rule for a database it cannot open, and a reader who does not know
/// the rule cannot follow it.
fn database_open_context(path: &Path) -> String {
    super::runtime::incompatible_database_advice(path).map_or_else(
        || {
            format!(
                "opening audit database {}; incompatible databases are not migrated or deleted; use a fresh path for a new scan",
                path.display()
            )
        },
        |advice| {
            format!(
                "opening audit database {}; it was left unchanged — {advice}",
                path.display()
            )
        },
    )
}

/// The `(component, version)` pairs recorded with every snapshot.
///
/// Detection rules that can change the group identities or their visibility.
/// Ranking is presentation metadata and deliberately lives outside this list:
/// a different ordering must not invalidate a baseline's judgement.
pub(super) fn detector_versions(
    literals: LiteralNorm,
    entropy_ratio_floor: f64,
) -> Vec<(String, String)> {
    vec![
        (
            "fast-engine".to_string(),
            engine::ENGINE_VERSION.to_string(),
        ),
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        (
            "literals".to_string(),
            ContentNorm::Normalized(literals).label().to_string(),
        ),
        (
            "noise-filter".to_string(),
            format!("entropy-ratio-v1:{entropy_ratio_floor:.6}"),
        ),
        (
            "normalization".to_string(),
            NORMALIZATION_VERSION.to_string(),
        ),
        (
            "frontend.rust".to_string(),
            codehelion_frontend_rust::FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.c".to_string(),
            codehelion_frontend_c::FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.cpp".to_string(),
            codehelion_frontend_cpp::FRONTEND_VERSION.to_string(),
        ),
    ]
}

/// Turn the engine report and its stable identifiers into store rows.
///
/// Only units that host at least one occurrence are written; each is written
/// once even when several members share it. The unit fingerprint is computed
/// exactly as the finding ids' host fingerprint was, so the stored unit row
/// and the finding identity always agree.
///
/// `ranked` is the report's own entries in the engine's order, which is where
/// the recorded ranking comes from: the audit database and the report are two
/// views of one verdict, not two verdicts that happen to agree.
#[allow(
    clippy::too_many_arguments,
    reason = "parallel detector, identity, suppression, and presentation rows are joined here"
)]
fn snapshot_rows(
    lexed: &[LexedSource],
    contexts: &[FileContext<'_>],
    variant: &BuildVariant,
    report: &EngineReport,
    ids: &[GroupIds],
    group_suppressed: &[Option<usize>],
    ranked: &[report::Group],
    retained_indices: &[usize],
    suppression: &crate::config::Suppression,
) -> (Vec<UnitRow>, Vec<GroupRow>) {
    let mut host_index: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for group in &report.groups {
        for member in &group.members {
            if let Some(unit) = member.unit {
                host_index.entry((member.file, unit)).or_insert(0);
            }
        }
    }
    let mut units = Vec::with_capacity(host_index.len());
    for (index, ((file, unit_idx), slot)) in host_index.iter_mut().enumerate() {
        *slot = index;
        let source = &lexed[*file];
        let unit = &source.units[*unit_idx];
        let end = unit.token_end.min(source.tokens.len());
        let tokens = &source.tokens[unit.token_start..end];
        let (_, end_line) = source.unit_lines[*unit_idx];
        units.push(UnitRow {
            fingerprint: stable_id::unit_fingerprint(
                variant,
                &contexts[*file],
                tokens,
                ContentNorm::Raw,
            ),
            language: source.language,
            kind: unit.kind,
            name: unit.name.clone(),
            file_path: source.relative_path.clone(),
            start_line: unit.span.start_line,
            end_line,
            token_count: tokens.len(),
        });
    }

    let groups = ranked
        .iter()
        .zip(retained_indices)
        .map(|(ranked_group, &source_index)| {
            let group = &report.groups[source_index];
            let group_ids = &ids[source_index];
            let suppressed_by = group_suppressed[source_index];
            let retained_findings = ranked_group
                .members
                .iter()
                .map(|member| member.finding_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let mut emitted_findings = std::collections::BTreeSet::new();
            let mut row = shared::stored_group(shared::StoredGroupCore {
                fingerprint: group_ids.fingerprint,
                clone_type: group.clone_type,
                scope: fast_group_scope(group, lexed),
                statements: None,
                score: group.score,
                entropy_bits: group.entropy_bits,
                suppressed_by,
                ranked_down: report::ranks_down(ranked_group, suppression),
                priority: priority_row(&ranked_group.priority),
                members: group
                    .members
                    .iter()
                    .zip(&group_ids.members)
                    .filter_map(|(instance, member_ids)| {
                        let finding = member_ids.finding.to_hex();
                        (retained_findings.contains(finding.as_str())
                            && emitted_findings.insert(finding))
                        .then_some(MemberRow {
                            content: member_ids.content,
                            finding: member_ids.finding,
                            language: lexed[instance.file].language,
                            host_unit: instance.unit.map(|unit| host_index[&(instance.file, unit)]),
                            boilerplate: None,
                            file_path: lexed[instance.file].relative_path.clone(),
                            start_line: instance.start_line,
                            end_line: instance.end_line,
                            token_count: instance.token_end - instance.token_start,
                        })
                    })
                    .collect(),
            });
            row.suppress_reason = group.suppressed.map(|reason| reason.name().to_string());
            row
        })
        .collect();
    (units, groups)
}
