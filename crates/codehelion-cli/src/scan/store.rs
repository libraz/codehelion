//! Fast-scan snapshot row construction and persistence.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares store helpers across scan modes"
)]

use super::{
    BTreeMap, BuildInputs, BuildVariant, Config, ContentHash, ContentNorm, Context, EngineReport,
    FP_SCHEMA_VERSION, FileContext, FileRow, GroupIds, GroupRow, LexedSource, LiteralNorm,
    MemberRow, NORMALIZATION_VERSION, Path, Result, Snapshot, SourceUnit, Store, SummaryRow,
    UnitRow, build_group, engine, fast_group_scope, literal_norm, priority_row, report, shared,
    stable_id,
};
use std::ffi::OsString;

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

/// Render a filesystem path as a unique database key.
///
/// Ordinary UTF-8 paths stay unchanged. A non-UTF-8 path is represented by
/// its native encoded bytes, rather than by `to_string_lossy`, so two distinct
/// names can never collapse into one `SQLite` primary key. The reserved prefix
/// is also escaped when it occurs in an otherwise UTF-8 path.
#[must_use]
pub(crate) fn path_key(path: &Path) -> String {
    const ESCAPED_PATH_PREFIX: &str = "\u{001f}codehelion-path-bytes:";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = path.as_os_str().as_encoded_bytes();
    if let Ok(text) = std::str::from_utf8(bytes)
        && !text.starts_with(ESCAPED_PATH_PREFIX)
    {
        #[cfg(windows)]
        {
            return text.replace('\\', "/");
        }
        #[cfg(not(windows))]
        {
            return text.to_string();
        }
    }
    let mut encoded = ESCAPED_PATH_PREFIX.to_string();
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Turn a stored path key into a safe human-facing path label.
///
/// The reversible storage encoding is deliberately not a public path format:
/// leaking it would expose an internal sentinel and, in SARIF, turn its colon
/// into a malformed path component. Valid UTF-8 escaped solely because it
/// begins with the sentinel is restored verbatim. Invalid native bytes remain
/// distinguishable without pretending they are a filesystem path.
#[must_use]
pub(crate) fn display_path(key: &str) -> String {
    const ESCAPED_PATH_PREFIX: &str = "\u{001f}codehelion-path-bytes:";
    let Some(hex) = key.strip_prefix(ESCAPED_PATH_PREFIX) else {
        return key.to_string();
    };
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let Some(high) = char::from(pair[0]).to_digit(16) else {
            return "<invalid stored path key>".to_string();
        };
        let Some(low) = char::from(pair[1]).to_digit(16) else {
            return "<invalid stored path key>".to_string();
        };
        bytes.push(u8::try_from((high << 4) | low).unwrap_or(u8::MAX));
    }
    if hex.len() % 2 != 0 {
        return "<invalid stored path key>".to_string();
    }
    String::from_utf8(bytes).unwrap_or_else(|_| format!("<non-UTF-8 path: {hex}>"))
}

/// Rank every entry, persist the snapshot, and fill in what the recording
/// decided: the run id and what became of the duplication since last time.
///
/// The order matters and is the point of the arrangement. The ranking reads
/// the assembled report entries, and the audit database stores what those
/// entries say, so a run's two accounts of where a finding belongs are one
/// account written twice rather than two derivations that happen to agree.
pub(super) fn rank_and_record(
    inputs: &mut BuildInputs<'_>,
    cfg: &Config,
    contexts: &[FileContext<'_>],
    files: Vec<FileRow>,
    summary: &SummaryRow,
) -> Result<Vec<report::Group>> {
    let ranked: Vec<report::Group> = (0..inputs.report.groups.len())
        .map(|index| build_group(inputs, index))
        .collect();
    let variant = &inputs.discovered.build_variant;
    let (units, groups) = snapshot_rows(
        inputs.lexed,
        contexts,
        variant,
        inputs.report,
        inputs.ids,
        inputs.group_suppressed,
        &ranked,
        &cfg.suppression,
    );
    let mut store = open_store(inputs.db_path)?;
    let config_text = format!(
        "{}\nreuse-profile-v1:untrusted={}",
        cfg.to_toml()?,
        inputs.untrusted
    );
    let config_hash = ContentHash::of(config_text.as_bytes());
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
            inputs.run_id = previous.id;
            inputs.reused = true;
            return Ok(ranked);
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
    inputs.run_id = store.record_snapshot(&snapshot)?;
    if let Some(previous) = predecessor {
        store.adopt_matching_lineages(inputs.run_id, previous.id)?;
    }
    Ok(ranked)
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

/// Open the v1 store, creating its parent directory when needed.
pub(crate) fn open_store(path: &Path) -> Result<Store> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    match Store::open(path) {
        Ok(store) => Ok(store),
        Err(codehelion_store::StoreError::UnsupportedSchema { .. }) => {
            remove_incompatible_database(path)?;
            Store::open(path)
                .with_context(|| format!("recreating audit database {}", path.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("opening audit database {}", path.display()))
        }
    }
}

/// Remove one incompatible pre-release baseline and its WAL sidecars.
///
/// This is called only from scan persistence after the command acquired the
/// database lease. Read paths use `Store::open_existing` and never reach it.
fn remove_incompatible_database(path: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let mut candidate: OsString = path.as_os_str().to_owned();
        candidate.push(suffix);
        let candidate = std::path::PathBuf::from(candidate);
        match std::fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing incompatible {}", candidate.display()));
            }
        }
    }
    Ok(())
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

    let groups = report
        .groups
        .iter()
        .zip(ids)
        .zip(group_suppressed)
        .enumerate()
        .map(|(index, ((group, group_ids), suppressed_by))| {
            let mut row = shared::stored_group(shared::StoredGroupCore {
                fingerprint: group_ids.fingerprint,
                clone_type: group.clone_type,
                scope: fast_group_scope(group, lexed),
                statements: None,
                score: group.score,
                entropy_bits: group.entropy_bits,
                suppressed_by: *suppressed_by,
                ranked_down: report::ranks_down(&ranked[index], suppression),
                priority: priority_row(&ranked[index].priority),
                members: group
                    .members
                    .iter()
                    .zip(&group_ids.members)
                    .map(|(instance, member_ids)| MemberRow {
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
                    .collect(),
            });
            row.suppress_reason = group.suppressed.map(|reason| reason.name().to_string());
            row
        })
        .collect();
    (units, groups)
}
