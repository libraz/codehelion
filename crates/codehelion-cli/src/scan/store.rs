//! Fast-scan snapshot row construction and persistence.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares store helpers across scan modes"
)]

use super::{
    BTreeMap, BuildInputs, BuildVariant, CloneScope, Config, ContentHash, ContentNorm, Context,
    EngineReport, FP_SCHEMA_VERSION, FileContext, FileRow, GroupIds, GroupRow, LexedSource,
    LiteralNorm, MemberRow, NORMALIZATION_VERSION, Path, Result, Snapshot, SourceUnit, Store,
    SummaryRow, UnitRow, build_group, literal_norm, priority_row, report, shared, stable_id,
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

/// Render a filesystem path as a unique database and report key.
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
        return text.to_string();
    }
    let mut encoded = ESCAPED_PATH_PREFIX.to_string();
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
    );
    let mut store = open_store(inputs.db_path)?;
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let mut detector_versions = detector_versions(
        literal_norm(cfg.literal_normalization),
        cfg.entropy_ratio_floor,
    );
    // Ranking is persisted beside the run so `report --run` can render the
    // historical ordering. It is intentionally excluded from the public
    // detector contract and baseline compatibility: changing presentation
    // cannot invalidate a judgement about detected duplication.
    detector_versions.push(("ranking".to_string(), cfg.priority.weights().recipe()));
    let root_path = inputs.root.to_string_lossy();
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
        features: Vec::new(),
        files,
        // No compiler was asked anything: this mode reads source and nothing
        // else, and an empty list is the whole truth about it.
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: summary.clone(),
    };
    inputs.run_id = store.record_snapshot(&snapshot)?;
    Ok(ranked)
}

/// Open the v1 store, creating its parent directory when needed.
pub(crate) fn open_store(path: &Path) -> Result<Store> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    Store::open(path).with_context(|| format!("opening audit database {}", path.display()))
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
fn snapshot_rows(
    lexed: &[LexedSource],
    contexts: &[FileContext<'_>],
    variant: &BuildVariant,
    report: &EngineReport,
    ids: &[GroupIds],
    group_suppressed: &[Option<usize>],
    ranked: &[report::Group],
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
                scope: CloneScope::Unit,
                statements: None,
                score: group.score,
                entropy_bits: group.entropy_bits,
                suppressed_by: *suppressed_by,
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
