//! Fast-scan snapshot row construction and persistence.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares store helpers across scan modes"
)]

use super::build::{BuildInputs, LexedSource, build_group, fast_group_scope};
use super::run_info::priority_row;
use super::runtime::literal_norm;
use super::shared;
use crate::config::Config;
use crate::report;
use anyhow::{Context, Result};
use codehelion_core::discovery::{BuildVariant, ContentHash, NORMALIZATION_VERSION, SourceUnit};
use codehelion_core::engine::{self, EngineReport, LiteralNorm};
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, FileContext, GroupIds};
use codehelion_store::compiler::{CompilerHelperRow, CompilerOutcome, CompilerUnitRow};
use codehelion_store::snapshot::SuppressionRuleRow;
use codehelion_store::snapshot::{FileRow, GroupRow, MemberRow, Snapshot, SummaryRow, UnitRow};
use codehelion_store::{Store, path_key};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

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

/// What one invocation decided outside the detector settings `Config`
/// serializes.
///
/// Everything here can change the rows a run records — which findings are
/// hidden, and where each is ranked — so two invocations that disagree about
/// any of it are asking different questions and may not stand in for one
/// another.
#[derive(Clone, Copy)]
pub(crate) struct ReuseProfile<'a> {
    /// Whether the run is subject to the untrusted execution contract.
    pub(crate) untrusted: bool,
    /// Whether the signature-based sibling detector ran.
    pub(crate) siblings_by_signature: bool,
    /// The suppression rules the run applied. This is what decides the
    /// `suppressed_by` of every recorded row: a baseline the run was told to
    /// compare against rather than suppress registers no rule here, so the two
    /// readings of one baseline are not interchangeable runs.
    pub(crate) rules: &'a [SuppressionRuleRow],
    /// The presentation policy the run ranked its findings under. An
    /// invocation may override it for itself without changing the
    /// configuration the run is recorded under.
    pub(crate) presentation: &'a crate::config::Suppression,
}

/// Hash the detection-relevant configuration and the reuse profile.
///
/// This digest is what a run is recorded under and what selects the
/// predecessor its lineage, churn and tree changes are measured against, so it
/// covers only inputs that change detected or recorded rows: settings read by
/// other commands, and the path a baseline was named by, leave it unchanged.
/// Reuse additionally requires [`reusable_run`], which compares the rest of
/// what decides the rows. Keeping this recipe in one place prevents the Fast,
/// Structural, and Semantic paths from selecting different predecessors for
/// the same invocation.
pub(crate) fn reuse_config_hash(cfg: &Config, profile: ReuseProfile<'_>) -> Result<ContentHash> {
    let mut config_text = format!(
        "{}\nreuse-profile-v3:untrusted={};siblings-by-signature={}\npresentation:{}\nrules:",
        detection_config(cfg).to_toml()?,
        profile.untrusted,
        profile.siblings_by_signature,
        serde_json::to_string(profile.presentation)
            .context("serializing the presentation policy of a scan")?,
    );
    for rule in profile.rules {
        // A baseline is named by a path as typed; what it hides is compared by
        // its digest when reuse is decided.
        let pattern = if rule.scope == crate::baseline::BASELINE_SCOPE {
            ""
        } else {
            rule.pattern.as_str()
        };
        write!(
            config_text,
            "\n{}\u{1f}{}\u{1f}{}",
            rule.scope,
            pattern,
            rule.reason.as_deref().unwrap_or_default(),
        )
        .context("describing a suppression rule of a scan")?;
    }
    Ok(ContentHash::of(config_text.as_bytes()))
}

/// `cfg` with every setting that changes no scan row reset to its default.
///
/// Settings at their defaults hash as they always have, so a configuration
/// that never set them keeps the predecessor it was recorded against.
fn detection_config(cfg: &Config) -> Config {
    let Config {
        include,
        exclude,
        min_clone_tokens,
        entropy_ratio_floor,
        literal_normalization,
        languages,
        suppression,
        priority,
        limits,
        semantic,
        helpers,
        database: _,
        seam: _,
        seam_tracking: _,
        report: _,
        artifact: _,
        jobs: _,
    } = cfg;
    Config {
        include: include.clone(),
        exclude: exclude.clone(),
        min_clone_tokens: *min_clone_tokens,
        entropy_ratio_floor: *entropy_ratio_floor,
        literal_normalization: *literal_normalization,
        languages: languages.clone(),
        suppression: suppression.clone(),
        priority: *priority,
        limits: limits.clone(),
        semantic: semantic.clone(),
        helpers: helpers.clone(),
        ..Config::default()
    }
}

/// What the run an invocation is about to record would be, beyond the
/// configuration and build variant a reuse candidate is selected by.
pub(crate) struct ReuseIdentity<'a> {
    /// Every `(component, version)` pair the run would be recorded under.
    pub(crate) detector_versions: &'a [(String, String)],
    /// The baseline the run's findings were compared against, if any.
    pub(crate) baseline_digest: Option<&'a str>,
    /// The tree the run read, by relative path and content hash.
    pub(crate) tree: &'a BTreeMap<String, String>,
    /// The compiler helpers the run would record; empty when none was asked.
    pub(crate) compiler_helpers: &'a [CompilerHelperRow],
    /// The per-unit compiler rows the run would record, in recording order.
    pub(crate) compiler_units: &'a [CompilerUnitRow],
}

/// One compiler unit row as reuse compares it: the unit, the helper that
/// answered, and the schema it answered in or the reason it did not.
type CompilerRowKey = (
    (String, String, String),
    Option<(String, String)>,
    Result<String, &'static str>,
);

/// One helper row as reuse compares it.
type CompilerHelperKey = (String, String, Option<u32>);

impl ReuseIdentity<'_> {
    /// The helpers this run would record, in the name order the store reads
    /// them back in.
    fn helper_keys(&self) -> Vec<CompilerHelperKey> {
        let mut keys: Vec<CompilerHelperKey> = self
            .compiler_helpers
            .iter()
            .map(|helper| {
                (
                    helper.identity.name.clone(),
                    helper.identity.version.clone(),
                    helper.restarts,
                )
            })
            .collect();
        keys.sort();
        keys
    }

    /// The unit rows this run would record, as reuse compares them.
    fn unit_keys(&self) -> Vec<CompilerRowKey> {
        self.compiler_units
            .iter()
            .map(|row| {
                let helper = row
                    .helper
                    .and_then(|index| self.compiler_helpers.get(index))
                    .map(|helper| {
                        (
                            helper.identity.name.clone(),
                            helper.identity.version.clone(),
                        )
                    });
                compiler_row_key(&row.outcome, helper)
            })
            .collect()
    }
}

fn compiler_row_key(outcome: &CompilerOutcome, helper: Option<(String, String)>) -> CompilerRowKey {
    let unit = outcome.unit();
    let answer = match outcome {
        CompilerOutcome::Analyzed(ir) => Ok(ir.schema_version.clone()),
        CompilerOutcome::Unavailable { reason, .. } => Err(reason.name()),
    };
    (
        (unit.unit.clone(), unit.file.clone(), unit.variant.clone()),
        helper,
        answer,
    )
}

/// Whether the completed run `previous` would record exactly the rows the
/// current invocation is about to, and may therefore stand in for it.
///
/// The candidate already agrees on root, configuration and build variant.
/// This compares the rest of what decides the rows: the binary that wrote
/// them, every detector version, the baseline, the tree, and what each helper
/// answered about each unit. Every reuse path asks this one question, so no
/// path can replay a run another would refuse.
///
/// # Errors
///
/// Returns any error reading the candidate run.
fn reusable_run(store: &Store, previous: i64, current: &ReuseIdentity<'_>) -> Result<bool> {
    let origin = store.run_origin(previous)?;
    if origin.tool_version != env!("CARGO_PKG_VERSION") {
        return Ok(false);
    }
    let mut detectors = current.detector_versions.to_vec();
    detectors.sort();
    detectors.dedup();
    if origin.detector_versions != detectors {
        return Ok(false);
    }
    let same_baseline = store
        .run_summary_row(previous)?
        .is_some_and(|stored| stored.baseline_digest.as_deref() == current.baseline_digest);
    if !same_baseline || store.run_tree(previous)? != *current.tree {
        return Ok(false);
    }
    let recorded_helpers: Vec<CompilerHelperKey> = store
        .run_compiler_helpers(previous)?
        .into_iter()
        .map(|helper| {
            (
                helper.identity.name,
                helper.identity.version,
                helper.restarts,
            )
        })
        .collect();
    if recorded_helpers != current.helper_keys() {
        return Ok(false);
    }
    let recorded_units: Vec<CompilerRowKey> = store
        .run_compiler_units(previous)?
        .iter()
        .map(|stored| {
            compiler_row_key(
                &stored.outcome,
                stored
                    .helper
                    .as_ref()
                    .map(|helper| (helper.name.clone(), helper.version.clone())),
            )
        })
        .collect();
    Ok(recorded_units == current.unit_keys())
}

/// The completed run a new run is recorded against.
pub(crate) struct Predecessor {
    /// Its row id.
    pub(crate) id: i64,
    /// What became of the tree since it.
    pub(crate) changes: report::TreeChanges,
    /// Whether it may stand in for the new run, per [`reusable_run`].
    pub(crate) reusable: bool,
}

/// Select the newest completed run under the same root, configuration and
/// build variant, and decide whether it may stand in for the run `current`
/// describes. Reuse is only considered when `consider_reuse` is set.
///
/// # Errors
///
/// Returns any error reading the audit database.
pub(crate) fn select_predecessor(
    store: &Store,
    root_path: &str,
    config_hash: &str,
    variant_fingerprint: &str,
    current: &ReuseIdentity<'_>,
    consider_reuse: bool,
) -> Result<Option<Predecessor>> {
    let Some(previous) =
        store.latest_compatible_run(root_path, config_hash, variant_fingerprint)?
    else {
        return Ok(None);
    };
    let previous_tree = store.run_tree(previous.id)?;
    Ok(Some(Predecessor {
        id: previous.id,
        changes: shared::tree_changes(previous.id, &previous_tree, current.tree),
        reusable: consider_reuse && reusable_run(store, previous.id, current)?,
    }))
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
    let config_hash = reuse_config_hash(
        cfg,
        ReuseProfile {
            untrusted: inputs.untrusted,
            siblings_by_signature: false,
            rules: &inputs.rules.rows,
            presentation: inputs.suppression,
        },
    )?;
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
    let current_tree = shared::file_tree(&files);
    let predecessor = select_predecessor(
        &store,
        &root_path,
        config_hash.as_str(),
        &variant.fingerprint(),
        &ReuseIdentity {
            detector_versions: &detector_versions,
            baseline_digest: summary.baseline_digest.as_deref(),
            tree: &current_tree,
            // A Fast run asks no compiler anything.
            compiler_helpers: &[],
            compiler_units: &[],
        },
        inputs.reuse_allowed,
    )?;
    if let Some(previous) = predecessor.as_ref() {
        inputs.changes = Some(previous.changes.clone());
        if previous.reusable {
            store.confirm_reused_run(
                previous.id,
                &inputs.rules.rows,
                inputs.started_at,
                inputs.finished_at,
            )?;
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

/// Open the current store, creating its parent directory when needed.
pub(crate) fn open_store(path: &Path) -> Result<Store> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
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
/// views of one verdict, not two verdicts that happen to agree. Member order
/// and the canonical nomination come from the same shared decision the public
/// report is assembled from, and the store records it as written: the first
/// member of a group is its canonical one.
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
        let tokens = codehelion_core::frontend::tokens_in_range(
            &source.tokens,
            unit.token_start,
            unit.token_end,
        );
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
            let members: Vec<MemberRow> =
                shared::nominated_occurrences(group.members.iter().zip(&group_ids.members).filter(
                    |(_, member_ids)| {
                        let finding = member_ids.finding.to_hex();
                        retained_findings.contains(finding.as_str())
                            && emitted_findings.insert(finding)
                    },
                ))
                .into_iter()
                .map(|occurrence| {
                    let instance = occurrence.instance;
                    MemberRow {
                        content: occurrence.ids.content,
                        finding: occurrence.ids.finding,
                        language: lexed[instance.file].language,
                        host_unit: instance.unit.map(|unit| host_index[&(instance.file, unit)]),
                        boilerplate: None,
                        file_path: lexed[instance.file].relative_path.clone(),
                        start_line: instance.start_line,
                        end_line: instance.end_line,
                        token_count: instance.token_end - instance.token_start,
                    }
                })
                .collect();
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
                members,
            });
            row.suppress_reason = group.suppressed.map(|reason| reason.name().to_string());
            row
        })
        .collect();
    (units, groups)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use codehelion_core::clone_class::CloneClass;
    use codehelion_core::discovery::{Language, LanguageSelection};
    use codehelion_core::engine::{CloneGroup, EngineStats, Instance};
    use codehelion_core::frontend::{SourceSpan, Token, TokenKind, Unit, UnitKind};

    use super::{
        BTreeMap, BuildVariant, Config, EngineReport, FileContext, LexedSource, ReuseIdentity,
        ReuseProfile, Snapshot, Store, SummaryRow, reuse_config_hash, select_predecessor,
        snapshot_rows,
    };

    fn digest(cfg: &Config, rules: &crate::suppress::Rules) -> String {
        reuse_config_hash(
            cfg,
            ReuseProfile {
                untrusted: false,
                siblings_by_signature: false,
                rules: &rules.rows,
                presentation: &cfg.suppression,
            },
        )
        .unwrap()
        .as_str()
        .to_string()
    }

    fn rules(cfg: &Config) -> crate::suppress::Rules {
        crate::suppress::Rules::compile(&cfg.suppression, false).unwrap()
    }

    /// Settings no scan row depends on leave the predecessor digest alone,
    /// while a detection setting still changes it.
    #[test]
    fn settings_that_change_no_row_keep_the_predecessor_digest() {
        let plain = Config::default();
        let edited = Config::from_toml(
            "jobs = 3\n\
             database = \"elsewhere/audit.db\"\n\
             [report]\nchurn-top = 7\n\
             [artifact]\nown = [\"mycrate\"]\n\
             [seam-tracking]\nbreach-window = 9\n\
             [[seam]]\nid = \"twins\"\nmembers = [\"a/**\", \"b/**\"]\n",
        )
        .unwrap();
        assert_eq!(
            digest(&plain, &rules(&plain)),
            digest(&edited, &rules(&edited))
        );
        let detection = Config {
            min_clone_tokens: plain.min_clone_tokens + 1,
            ..Config::default()
        };
        assert_ne!(
            digest(&plain, &rules(&plain)),
            digest(&detection, &rules(&detection))
        );
    }

    /// However the baseline file is spelled, the digest is the same; whether a
    /// baseline hides findings at all still changes it.
    #[test]
    fn the_spelling_of_a_baseline_path_keeps_the_predecessor_digest() {
        let cfg = Config::default();
        let spelled = ["b.json", "./b.json", "/repo/b.json"].map(|path| {
            let mut with_baseline = rules(&cfg);
            with_baseline.add_baseline(path, BTreeMap::new());
            digest(&cfg, &with_baseline)
        });
        assert_eq!(spelled[0], spelled[1]);
        assert_eq!(spelled[0], spelled[2]);
        assert_ne!(spelled[0], digest(&cfg, &rules(&cfg)));
    }

    /// A run recorded before an unrelated setting changed is still the
    /// predecessor of the next scan, and is reused only when every
    /// row-deciding input agrees.
    #[test]
    fn a_run_recorded_under_other_unrelated_settings_is_the_predecessor() {
        let before = Config::default();
        let after = Config {
            jobs: Some(3),
            ..Config::default()
        };
        let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
        let detectors = vec![("fast-engine".to_string(), "v1".to_string())];
        let tree = BTreeMap::new();
        let recorded_hash = digest(&before, &rules(&before));
        let mut store = Store::open_in_memory().unwrap();
        let recorded = store
            .record_snapshot(&Snapshot {
                root_path: "/repo",
                tool_version: env!("CARGO_PKG_VERSION"),
                config_hash: &recorded_hash,
                config_source: "defaults",
                config_path: None,
                started_at: "2026-07-24T00:00:00Z",
                finished_at: "2026-07-24T00:00:01Z",
                variant: &variant,
                min_clone_tokens: before.min_clone_tokens,
                detector_versions: &detectors,
                suppressions: Vec::new(),
                units: Vec::new(),
                groups: Vec::new(),
                sibling_groups: Vec::new(),
                near_misses: Vec::new(),
                files: Vec::new(),
                compiler_helpers: Vec::new(),
                compiler_units: Vec::new(),
                summary: SummaryRow::default(),
            })
            .unwrap();
        let select = |detectors: &[(String, String)]| {
            select_predecessor(
                &store,
                "/repo",
                &digest(&after, &rules(&after)),
                &variant.fingerprint(),
                &ReuseIdentity {
                    detector_versions: detectors,
                    baseline_digest: None,
                    tree: &tree,
                    compiler_helpers: &[],
                    compiler_units: &[],
                },
                true,
            )
            .unwrap()
            .expect("the earlier run is the predecessor")
        };
        let same = select(&detectors);
        assert_eq!(same.id, recorded);
        assert!(same.reusable);
        let changed = select(&[("fast-engine".to_string(), "v2".to_string())]);
        assert_eq!(changed.id, recorded);
        assert!(!changed.reusable);
    }

    fn token() -> Token {
        Token {
            kind: TokenKind::Identifier,
            text: "x".into(),
            span: SourceSpan {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_column: 1,
            },
        }
    }

    /// A `Unit` whose token range reaches past the end of its file's token
    /// stream, as an error-tolerant frontend may legitimately hand back after
    /// recovering from a parse error.
    #[test]
    fn a_unit_with_a_token_start_past_the_token_count_does_not_panic() {
        let unit = Unit {
            kind: UnitKind::Function,
            name: Some("f".to_string()),
            token_start: 10,
            token_end: 20,
            span: SourceSpan {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_column: 1,
            },
        };
        let lexed = vec![LexedSource {
            relative_path: "src/lib.rs".to_string(),
            language: Language::Rust,
            frontend_version: "test-v1",
            tokens: vec![token(), token()],
            arm_paths: None,
            units: vec![unit],
            unit_lines: vec![(1, 2)],
            marker_lines: Vec::new(),
            lines: 2,
            diagnostics: 0,
        }];
        let contexts = vec![FileContext {
            frontend_version: "test-v1",
            language: Language::Rust,
        }];
        let report = EngineReport {
            groups: vec![CloneGroup {
                content_key: 0,
                clone_type: CloneClass::Type1,
                score: 1.0,
                members: vec![Instance {
                    file: 0,
                    token_start: 0,
                    token_end: 2,
                    start_line: 1,
                    end_line: 2,
                    unit: Some(0),
                }],
                entropy_bits: 1.0,
                suppressed: None,
            }],
            stats: EngineStats::default(),
        };
        let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
        let suppression = crate::config::Suppression::default();

        let (units, groups) = snapshot_rows(
            &lexed,
            &contexts,
            &variant,
            &report,
            &[],
            &[],
            &[],
            &[],
            &suppression,
        );

        assert_eq!(units.len(), 1, "the out-of-range unit is still recorded");
        assert_eq!(
            units[0].token_count, 0,
            "a range past the token count clamps to an empty slice rather than panicking"
        );
        assert!(groups.is_empty());
    }
}
