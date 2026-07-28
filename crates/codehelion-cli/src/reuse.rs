//! Reporting a recorded run again when the tree it read has not moved.
//!
//! A periodic audit spends most of its runs on a tree nobody touched. Nothing
//! about the answer can differ in that case, so the scan is skipped and the
//! recorded run is reported again: the sources are still read and hashed —
//! that is how "not moved" is established — but nothing is parsed, compared or
//! recorded.
//!
//! The bar is deliberately blunt. Everything that shapes a report has to be
//! identical, and anything this module cannot compare counts as a difference:
//! the same root, build variant, configuration, release and detector versions,
//! the same file set hashing the same, and the same frozen set from a
//! baseline. A run recorded before any one of those was stored is not reusable,
//! because "recorded nothing about it" and "recorded that it matched" are not
//! the same claim.
//!
//! No new run is recorded. There is nothing to record — the tree is the one
//! the stored run read — and a second identical run would leave the audit
//! history claiming a comparison that never happened.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use codehelion_core::discovery::{BuildVariant, ContentHash, Language, SourceUnit};
use codehelion_core::priority::Weights;
use codehelion_store::Store;
use codehelion_store::query::{RunRecord, StoredGroup, StoredMember, StoredSimilarity};
use codehelion_store::snapshot::SummaryRow;

use crate::report::{self, Report};

/// Everything the decision reads about the invocation asking for a scan.
pub(crate) struct Request<'a> {
    /// Scan root, canonicalized.
    pub root: &'a Path,
    /// Audit database the run would be recorded in.
    pub db_path: &'a Path,
    /// The variant the results would belong to.
    pub variant: &'a BuildVariant,
    /// Hash of the effective configuration.
    pub config_hash: &'a str,
    /// The `(component, version)` pairs this build would record.
    pub detector_versions: &'a [(String, String)],
    /// Digest of the frozen set a baseline froze, when one was given.
    pub baseline_digest: Option<String>,
    /// How the ranking weighs its measures, which the stored groups are
    /// re-ranked under.
    pub weights: Weights,
    /// What the report does with each classification a group can carry, which
    /// is what decides where a classified group is listed.
    pub suppression: &'a crate::config::Suppression,
    /// The run's minimum clone length, which the ranking reads sizes against.
    pub min_clone_tokens: u64,
    /// The files discovery found, with the hash of what it read.
    pub sources: &'a [SourceUnit],
}

/// The recorded run to report again, or `None` when this invocation has to do
/// the work.
///
/// # Errors
///
/// Returns an error when the audit database cannot be opened or read. A scan
/// that cannot read its own database is about to fail recording anyway, so it
/// fails here rather than quietly analysing and failing later.
pub(crate) fn recorded(request: &Request<'_>) -> Result<Option<Report>> {
    if !request.db_path.exists() {
        return Ok(None);
    }
    let store = crate::scan::open_store(request.db_path)?;
    let root = request.root.to_string_lossy();
    let Some(run) = store.previous_run_record(&root, &request.variant.fingerprint())? else {
        return Ok(None);
    };
    let Some(summary) = store.run_summary_row(run.id)? else {
        return Ok(None);
    };
    if !matches(&store, request, &run, &summary)? {
        return Ok(None);
    }
    restore(&store, request, &run, &summary).map(Some)
}

/// Whether the recorded run answers the question this invocation is asking.
fn matches(
    store: &Store,
    request: &Request<'_>,
    run: &RunRecord,
    summary: &SummaryRow,
) -> Result<bool> {
    if run.tool_version != env!("CARGO_PKG_VERSION")
        || run.config_hash != request.config_hash
        || run.analysis_mode != request.variant.mode.name()
        || run.min_clone_tokens != Some(i64::try_from(request.min_clone_tokens).unwrap_or(i64::MAX))
        || summary.baseline_digest != request.baseline_digest
    {
        return Ok(false);
    }
    // Compared as sets: the store returns them ordered by component and the
    // caller lists them as the pipeline mentions them, which is a difference
    // in presentation and not in what ran.
    let mut asked: Vec<(String, String)> = request.detector_versions.to_vec();
    asked.sort_unstable();
    if store.run_origin(run.id)?.detector_versions != asked {
        return Ok(false);
    }
    Ok(same_tree(&store.run_tree(run.id)?, request.sources))
}

/// Whether the run read exactly these files and they still hash the same.
///
/// A run that recorded no tree at all is not a match: an empty record and a
/// tree that turned out to be empty are the same rows, and only one of them
/// means the comparison succeeded.
fn same_tree(recorded: &BTreeMap<String, String>, sources: &[SourceUnit]) -> bool {
    if recorded.is_empty() || recorded.len() != sources.len() {
        return false;
    }
    sources.iter().all(|source| {
        recorded
            .get(source.relative_path.to_string_lossy().as_ref())
            .is_some_and(|hash| hash.as_str() == source.content_hash.as_str())
    })
}

/// Rebuild the run's report from its rows.
fn restore(
    store: &Store,
    request: &Request<'_>,
    run: &RunRecord,
    summary: &SummaryRow,
) -> Result<Report> {
    let mut groups: Vec<report::Group> = store
        .run_groups(run.id)?
        .iter()
        .map(|group| report::ranked(rebuild(group), &request.weights, request.min_clone_tokens))
        .collect();
    report::order(&mut groups, request.suppression);
    let counts = store.run_language_counts(run.id)?;
    let files = report::FileCounts {
        total: counts.values().sum(),
        rust: counts.get(Language::Rust.name()).copied().unwrap_or(0),
        c: counts.get(Language::C.name()).copied().unwrap_or(0),
        cpp: counts.get(Language::Cpp.name()).copied().unwrap_or(0),
    };
    let variant = request.variant;
    Ok(Report {
        schema_version: report::SCHEMA_VERSION,
        run: report::RunInfo {
            tool_version: run.tool_version.clone(),
            mode: variant.mode.name().to_string(),
            root: request.root.display().to_string(),
            started_at: run.started_at.clone(),
            finished_at: run.finished_at.clone(),
            build_variant: report::BuildVariantInfo {
                mode: variant.mode.name().to_string(),
                languages: variant
                    .languages
                    .enabled()
                    .into_iter()
                    .map(|language| language.name().to_string())
                    .collect(),
                headers: variant.headers.map(|language| language.name().to_string()),
                normalization_version: variant.normalization_version,
                fingerprint: variant.fingerprint(),
            },
            detector_versions: request
                .detector_versions
                .iter()
                .map(|(component, version)| report::DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            ranking: report::RankingInfo {
                recipe: request.weights.recipe(),
                maintenance_risk: request.weights.maintenance_risk,
                refactoring_ease: request.weights.refactoring_ease,
            },
            database: request.db_path.display().to_string(),
            run_id: run.id,
            reused: true,
        },
        summary: report::restored(files, summary, &groups),
        groups,
    })
}

/// One stored group as the report model carries it, ranking aside.
///
/// The ranking is recomputed rather than read back: it is a pure function of
/// the group, the weights and the length floor, and this path runs only when
/// all three are the ones the run used. Reading it back would need the same
/// three to be trusted anyway, with one more table in the way.
fn rebuild(group: &StoredGroup) -> report::Group {
    report::Group {
        fingerprint: group.fingerprint_hex.clone(),
        clone_type: group.clone_type.clone(),
        scope: group.member_scope.clone(),
        statements: group
            .statements
            .map(|count| u64::try_from(count).unwrap_or(0)),
        confidence: group.score,
        priority: report::Priority::unranked(),
        similarity: group.similarity.as_ref().map(similarity),
        boilerplate: group.boilerplate.clone(),
        test_code: group.test_code,
        width_family: group.width_family,
        split_pair: group.split_pair,
        suppressed: suppression(group),
        members: group.members.iter().map(member).collect(),
    }
}

/// Why the run hid the group, if it did.
///
/// Noise before rule, as the scan decides it: a group the engine set aside is
/// set aside whether or not a rule also covers where its members sit.
fn suppression(group: &StoredGroup) -> Option<report::Suppression> {
    if let Some(reason) = &group.suppress_reason {
        return Some(report::Suppression {
            kind: report::SuppressionKind::Noise,
            reason: Some(reason.clone()),
            scope: None,
            pattern: None,
        });
    }
    group
        .suppressed_by
        .as_ref()
        .map(|rule| report::Suppression {
            kind: report::SuppressionKind::Rule,
            reason: None,
            scope: Some(rule.scope.clone()),
            pattern: Some(rule.pattern.clone()),
        })
}

fn similarity(stored: &StoredSimilarity) -> report::Similarity {
    report::Similarity {
        weight_version: stored.weight_version.clone(),
        lexical: stored.lexical,
        structural: stored.structural,
        control_flow: stored.control_flow,
        type_similarity: stored.type_similarity,
        api: stored.api,
        composite: stored.composite,
        min_pairwise: stored.min_pairwise,
        confidence_band: stored.confidence_band.clone(),
    }
}

fn member(stored: &StoredMember) -> report::Member {
    let line = |value: Option<i64>| u32::try_from(value.unwrap_or(0)).unwrap_or(0);
    report::Member {
        finding_id: stored.finding_hex.clone(),
        content: stored.content_hex.clone(),
        file: stored.file_path.clone(),
        language: stored.language.clone(),
        start_line: line(stored.start_line),
        end_line: line(stored.end_line),
        unit: stored.unit_name.clone(),
        tokens: u64::try_from(stored.token_count).unwrap_or(0),
        canonical: stored.is_canonical,
    }
}

/// A digest of the finding ids a baseline froze.
///
/// Over the ids alone: the file's path and the order its entries are written
/// in change nothing about what is hidden, and two runs given the same frozen
/// set under two names report the same findings.
pub(crate) fn baseline_digest(ids: &BTreeSet<String>) -> String {
    let mut joined = String::new();
    for id in ids {
        joined.push_str(id);
        joined.push('\n');
    }
    ContentHash::of(joined.as_bytes()).as_str().to_string()
}

/// Read the frozen set a `--baseline` file holds, without applying it.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not a baseline this
/// build understands, which is the same answer the scan itself would give.
pub(crate) fn baseline_ids(path: Option<&Path>) -> Result<Option<BTreeSet<String>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let baseline = crate::baseline::Baseline::load(path)
        .with_context(|| format!("reading baseline {}", path.display()))?;
    Ok(Some(
        baseline
            .entries
            .iter()
            .map(|entry| entry.group.clone())
            .collect(),
    ))
}
