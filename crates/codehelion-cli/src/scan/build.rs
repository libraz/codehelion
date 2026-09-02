//! Assembly of the Fast pipeline's report model and of the summary row the
//! same run records, from the lexed sources and the engine's findings.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use codehelion_core::clone_class::CloneScope;
use codehelion_core::conditional::ArmPath;
use codehelion_core::discovery::{BuildVariant, DiscoveryReport, Language};
use codehelion_core::engine::{CloneGroup, EngineReport, LiteralNorm};
use codehelion_core::frontend::{Token, Unit};
use codehelion_core::priority::Weights;
use codehelion_core::stable_id::GroupIds;
use codehelion_store::snapshot::SummaryRow;

use super::run_info::{RunInfoInputs, common_run_info, file_counts, guardrails_row};
use super::{
    ScanBaseline, detector_versions, display_path, funnel, literal_norm, load_baseline, shared,
};
use crate::cli::ScanArgs;
use crate::config::{self, Config};
use crate::report::{self, Report};
use crate::suppress;

/// One lexed source file, ready for the engine.
pub(super) struct LexedSource {
    pub(super) relative_path: String,
    pub(super) language: Language,
    pub(super) frontend_version: &'static str,
    pub(super) tokens: Vec<Token>,
    /// Preprocessor arms for C-family tokens; Rust has none.
    pub(super) arm_paths: Option<Vec<ArmPath>>,
    pub(super) units: Vec<Unit>,
    /// `(start, end)` line range of each unit, parallel to `units`.
    pub(super) unit_lines: Vec<(u32, u32)>,
    /// 1-based lines carrying an inline suppression marker.
    pub(super) marker_lines: Vec<u32>,
    /// Source lines in the file.
    pub(super) lines: u64,
    pub(super) diagnostics: usize,
}

/// What suppression decided for one run.
pub(super) struct Suppression {
    /// The compiled rules, which the snapshot records.
    pub(super) rules: suppress::Rules,
    /// The baseline the scan was given, if any.
    pub(super) baseline: Option<ScanBaseline>,
    /// The rule hiding each group, parallel to the engine's groups.
    pub(super) groups: Vec<Option<usize>>,
    /// Selectors that matched scanned source, even when another rule had
    /// precedence for a particular finding.
    pub(super) matched_rules: BTreeSet<usize>,
}

/// Compile the suppression rules, apply the baseline, and decide which rule
/// hides each detected group.
pub(super) fn evaluate_suppression(
    args: &ScanArgs,
    cfg: &Config,
    variant: &BuildVariant,
    lexed: &[LexedSource],
    report: &EngineReport,
    ids: &[GroupIds],
) -> Result<Suppression> {
    let any_markers = lexed.iter().any(|file| !file.marker_lines.is_empty());
    let mut rules = suppress::Rules::compile(&cfg.suppression, any_markers)?;
    let baseline = load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules,
        variant,
        &detector_versions(
            literal_norm(cfg.literal_normalization),
            cfg.entropy_ratio_floor,
        ),
        cfg.min_clone_tokens,
    )?;
    let file_suppressions: Vec<suppress::FileSuppression> = lexed
        .iter()
        .map(|file| rules.evaluate_file(&file.relative_path, &file.marker_lines, &unit_spans(file)))
        .collect();
    let matched_rules = file_suppressions
        .iter()
        .flat_map(suppress::FileSuppression::matched_rules)
        .collect();
    let groups = report
        .groups
        .iter()
        .zip(ids)
        .map(|(group, group_ids)| {
            // A clone id names this exact group, so it decides before any
            // rule that happens to cover where the members sit. The baseline
            // decides last: that a finding is not new says less about it than
            // anything the rules say about the code.
            shared::SuppressionPriority::first(|| {
                rules.clone_id_rule(&group_ids.fingerprint.to_hex())
            })
            .or_else(|| group_rule(&rules, &file_suppressions, group))
            .or_else(|| {
                rules.baseline_rule(&group_ids.fingerprint.to_hex(), as_u64(group.members.len()))
            })
            .finish()
        })
        .collect();
    Ok(Suppression {
        rules,
        baseline,
        groups,
        matched_rules,
    })
}

/// Everything [`build_report`] needs from the pipeline.
pub(super) struct BuildInputs<'a> {
    pub(super) root: &'a Path,
    pub(super) db_path: &'a Path,
    /// The `--db` the commands this report prints have to repeat.
    pub(super) replay_database: Option<&'a str>,
    pub(super) configuration: &'a report::ConfigurationInfo,
    pub(super) run_id: Option<i64>,
    pub(super) started_at: &'a str,
    pub(super) finished_at: &'a str,
    pub(super) discovered: &'a DiscoveryReport,
    pub(super) glob_excluded: usize,
    pub(super) unreadable: u64,
    pub(super) timed_out: u64,
    pub(super) lexed: &'a [LexedSource],
    pub(super) report: &'a EngineReport,
    pub(super) ids: &'a [GroupIds],
    pub(super) rules: &'a suppress::Rules,
    pub(super) group_suppressed: &'a [Option<usize>],
    pub(super) matched_rules: &'a BTreeSet<usize>,
    /// What the report does with each classification a group can carry, which
    /// is what decides where a classified group is listed.
    pub(super) suppression: &'a config::Suppression,
    /// How the run weighs the priority measures against one another.
    pub(super) weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    pub(super) min_clone_tokens: u64,
    /// The literal strategy the content ids were folded under.
    pub(super) literals: LiteralNorm,
    /// The configured low-entropy suppression floor, normalized by clone
    /// length. It changes which groups are visible, so it is baseline input.
    pub(super) entropy_ratio_floor: f64,
    /// The axis the run puts its entries in order on.
    pub(super) sort: report::Sort,
    pub(super) reuse_allowed: bool,
    pub(super) untrusted: bool,
    pub(super) reused: bool,
    pub(super) changes: Option<report::TreeChanges>,
}

/// The configured suppression rules whose selectors matched no scanned source
/// or finding in this run.
fn unused_suppressions(inputs: &BuildInputs<'_>) -> Vec<report::UnusedRule> {
    shared::unused_suppressions(
        inputs.rules,
        inputs
            .matched_rules
            .iter()
            .copied()
            .chain(inputs.group_suppressed.iter().filter_map(|rule| *rule)),
    )
}

/// A count as the report model carries it. Saturating rather than fallible:
/// a count this large is already past any meaning a report could carry.
pub(super) fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// What the run reported about itself beyond the groups it found, in the shape
/// the audit database stores.
///
/// Built before the snapshot is written and read back out of it by
/// [`build_summary`], so the recorded run and the printed report carry one set
/// of numbers rather than two derivations that happen to agree.
pub(super) fn summary_row(
    inputs: &BuildInputs<'_>,
    baseline_digest: Option<String>,
    guardrails: Option<&report::Guardrails>,
) -> SummaryRow {
    shared::summary(shared::SummaryInputs {
        analyzed_files: file_counts(inputs.lexed.iter().map(|file| file.language)),
        lines: inputs.lexed.iter().map(|file| file.lines).sum(),
        tokens: as_u64(inputs.report.stats.tokens),
        lexer_diagnostics: as_u64(inputs.lexed.iter().map(|file| file.diagnostics).sum()),
        // Fast mode lexes and does not parse, so it has nothing to report
        // here; a zero would read as "the parser followed everything".
        unparsed: None,
        excluded_generated: as_u64(inputs.discovered.suppressed_generated.len()),
        excluded_by_glob: as_u64(inputs.glob_excluded),
        excluded_too_large: inputs.discovered.skipped.too_large,
        excluded_oversized_metadata: inputs.discovered.skipped.oversized_metadata,
        excluded_binary: inputs.discovered.skipped.binary,
        excluded_unreadable: inputs.discovered.skipped.unreadable + inputs.unreadable,
        excluded_symlinks: inputs.discovered.skipped.symlinks,
        excluded_walk_errors: inputs.discovered.skipped.walk_errors,
        excluded_timed_out: inputs.timed_out,
        excluded_language: inputs.discovered.skipped.language_excluded,
        excluded_symlink_files: inputs.discovered.skipped.symlink_files,
        excluded_symlink_directories: inputs.discovered.skipped.symlink_directories,
        guardrails: guardrails.map(guardrails_row),
        excluded_skipped: inputs.discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
        // The Fast engine compares whole units, so it folds and subsumes no
        // runs, and its equivalence classes need no refinement to bound.
        folded_runs: 0,
        subsumed_runs: 0,
        split_components: 0,
        // The signature-sibling channel is structural-only, so a Fast run has
        // no signature to have judged too common.
        common_signatures_skipped: 0,
        largest_skipped_signature_units: 0,
        pair_budget_exhausted: inputs.report.stats.pair_budget_exhausted,
        baseline_digest,
        funnel: funnel::fast(&inputs.report.stats, inputs.report.groups.len()),
        unused_suppressions: unused_suppressions(inputs),
    })
}

/// Assemble the report model both output formats render from, from the groups
/// the run already ranked, in the order every view shows them in.
pub(super) fn build_report(
    inputs: &BuildInputs<'_>,
    stored: &SummaryRow,
    mut groups: Vec<report::Group>,
) -> Report {
    report::order(&mut groups, inputs.suppression, inputs.sort);
    shared::report(
        common_run_info(RunInfoInputs {
            root: inputs.root,
            db_path: inputs.db_path,
            replay_database: inputs.replay_database,
            configuration: inputs.configuration,
            run_id: inputs.run_id,
            started_at: inputs.started_at,
            finished_at: inputs.finished_at,
            variant: &inputs.discovered.build_variant,
            detector_versions: detector_versions(inputs.literals, inputs.entropy_ratio_floor)
                .into_iter()
                .map(|(component, version)| report::DetectorVersion { component, version })
                .collect(),
            weights: &inputs.weights,
        }),
        stored,
        groups,
        inputs.discovered.build_variant.mode.name(),
    )
}

/// One group of the report model, ranked, with its suppression cause resolved.
pub(super) fn build_group(inputs: &BuildInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.report.groups[index];
    let suppressed = group.suppressed.map_or_else(
        || inputs.group_suppressed[index].map(|rule| shared::rule_suppression(inputs.rules, rule)),
        |reason| {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some(reason.name().to_string()),
                scope: None,
                pattern: None,
                active: None,
            })
        },
    );
    report::ranked(
        {
            let mut report_group = shared::report_group(shared::ReportGroupCore {
                fingerprint: inputs.ids[index].fingerprint.to_hex(),
                clone_type: group.clone_type,
                scope: fast_group_scope(group, inputs.lexed),
                statements: None,
                confidence: group.score,
                entropy_bits: group.entropy_bits,
                members: shared::nominated_occurrences(
                    group.members.iter().zip(&inputs.ids[index].members),
                )
                .into_iter()
                .map(|occurrence| {
                    let instance = occurrence.instance;
                    let source = &inputs.lexed[instance.file];
                    report::Member {
                        finding_id: occurrence.ids.finding.to_hex(),
                        content: occurrence.ids.content.to_hex(),
                        file: display_path(&source.relative_path),
                        language: source.language.name().to_string(),
                        start_line: instance.start_line,
                        end_line: instance.end_line,
                        unit: instance
                            .unit
                            .and_then(|unit| source.units[unit].name.clone()),
                        boilerplate: None,
                        tokens: u64::try_from(instance.token_end - instance.token_start)
                            .unwrap_or(u64::MAX),
                        canonical: occurrence.canonical,
                    }
                })
                .collect(),
            });
            report_group.suppressed = suppressed;
            report_group
        },
        &inputs.weights,
        inputs.min_clone_tokens,
    )
}

/// Classify a Fast finding by what its matched spans actually cover.
///
/// The lexer can anchor a token-window clone inside a unit, but that anchor
/// does not make the window a whole-unit finding. Every occurrence must cover
/// its host exactly before the group can use unit scope.
pub(super) fn fast_group_scope(group: &CloneGroup, lexed: &[LexedSource]) -> CloneScope {
    if group.members.iter().all(|member| {
        member.unit.is_some_and(|unit| {
            let host = &lexed[member.file].units[unit];
            member.token_start == host.token_start && member.token_end == host.token_end
        })
    }) {
        CloneScope::Unit
    } else {
        CloneScope::Fragment
    }
}

/// One lexed file's units as the suppression rules see them: their line
/// ranges paired with the names the lexer recovered.
fn unit_spans(file: &LexedSource) -> Vec<suppress::UnitSpan<'_>> {
    file.units
        .iter()
        .zip(&file.unit_lines)
        .map(|(unit, &(start_line, end_line))| suppress::UnitSpan {
            start_line,
            end_line,
            name: unit.name.as_deref(),
        })
        .collect()
}

/// The rule suppressing a whole group: present only when *every* member is
/// suppressed. The canonical (first) member's rule is the one recorded.
fn group_rule(
    rules: &suppress::Rules,
    files: &[suppress::FileSuppression],
    group: &CloneGroup,
) -> Option<usize> {
    let mut first = None;
    for member in &group.members {
        let rule = rules.member_rule(
            &files[member.file],
            member.start_line,
            member.end_line,
            member.unit,
        )?;
        if first.is_none() {
            first = Some(rule);
        }
    }
    first
}
