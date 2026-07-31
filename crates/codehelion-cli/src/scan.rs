//! The `scan` command: the Fast pipeline from project discovery to the
//! recorded snapshot.
//!
//! The stages are: resolve configuration, discover source files, lex them
//! with the per-language frontends (files spread across worker threads),
//! detect clones, derive stable identifiers, record one atomic snapshot in
//! the audit database, and render a report. Nothing in this path executes
//! target code: files are only read.
//!
//! Everything the pipeline drops is accounted for in the report — generated
//! files, glob-excluded files, unreadable files and engine budget exhaustion
//! all surface as counts or notes, never as silent omissions.

pub mod structural;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::clone_class::CloneScope;
use codehelion_core::discovery::{
    self, BuildVariant, ContentHash, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport,
    GeneratedMarkers, Language, LanguageSelection, NORMALIZATION_VERSION, SourceUnit,
};
use codehelion_core::engine::{
    self, CloneGroup, EngineConfig, EngineReport, InputFile, LiteralNorm,
};
use codehelion_core::execution::ExecutionPolicy;
use codehelion_core::frontend::{Frontend, Token, Unit};
use codehelion_core::priority::Weights;
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, FileContext, GroupIds};
use codehelion_store::Store;
use codehelion_store::snapshot::{
    FileRow, GroupRow, MemberRow, PriorityRow, Snapshot, SummaryRow, UnitRow,
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::{Value, json};

use crate::Outcome;
use crate::cli::{Format, Mode, ScanArgs};
use crate::config::{self, Config, LiteralNormalization};
use crate::report::{self, Report};
use crate::suppress;

/// One lexed source file, ready for the engine.
struct LexedSource {
    relative_path: String,
    language: Language,
    frontend_version: &'static str,
    tokens: Vec<Token>,
    units: Vec<Unit>,
    /// `(start, end)` line range of each unit, parallel to `units`.
    unit_lines: Vec<(u32, u32)>,
    /// 1-based lines carrying an inline suppression marker.
    marker_lines: Vec<u32>,
    /// Source lines in the file.
    lines: u64,
    diagnostics: usize,
}

/// Execute `codehelion scan` in Fast mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report
/// output fails. Per-file problems (unreadable or malformed sources) are
/// counted and reported instead of failing the scan.
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    let started_at = rfc3339_now();
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let (cfg, guardrails) = guarded(config::load(args.config.as_deref(), &root)?.config, args);
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(&root, &cfg, args.no_ignore)?;
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;

    let db_path = database_path(&root, args.db.as_deref(), &cfg);
    let lex_timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (lexed, unreadable, timed_out) = lex_sources(&sources, jobs, lex_timeout)?;

    let engine_config = engine_config(&cfg)?;
    let input: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|file| InputFile {
            tokens: &file.tokens,
            units: &file.units,
        })
        .collect();
    let contexts: Vec<FileContext<'_>> = lexed
        .iter()
        .map(|file| FileContext {
            frontend_version: file.frontend_version,
            language: file.language,
        })
        .collect();
    let report = engine::detect(&input, &engine_config);
    let ids = stable_id::report_ids(
        &input,
        &contexts,
        &discovered.build_variant,
        &report,
        engine_config.literals,
    );

    let suppression =
        evaluate_suppression(args, &cfg, &discovered.build_variant, &lexed, &report, &ids)?;
    let Suppression {
        rules,
        baseline,
        groups: group_suppressed,
    } = suppression;

    let finished_at = rfc3339_now();
    let mut inputs = BuildInputs {
        root: &root,
        db_path: &db_path,
        // Both filled in from the recording below, which cannot run until the
        // entries it records the ranking of exist.
        run_id: 0,
        started_at: &started_at,
        finished_at: &finished_at,
        discovered: &discovered,
        glob_excluded,
        unreadable,
        timed_out,
        lexed: &lexed,
        report: &report,
        ids: &ids,
        rules: &rules,
        group_suppressed: &group_suppressed,
        suppression: &cfg.suppression,
        weights: cfg.priority.weights(),
        min_clone_tokens: u64::from(cfg.min_clone_tokens),
        literals: engine_config.literals,
    };
    let stored = summary_row(&inputs, baseline.as_ref().map(ScanBaseline::digest));
    let groups = rank_and_record(&mut inputs, &cfg, &contexts, file_rows(&sources), &stored)?;
    let mut model = build_report(&inputs, &stored, groups);
    model.summary.guardrails = guardrails;
    // Counted against the assembled report rather than the raw analysis: a
    // stale entry is one whose duplication this run does not list.
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| baseline_status(baseline, &model.groups));
    write_report(args, out, &model)?;
    Ok(outcome(args, &model))
}

/// What this invocation lets a compiler helper run out of the project.
///
/// Every way the permission could not take effect is refused here rather than
/// accepted and quietly dropped. A granted permission changes what a person
/// believes the run did: they think the thin part of the answer is the
/// project's, when it is the tool's.
///
/// # Errors
///
/// Fails on a class name that does not exist, on a permission given to a mode
/// that runs nothing, and on one given alongside `--untrusted`.
pub(crate) fn permitted(args: &ScanArgs) -> Result<ExecutionPolicy> {
    let Some(names) = args.allow_execution.as_deref() else {
        return Ok(ExecutionPolicy::deny_all());
    };
    if args.untrusted {
        bail!(
            "--untrusted permits nothing to run, and --allow-execution={names} \
             asks for something to. Drop whichever of the two was not meant"
        );
    }
    if args.mode != Mode::Semantic {
        bail!(
            "--allow-execution={names} has nothing to act on in {} mode, which \
             reads source and runs nothing; it applies to --mode semantic",
            args.mode.name()
        );
    }
    ExecutionPolicy::parse(names).map_err(Into::into)
}

/// What a finished scan exits with: findings present only when the caller
/// asked to be told by the status, and only counting what the report shows —
/// a suppressed group is one the reader said not to be told about.
pub(crate) fn outcome(args: &ScanArgs, model: &Report) -> Outcome {
    let visible = model
        .groups
        .iter()
        .filter(|group| group.suppressed.is_none())
        .count();
    if args.fail_on_findings && visible > 0 {
        Outcome::FindingsPresent
    } else {
        Outcome::Success
    }
}

/// What suppression decided for one run.
struct Suppression {
    /// The compiled rules, which the snapshot records.
    rules: suppress::Rules,
    /// The baseline the scan was given, if any.
    baseline: Option<ScanBaseline>,
    /// The rule hiding each group, parallel to the engine's groups.
    groups: Vec<Option<usize>>,
}

/// Compile the suppression rules, apply the baseline, and decide which rule
/// hides each detected group.
fn evaluate_suppression(
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
        &mut rules,
        variant,
        &detector_versions(
            cfg.priority.weights(),
            literal_norm(cfg.literal_normalization),
        ),
    )?;
    let file_suppressions: Vec<suppress::FileSuppression> = lexed
        .iter()
        .map(|file| rules.evaluate_file(&file.relative_path, &file.marker_lines, &unit_spans(file)))
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
            rules
                .clone_id_rule(&group_ids.fingerprint.to_hex())
                .or_else(|| group_rule(&rules, &file_suppressions, group))
                .or_else(|| rules.baseline_rule(&group_ids.fingerprint.to_hex()))
        })
        .collect();
    Ok(Suppression {
        rules,
        baseline,
        groups,
    })
}

/// Everything [`build_report`] needs from the pipeline.
struct BuildInputs<'a> {
    root: &'a Path,
    db_path: &'a Path,
    run_id: i64,
    started_at: &'a str,
    finished_at: &'a str,
    discovered: &'a DiscoveryReport,
    glob_excluded: usize,
    unreadable: u64,
    timed_out: u64,
    lexed: &'a [LexedSource],
    report: &'a EngineReport,
    ids: &'a [GroupIds],
    rules: &'a suppress::Rules,
    group_suppressed: &'a [Option<usize>],
    /// What the report does with each classification a group can carry, which
    /// is what decides where a classified group is listed.
    suppression: &'a config::Suppression,
    /// How the run weighs the priority measures against one another.
    weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    min_clone_tokens: u64,
    /// The literal strategy the content ids were folded under.
    literals: LiteralNorm,
}

/// The configured suppression rules that hid nothing this run, read off the
/// rules the groups actually cited.
fn unused_suppressions(inputs: &BuildInputs<'_>) -> Vec<report::UnusedRule> {
    let used: BTreeSet<usize> = inputs
        .group_suppressed
        .iter()
        .filter_map(|rule| *rule)
        .collect();
    inputs
        .rules
        .unused(&used)
        .into_iter()
        .map(|row| report::UnusedRule {
            scope: row.scope.clone(),
            pattern: row.pattern.clone(),
        })
        .collect()
}

/// A count as the report model carries it. Saturating rather than fallible:
/// a count this large is already past any meaning a report could carry.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The Fast pipeline's pass counts, stage by stage: a winnowed fingerprint
/// index, the seed pairs its posting lists propose, the fragments the
/// identifier-normalized pass cuts from those seeds, the pairs that pass
/// proposes in turn, and the pairs that survive verification.
///
/// Both pairing stages carry their own budget accounting, because both hold
/// their own allowance.
fn funnel(stats: &engine::EngineStats) -> Vec<report::FunnelStage> {
    vec![
        report::FunnelStage::new("tokens", as_u64(stats.tokens)),
        report::FunnelStage::new("fingerprints", as_u64(stats.raw_fingerprints)),
        report::FunnelStage::new(
            "indexed values",
            as_u64(stats.raw_distinct.saturating_sub(stats.stop_fingerprints)),
        )
        .dropping("high_frequency", as_u64(stats.stop_fingerprints))
        .dropping("high_frequency_postings", as_u64(stats.stop_postings)),
        report::FunnelStage::new("seed pairs", as_u64(stats.seed_candidates)).dropping(
            "pair_budget",
            as_u64(
                stats
                    .raw_pairs_available
                    .saturating_sub(stats.seed_candidates),
            ),
        ),
        report::FunnelStage::new("fragments", as_u64(stats.fragments)),
        report::FunnelStage::new("fragment classes", as_u64(stats.fragment_classes))
            .dropping("class_cap", as_u64(stats.class_cap_dropped))
            .dropping("hash_collision", as_u64(stats.hash_collisions)),
        // The two passes hold separate allowances, so each says separately how
        // much of its own search it got through. One combined figure would let
        // a pass that stopped early hide behind one that finished.
        report::FunnelStage::new("fragment pairs", as_u64(stats.fragment_candidates)).dropping(
            "pair_budget",
            as_u64(
                stats
                    .fragment_pairs_available
                    .saturating_sub(stats.fragment_candidates),
            ),
        ),
        report::FunnelStage::new("verified pairs", as_u64(stats.pairs)),
    ]
}

/// What the run reported about itself beyond the groups it found, in the shape
/// the audit database stores.
///
/// Built before the snapshot is written and read back out of it by
/// [`build_summary`], so the recorded run and the printed report carry one set
/// of numbers rather than two derivations that happen to agree.
fn summary_row(inputs: &BuildInputs<'_>, baseline_digest: Option<String>) -> SummaryRow {
    SummaryRow {
        lines: inputs.lexed.iter().map(|file| file.lines).sum(),
        tokens: as_u64(inputs.report.stats.tokens),
        lexer_diagnostics: as_u64(inputs.lexed.iter().map(|file| file.diagnostics).sum()),
        // Fast mode lexes and does not parse, so it has nothing to report
        // here; a zero would read as "the parser followed everything".
        unparsed: None,
        excluded_generated: as_u64(inputs.discovered.suppressed_generated.len()),
        excluded_by_glob: as_u64(inputs.glob_excluded),
        excluded_skipped: inputs.discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
        // The Fast engine compares whole units, so it folds and subsumes no
        // runs, and its equivalence classes need no refinement to bound.
        folded_runs: 0,
        subsumed_runs: 0,
        split_components: 0,
        pair_budget_exhausted: inputs.report.stats.pair_budget_exhausted,
        baseline_digest,
        funnel: report::stored_funnel(&funnel(&inputs.report.stats)),
        unused_suppressions: report::stored_rules(&unused_suppressions(inputs)),
    }
}

/// The summary block, counted off the assembled entries and the stored row so
/// that neither the listing nor the database can disagree with it.
fn build_summary(
    inputs: &BuildInputs<'_>,
    stored: &SummaryRow,
    groups: &[report::Group],
) -> report::Summary {
    let count = |language: Language| {
        u64::try_from(
            inputs
                .lexed
                .iter()
                .filter(|file| file.language == language)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    let files = report::FileCounts {
        total: as_u64(inputs.lexed.len()),
        rust: count(Language::Rust),
        c: count(Language::C),
        cpp: count(Language::Cpp),
    };
    report::restored(files, stored, groups)
}

/// Assemble the report model both output formats render from, from the groups
/// the run already ranked, in the order every view shows them in.
fn build_report(
    inputs: &BuildInputs<'_>,
    stored: &SummaryRow,
    mut groups: Vec<report::Group>,
) -> Report {
    report::order(&mut groups, inputs.suppression);
    Report {
        schema_version: report::SCHEMA_VERSION,
        run: run_info(inputs),
        summary: build_summary(inputs, stored, &groups),
        groups,
    }
}

/// What produced the results: the tool, the settings, and where the snapshot
/// went. Every value here qualifies the findings rather than describing them.
fn run_info(inputs: &BuildInputs<'_>) -> report::RunInfo {
    let variant = &inputs.discovered.build_variant;
    report::RunInfo {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        mode: variant.mode.name().to_string(),
        root: inputs.root.display().to_string(),
        started_at: inputs.started_at.to_string(),
        finished_at: inputs.finished_at.to_string(),
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
        detector_versions: detector_versions(inputs.weights, inputs.literals)
            .into_iter()
            .map(|(component, version)| report::DetectorVersion { component, version })
            .collect(),
        ranking: report::RankingInfo {
            recipe: inputs.weights.recipe(),
            maintenance_risk: inputs.weights.maintenance_risk,
            refactoring_ease: inputs.weights.refactoring_ease,
        },
        database: inputs.db_path.display().to_string(),
        run_id: inputs.run_id,
    }
}

/// One group of the report model, ranked, with its suppression cause resolved.
fn build_group(inputs: &BuildInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.report.groups[index];
    let suppressed = group.suppressed.map_or_else(
        || {
            inputs.group_suppressed[index].map(|rule| {
                let row = &inputs.rules.rows[rule];
                report::Suppression {
                    kind: report::SuppressionKind::Rule,
                    reason: None,
                    scope: Some(row.scope.clone()),
                    pattern: Some(row.pattern.clone()),
                }
            })
        },
        |reason| {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some(reason.name().to_string()),
                scope: None,
                pattern: None,
            })
        },
    );
    report::ranked(
        report::Group {
            fingerprint: inputs.ids[index].fingerprint.to_hex(),
            clone_type: group.clone_type.name().to_string(),
            scope: CloneScope::Unit.name().to_string(),
            statements: None,
            confidence: group.score,
            priority: report::Priority::unranked(),
            // The Fast engine groups on identical content; it scores no
            // similarity dimensions to report, classifies no shapes and reads no
            // test marker: all three need Syntax IR, which this mode never builds.
            // Members of identical content differ in nothing, so no substitution
            // could say they were written per width either.
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            width_family: false,
            suppressed,
            split_pair: false,
            semantic: None,
            members: group
                .members
                .iter()
                .zip(&inputs.ids[index].members)
                .enumerate()
                .map(|(position, (instance, member_ids))| {
                    let source = &inputs.lexed[instance.file];
                    report::Member {
                        finding_id: member_ids.finding.to_hex(),
                        content: member_ids.content.to_hex(),
                        file: source.relative_path.clone(),
                        language: source.language.name().to_string(),
                        start_line: instance.start_line,
                        end_line: instance.end_line,
                        unit: instance
                            .unit
                            .and_then(|unit| source.units[unit].name.clone()),
                        boilerplate: None,
                        tokens: u64::try_from(instance.token_end - instance.token_start)
                            .unwrap_or(u64::MAX),
                        canonical: position == 0,
                    }
                })
                .collect(),
        },
        &inputs.weights,
        inputs.min_clone_tokens,
    )
}

/// Render the model in the requested format, to `--output` when given,
/// otherwise to `out`. Colour is used only for text going to a terminal.
pub(crate) fn write_report(args: &ScanArgs, out: &mut impl Write, model: &Report) -> Result<()> {
    write_report_options(
        ReportOutput {
            format: args.format,
            output: args.output.as_deref(),
            verbose: args.verbose,
            show_suppressed: args.show_suppressed,
        },
        out,
        model,
    )
}

/// Output choices shared by a freshly scanned and a recorded report.
#[derive(Clone, Copy)]
pub(crate) struct ReportOutput<'a> {
    /// Chosen serialization.
    pub format: Format,
    /// Optional destination instead of standard output.
    pub output: Option<&'a Path>,
    /// Whether text output lists every group and member.
    pub verbose: bool,
    /// Whether text output includes suppressed groups.
    pub show_suppressed: bool,
}

/// Render a complete report with the common output path.
pub(crate) fn write_report_options(
    options: ReportOutput<'_>,
    out: &mut impl Write,
    model: &Report,
) -> Result<()> {
    let text = match options.format {
        Format::Json => model.to_json().context("serializing the JSON report")?,
        Format::Sarif => sarif_with_artifact_savings(model)?,
        Format::Text => {
            let options = report::TextOptions {
                verbose: options.verbose,
                color: options.output.is_none() && std::io::stdout().is_terminal(),
                show_suppressed: options.show_suppressed,
            };
            let mut buffer = Vec::new();
            model.render_text(options, &mut buffer)?;
            String::from_utf8(buffer).context("rendering the text report")?
        }
    };
    match options.output {
        Some(path) => {
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
        }
        None => out.write_all(text.as_bytes())?,
    }
    Ok(())
}

/// Render source SARIF and attach artifact data only where local correlation
/// established a group-level estimate. Source-only scans therefore retain the
/// exact SARIF shape they had before artifact analysis existed.
fn sarif_with_artifact_savings(model: &Report) -> Result<String> {
    let mut sarif: Value =
        serde_json::from_str(&model.to_sarif()?).context("parsing the generated SARIF document")?;
    let store = Store::open(Path::new(&model.run.database))
        .with_context(|| format!("opening audit database {}", model.run.database))?;
    let mut savings = BTreeMap::new();
    for group in &model.groups {
        let entries = store.clone_group_savings(model.run.run_id, &group.fingerprint)?;
        if !entries.is_empty() {
            let entries = entries
                .into_iter()
                .map(|(analysis_id, entry)| {
                    let assumptions = serde_json::from_str::<Value>(&entry.assumptions_json)
                        .context("parsing persisted artifact savings assumptions for SARIF")?;
                    Ok(json!({
                        "artifact_analysis_id": analysis_id,
                        "source_build_variant_fingerprint": artifact_fingerprint_hex(entry.source_build_variant_fingerprint),
                        "artifact_build_variant_fingerprint": artifact_fingerprint_hex(entry.artifact_build_variant_fingerprint),
                        "duplicated_bytes": entry.duplicated_bytes,
                        "estimated_refactor_savings_bytes": entry.estimated_refactor_savings_bytes,
                        "mapping_confidence": artifact_savings_confidence(entry.mapping_confidence),
                        "clone_confidence": entry.clone_confidence,
                        "model_confidence": artifact_savings_confidence(entry.model_confidence),
                        "savings_confidence": artifact_savings_confidence(entry.savings_confidence),
                        "model_schema_version": entry.model_schema_version,
                        "assumptions": assumptions,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            savings.insert(group.fingerprint.clone(), Value::Array(entries));
        }
    }
    attach_sarif_artifact_savings(&mut sarif, &savings)?;
    let mut text = serde_json::to_string_pretty(&sarif)?;
    text.push('\n');
    Ok(text)
}

fn attach_sarif_artifact_savings(
    sarif: &mut Value,
    savings: &BTreeMap<String, Value>,
) -> Result<()> {
    let results = sarif
        .pointer_mut("/runs/0/results")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("generated SARIF has no result array"))?;
    for result in results {
        let Some(fingerprint) = result
            .pointer("/partialFingerprints/cloneGroupFingerprint~1v1")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(group_savings) = savings.get(fingerprint) else {
            continue;
        };
        let properties = result
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("generated SARIF result has no property bag"))?;
        properties.insert("artifact_savings".to_owned(), group_savings.clone());
    }
    Ok(())
}

fn artifact_fingerprint_hex(fingerprint: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(fingerprint.len().saturating_mul(2));
    for byte in fingerprint {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

const fn artifact_savings_confidence(
    confidence: codehelion_store::artifact::ArtifactAnalysisSavingsConfidence,
) -> &'static str {
    use codehelion_store::artifact::ArtifactAnalysisSavingsConfidence;
    match confidence {
        ArtifactAnalysisSavingsConfidence::High => "high",
        ArtifactAnalysisSavingsConfidence::Medium => "medium",
        ArtifactAnalysisSavingsConfidence::Low => "low",
        ArtifactAnalysisSavingsConfidence::Unavailable => "unavailable",
    }
}

/// Render independent semantic reports without inventing a combined variant.
///
/// A compilation database can describe several programs in one source tree.
/// JSON therefore names every report under `partitions`; text separates whole
/// reports, and SARIF joins its standard `runs` array. None of those sums
/// findings or coverage across different build variants.
pub(crate) fn write_partitioned_reports(
    args: &ScanArgs,
    out: &mut impl Write,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_language: Option<&report::CrossLanguageComparison>,
) -> Result<()> {
    if let ([model], None, None) = (models, cross_variant, cross_language) {
        return write_report(args, out, model);
    }
    let text = match args.format {
        Format::Json => partitioned_json(models, cross_variant, cross_language)?,
        Format::Sarif => partitioned_sarif(models, cross_variant, cross_language)?,
        Format::Text => partitioned_text(args, models, cross_variant, cross_language)?,
    };
    write_partitioned_text(args, out, &text)
}

fn partitioned_json(
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_language: Option<&report::CrossLanguageComparison>,
) -> Result<String> {
    let mut value = serde_json::Map::new();
    value.insert("partitions".to_string(), serde_json::json!(models));
    if let Some(comparison) = cross_variant {
        value.insert(
            "cross_variant_comparison".to_string(),
            serde_json::json!(comparison),
        );
    }
    if let Some(comparison) = cross_language {
        value.insert(
            "cross_language_comparison".to_string(),
            serde_json::json!(comparison),
        );
    }
    serde_json::to_string_pretty(&Value::Object(value))
        .context("serializing partitioned JSON reports")
}

fn partitioned_sarif(
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_language: Option<&report::CrossLanguageComparison>,
) -> Result<String> {
    let mut runs = Vec::new();
    for model in models {
        let log: Value = serde_json::from_str(
            &model
                .to_sarif()
                .context("serializing a partitioned SARIF report")?,
        )
        .context("reading a partitioned SARIF report")?;
        if let Some(mut contained) = log.get("runs").and_then(Value::as_array).cloned() {
            runs.append(&mut contained);
        }
    }
    if let Some(comparison) = cross_variant {
        runs.push(cross_variant_sarif_run(comparison));
    }
    if let Some(comparison) = cross_language {
        runs.push(cross_language_sarif_run(comparison));
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }))
    .context("serializing partitioned SARIF reports")
}

fn cross_variant_sarif_run(comparison: &report::CrossVariantComparison) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-build-variant-exact",
                "name": "CrossBuildVariantExactClone",
                "shortDescription": { "text": "Exact clone across build variants" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-build-variants" },
        "results": comparison.groups.iter().map(cross_variant_sarif_result).collect::<Vec<_>>(),
        "properties": { "crossVariantComparison": comparison }
    })
}

fn cross_variant_sarif_result(group: &report::CrossVariantGroup) -> Value {
    serde_json::json!({
        "ruleId": "comparison/cross-build-variant-exact", "level": "note",
        "message": { "text": "Exact Type-1 clone across independent build variants" },
        "partialFingerprints": { "crossVariantGroupFingerprint/v1": group.id },
        "locations": group.members.first().map(cross_variant_sarif_location).into_iter().collect::<Vec<_>>(),
        "relatedLocations": group.members.iter().map(cross_variant_sarif_location).collect::<Vec<_>>()
    })
}

fn cross_variant_sarif_location(member: &report::CrossVariantMember) -> Value {
    serde_json::json!({
        "physicalLocation": { "artifactLocation": { "uri": member.file },
            "region": { "startLine": member.start_line, "endLine": member.end_line } },
        "properties": { "originVariant": member.origin_variant }
    })
}

fn cross_language_sarif_run(comparison: &report::CrossLanguageComparison) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-language-semantic",
                "name": "CrossLanguageRestrictedSemantic",
                "shortDescription": { "text": "Registered Rust-to-C++ semantic pipeline" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-language" },
        "results": comparison.groups.iter().map(cross_language_sarif_result).collect::<Vec<_>>(),
        "properties": { "crossLanguageComparison": comparison }
    })
}

fn cross_language_sarif_result(group: &report::CrossLanguageGroup) -> Value {
    serde_json::json!({
        "ruleId": "comparison/cross-language-semantic", "level": "note",
        "message": { "text": format!("Registered cross-language semantic rule {}", group.rule_id) },
        "partialFingerprints": { "crossLanguageGroupFingerprint/v1": group.id },
        "locations": group.members.first().map(cross_language_sarif_location).into_iter().collect::<Vec<_>>(),
        "relatedLocations": group.members.iter().map(cross_language_sarif_location).collect::<Vec<_>>(),
        "properties": {
            "ruleVersion": group.rule_version,
            "semanticConfidence": group.semantic_confidence,
            "correspondenceIds": group.correspondence_ids,
        }
    })
}

fn cross_language_sarif_location(member: &report::CrossLanguageMember) -> Value {
    serde_json::json!({
        "physicalLocation": { "artifactLocation": { "uri": member.file },
            "region": { "startLine": member.start_line, "endLine": member.end_line } },
        "properties": { "originVariant": member.origin_variant, "language": member.language }
    })
}

fn partitioned_text(
    args: &ScanArgs,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_language: Option<&report::CrossLanguageComparison>,
) -> Result<String> {
    let options = report::TextOptions {
        verbose: args.verbose,
        color: args.output.is_none() && std::io::stdout().is_terminal(),
        show_suppressed: args.show_suppressed,
    };
    let mut rendered = Vec::new();
    for model in models {
        model.render_text(options, &mut rendered)?;
        rendered.extend_from_slice(b"\n\n");
    }
    let mut text = String::from_utf8(rendered).context("rendering partitioned text reports")?;
    if let Some(comparison) = cross_variant {
        append_cross_variant_text(&mut text, comparison)?;
    }
    if let Some(comparison) = cross_language {
        if cross_variant.is_some() {
            text.push('\n');
        }
        append_cross_language_text(&mut text, comparison)?;
    }
    Ok(text)
}

fn append_cross_variant_text(
    text: &mut String,
    comparison: &report::CrossVariantComparison,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(
        text,
        "Cross-build-variant comparison (exact Type-1 units only)"
    )?;
    writeln!(text, "policy: {}", comparison.policy_version)?;
    writeln!(text, "comparison: {}", comparison.comparison_id)?;
    writeln!(
        text,
        "origin variants: {}",
        comparison.origin_variants.join(", ")
    )?;
    for group in &comparison.groups {
        writeln!(text, "  {} ({})", group.id, group.clone_type)?;
        for member in &group.members {
            writeln!(
                text,
                "    [{}] {}:{}-{}",
                member.origin_variant, member.file, member.start_line, member.end_line
            )?;
        }
    }
    Ok(())
}

fn append_cross_language_text(
    text: &mut String,
    comparison: &report::CrossLanguageComparison,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(
        text,
        "Cross-language comparison (registered semantic pipelines only)"
    )?;
    writeln!(text, "policy: {}", comparison.policy_version)?;
    writeln!(text, "comparison: {}", comparison.comparison_id)?;
    writeln!(
        text,
        "origin variants: {}",
        comparison.origin_variants.join(", ")
    )?;
    for group in &comparison.groups {
        writeln!(
            text,
            "  {} ({} v{}, confidence {:.2})",
            group.id, group.rule_id, group.rule_version, group.semantic_confidence
        )?;
        writeln!(
            text,
            "    Correspondences: {}",
            group.correspondence_ids.join(", ")
        )?;
        for member in &group.members {
            writeln!(
                text,
                "    [{} {}] {}:{}-{}",
                member.origin_variant,
                member.language,
                member.file,
                member.start_line,
                member.end_line
            )?;
        }
    }
    Ok(())
}

fn write_partitioned_text(args: &ScanArgs, out: &mut impl Write, text: &str) -> Result<()> {
    match args.output.as_deref() {
        Some(path) => {
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
        }
        None => out.write_all(text.as_bytes())?,
    }
    Ok(())
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

/// A report entry's ranking as the audit database records it.
///
/// Both analysis modes go through here, so what the store holds is what the
/// report showed rather than a second derivation of it.
pub(crate) const fn priority_row(priority: &report::Priority) -> PriorityRow {
    PriorityRow {
        clone_confidence: priority.clone_confidence,
        maintenance_risk: priority.maintenance_risk,
        refactoring_difficulty: priority.refactoring_difficulty,
        final_priority: priority.value,
        semantic_confidence: priority.semantic_confidence,
        source_artifact_confidence: priority.source_artifact_confidence,
        savings_confidence: priority.savings_confidence,
    }
}

/// Resolve the worker-thread count: flag over configuration over the number
/// of available CPUs.
pub(crate) fn effective_jobs(flag: Option<usize>, configured: Option<usize>) -> Result<usize> {
    match flag.or(configured) {
        Some(0) => bail!("jobs must be at least 1"),
        Some(jobs) => Ok(jobs),
        None => Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)),
    }
}

/// The name the lowered-ceiling profile is reported under.
const UNTRUSTED_PROFILE: &str = "untrusted";

/// The configuration a scan actually works under, once the command line has
/// had its say, and what to report about it.
///
/// The profile only ever *lowers* a ceiling. A configuration already stricter
/// than the profile stays where it is: taking the profile's number outright
/// would let asking for less trust loosen a deliberately tight setting, which
/// is the opposite of what asking for it means.
///
/// The candidate ceiling is set rather than clamped because leaving it unset
/// means "each pass keeps its own default", and every one of those defaults is
/// above the profile's number.
pub(crate) fn guarded(mut cfg: Config, args: &ScanArgs) -> (Config, Option<report::Guardrails>) {
    if !args.untrusted {
        return (cfg, None);
    }
    let profile = codehelion_core::execution::Limits::untrusted();
    let timeout = u64::try_from(profile.parse_timeout.as_millis()).unwrap_or(u64::MAX);
    cfg.limits.max_file_bytes = cfg.limits.max_file_bytes.min(profile.max_file_bytes);
    cfg.limits.parse_timeout_ms = cfg.limits.parse_timeout_ms.min(timeout);
    let budget = cfg
        .limits
        .pair_budget
        .map_or(profile.max_candidates, |set| {
            set.min(profile.max_candidates)
        });
    cfg.limits.pair_budget = Some(budget);
    let guardrails = report::Guardrails {
        profile: UNTRUSTED_PROFILE,
        max_file_bytes: cfg.limits.max_file_bytes,
        parse_timeout_ms: cfg.limits.parse_timeout_ms,
        pair_budget: budget,
    };
    (cfg, Some(guardrails))
}

/// Build the engine configuration from the effective scan configuration:
/// detection knobs plus any candidate ceiling the configuration overrides.
fn engine_config(cfg: &Config) -> Result<EngineConfig> {
    let defaults = EngineConfig::default();
    Ok(EngineConfig {
        min_clone_tokens: usize::try_from(cfg.min_clone_tokens)
            .context("min-clone-tokens out of range")?,
        literals: literal_norm(cfg.literal_normalization),
        posting_cap: cfg.limits.posting_cap.unwrap_or(defaults.posting_cap),
        pair_budget: cfg.limits.pair_budget.unwrap_or(defaults.pair_budget),
        ..defaults
    })
}

/// Map the configured literal strategy onto the engine's.
pub(crate) const fn literal_norm(setting: LiteralNormalization) -> LiteralNorm {
    match setting {
        LiteralNormalization::Preserve => LiteralNorm::Preserve,
        LiteralNormalization::Category => LiteralNorm::Category,
        LiteralNormalization::Full => LiteralNorm::Full,
    }
}

/// Run project discovery under the effective configuration.
pub(crate) fn discover_sources(
    root: &Path,
    cfg: &Config,
    no_ignore: bool,
) -> Result<DiscoveryReport> {
    let discovery_config = DiscoveryConfig {
        respect_gitignore: !no_ignore,
        max_file_bytes: cfg.limits.max_file_bytes,
        languages: LanguageSelection {
            rust: cfg.languages.rust,
            c: cfg.languages.c,
            cpp: cfg.languages.cpp,
        },
        header_policy: cfg.languages.headers.into(),
        generated_markers: GeneratedMarkers::new(
            &cfg.suppression.generated_markers,
            DEFAULT_SCAN_LINES,
        ),
    };
    Ok(discovery::discover(root, &discovery_config)?)
}

/// Apply the configured include/exclude globs to the discovered sources.
/// Returns the retained sources and how many were filtered out.
pub(crate) fn filter_globs(
    cfg: &Config,
    sources: Vec<SourceUnit>,
) -> Result<(Vec<SourceUnit>, usize)> {
    let include = build_globset(&cfg.include).context("in include globs")?;
    let exclude = build_globset(&cfg.exclude).context("in exclude globs")?;
    let before = sources.len();
    let kept: Vec<SourceUnit> = sources
        .into_iter()
        .filter(|source| {
            let path = &source.relative_path;
            include.as_ref().is_none_or(|globs| globs.is_match(path))
                && exclude.as_ref().is_none_or(|globs| !globs.is_match(path))
        })
        .collect();
    let excluded = before - kept.len();
    Ok((kept, excluded))
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("glob pattern {pattern:?}"))?);
    }
    Ok(Some(builder.build()?))
}

/// What became of one source file handed to a frontend.
pub(crate) enum FileOutcome<T> {
    /// Read and analysed within the time ceiling.
    Done(Box<T>),
    /// The file could not be read.
    Unreadable,
    /// The frontend exceeded the configured time ceiling; the file is
    /// excluded.
    TimedOut,
}

/// Run `frontend` over every source, spreading contiguous chunks across
/// `jobs` worker threads.
///
/// Chunks are joined in order, so the result order equals the (deterministic)
/// discovery order regardless of thread scheduling. Files that vanished since
/// discovery or blew the time ceiling are counted, not fatal. Returns the
/// analysed files plus the unreadable and timed-out counts.
pub(crate) fn map_sources<T: Send>(
    sources: &[SourceUnit],
    jobs: usize,
    frontend: impl Fn(&SourceUnit) -> FileOutcome<T> + Sync,
) -> Result<(Vec<T>, u64, u64)> {
    if sources.is_empty() {
        return Ok((Vec::new(), 0, 0));
    }
    let chunk_size = sources.len().div_ceil(jobs);
    let mut chunk_results: Vec<Vec<FileOutcome<T>>> = Vec::new();
    let mut worker_panicked = false;
    let frontend = &frontend;
    std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(frontend).collect::<Vec<_>>()))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(results) => chunk_results.push(results),
                Err(_) => worker_panicked = true,
            }
        }
    });
    if worker_panicked {
        bail!("a frontend worker thread panicked");
    }
    let mut analysed = Vec::with_capacity(sources.len());
    let mut unreadable = 0u64;
    let mut timed_out = 0u64;
    for result in chunk_results.into_iter().flatten() {
        match result {
            FileOutcome::Done(file) => analysed.push(*file),
            FileOutcome::Unreadable => unreadable += 1,
            FileOutcome::TimedOut => timed_out += 1,
        }
    }
    Ok((analysed, unreadable, timed_out))
}

/// Lex every source with the Fast frontends.
fn lex_sources(
    sources: &[SourceUnit],
    jobs: usize,
    timeout: std::time::Duration,
) -> Result<(Vec<LexedSource>, u64, u64)> {
    map_sources(sources, jobs, |source| lex_one(source, timeout))
}

/// Read and lex one source file, enforcing the per-file time ceiling.
///
/// The ceiling is checked after the (single-pass, linear-time) lexer
/// returns: with the discovery size ceiling bounding the input, lexing
/// cannot run away, so a post-hoc check suffices to keep an unexpectedly
/// slow file out of the results while the skipped count keeps it visible.
fn lex_one(source: &SourceUnit, timeout: std::time::Duration) -> FileOutcome<LexedSource> {
    let started = std::time::Instant::now();
    let Ok(bytes) = std::fs::read(&source.absolute_path) else {
        return FileOutcome::Unreadable;
    };
    let text = String::from_utf8_lossy(&bytes);
    let file = match source.language {
        Language::Rust => codehelion_frontend_rust::RustFrontend.lex(&text),
        Language::C => codehelion_frontend_c::CFrontend.lex(&text),
        Language::Cpp => codehelion_frontend_cpp::CppFrontend.lex(&text),
    };
    if started.elapsed() > timeout {
        return FileOutcome::TimedOut;
    }
    let unit_lines = file
        .units
        .iter()
        .map(|unit| {
            let end = unit.token_end.min(file.tokens.len());
            let end_line = file.tokens[unit.token_start..end]
                .last()
                .map_or(unit.span.start_line, |token| token.span.start_line);
            (unit.span.start_line, end_line)
        })
        .collect();
    FileOutcome::Done(Box::new(LexedSource {
        relative_path: source.relative_path.to_string_lossy().into_owned(),
        language: file.language,
        frontend_version: file.frontend_version,
        tokens: file.tokens,
        units: file.units,
        unit_lines,
        marker_lines: suppress::marker_lines(&text),
        lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
        diagnostics: file.diagnostics.len(),
    }))
}

/// The audit-database location: an explicit flag is taken as given (relative
/// to the working directory); the configured path resolves against the
/// repository root unless absolute.
pub(crate) fn database_path(root: &Path, flag: Option<&Path>, cfg: &Config) -> PathBuf {
    flag.map_or_else(
        || {
            if cfg.database.is_absolute() {
                cfg.database.clone()
            } else {
                repository_root(root).join(&cfg.database)
            }
        },
        Path::to_path_buf,
    )
}

/// Find the repository containing a scan root, falling back to the scan root
/// when it is not inside a Git worktree.
fn repository_root(root: &Path) -> PathBuf {
    let mut current = Some(root);
    while let Some(directory) = current {
        if directory.join(".git").exists() {
            return directory.to_path_buf();
        }
        current = directory.parent();
    }
    root.to_path_buf()
}

/// A baseline a scan was told to apply.
pub(crate) struct ScanBaseline {
    /// The file as it was named on the command line.
    file: String,
    /// The group ids it froze.
    ids: BTreeSet<String>,
    /// Why it does not describe this run, when it does not.
    mismatch: Option<String>,
    /// What differs without stopping its entries matching.
    caveat: Option<String>,
}

impl ScanBaseline {
    /// A digest of the frozen set, for recording which one a run was reported
    /// against.
    ///
    /// Over the ids alone: the file's path and the order its entries are
    /// written in change nothing about what is hidden, and two runs given the
    /// same frozen set under two names report the same findings.
    pub(crate) fn digest(&self) -> String {
        let mut joined = String::new();
        for id in &self.ids {
            joined.push_str(id);
            joined.push('\n');
        }
        ContentHash::of(joined.as_bytes()).as_str().to_string()
    }
}

/// Load the baseline a scan was given and register it as a suppression rule.
///
/// A baseline recorded under conditions this run does not share is loaded and
/// registered all the same: none of its ids can match, so it hides nothing,
/// and letting that happen through the ordinary path keeps the reported
/// counts true. What it must not do is happen quietly — the mismatch travels
/// with the status so the report can say it outright.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not a baseline this
/// build understands. A named file that cannot be applied is a mistake worth
/// stopping for; silently scanning without it would report findings the user
/// asked to have hidden.
pub(crate) fn load_baseline(
    path: Option<&Path>,
    rules: &mut suppress::Rules,
    variant: &BuildVariant,
    detectors: &[(String, String)],
) -> Result<Option<ScanBaseline>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let baseline = crate::baseline::Baseline::load(path)?;
    let fit = baseline.compatibility(&variant.fingerprint(), detectors);
    let ids: BTreeSet<String> = baseline
        .entries
        .iter()
        .map(|entry| entry.group.clone())
        .collect();
    let file = path.display().to_string();
    rules.add_baseline(&file, ids.clone());
    Ok(Some(ScanBaseline {
        file,
        ids,
        mismatch: fit.mismatch,
        caveat: fit.caveat,
    }))
}

/// What the baseline did to this run, counted against what the run found.
///
/// An entry counts as matched when the duplication it froze is still detected,
/// whichever rule ended up hiding it: the question a stale count answers is
/// whether the duplication is gone, not which reason won.
pub(crate) fn baseline_status(
    baseline: &ScanBaseline,
    groups: &[report::Group],
) -> report::BaselineStatus {
    let reported: BTreeSet<&str> = groups
        .iter()
        .map(|group| group.fingerprint.as_str())
        .collect();
    let matched = baseline
        .ids
        .iter()
        .filter(|id| reported.contains(id.as_str()))
        .count();
    report::BaselineStatus {
        file: baseline.file.clone(),
        entries: as_u64(baseline.ids.len()),
        matched: as_u64(matched),
        stale: as_u64(baseline.ids.len().saturating_sub(matched)),
        mismatch: baseline.mismatch.clone(),
        caveat: baseline.caveat.clone(),
    }
}

/// The tree a scan read, as rows to record beside its findings.
///
/// Every discovered file is here, including the ones that yielded no unit: a
/// later scan compares trees, and a file missing from the record is one it
/// would call newly added.
pub(crate) fn file_rows(units: &[SourceUnit]) -> Vec<FileRow> {
    units
        .iter()
        .map(|unit| FileRow {
            relative_path: unit.relative_path.to_string_lossy().into_owned(),
            content_hash: unit.content_hash.as_str().to_string(),
            language: unit.language,
            byte_len: unit.byte_len,
        })
        .collect()
}

/// Rank every entry, persist the snapshot, and fill in what the recording
/// decided: the run id and what became of the duplication since last time.
///
/// The order matters and is the point of the arrangement. The ranking reads
/// the assembled report entries, and the audit database stores what those
/// entries say, so a run's two accounts of where a finding belongs are one
/// account written twice rather than two derivations that happen to agree.
fn rank_and_record(
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
    let detector_versions = detector_versions(
        cfg.priority.weights(),
        literal_norm(cfg.literal_normalization),
    );
    let root_path = inputs.root.to_string_lossy();
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
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
/// Everything that can differ between two builds and be *seen* in the result
/// belongs here, including the ranking recipe, which moves no identifier at
/// all. Baselines require this complete list to match exactly; the unreleased
/// v1 format does not reinterpret prior detector configurations.
fn detector_versions(weights: Weights, literals: LiteralNorm) -> Vec<(String, String)> {
    vec![
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        ("ranking".to_string(), weights.recipe()),
        (
            "literals".to_string(),
            ContentNorm::Normalized(literals).label().to_string(),
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
        .map(|(index, ((group, group_ids), suppressed_by))| GroupRow {
            fingerprint: group_ids.fingerprint,
            clone_type: group.clone_type,
            member_scope: CloneScope::Unit,
            // A whole unit's extent is the unit; only a run inside one has a
            // statement count to record.
            statements: None,
            // Fast mode compares tokens without a syntax tree, so it never
            // sees the attribute that marks a test.
            split_pair: false,
            test_code: false,
            score: group.score,
            entropy_bits: group.entropy_bits,
            suppress_reason: group.suppressed.map(|reason| reason.name().to_string()),
            boilerplate: None,
            identifier_jaccard: None,
            has_loop: None,
            has_dynamic_allocation: None,
            call_count: None,
            width_family: false,
            suppressed_by: *suppressed_by,
            priority: priority_row(&ranked[index].priority),
            // Fast mode measures no similarity breakdown and classifies no
            // boilerplate shapes.
            similarity: None,
            semantic: None,
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
        })
        .collect();
    (units, groups)
}

/// The current time as fixed-width RFC 3339 UTC with microsecond precision.
///
/// Hand-formatted so the width never varies: lexicographic order then equals
/// chronological order, which the store's latest-run ordering relies on.
pub(crate) fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let micros = now.subsec_micros();
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rem = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
    )
}

/// Convert days since 1970-01-01 to a proleptic-Gregorian civil date.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_point = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_point + 2) / 5 + 1;
    let month = if month_point < 10 {
        month_point + 3
    } else {
        month_point - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cross_language_comparison_stays_in_its_own_report_domain() {
        let comparison = report::CrossLanguageComparison {
            policy_version: "cross-language-semantic-v1".to_string(),
            comparison_id: "aabb".to_string(),
            comparison_kind: "restricted-semantic-rust-cpp-pipelines".to_string(),
            origin_variants: vec!["cpp".to_string(), "rust".to_string()],
            groups: Vec::new(),
        };
        let json: Value = serde_json::from_str(
            &partitioned_json(&[], None, Some(&comparison)).expect("JSON report"),
        )
        .expect("valid JSON");
        assert!(json.get("cross_variant_comparison").is_none());
        assert_eq!(
            json["cross_language_comparison"]["comparison_kind"],
            "restricted-semantic-rust-cpp-pipelines"
        );

        let sarif: Value = serde_json::from_str(
            &partitioned_sarif(&[], None, Some(&comparison)).expect("SARIF report"),
        )
        .expect("valid SARIF JSON");
        assert_eq!(
            sarif["runs"][0]["automationDetails"]["id"],
            "codehelion/cross-language"
        );
    }

    #[test]
    fn sarif_attaches_artifact_savings_only_to_matching_results() {
        let mut sarif = json!({
            "runs": [{
                "results": [
                    {
                        "partialFingerprints": { "cloneGroupFingerprint/v1": "aabb" },
                        "properties": {}
                    },
                    {
                        "partialFingerprints": { "cloneGroupFingerprint/v1": "ccdd" },
                        "properties": {}
                    }
                ]
            }]
        });
        let savings = BTreeMap::from([(
            "aabb".to_owned(),
            json!([{
                "estimated_refactor_savings_bytes": 9,
                "source_build_variant_fingerprint": "01".repeat(16),
                "artifact_build_variant_fingerprint": "02".repeat(16),
                "savings_confidence": "low",
                "assumptions": [{ "kind": "inlining_outcome_unknown" }],
            }]),
        )]);
        attach_sarif_artifact_savings(&mut sarif, &savings).unwrap();
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["artifact_savings"][0]["estimated_refactor_savings_bytes"],
            9
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["artifact_savings"][0]["source_build_variant_fingerprint"],
            "01".repeat(16)
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["artifact_savings"][0]["assumptions"][0]["kind"],
            "inlining_outcome_unknown"
        );
        assert!(
            sarif["runs"][0]["results"][1]["properties"]
                .get("artifact_savings")
                .is_none()
        );
    }

    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // leap year start
        assert_eq!(civil_from_days(19_783), (2024, 3, 1)); // day after Feb 29
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn timestamps_are_fixed_width_rfc3339() {
        let stamp = rfc3339_now();
        assert_eq!(stamp.len(), "1970-01-01T00:00:00.000000Z".len());
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp.as_bytes()[10], b'T');
    }

    fn scan_args(untrusted: bool) -> ScanArgs {
        ScanArgs {
            path: PathBuf::from("."),
            mode: Mode::Fast,
            format: Format::Text,
            output: None,
            config: None,
            no_ignore: false,
            jobs: None,
            db: None,
            baseline: None,
            allow_execution: None,
            compare_build_variants: false,
            compare_languages: false,
            show_suppressed: false,
            include_trivial: false,
            verbose: false,
            fail_on_findings: false,
            untrusted,
        }
    }

    #[test]
    fn a_scan_that_was_not_told_to_distrust_the_tree_keeps_its_settings() {
        let before = Config::default();
        let (after, guardrails) = guarded(Config::default(), &scan_args(false));
        assert_eq!(after.limits, before.limits);
        assert!(guardrails.is_none());
    }

    /// The ceilings a repository nobody vouches for is read under, and the
    /// report line that says so — a scan that read less has to be
    /// distinguishable from a tree that holds less.
    #[test]
    fn distrusting_the_tree_lowers_every_ceiling_and_says_which() {
        let defaults = Config::default();
        let (tightened, guardrails) = guarded(Config::default(), &scan_args(true));
        assert!(tightened.limits.max_file_bytes < defaults.limits.max_file_bytes);
        assert!(tightened.limits.parse_timeout_ms < defaults.limits.parse_timeout_ms);
        assert_eq!(tightened.limits.pair_budget, Some(500_000));
        let reported = guardrails.expect("a lowered ceiling is reported");
        assert_eq!(reported.profile, UNTRUSTED_PROFILE);
        assert_eq!(reported.max_file_bytes, tightened.limits.max_file_bytes);
        assert_eq!(reported.parse_timeout_ms, tightened.limits.parse_timeout_ms);
    }

    /// Asking for less trust must not hand back more room. A configuration
    /// already stricter than the profile is the stricter of the two, or the
    /// flag would be a way to loosen a deliberately tight setting.
    #[test]
    fn a_setting_already_stricter_than_the_profile_survives_it() {
        let mut cfg = Config::default();
        cfg.limits.max_file_bytes = 1024;
        cfg.limits.parse_timeout_ms = 1;
        cfg.limits.pair_budget = Some(10);
        let (tightened, _) = guarded(cfg, &scan_args(true));
        assert_eq!(tightened.limits.max_file_bytes, 1024);
        assert_eq!(tightened.limits.parse_timeout_ms, 1);
        assert_eq!(tightened.limits.pair_budget, Some(10));
    }

    /// A distrusting scan keeps the stricter ceilings in its effective
    /// configuration, so it never reads more of the tree than requested.
    #[test]
    fn distrust_changes_the_effective_configuration() {
        let plain = Config::default().to_toml().unwrap();
        let (tightened, _) = guarded(Config::default(), &scan_args(true));
        assert_ne!(tightened.to_toml().unwrap(), plain);
    }

    #[test]
    fn jobs_resolution_prefers_flag_then_config() {
        assert_eq!(effective_jobs(Some(3), Some(8)).unwrap(), 3);
        assert_eq!(effective_jobs(None, Some(8)).unwrap(), 8);
        assert!(effective_jobs(None, None).unwrap() >= 1);
        assert!(effective_jobs(Some(0), None).is_err());
    }

    #[test]
    fn engine_config_applies_configured_ceilings() {
        let cfg = Config {
            limits: config::Limits {
                posting_cap: Some(5),
                pair_budget: Some(7),
                ..config::Limits::default()
            },
            ..Config::default()
        };
        let engine = engine_config(&cfg).unwrap();
        assert_eq!(engine.posting_cap, 5);
        assert_eq!(engine.pair_budget, 7);
        // Detection knobs stay at their defaults.
        assert_eq!(engine.min_clone_tokens, 20);
    }

    /// An unset ceiling leaves the mode at the default measured for it, rather
    /// than at a number carried over from the configuration type.
    #[test]
    fn an_unset_ceiling_leaves_the_engine_at_its_own_default() {
        let engine = engine_config(&Config::default()).unwrap();
        let defaults = EngineConfig::default();
        assert_eq!(engine.posting_cap, defaults.posting_cap);
        assert_eq!(engine.pair_budget, defaults.pair_budget);
    }

    #[test]
    fn glob_filter_applies_include_then_exclude() {
        let cfg = Config {
            include: vec!["src/**".to_string()],
            exclude: vec!["src/gen/**".to_string()],
            ..Config::default()
        };
        let sources = ["src/a.rs", "src/gen/b.rs", "vendor/c.rs"]
            .iter()
            .map(|path| SourceUnit {
                relative_path: PathBuf::from(path),
                absolute_path: PathBuf::from(path),
                language: Language::Rust,
                is_header: false,
                content_hash: ContentHash::of(b""),
                byte_len: 0,
                package: None,
                crate_name: None,
                target_kind: discovery::TargetKind::Library,
            })
            .collect();
        let (kept, excluded) = filter_globs(&cfg, sources).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].relative_path, PathBuf::from("src/a.rs"));
        assert_eq!(excluded, 2);
    }

    #[test]
    fn malformed_globs_are_an_error() {
        let cfg = Config {
            include: vec!["src/[".to_string()],
            ..Config::default()
        };
        assert!(filter_globs(&cfg, Vec::new()).is_err());
    }
}
