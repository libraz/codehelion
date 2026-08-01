//! The `scan --mode structural` pipeline: from project discovery to the
//! recorded snapshot, over parsed Syntax IR instead of a raw token stream.
//!
//! The stages mirror the Fast pipeline — resolve configuration, discover
//! sources, run the per-language frontends across worker threads, detect,
//! record one atomic snapshot, render a report — but the frontends here are
//! parsers and detection is the structural funnel (candidate extraction,
//! near-match, weighted verification, medoid grouping). Like Fast, nothing in
//! this path executes target code: files are only read and parsed.
//!
//! What a group carries differs: members are similar rather than identical,
//! so every group reports its per-dimension similarity breakdown, and the
//! dimension the mode cannot measure (types) is reported as absent rather
//! than guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::CloneScope;
use codehelion_core::discovery::{
    BuildConfiguration, BuildVariant, ContentHash, CppBuild, DiscoveryReport, Language,
    LanguageSelection, RustBuild, SourceUnit, content_hash,
};
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::features;
use codehelion_core::frontend::Token;
use codehelion_core::grouping::{GroupingConfig, StructuralGroup};
use codehelion_core::ir::{ByteRange, StructuralFrontend, SyntaxIrFile};
use codehelion_core::priority::Weights;
use codehelion_core::semantic::{
    CrossLanguageCandidateInput, SemanticCandidateConfig, SemanticCandidateStats,
    SemanticGroupingStats, SemanticGroupingUnit, SemanticOperationGraph, SemanticRule,
    VerifiedSemanticPair, extract_cross_language_candidates, extract_registered_candidates,
    group_verified_semantic_pairs, registered_semantic_windows, verify_cross_language_candidates,
    verify_registered_candidates,
};
use codehelion_core::stable_id;
use codehelion_core::structural::{
    self, CrossVariantUnit, GroupDetail, RegionOccurrence, SourceTokenSpan, StructuralConfig,
    StructuralRegion, StructuralReport, StructuralUnit, VerifiedPair,
};
use codehelion_core::test_code::{self, TestCodeEvidence};
use codehelion_core::verify::WEIGHT_VERSION;
use codehelion_store::compiler::{self as store_compiler, CompilerHelperRow, CompilerOutcome};
use codehelion_store::snapshot::{
    CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow, CrossLanguageSemanticMemberRow,
    CrossVariantComparisonSnapshot, CrossVariantGroupRow, CrossVariantMemberRow, FeatureRow,
    FileRow, GroupRow, MemberRow, PriorityRow, SemanticEvidenceRow, SemanticNodeMappingRow,
    SemanticOperationGraphRow, SiblingGroupRow, SiblingRow, SimilarityBreakdownRow, Snapshot,
    SummaryRow, UnitRow,
};

use super::{
    FileOutcome, ScanBaseline, as_u64, database_path, discover_sources, effective_jobs,
    exceeds_parse_budget, filter_globs, literal_norm, map_sources, open_store, path_key,
    rfc3339_now, shared, write_partitioned_reports,
};

use crate::Outcome;
use crate::cli::ScanArgs;
use crate::config::{self, BoilerplatePolicy, CategoryAction, Config};
use crate::report::{self, Report};
use crate::semantic;
use crate::suppress;
use codehelion_core::doctor;
use codehelion_core::execution::{Execution as PermittedExecution, ExecutionPolicy};
use codehelion_helper::ir::{ControlFlowGraph, DataFlowSummary, EdgeKind};
use codehelion_helper::protocol::{CompileCommandSelector, Execution};
use codehelion_helper::{Helper, SandboxRequest};

/// The reporting metadata of one parsed source file.
struct SourceMeta {
    relative_path: String,
    language: Language,
    /// 1-based lines carrying an inline suppression marker.
    marker_lines: Vec<u32>,
    /// Source lines in the file.
    lines: u64,
    diagnostics: usize,
    /// Tokens the parser could not attach to any structure.
    unaccounted_tokens: u64,
    /// Whether parsing stopped at the structural depth ceiling.
    depth_truncated: bool,
}

/// One parsed source file: its Syntax IR plus the metadata that travels with
/// it. The two are split apart before analysis, which consumes the IR files
/// as one slice.
struct ParsedSource {
    meta: SourceMeta,
    ir: SyntaxIrFile,
}

/// One normalized SOG anchored to the syntactic unit it describes.
#[derive(Debug, Clone)]
struct SemanticUnitGraph {
    unit: usize,
    /// Exact source bytes for this semantic window, used only for reporting.
    range: ByteRange,
    /// First source line covered by this semantic window.
    start_line: u32,
    /// Last source line covered by this semantic window.
    end_line: u32,
    /// Parsed tokens covered by this semantic window.
    token_count: usize,
    graph: SemanticOperationGraph,
    content: stable_id::FragmentFingerprint,
    /// How completely the closed API registry described this parser-owned
    /// unit. This may lower semantic confidence but never invents or removes
    /// a registered-rule match.
    normalization_confidence: f64,
    /// Closed interactions observed inside this exact SOG window. An empty
    /// set is unknown evidence, never a purity claim.
    interactions: BTreeSet<String>,
    /// Compiler-confirmed direct `filter`/`map` receiver flows in this exact
    /// window. Missing evidence is neutral rather than a claim that no flow
    /// exists.
    data_flows: BTreeSet<(String, String)>,
    /// Compiler-produced CFG shape that overlaps this exact window. It is
    /// supplementary confidence evidence only; absence never removes a match.
    cfg_shape: Option<CfgShape>,
}

/// A deliberately small, language-neutral summary of the CFG that covers one
/// semantic window.
///
/// The summary counts blocks and interior edge kinds rather than preserving
/// compiler-local block indices. It cannot establish semantic equivalence; it
/// only corroborates or weakens a match the closed SOG rule already verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CfgShape {
    blocks: u32,
    flow_edges: u32,
    taken_edges: u32,
    not_taken_edges: u32,
    unwind_edges: u32,
    return_edges: u32,
}

/// Non-authoritative compiler evidence that can adjust one SOG match's
/// confidence without changing whether the registered rule matched.
#[derive(Clone, Copy)]
struct SemanticConfidenceEvidence<'a> {
    normalization: f64,
    interactions: &'a BTreeSet<String>,
    data_flows: &'a BTreeSet<(String, String)>,
    cfg_shape: Option<CfgShape>,
}

impl SemanticUnitGraph {
    const fn confidence_evidence(&self) -> SemanticConfidenceEvidence<'_> {
        SemanticConfidenceEvidence {
            normalization: self.normalization_confidence,
            interactions: &self.interactions,
            data_flows: &self.data_flows,
            cfg_shape: self.cfg_shape,
        }
    }
}

/// One registered semantic correspondence between two whole units that no
/// cohesive semantic group jointly represents.
#[derive(Debug, Clone)]
struct SemanticPair {
    canonical: SemanticUnitGraph,
    corresponding: SemanticUnitGraph,
    rule: SemanticRule,
    /// Rule confidence after the two normalizations' coverage is considered.
    semantic_confidence: f64,
}

/// A cohesive registered-rule correspondence group, with a medoid chosen by
/// the core-owned complete-linkage adapter.
#[derive(Debug, Clone)]
struct SemanticGroup {
    canonical: SemanticUnitGraph,
    /// The canonical member is first; every other member has a separately
    /// verified correspondence to every member in this group.
    members: Vec<SemanticUnitGraph>,
    rule: SemanticRule,
    semantic_confidence: f64,
}

/// Bounded registered-semantic matching plus the accounting that makes every
/// omitted candidate visible in the scan funnel.
#[derive(Debug, Clone)]
struct SemanticDetection {
    groups: Vec<SemanticGroup>,
    pairs: Vec<SemanticPair>,
    /// Every normalized graph retained for an explicit cross-language
    /// comparison. Ordinary partition reports never inspect this collection.
    units: Vec<SemanticUnitGraph>,
    candidates: SemanticCandidateStats,
    /// Compiler-resolved API observations accepted by the closed registry.
    registered_observations: usize,
    /// Compiler-resolved API observations that the closed registry declined
    /// to normalize. They remain visible in the funnel but never become a
    /// semantic finding by approximation.
    excluded_observations: usize,
    /// Parser-owned units with no registered operation after normalization.
    unrepresentable_units: usize,
    /// Semantic windows excluded because they are shorter than the scan's
    /// configured minimum clone length.
    below_min_clone_tokens: usize,
    verified_pairs: usize,
    disabled_pairs: usize,
    grouping: SemanticGroupingStats,
}

/// One owned unit retained solely until an opt-in cross-variant comparison is
/// recorded. Normal partition reports never hold or consume these values.
struct CrossComparisonUnit {
    origin_variant: String,
    language: Language,
    file_path: String,
    start_line: u32,
    end_line: u32,
    name: Option<String>,
    tokens: Vec<Token>,
}

/// One owned semantic unit retained solely for an opt-in Rust-to-C++ comparison.
struct CrossLanguageComparisonUnit {
    origin_variant: String,
    language: Language,
    file_path: String,
    start_line: u32,
    end_line: u32,
    name: Option<String>,
    graph: SemanticOperationGraph,
    content: stable_id::FragmentFingerprint,
    normalization_confidence: f64,
    interactions: BTreeSet<String>,
    data_flows: BTreeSet<(String, String)>,
    cfg_shape: Option<CfgShape>,
}

impl CrossLanguageComparisonUnit {
    const fn confidence_evidence(&self) -> SemanticConfidenceEvidence<'_> {
        SemanticConfidenceEvidence {
            normalization: self.normalization_confidence,
            interactions: &self.interactions,
            data_flows: &self.data_flows,
            cfg_shape: self.cfg_shape,
        }
    }
}

/// The ordinary report plus source units available to an opt-in comparison.
struct PartitionOutcome {
    outcome: Outcome,
    report: Report,
    comparison_units: Vec<CrossComparisonUnit>,
    cross_language_units: Vec<CrossLanguageComparisonUnit>,
}

/// Execute `codehelion scan` in Structural mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report output
/// fails. Per-file problems (unreadable or malformed sources) are counted and
/// reported instead of failing the scan.
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    run_with(args, out, None)
}

/// Execute `codehelion scan` in Semantic mode: the same pipeline, over what a
/// compiler resolved about the same files.
///
/// # Errors
///
/// Additionally fails when no compiler helper is installed or the installed
/// one cannot be talked to. Semantic mode does not fall back to Structural: a
/// run that answered without a compiler and called itself semantic would be
/// syntactic results under another name, and nothing downstream could tell.
pub fn semantic(
    args: &ScanArgs,
    permitted: &ExecutionPolicy,
    out: &mut impl Write,
) -> Result<Outcome> {
    let sandbox = semantic_sandbox(args)?;
    let compilers = Compilers::found(permitted, sandbox)?;
    run_with(args, out, Some(&compilers))
}

/// Containment requested for compiler helpers in this semantic run.
///
/// The untrusted profile requires the core profile's subprocess ceiling. A
/// platform that cannot apply it fails before any helper is launched rather
/// than analysing an untrusted tree with an unenforced policy.
mod helpers;

use helpers::{Compilers, Installed, asking_about, helper_timeout, semantic_sandbox};

#[cfg(test)]
use helpers::{installed_helper, unavailable_execution_message};

#[allow(clippy::too_many_lines)]
fn run_with(
    args: &ScanArgs,
    out: &mut impl Write,
    compilers: Option<&Compilers>,
) -> Result<Outcome> {
    if args.compare_build_variants && compilers.is_none() {
        bail!("--compare-build-variants requires --mode semantic");
    }
    if args.compare_languages && compilers.is_none() {
        bail!("--compare-languages requires --mode semantic");
    }
    let started_at = rfc3339_now();
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = database_path(&root, args.db.as_deref(), &resolved_config, args.untrusted)?;
    let _database_lock = crate::scan_lock::acquire(&db_path)?;
    let configuration = crate::scan::configuration_info(
        &resolved_config.source,
        resolved_config.config.min_clone_tokens,
    );
    let (cfg, guardrails) = crate::scan::guarded(resolved_config.config, args);
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(&root, &cfg, args.no_ignore)?;
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;

    let asking = asking_about(compilers, &sources)?;
    if compilers.is_some() {
        let compiler_version = clang_toolchain(asking.as_deref());
        let mut partitions =
            cpp_partitions(&discovered, &sources, &cfg, compiler_version.as_deref());
        if let Some(unconfigured) = unconfigured_cpp_partition(&discovered, &sources) {
            partitions.push(unconfigured);
        }
        if let Some(rust) = rust_partition(
            &sources,
            asking.as_deref(),
            discovered.header_language,
            &root,
            helper_timeout(&cfg),
        )? {
            partitions.push(rust);
        }
        partitions.sort_by_cached_key(|partition| partition.variant.fingerprint());
        if !partitions.is_empty() {
            let mut reports = Vec::with_capacity(partitions.len());
            let mut comparison_units = Vec::new();
            let mut cross_language_units = Vec::new();
            let mut outcome = Outcome::Success;
            for (index, partition) in partitions.into_iter().enumerate() {
                // Discovery happens before a source can belong to a build
                // variant. Record its exclusions exactly once rather than
                // copying them into every independent semantic report. The
                // partition list is fingerprint-sorted above, so this owner
                // is deterministic.
                let shared_discovery = (index == 0).then_some(&discovered);
                let partition = run_semantic_partition(
                    args,
                    &cfg,
                    guardrails.as_ref(),
                    jobs,
                    &root,
                    &db_path,
                    &configuration,
                    &started_at,
                    shared_discovery,
                    &partition.sources,
                    glob_excluded,
                    asking.as_deref(),
                    &partition,
                )?;
                if partition.outcome == Outcome::FindingsPresent {
                    outcome = Outcome::FindingsPresent;
                }
                comparison_units.extend(partition.comparison_units);
                cross_language_units.extend(partition.cross_language_units);
                reports.push(partition.report);
            }
            let comparison = if args.compare_build_variants {
                record_cross_variant_comparison(&db_path, &root, &started_at, &comparison_units)?
            } else {
                None
            };
            let comparison_not_run = args
                .compare_build_variants
                .then(|| comparison.is_none())
                .filter(|not_run| *not_run)
                .map(|_| cross_variant_comparison_not_run(&reports));
            let cross_language_comparison = if args.compare_languages {
                record_cross_language_comparison(
                    &db_path,
                    &root,
                    &started_at,
                    &cross_language_units,
                    &cfg,
                )?
            } else {
                None
            };
            let run_ids: Vec<i64> = reports.iter().map(|report| report.run.run_id).collect();
            open_store(&db_path)?.complete_snapshot_parts(&run_ids)?;
            write_partitioned_reports(
                args,
                out,
                &reports,
                comparison.as_ref(),
                comparison_not_run.as_ref(),
                cross_language_comparison.as_ref(),
            )?;
            return Ok(outcome);
        }
    }
    let variant = variant_of(asking.as_deref(), &cfg, discovered.header_language, &root)?;
    let timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (parsed, unreadable, timed_out) =
        map_sources(&sources, jobs, |source| parse_one(source, timeout))?;
    let (files, mut irs): (Vec<SourceMeta>, Vec<SyntaxIrFile>) = parsed
        .into_iter()
        .map(|source| (source.meta, source.ir))
        .unzip();
    mark_test_modules(&files, &mut irs);

    let (asked, resolved) = resolve(
        asking.as_deref(),
        &sources,
        &files,
        &variant,
        &BTreeMap::new(),
        std::time::Duration::from_millis(cfg.limits.helper_timeout_ms),
    );
    let mut analysis =
        structural::analyze_resolved(&irs, &variant, &structural_config(&cfg), &resolved);
    mark_test_paths(&cfg, &files, &mut analysis)?;
    let semantic = registered_semantic_pairs(
        asked.as_ref(),
        &sources,
        &files,
        &irs,
        &analysis,
        &variant,
        &cfg,
    )?;

    let mut rules = compile_rules(&cfg, &files, &analysis)?;
    let matched_rules: BTreeSet<usize> = rules
        .files
        .iter()
        .flat_map(suppress::FileSuppression::matched_rules)
        .collect();
    let baseline = crate::scan::load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules.rules,
        &variant,
        &detector_versions(literal_norm(cfg.literal_normalization)),
    )?;
    let regions = reportable_regions(&analysis);
    let mut presentation_cfg = cfg.clone();
    presentation_cfg.suppression = presentation_suppression(&cfg, args.include_trivial);
    let suppressed = evaluate_suppression(
        &presentation_cfg,
        &mut rules,
        &analysis,
        &regions,
        &semantic.groups,
        &semantic.pairs,
        &variant,
    );

    let finished_at = rfc3339_now();
    let inputs = ReportInputs {
        root: &root,
        db_path: &db_path,
        configuration: &configuration,
        started_at: &started_at,
        finished_at: &finished_at,
        variant: &variant,
        files: &files,
        irs: &irs,
        analysis: &analysis,
        semantic_groups: &semantic.groups,
        semantic_pairs: &semantic.pairs,
        semantic_detection: &semantic,
        rules: &rules.rules,
        matched_rules: &matched_rules,
        group_suppressed: &suppressed.groups,
        regions: &regions,
        region_suppressed: &suppressed.regions,
        suppression: &presentation_cfg.suppression,
        pair_suppressed: &suppressed.pairs,
        semantic_pair_suppressed: &suppressed.semantic_pairs,
        semantic_group_suppressed: &suppressed.semantic_groups,
        literals: literal_norm(cfg.literal_normalization),
        glob_excluded,
        unreadable,
        timed_out,
        weights: cfg.priority.weights(),
        min_clone_tokens: u64::from(cfg.min_clone_tokens),
        sort: args.sort.axis(),
    };
    // Ranked before recorded: the audit database and the report are two views
    // of one verdict about where each finding belongs, not two derivations of
    // it that happen to agree.
    let groups = build_groups(&inputs);
    let stored = summary_row(
        &inputs,
        Some(&discovered),
        baseline.as_ref().map(ScanBaseline::digest),
        guardrails.as_ref(),
    );
    let run_id = record(
        &cfg,
        &inputs,
        &groups,
        crate::scan::file_rows(&sources),
        &stored,
        asked.as_ref(),
        true,
    )?;
    let mut model = build_report(&inputs, run_id, &stored, groups);
    model.summary.guardrails = guardrails;
    model.summary.compiler = asked.as_ref().map(coverage);
    // Counted against the assembled report rather than the raw analysis: a
    // stale entry is one whose duplication this run does not list.
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| crate::scan::apply_baseline(baseline, &mut model.groups));
    let outcome = crate::scan::outcome(args, &model);
    let models = [model];
    let comparison_not_run = args
        .compare_build_variants
        .then(|| cross_variant_comparison_not_run(&models));
    write_partitioned_reports(args, out, &models, None, comparison_not_run.as_ref(), None)?;
    Ok(outcome)
}

mod comparison;

use comparison::{
    cross_variant_comparison_not_run, record_cross_language_comparison,
    record_cross_variant_comparison,
};

#[cfg(test)]
use comparison::{copy_guardrails, cross_language_funnel, enabled_cross_language_matches};

/// What the results belong to.
///
/// Discovery reports the Fast variant; these results belong to the Structural
/// or Semantic one, and no two of the three ever share a fingerprint. The
/// header grammar carries over unchanged: it decided which frontend read every
/// `.h` below, so it describes these results just as it does Fast's.
fn variant_of(
    asking: Option<&[&Installed]>,
    cfg: &Config,
    headers: Language,
    root: &Path,
) -> Result<BuildVariant> {
    let languages = LanguageSelection {
        rust: cfg.languages.rust,
        c: cfg.languages.c,
        cpp: cfg.languages.cpp,
    };
    let Some(asking) = asking else {
        return Ok(BuildVariant::structural(languages, headers));
    };
    let builds = asking
        .iter()
        .map(|helper| helper.build(root, helper_timeout(cfg)))
        .collect::<Result<Vec<_>>>()?;
    Ok(BuildVariant::semantic(languages, headers, builds))
}

/// One independently recorded semantic program. Headers are present in every
/// C/C++ partition because the selected translation units are what give them
/// meaning; their compiler answers never cross this boundary.
mod semantic_analysis;

use comparison::run_semantic_partition;
use semantic_analysis::{
    SemanticPartition, clang_toolchain, cpp_partitions, registered_semantic_pairs, resolve,
    rust_partition, semantic_confidence, semantic_member_ranks, semantic_scope,
    unconfigured_cpp_partition,
};

#[cfg(test)]
use semantic_analysis::{
    cfg_confidence, data_flow_confidence, interaction_confidence, normalization_confidence,
    semantic_window_cfg_shape, semantic_window_data_flows,
};

/// What the compilers managed to say about the tree, as the report puts it.
///
/// The restarts are summed across the helpers, because a restart is trouble the
/// run had rather than trouble one program had: what a reader does with the
/// number is decide whether a thin result was the tree's fault.
fn coverage(asked: &semantic::Answers) -> report::CompilerCoverage {
    let mut unavailable: BTreeMap<String, u64> = BTreeMap::new();
    let mut answered = 0;
    let mut not_asked = 0;
    let mut build_script_refused = 0_u64;
    for answer in &asked.per_source {
        match answer {
            semantic::Answer::Analyzed { .. } => answered += 1,
            semantic::Answer::NotAsked { .. } => not_asked += 1,
            semantic::Answer::Unavailable { reason, .. } => {
                *unavailable.entry(reason.name().to_string()).or_default() += 1;
                // The only whole-unit `RequiresExecution` outcome the shipped
                // helper emits is a Cargo build script. Procedural macros are
                // recorded as individual unexpanded invocations instead, so
                // this mapping neither guesses a broader permission nor
                // hides the precise one the user can grant.
                if *reason == codehelion_helper::ir::Unavailability::RequiresExecution {
                    build_script_refused = build_script_refused.saturating_add(1);
                }
            }
        }
    }
    let execution_refusals = ExecutionPolicy::deny_all()
        .refusal(PermittedExecution::BuildScript)
        .filter(|_| build_script_refused > 0)
        .map(|refusal| {
            let message = refusal.describe();
            report::ExecutionRefusal {
                execution: refusal.execution.name().to_string(),
                files: build_script_refused,
                cost: refusal.cost.to_string(),
                permission_argument: refusal.permission_argument,
                message,
            }
        })
        .into_iter()
        .collect();
    report::CompilerCoverage {
        answered,
        not_asked,
        unavailable,
        execution_refusals,
        restarts: asked
            .helpers
            .iter()
            .map(|helper| helper.restarts)
            .fold(0, u32::saturating_add),
    }
}

/// Read and parse one source file, enforcing the deterministic parse-work
/// budget before frontend work begins.
fn parse_one(source: &SourceUnit, budget: std::time::Duration) -> FileOutcome<ParsedSource> {
    let Ok(bytes) = std::fs::read(&source.absolute_path) else {
        return FileOutcome::Unreadable;
    };
    if exceeds_parse_budget(&bytes, budget) {
        return FileOutcome::TimedOut;
    }
    let text = String::from_utf8_lossy(&bytes);
    let ir = match source.language {
        Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(&text),
        Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(&text),
        Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(&text),
    };
    let unaccounted_tokens = as_u64(ir.unaccounted_tokens());
    FileOutcome::Done(Box::new(ParsedSource {
        meta: SourceMeta {
            relative_path: path_key(&source.relative_path),
            language: source.language,
            marker_lines: suppress::marker_lines(&text),
            lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
            diagnostics: ir.diagnostics.len(),
            unaccounted_tokens,
            depth_truncated: ir.depth_truncated,
        },
        ir,
    }))
}

/// Record which parsed files are the body of a module the tree declares
/// test-only.
///
/// A parse sees one file, and the `#[cfg(test)]` that puts a file in the suite
/// is written on the declaration in another one. This is where the whole set
/// is in hand, so it is where the two are put together.
mod suppression;

use suppression::{
    ReportableRegions, aggregate_test_code_evidence, compile_rules, evaluate_suppression,
    local_unit_indices, mark_test_modules, mark_test_paths, presentation_suppression,
    region_identifier_jaccard, region_test_code_evidence, reportable_regions, structural_config,
    unit_token_span,
};

#[cfg(test)]
use suppression::{pair_shape_suppression, unanimous_boilerplate};

/// Everything the report and the snapshot are assembled from.
struct ReportInputs<'a> {
    root: &'a Path,
    db_path: &'a Path,
    configuration: &'a report::ConfigurationInfo,
    started_at: &'a str,
    finished_at: &'a str,
    variant: &'a BuildVariant,
    files: &'a [SourceMeta],
    irs: &'a [SyntaxIrFile],
    analysis: &'a StructuralReport,
    /// Cohesive registered-rule findings from complete-linkage refinement.
    semantic_groups: &'a [SemanticGroup],
    /// Explainable restricted-semantic correspondences produced from compiler
    /// facts for this exact `BuildVariant`.
    semantic_pairs: &'a [SemanticPair],
    /// Bounded-candidate accounting for the restricted-semantic branch.
    semantic_detection: &'a SemanticDetection,
    rules: &'a suppress::Rules,
    /// Selectors that matched scanned source, independently from the rule
    /// that ultimately hid each finding.
    matched_rules: &'a BTreeSet<usize>,
    group_suppressed: &'a [Option<usize>],
    /// The duplicated runs the report lists.
    regions: &'a ReportableRegions,
    /// The rule hiding each listed run, parallel to [`Self::regions`].
    region_suppressed: &'a [Option<usize>],
    /// What the report does with each classification a group can carry:
    /// boilerplate shape, test-suite residence, width family, and being a
    /// pair no group could hold.
    suppression: &'a config::Suppression,
    /// The rule hiding each verified pair no group could hold, parallel to
    /// the analysis's own list of them.
    pair_suppressed: &'a [Option<usize>],
    /// The rule hiding each restricted-semantic pair, parallel to
    /// [`Self::semantic_pairs`].
    semantic_pair_suppressed: &'a [Option<usize>],
    /// The rule hiding each cohesive semantic group, parallel to
    /// [`Self::semantic_groups`].
    semantic_group_suppressed: &'a [Option<usize>],
    /// Literal strategy the group content is scored under.
    literals: LiteralNorm,
    glob_excluded: usize,
    unreadable: u64,
    timed_out: u64,
    /// How the run weighs the priority measures against one another.
    weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    min_clone_tokens: u64,
    /// The axis the run puts its entries in order on.
    sort: report::Sort,
}

impl ReportInputs<'_> {
    /// The tokens one analysed unit covers, in its own file.
    fn unit_tokens(&self, unit: &StructuralUnit) -> &[Token] {
        let tokens = &self.irs[unit.file].tokens;
        let end = unit.token_end.min(tokens.len());
        let start = unit.token_start.min(end);
        &tokens[start..end]
    }

    /// The configured suppression rules whose selectors matched no scanned
    /// source or finding in this run.
    fn unused_suppressions(&self) -> Vec<report::UnusedRule> {
        shared::unused_suppressions(
            self.rules,
            self.matched_rules.iter().copied().chain(
                self.group_suppressed
                    .iter()
                    .chain(self.region_suppressed)
                    .chain(self.pair_suppressed)
                    .chain(self.semantic_pair_suppressed)
                    .chain(self.semantic_group_suppressed)
                    .filter_map(|rule| *rule),
            ),
        )
    }

    /// The tokens one occurrence of a duplicated run covers, in its own file.
    fn region_tokens(&self, occurrence: &RegionOccurrence) -> &[Token] {
        let tokens = &self.irs[occurrence.file].tokens;
        let end = occurrence.token_end.min(tokens.len());
        let start = occurrence.token_start.min(end);
        &tokens[start..end]
    }

    /// The suppression a report entry carries, from the index of the rule
    /// that hid it.
    fn suppression(&self, rule: usize) -> report::Suppression {
        shared::rule_suppression(self.rules, rule)
    }
}

/// Similarity reported for a confirmed duplicated run.
///
/// A run is confirmed by hashing the tokens its occurrences cover, so every
/// occurrence carries identical content under the run's literal strategy.
/// That is an exact match rather than a scored one: the similarity is 1 and
/// there is no per-dimension breakdown to report, for the same reason the
/// Fast engine reports none.
const REGION_SIMILARITY: f64 = 1.0;

/// Every reported entry, in the order the views render them: ranked-down
/// entries last, then the run's chosen axis descending, then fingerprint
/// ascending, so every view is stable across reruns.
///
/// Duplicated units and duplicated runs share one ranking. They describe the
/// code differently, and each entry says which it is, but they compete for
/// the same attention and a reader wants the biggest duplication first
/// whichever shape it has.
mod reporting;

#[cfg(test)]
use reporting::{DiscoveryExclusions, discovery_exclusions, funnel};
use reporting::{build_groups, build_report, detector_versions, summary_row};

mod store;

use store::record;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
