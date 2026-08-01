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
use codehelion_core::boilerplate::{BOILERPLATE_VERSION, Boilerplate};
use codehelion_core::clone_class::CloneScope;
use codehelion_core::discovery::{
    BuildConfiguration, BuildVariant, ContentHash, CppBuild, DiscoveryReport, Language,
    LanguageSelection, NORMALIZATION_VERSION, RustBuild, SourceUnit, content_hash,
};
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::features::FEATURE_SCHEMA_VERSION;
use codehelion_core::frontend::Token;
use codehelion_core::grouping::{GROUPING_VERSION, GroupingConfig, StructuralGroup};
use codehelion_core::ir::{ByteRange, StructuralFrontend, SyntaxIrFile};
use codehelion_core::priority::Weights;
use codehelion_core::semantic::{
    CrossLanguageCandidateInput, SEMANTIC_CANDIDATE_INDEX_VERSION, SEMANTIC_RULE_REGISTRY_VERSION,
    SEMANTIC_WINDOWING_VERSION, SOG_SCHEMA_VERSION, SemanticCandidateConfig,
    SemanticCandidateStats, SemanticGroupingStats, SemanticGroupingUnit, SemanticOperationGraph,
    SemanticRule, VerifiedSemanticPair, extract_cross_language_candidates,
    extract_registered_candidates, group_verified_semantic_pairs, registered_semantic_windows,
    verify_cross_language_candidates, verify_registered_candidates,
};
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, UnitFingerprint};
use codehelion_core::structural::{
    self, CrossVariantUnit, GroupDetail, RegionOccurrence, StructuralConfig, StructuralRegion,
    StructuralReport, StructuralUnit, VerifiedPair,
};
use codehelion_core::test_code::{self, TEST_CODE_VERSION};
use codehelion_core::verify::{SimilarityBreakdown, WEIGHT_VERSION};
use codehelion_store::compiler::{self as store_compiler, CompilerHelperRow, CompilerOutcome};
use codehelion_store::snapshot::{
    CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow, CrossLanguageSemanticMemberRow,
    CrossVariantComparisonSnapshot, CrossVariantGroupRow, CrossVariantMemberRow, FileRow, GroupRow,
    MemberRow, PriorityRow, SemanticEvidenceRow, SemanticNodeMappingRow, SemanticOperationGraphRow,
    SimilarityBreakdownRow, Snapshot, SummaryRow, UnitRow, UnparsedRow,
};

use super::{
    FileOutcome, ScanBaseline, as_u64, database_path, discover_sources, effective_jobs,
    filter_globs, literal_norm, map_sources, open_store, rfc3339_now, write_partitioned_reports,
    write_report,
};

use crate::Outcome;
use crate::cli::ScanArgs;
use crate::config::{self, BoilerplatePolicy, CategoryAction, Config};
use crate::report::{self, Report};
use crate::semantic;
use crate::suppress;
use codehelion_core::doctor;
use codehelion_core::execution::ExecutionPolicy;
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
fn semantic_sandbox(args: &ScanArgs) -> Result<SandboxRequest> {
    if !args.untrusted {
        return Ok(SandboxRequest::unrestricted());
    }
    let Some(bytes) = codehelion_core::execution::Limits::untrusted().max_subprocess_bytes else {
        bail!("the untrusted profile must require a subprocess memory ceiling");
    };
    let request = SandboxRequest::require_memory_limit(bytes);
    codehelion_helper::sandbox::validate(request)?;
    Ok(request)
}

/// One helper a semantic run can ask, what it said about itself, and what it
/// is allowed to run while answering.
struct Installed {
    component: doctor::HelperComponent,
    program: PathBuf,
    greeting: doctor::Greeting,
    permitted: Vec<Execution>,
    sandbox: SandboxRequest,
}

impl Installed {
    /// What this helper's half of the run was analysed under.
    ///
    /// The compiler version is the helper's own, not the project's: the
    /// answers came from what this program holds, and a variant that recorded
    /// the project's toolchain would attribute them to a compiler that never
    /// ran. The lockfile is the project's, because the dependency versions are
    /// part of what its source means.
    ///
    /// The features and settings are asked of the helper, because it is the
    /// side that resolves them, and asked before anything is analysed, because
    /// they are what the answers get filed under. Two runs of one tree under
    /// different features resolve different types; recorded under one identity
    /// they would be compared against each other, and the older of the two
    /// would be reported as findings that this run did not make.
    ///
    /// # Errors
    ///
    /// Fails if the helper cannot say. A run that could not name what it
    /// analysed the tree under would file its results under conditions it
    /// guessed at, which is worse than not running.
    fn build(&self, root: &Path) -> Result<BuildConfiguration> {
        let described = self.describe(root)?;
        let permitted_execution: Vec<String> = self
            .permitted
            .iter()
            .map(|class| class.name().to_string())
            .collect();
        if self.component.analyses.contains(&Language::Rust) {
            return Ok(BuildConfiguration::Rust(Box::new(RustBuild {
                compiler_version: self.greeting.toolchains.join(", "),
                lockfile_hash: std::fs::read_to_string(root.join("Cargo.lock"))
                    .ok()
                    .map(|text| content_hash(&text)),
                features: described.features,
                cfgs: described.cfgs,
                permitted_execution,
                ..RustBuild::default()
            })));
        }
        Ok(BuildConfiguration::Cpp(Box::new(CppBuild {
            // The compiler that answered rather than the one the database
            // names, for the reason the Rust side records its own: what a type
            // resolved to is a fact about the compiler that resolved it.
            compiler: self.greeting.toolchains.join(", "),
            // What a C or C++ file means is decided before it is parsed, by the
            // macros its command defines — the same question a cfg answers.
            macros: described.cfgs,
            ..CppBuild::default()
        })))
    }

    /// Ask one helper what the tree is read under, and let it go again.
    ///
    /// Its own short conversation rather than the one the analysis holds: this
    /// is asked before a run knows whether it will analyse anything at all,
    /// and a scan of an unchanged tree is answered from what was recorded
    /// without a compiler being asked about a single file.
    fn describe(&self, root: &Path) -> Result<codehelion_helper::BuildDescription> {
        let mut helper =
            Helper::start_with_sandbox(&self.program, &[], DESCRIBE_TIMEOUT, self.sandbox)
                .with_context(|| {
                    format!(
                        "asking {} what this tree is built with",
                        self.program.display()
                    )
                })?;
        let described = helper.describe(root);
        let _ = helper.shutdown();
        described.with_context(|| {
            format!(
                "the helper at {} could not say what this tree is built with",
                self.program.display()
            )
        })
    }
}

/// The helpers a semantic run can ask, in the order they are tried.
struct Compilers {
    installed: Vec<Installed>,
}

impl Compilers {
    /// Locate every helper and shake hands with it, before anything is read.
    ///
    /// Up front because the alternative is discovering after a full parse that
    /// the run cannot be what it was asked to be, and because the two failures
    /// need different answers: one is a program to install, the other a
    /// program to update.
    ///
    /// A helper that is not installed is not a failure. One machine has the
    /// Rust helper and no Clang; the tree it is pointed at may be entirely
    /// Rust, in which case nothing is missing at all. What the run cannot do
    /// without is *some* helper, and which languages went unanswered is the
    /// coverage report's answer rather than this one's.
    ///
    /// It is also where a permission meets the program it was granted to. A
    /// helper says at the handshake what it acts on; anything permitted beyond
    /// that is dropped for that helper rather than sent and ignored, because
    /// the answer that comes back from ignoring it is thinner than the one that
    /// was asked for and looks exactly like the project's own.
    fn found(permitted: &ExecutionPolicy, sandbox: SandboxRequest) -> Result<Self> {
        let mut installed = Vec::new();
        for component in doctor::OPTIONAL_HELPERS {
            let Some(facts) = crate::interrogate(component.binary, None, sandbox) else {
                continue;
            };
            match facts.state {
                doctor::HelperState::Answered(greeting) => installed.push(Installed {
                    permitted: acted_on(permitted, &greeting),
                    component,
                    program: facts.path,
                    greeting,
                    sandbox,
                }),
                // Installed and unable to answer is its own problem, and
                // telling someone to install what they have already installed
                // sends them to solve the wrong one.
                doctor::HelperState::Silent(why) => bail!(
                    "the helper at {} did not answer: {why}; \
                     `codehelion doctor` reports what it is",
                    facts.path.display()
                ),
            }
        }
        if installed.is_empty() {
            bail!(
                "semantic mode needs a compiler helper, and there is none beside \
                 this program or on PATH: {}",
                doctor::OPTIONAL_HELPERS
                    .iter()
                    .map(|component| component.advice)
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        for class in permitted.permitted() {
            if Execution::from_name(class.name()).is_none() {
                bail!(
                    "this build has no protocol name for the execution class {}",
                    class.name()
                );
            }
            if !installed.iter().any(|helper| {
                helper
                    .permitted
                    .iter()
                    .any(|acts| acts.name() == class.name())
            }) {
                bail!(
                    "no helper installed here runs {}, so --allow-execution={} would \
                     change nothing about this scan; `codehelion doctor` lists what \
                     each of them runs",
                    class.name(),
                    class.name()
                );
            }
        }
        Ok(Self { installed })
    }

    /// The helpers that have something to answer about, given the languages the
    /// tree turned out to hold.
    ///
    /// Narrowed after discovery rather than at the handshake, because what a
    /// helper is worth to a run is decided by the tree and not by the machine.
    /// A Rust-only project scanned where the Clang helper happens to be
    /// installed must be identified as the same run as one scanned where it is
    /// not: a variant that moved with what is installed would make every
    /// recorded run incomparable with the next machine's.
    fn at_work(&self, present: LanguageSelection) -> Vec<&Installed> {
        self.installed
            .iter()
            .filter(|helper| {
                helper
                    .component
                    .analyses
                    .iter()
                    .any(|language| present.includes(*language))
            })
            .collect()
    }
}

/// The helpers this run will put files to, or `None` when it asks nobody.
///
/// Decided after discovery, because which helpers have anything to answer about
/// is a fact about the tree. The same answer serves both the identity the
/// results are filed under and the asking itself, which is what keeps a run from
/// being identified by a compiler it never put a file to.
///
/// # Errors
///
/// Fails when the tree holds sources and no installed helper reads any of their
/// languages. Semantic mode does not fall back to Structural: a run that
/// answered without a compiler and called itself semantic would be syntactic
/// results under another name. An empty tree is not that — nothing to scan and
/// nothing to scan it with are different, and only the second is a problem.
fn asking_about<'a>(
    compilers: Option<&'a Compilers>,
    sources: &[SourceUnit],
) -> Result<Option<Vec<&'a Installed>>> {
    let present = languages_in(sources);
    let asking = compilers.map(|compilers| compilers.at_work(present));
    if let Some(asking) = &asking
        && asking.is_empty()
        && !sources.is_empty()
    {
        bail!(
            "semantic mode found no helper that reads {}; \
             `codehelion doctor` lists which languages each helper answers about, \
             and `--mode structural` analyses this tree without one",
            present
                .enabled()
                .into_iter()
                .map(Language::name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(asking)
}

/// The languages the tree turned out to hold.
fn languages_in(sources: &[SourceUnit]) -> LanguageSelection {
    let mut present = LanguageSelection {
        rust: false,
        c: false,
        cpp: false,
    };
    for source in sources {
        match source.language {
            Language::Rust => present.rust = true,
            Language::C => present.c = true,
            Language::Cpp => present.cpp = true,
        }
    }
    present
}

/// The permitted classes as the protocol names them, keeping the ones this
/// helper said it acts on.
///
/// The greeting carries the classes as strings, so the round trip through the
/// protocol's own spelling is also what checks that both sides mean the same
/// class by the same word.
///
/// Narrowed per helper rather than refused: one permission can be meaningful
/// for one helper and meaningless for another — the Clang helper runs nothing
/// out of a project whatever it is allowed — and refusing on behalf of all of
/// them would make permitting anything at all impossible as soon as a helper
/// that runs nothing is installed.
fn acted_on(permitted: &ExecutionPolicy, greeting: &doctor::Greeting) -> Vec<Execution> {
    permitted
        .permitted()
        .into_iter()
        .filter(|class| greeting.executes.iter().any(|acts| acts == class.name()))
        .filter_map(|class| Execution::from_name(class.name()))
        .collect()
}

/// How long the helper has to say what a tree is built with.
///
/// Shorter than an analysis and longer than anything this program does itself:
/// answering means reading the project's own manifests, which is a fraction of
/// what analysing it costs but is still somebody else's process doing work.
const DESCRIBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[allow(clippy::too_many_lines)]
fn run_with(
    args: &ScanArgs,
    out: &mut impl Write,
    compilers: Option<&Compilers>,
) -> Result<Outcome> {
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
    let (cfg, guardrails) =
        crate::scan::guarded(config::load(args.config.as_deref(), &root)?.config, args);
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
        )? {
            partitions.push(rust);
        }
        partitions.sort_by_cached_key(|partition| partition.variant.fingerprint());
        if !partitions.is_empty() {
            let db_path = database_path(&root, args.db.as_deref(), &cfg);
            let mut reports = Vec::with_capacity(partitions.len());
            let mut comparison_units = Vec::new();
            let mut cross_language_units = Vec::new();
            let mut outcome = Outcome::Success;
            for (index, partition) in partitions.into_iter().enumerate() {
                let partition = run_semantic_partition(
                    args,
                    &cfg,
                    guardrails.as_ref(),
                    jobs,
                    &root,
                    &db_path,
                    &discovered,
                    &partition.sources,
                    glob_excluded,
                    asking.as_deref(),
                    &partition,
                    index == 0,
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
            write_partitioned_reports(
                args,
                out,
                &reports,
                comparison.as_ref(),
                cross_language_comparison.as_ref(),
            )?;
            return Ok(outcome);
        }
    }
    let variant = variant_of(asking.as_deref(), &cfg, discovered.header_language, &root)?;
    let db_path = database_path(&root, args.db.as_deref(), &cfg);
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
    let analysis =
        structural::analyze_resolved(&irs, &variant, &structural_config(&cfg), &resolved);
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
    let baseline = crate::scan::load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules.rules,
        &variant,
        &detector_versions(
            cfg.priority.weights(),
            literal_norm(cfg.literal_normalization),
        ),
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
        &discovered,
        baseline.as_ref().map(ScanBaseline::digest),
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
    write_report(args, out, &model)?;
    Ok(crate::scan::outcome(args, &model))
}

/// Execute and record one semantic partition.
///
/// The parser is intentionally run per partition for now. It never executes
/// target code, and keeping its products private to the partition makes it
/// impossible for a future resolved-type refinement to accidentally reconnect
/// clone grouping across build variants.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_semantic_partition(
    args: &ScanArgs,
    cfg: &Config,
    guardrails: Option<&report::Guardrails>,
    jobs: usize,
    root: &Path,
    db_path: &Path,
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
    glob_excluded: usize,
    asking: Option<&[&Installed]>,
    partition: &SemanticPartition,
    replace_existing: bool,
) -> Result<PartitionOutcome> {
    let started_at = rfc3339_now();
    let timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (parsed, unreadable, timed_out) =
        map_sources(sources, jobs, |source| parse_one(source, timeout))?;
    let (files, mut irs): (Vec<SourceMeta>, Vec<SyntaxIrFile>) = parsed
        .into_iter()
        .map(|source| (source.meta, source.ir))
        .unzip();
    mark_test_modules(&files, &mut irs);

    let (asked, resolved) = resolve(
        asking,
        sources,
        &files,
        &partition.variant,
        &partition.commands,
        std::time::Duration::from_millis(cfg.limits.helper_timeout_ms),
    );
    let analysis =
        structural::analyze_resolved(&irs, &partition.variant, &structural_config(cfg), &resolved);
    let semantic = registered_semantic_pairs(
        asked.as_ref(),
        sources,
        &files,
        &irs,
        &analysis,
        &partition.variant,
        cfg,
    )?;
    let mut rules = compile_rules(cfg, &files, &analysis)?;
    let baseline = crate::scan::load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules.rules,
        &partition.variant,
        &detector_versions(
            cfg.priority.weights(),
            literal_norm(cfg.literal_normalization),
        ),
    )?;
    let regions = reportable_regions(&analysis);
    let mut presentation_cfg = cfg.clone();
    presentation_cfg.suppression = presentation_suppression(cfg, args.include_trivial);
    let suppressed = evaluate_suppression(
        &presentation_cfg,
        &mut rules,
        &analysis,
        &regions,
        &semantic.groups,
        &semantic.pairs,
        &partition.variant,
    );
    let finished_at = rfc3339_now();
    let inputs = ReportInputs {
        root,
        db_path,
        started_at: &started_at,
        finished_at: &finished_at,
        variant: &partition.variant,
        files: &files,
        irs: &irs,
        analysis: &analysis,
        semantic_groups: &semantic.groups,
        semantic_pairs: &semantic.pairs,
        semantic_detection: &semantic,
        rules: &rules.rules,
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
    let groups = build_groups(&inputs);
    let stored = summary_row(
        &inputs,
        discovered,
        baseline.as_ref().map(ScanBaseline::digest),
    );
    let run_id = record(
        cfg,
        &inputs,
        &groups,
        crate::scan::file_rows(sources),
        &stored,
        asked.as_ref(),
        replace_existing,
    )?;
    let mut model = build_report(&inputs, run_id, &stored, groups);
    model.summary.guardrails = guardrails.map(copy_guardrails);
    model.summary.compiler = asked.as_ref().map(coverage);
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| crate::scan::apply_baseline(baseline, &mut model.groups));
    let comparison_units =
        maybe_cross_comparison_units(args, &partition.variant, &files, &irs, &analysis);
    let cross_language_units = maybe_cross_language_comparison_units(
        args,
        &partition.variant,
        &files,
        &analysis,
        &semantic,
    );
    let outcome = crate::scan::outcome(args, &model);
    Ok(PartitionOutcome {
        outcome,
        report: model,
        comparison_units,
        cross_language_units,
    })
}

fn maybe_cross_comparison_units(
    args: &ScanArgs,
    variant: &BuildVariant,
    files: &[SourceMeta],
    irs: &[SyntaxIrFile],
    analysis: &StructuralReport,
) -> Vec<CrossComparisonUnit> {
    if args.compare_build_variants {
        cross_comparison_units(variant, files, irs, analysis)
    } else {
        Vec::new()
    }
}

fn maybe_cross_language_comparison_units(
    args: &ScanArgs,
    variant: &BuildVariant,
    files: &[SourceMeta],
    analysis: &StructuralReport,
    semantic: &SemanticDetection,
) -> Vec<CrossLanguageComparisonUnit> {
    if !args.compare_languages {
        return Vec::new();
    }
    let origin_variant = variant.fingerprint();
    semantic
        .units
        .iter()
        .filter_map(|semantic_unit| {
            let unit = analysis.units.get(semantic_unit.unit)?;
            let file = files.get(unit.file)?;
            matches!(file.language, Language::Rust | Language::Cpp).then_some(())?;
            Some(CrossLanguageComparisonUnit {
                origin_variant: origin_variant.clone(),
                language: file.language,
                file_path: file.relative_path.clone(),
                start_line: semantic_unit.start_line,
                end_line: semantic_unit.end_line,
                name: unit.name.as_ref().map(ToString::to_string),
                graph: semantic_unit.graph.clone(),
                content: semantic_unit.content,
                normalization_confidence: semantic_unit.normalization_confidence,
                interactions: semantic_unit.interactions.clone(),
                data_flows: semantic_unit.data_flows.clone(),
                cfg_shape: semantic_unit.cfg_shape,
            })
        })
        .collect()
}

const fn copy_guardrails(guardrails: &report::Guardrails) -> report::Guardrails {
    report::Guardrails {
        profile: guardrails.profile,
        max_file_bytes: guardrails.max_file_bytes,
        parse_timeout_ms: guardrails.parse_timeout_ms,
        pair_budget: guardrails.pair_budget,
    }
}

/// Retain C/C++ units from one completed partition for an explicitly requested
/// comparison. The normal report owns neither this data nor its interpretation.
fn cross_comparison_units(
    variant: &BuildVariant,
    files: &[SourceMeta],
    irs: &[SyntaxIrFile],
    analysis: &StructuralReport,
) -> Vec<CrossComparisonUnit> {
    let origin_variant = variant.fingerprint();
    analysis
        .units
        .iter()
        .filter_map(|unit| {
            let file = files.get(unit.file)?;
            matches!(file.language, Language::C | Language::Cpp).then_some(())?;
            let tokens = irs
                .get(unit.file)?
                .tokens
                .get(unit.token_start..unit.token_end)?;
            Some(CrossComparisonUnit {
                origin_variant: origin_variant.clone(),
                language: file.language,
                file_path: file.relative_path.clone(),
                start_line: unit.start_line,
                end_line: unit.end_line,
                name: unit.name.as_ref().map(ToString::to_string),
                tokens: tokens.to_vec(),
            })
        })
        .collect()
}

/// Directly compare the completed C/C++ partitions and persist the result in
/// tables outside normal snapshots. This opt-in invocation records what it
/// compared now.
fn record_cross_variant_comparison(
    db_path: &Path,
    root: &Path,
    started_at: &str,
    units: &[CrossComparisonUnit],
) -> Result<Option<report::CrossVariantComparison>> {
    let inputs: Vec<CrossVariantUnit<'_>> = units
        .iter()
        .map(|unit| CrossVariantUnit {
            origin_variant: &unit.origin_variant,
            language: unit.language,
            file_path: &unit.file_path,
            start_line: unit.start_line,
            end_line: unit.end_line,
            name: unit.name.as_deref(),
            tokens: &unit.tokens,
        })
        .collect();
    let Some(comparison) = structural::compare_build_variants(&inputs) else {
        return Ok(None);
    };
    let groups: Vec<CrossVariantGroupRow> = comparison
        .groups
        .iter()
        .map(|group| CrossVariantGroupRow {
            group_id: group.id,
            clone_type: group.clone_type,
            members: group
                .members
                .iter()
                .map(|member| CrossVariantMemberRow {
                    origin_variant: member.origin_variant.clone(),
                    language: member.language,
                    file_path: member.file_path.clone(),
                    start_line: member.start_line,
                    end_line: member.end_line,
                    unit_name: member.name.clone(),
                    token_count: member.token_count,
                })
                .collect(),
        })
        .collect();
    let finished_at = rfc3339_now();
    let root_path = root.to_string_lossy();
    let snapshot = CrossVariantComparisonSnapshot {
        root_path: &root_path,
        comparison_id: comparison.id,
        policy_version: stable_id::CROSS_VARIANT_POLICY_VERSION,
        started_at,
        finished_at: &finished_at,
        origins: &comparison.origin_variants,
        groups: &groups,
    };
    let mut store = open_store(db_path)?;
    store.record_cross_variant_comparison(&snapshot)?;
    Ok(Some(report::CrossVariantComparison {
        policy_version: stable_id::CROSS_VARIANT_POLICY_VERSION.to_string(),
        comparison_id: comparison.id.to_hex(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        origin_variants: comparison.origin_variants,
        groups: comparison
            .groups
            .into_iter()
            .map(|group| report::CrossVariantGroup {
                id: group.id.to_hex(),
                clone_type: group.clone_type.name().to_string(),
                members: group
                    .members
                    .into_iter()
                    .map(|member| report::CrossVariantMember {
                        origin_variant: member.origin_variant,
                        language: member.language.name().to_string(),
                        file: member.file_path,
                        start_line: member.start_line,
                        end_line: member.end_line,
                        name: member.name,
                        token_count: member.token_count,
                    })
                    .collect(),
            })
            .collect(),
    }))
}

/// Directly compare the completed Rust and C++ semantic partitions and retain
/// the closed API correspondence evidence outside normal snapshots.
#[allow(
    clippy::too_many_lines,
    reason = "the comparison boundary constructs report and persistence evidence together"
)]
fn record_cross_language_comparison(
    db_path: &Path,
    root: &Path,
    started_at: &str,
    units: &[CrossLanguageComparisonUnit],
    cfg: &Config,
) -> Result<Option<report::CrossLanguageComparison>> {
    let mut origins: Vec<String> = units
        .iter()
        .map(|unit| unit.origin_variant.clone())
        .collect();
    origins.sort_unstable();
    origins.dedup();
    if origins.len() < 2
        || !units.iter().any(|unit| unit.language == Language::Rust)
        || !units.iter().any(|unit| unit.language == Language::Cpp)
    {
        return Ok(None);
    }

    let comparison_id = stable_id::cross_language_comparison_id(&origins);
    let inputs: Vec<CrossLanguageCandidateInput> = units
        .iter()
        .map(|unit| CrossLanguageCandidateInput {
            comparison_partition: *comparison_id.as_bytes(),
            graph: unit.graph.clone(),
        })
        .collect();
    let max_candidate_pairs = cfg
        .limits
        .pair_budget
        .unwrap_or_else(|| SemanticCandidateConfig::default().max_candidate_pairs);
    let candidates = extract_cross_language_candidates(
        &inputs,
        SemanticCandidateConfig {
            max_bucket_members: SemanticCandidateConfig::default().max_bucket_members,
            max_candidate_pairs,
        },
    );
    let verified = enabled_cross_language_matches(
        verify_cross_language_candidates(&inputs, &candidates.pairs),
        cfg,
    );
    let mut store_groups = Vec::with_capacity(verified.len());
    let mut report_groups = Vec::with_capacity(verified.len());
    for (candidate, matched) in verified {
        let left = &units[candidate.left];
        let right = &units[candidate.right];
        let group_id = stable_id::cross_language_group_id(
            &comparison_id,
            matched.rule.id,
            matched.rule.version,
            &[left.content, right.content],
        );
        let semantic_confidence = semantic_confidence(
            matched.rule.confidence,
            left.confidence_evidence(),
            right.confidence_evidence(),
        );
        let correspondence_ids: Vec<String> = matched
            .correspondence_ids
            .iter()
            .map(|id| (*id).to_string())
            .collect();
        let members = [left, right];
        let store_members = members
            .iter()
            .map(|unit| {
                Ok(CrossLanguageSemanticMemberRow {
                    origin_variant: unit.origin_variant.clone(),
                    language: unit.language,
                    file_path: unit.file_path.clone(),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    unit_name: unit.name.clone(),
                    graph_schema_version: unit.graph.schema_version.clone(),
                    graph_json: serde_json::to_string(&unit.graph)
                        .context("serializing cross-language semantic graph")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        store_groups.push(CrossLanguageSemanticGroupRow {
            group_id,
            rule_id: matched.rule.id.to_string(),
            rule_version: matched.rule.version,
            semantic_confidence,
            correspondence_ids: correspondence_ids.clone(),
            members: store_members,
        });
        report_groups.push(report::CrossLanguageGroup {
            id: group_id.to_hex(),
            rule_id: matched.rule.id.to_string(),
            rule_version: matched.rule.version,
            semantic_confidence,
            correspondence_ids,
            members: members
                .iter()
                .map(|unit| report::CrossLanguageMember {
                    origin_variant: unit.origin_variant.clone(),
                    language: unit.language.name().to_string(),
                    file: unit.file_path.clone(),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    name: unit.name.clone(),
                    graph: unit.graph.clone(),
                })
                .collect(),
        });
    }
    let finished_at = rfc3339_now();
    let root_path = root.to_string_lossy();
    let snapshot = CrossLanguageComparisonSnapshot {
        root_path: &root_path,
        comparison_id,
        policy_version: stable_id::CROSS_LANGUAGE_POLICY_VERSION,
        started_at,
        finished_at: &finished_at,
        origins: &origins,
        groups: &store_groups,
    };
    let mut store = open_store(db_path)?;
    store.record_cross_language_comparison(&snapshot)?;
    Ok(Some(report::CrossLanguageComparison {
        policy_version: stable_id::CROSS_LANGUAGE_POLICY_VERSION.to_string(),
        comparison_id: comparison_id.to_hex(),
        comparison_kind: "restricted-semantic-rust-cpp-pipelines".to_string(),
        origin_variants: origins,
        groups: report_groups,
    }))
}

/// Keep only opt-in cross-language rule applications enabled for this project.
///
/// The candidate index remains independent of configuration for complete,
/// deterministic accounting; this policy boundary decides only whether an
/// already explained correspondence may become a reported finding.
fn enabled_cross_language_matches(
    verified: Vec<(
        codehelion_core::semantic::SemanticCandidatePair,
        codehelion_core::semantic::CrossLanguageRuleMatch,
    )>,
    cfg: &Config,
) -> Vec<(
    codehelion_core::semantic::SemanticCandidatePair,
    codehelion_core::semantic::CrossLanguageRuleMatch,
)> {
    verified
        .into_iter()
        .filter(|(_, matched)| cfg.semantic.enabled(matched.rule.id))
        .collect()
}

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
        .map(|helper| helper.build(root))
        .collect::<Result<Vec<_>>>()?;
    Ok(BuildVariant::semantic(languages, headers, builds))
}

/// One independently recorded semantic program. Headers are present in every
/// C/C++ partition because the selected translation units are what give them
/// meaning; their compiler answers never cross this boundary.
struct SemanticPartition {
    variant: BuildVariant,
    sources: Vec<SourceUnit>,
    commands: BTreeMap<PathBuf, CompileCommandSelector>,
}

/// Split a C/C++ scan by the exact command-derived build variant.
///
fn cpp_partitions(
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
    cfg: &Config,
    compiler_version: Option<&str>,
) -> Vec<SemanticPartition> {
    let Some(database) = &discovered.compile_commands else {
        return Vec::new();
    };
    let languages = LanguageSelection {
        rust: false,
        c: cfg.languages.c,
        cpp: cfg.languages.cpp,
    };
    database
        .build_partitions()
        .into_values()
        .filter_map(|entries| {
            let first = entries.first()?;
            let mut command_build = first.build(database.content_hash.clone());
            command_build.compiler_version = compiler_version.map(ToString::to_string);
            let build = BuildConfiguration::Cpp(Box::new(command_build));
            let mut commands = BTreeMap::new();
            let entry_paths: BTreeSet<PathBuf> = entries
                .iter()
                .map(|entry| {
                    entry
                        .file
                        .canonicalize()
                        .unwrap_or_else(|_| entry.file.clone())
                })
                .collect();
            for entry in entries {
                let (file, directory, arguments) = entry.selector_fields();
                let path = entry
                    .file
                    .canonicalize()
                    .unwrap_or_else(|_| entry.file.clone());
                commands.insert(
                    path,
                    CompileCommandSelector {
                        file,
                        directory,
                        arguments,
                    },
                );
            }
            let selected = sources
                .iter()
                .filter(|source| {
                    source.is_header
                        || (matches!(source.language, Language::C | Language::Cpp)
                            && entry_paths.contains(&source.absolute_path))
                })
                .cloned()
                .collect();
            Some(SemanticPartition {
                variant: BuildVariant::semantic(languages, discovered.header_language, vec![build]),
                sources: selected,
                commands,
            })
        })
        .collect()
}

/// C/C++ source a database did not name, recorded as an explicit no-build
/// partition rather than silently dropped or assigned to a real command.
fn unconfigured_cpp_partition(
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
) -> Option<SemanticPartition> {
    let database = discovered.compile_commands.as_ref()?;
    let configured: BTreeSet<PathBuf> = database
        .entries
        .iter()
        .map(|entry| {
            entry
                .file
                .canonicalize()
                .unwrap_or_else(|_| entry.file.clone())
        })
        .collect();
    let selected: Vec<SourceUnit> = sources
        .iter()
        .filter(|source| {
            matches!(source.language, Language::C | Language::Cpp)
                && !source.is_header
                && !configured.contains(&source.absolute_path)
        })
        .cloned()
        .collect();
    if selected.is_empty() {
        return None;
    }
    let mut languages = LanguageSelection {
        rust: false,
        c: false,
        cpp: false,
    };
    for source in &selected {
        match source.language {
            Language::C => languages.c = true,
            Language::Cpp => languages.cpp = true,
            Language::Rust => {}
        }
    }
    Some(SemanticPartition {
        variant: BuildVariant::semantic(languages, discovered.header_language, Vec::new()),
        sources: selected,
        commands: BTreeMap::new(),
    })
}

/// The runtime Clang that actually produced semantic answers.
fn clang_toolchain(asking: Option<&[&Installed]>) -> Option<String> {
    asking.and_then(|helpers| {
        helpers
            .iter()
            .find(|helper| {
                helper.component.analyses.contains(&Language::C)
                    || helper.component.analyses.contains(&Language::Cpp)
            })
            .map(|helper| helper.greeting.toolchains.join(", "))
    })
}

/// The existing single Rust semantic build, kept apart from C/C++ command
/// variants without adding per-source or per-feature Rust partitioning.
fn rust_partition(
    sources: &[SourceUnit],
    asking: Option<&[&Installed]>,
    headers: Language,
    root: &Path,
) -> Result<Option<SemanticPartition>> {
    let selected: Vec<SourceUnit> = sources
        .iter()
        .filter(|source| source.language == Language::Rust)
        .cloned()
        .collect();
    if selected.is_empty() {
        return Ok(None);
    }
    let helper = asking.and_then(|helpers| {
        helpers
            .iter()
            .copied()
            .find(|helper| helper.component.analyses.contains(&Language::Rust))
    });
    let builds = helper
        .map(|helper| helper.build(root))
        .transpose()?
        .into_iter()
        .collect();
    let variant = BuildVariant::semantic(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        headers,
        builds,
    );
    Ok(Some(SemanticPartition {
        variant,
        sources: selected,
        commands: BTreeMap::new(),
    }))
}

/// Ask each helper about the sources it reads, under the variant the results
/// belong to.
fn ask_about(
    asking: &[&Installed],
    sources: &[SourceUnit],
    variant: &BuildVariant,
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    timeout: std::time::Duration,
) -> semantic::Answers {
    let backends: Vec<semantic::Backend<'_>> = asking
        .iter()
        .map(|helper| semantic::Backend {
            program: &helper.program,
            analyzes: helper.component.analyses,
            permitted: &helper.permitted,
            sandbox: helper.sandbox,
        })
        .collect();
    semantic::ask_with_commands(
        &backends,
        sources,
        &variant.fingerprint(),
        commands,
        timeout,
    )
}

/// Ask the helpers about the tree, and index what they resolved as the analysis
/// reads it.
///
/// Both come back because both are wanted and neither is derivable from the
/// other: the analysis reads the types, and the report reads how much of the
/// tree a compiler could speak for at all. A run that asked nobody produces no
/// answers and no types, which is a mode that reads source and nothing else
/// rather than a compiler that found nothing.
fn resolve(
    asking: Option<&[&Installed]>,
    sources: &[SourceUnit],
    files: &[SourceMeta],
    variant: &BuildVariant,
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    timeout: std::time::Duration,
) -> (Option<semantic::Answers>, structural::ResolvedTypes) {
    let asked = asking.map(|asking| ask_about(asking, sources, variant, commands, timeout));
    let resolved = asked
        .as_ref()
        .map_or_else(structural::ResolvedTypes::default, |asked| {
            resolved_types(asked, sources, files)
        });
    (asked, resolved)
}

/// What was resolved about each file that parsed, indexed as the analysis
/// reads them.
///
/// Keyed on the path rather than on position: the sources that parsed are a
/// subset of the sources that were asked about, and lining up two lists of
/// different lengths by index would attribute one file's types to another.
///
/// A helper anchors what it found at the path the project spells, against the
/// root it read the project from, and the analysis says which root that was.
/// So the name a file's answers are looked up under is the one that analysis
/// would have filed it under — asked of the analysis rather than guessed, which
/// is what lets a scan rooted in a subdirectory of a workspace still be given
/// what the compiler resolved about its files.
fn resolved_types(
    asked: &semantic::Answers,
    sources: &[SourceUnit],
    files: &[SourceMeta],
) -> structural::ResolvedTypes {
    let answered: BTreeMap<&str, (&SourceUnit, &semantic::Answer)> = sources
        .iter()
        .zip(&asked.per_source)
        .filter_map(|(source, answer)| Some((source.relative_path.to_str()?, (source, answer))))
        .collect();
    let resolved: Vec<_> = files
        .iter()
        .map(|meta| {
            answered
                .get(meta.relative_path.as_str())
                .and_then(|(source, answer)| {
                    let ir = answer.analysis()?;
                    let spelling = ir.spelling(&source.absolute_path);
                    Some((
                        semantic::resolved_types_for(ir, &spelling),
                        semantic::resolved_api_for(ir, &spelling),
                    ))
                })
                .unwrap_or_default()
        })
        .collect();
    structural::ResolvedTypes::per_file_with_apis(
        resolved.iter().map(|(types, _)| types.clone()).collect(),
        resolved.into_iter().map(|(_, apis)| apis).collect(),
    )
}

/// Normalize compiler-resolved calls within each parser-owned unit and match
/// only the pairs selected by the bounded core-owned SOG index.
#[allow(
    clippy::too_many_lines,
    reason = "the adapter keeps compiler answers, range ownership, and bounded matching in one auditable boundary"
)]
fn registered_semantic_pairs(
    asked: Option<&semantic::Answers>,
    sources: &[SourceUnit],
    files: &[SourceMeta],
    irs: &[SyntaxIrFile],
    analysis: &StructuralReport,
    variant: &BuildVariant,
    cfg: &Config,
) -> Result<SemanticDetection> {
    let Some(asked) = asked else {
        return Ok(SemanticDetection {
            groups: Vec::new(),
            pairs: Vec::new(),
            units: Vec::new(),
            candidates: SemanticCandidateStats::default(),
            registered_observations: 0,
            excluded_observations: 0,
            unrepresentable_units: 0,
            verified_pairs: 0,
            disabled_pairs: 0,
            grouping: SemanticGroupingStats::default(),
        });
    };
    let variant_fingerprint = semantic_variant_fingerprint(variant)?;
    let answered: BTreeMap<&str, (&SourceUnit, &semantic::Answer)> = sources
        .iter()
        .zip(&asked.per_source)
        .filter_map(|(source, answer)| Some((source.relative_path.to_str()?, (source, answer))))
        .collect();
    let mut units = Vec::new();
    let mut registered_observations = 0_usize;
    let mut excluded_observations = 0_usize;
    let mut unrepresentable_units = 0_usize;
    for (unit_index, unit) in analysis.units.iter().enumerate() {
        let Some(file) = files.get(unit.file) else {
            continue;
        };
        let Some((source, answer)) = answered.get(file.relative_path.as_str()) else {
            continue;
        };
        let Some(compiler_ir) = answer.analysis() else {
            continue;
        };
        let spelling = compiler_ir.spelling(&source.absolute_path);
        let normalized = semantic::registered_sog_in_range(
            compiler_ir,
            &spelling,
            file.language,
            variant_fingerprint,
            Some(unit.range),
        )
        .with_context(|| {
            format!(
                "normalizing registered semantic APIs in {}:{}-{}",
                file.relative_path, unit.start_line, unit.end_line
            )
        })?;
        excluded_observations =
            excluded_observations.saturating_add(normalized.excluded_observations);
        let Some(graph) = normalized.graph.as_ref() else {
            unrepresentable_units = unrepresentable_units.saturating_add(1);
            continue;
        };
        registered_observations = registered_observations.saturating_add(graph.nodes.len());
        let normalization_confidence =
            normalization_confidence(graph.nodes.len(), normalized.excluded_observations);
        let windows = registered_semantic_windows(&normalized).with_context(|| {
            format!(
                "extracting bounded registered semantic windows in {}:{}-{}",
                file.relative_path, unit.start_line, unit.end_line
            )
        })?;
        if windows.is_empty() {
            unrepresentable_units = unrepresentable_units.saturating_add(1);
        }
        let Some(syntax_ir) = irs.get(unit.file) else {
            continue;
        };
        for window in windows {
            let range = ByteRange {
                start: usize::try_from(window.source_range.start)
                    .context("semantic source range start exceeds this platform")?,
                end: usize::try_from(window.source_range.end)
                    .context("semantic source range end exceeds this platform")?,
            };
            let (start_line, end_line, token_count) =
                semantic_window_location(syntax_ir, unit, range);
            let content = stable_id::semantic_fragment_fingerprint(variant, &window.graph);
            let interactions = semantic_window_interactions(&window.graph);
            let data_flows =
                semantic_window_data_flows(&compiler_ir.data_flow, window.source_range);
            let cfg_shape = semantic_window_cfg_shape(
                compiler_ir.cfg.as_ref(),
                &file.relative_path,
                window.source_range,
            );
            units.push(SemanticUnitGraph {
                unit: unit_index,
                range,
                start_line,
                end_line,
                token_count,
                graph: window.graph,
                content,
                normalization_confidence,
                interactions,
                data_flows,
                cfg_shape,
            });
        }
    }
    let graphs: Vec<_> = units.iter().map(|unit| unit.graph.clone()).collect();
    let max_candidate_pairs = cfg
        .limits
        .pair_budget
        .unwrap_or_else(|| SemanticCandidateConfig::default().max_candidate_pairs);
    let candidates = extract_registered_candidates(
        &graphs,
        SemanticCandidateConfig {
            max_bucket_members: SemanticCandidateConfig::default().max_bucket_members,
            max_candidate_pairs,
        },
    );
    let verified = verify_registered_candidates(&graphs, &candidates.pairs);
    let verified_pairs = verified.len();
    let disabled_pairs = verified
        .iter()
        .filter(|(_, matched)| !cfg.semantic.enabled(matched.rule.id))
        .count();
    let enabled = verified
        .into_iter()
        .filter(|(_, matched)| cfg.semantic.enabled(matched.rule.id))
        .map(|(candidate, matched)| VerifiedSemanticPair { candidate, matched })
        .collect::<Vec<_>>();
    let grouping_units = units
        .iter()
        .map(|unit| SemanticGroupingUnit {
            key: *unit.content.as_bytes(),
        })
        .collect::<Vec<_>>();
    let grouped =
        group_verified_semantic_pairs(&grouping_units, &enabled, &GroupingConfig::default());
    let grouping = grouped.stats.clone();
    let mut groups = grouped
        .groups
        .into_iter()
        .map(|group| {
            let members = group
                .members
                .into_iter()
                .map(|index| units[index].clone())
                .collect::<Vec<_>>();
            SemanticGroup {
                canonical: units[group.canonical].clone(),
                semantic_confidence: semantic_group_confidence(group.rule.confidence, &members),
                members,
                rule: group.rule,
            }
        })
        .collect::<Vec<_>>();
    let mut pairs = grouped
        .ungrouped
        .into_iter()
        .map(|ungrouped| semantic_pair_from_indices(&units, ungrouped.pair))
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        (left.canonical.content, left.rule.id, left.members.len()).cmp(&(
            right.canonical.content,
            right.rule.id,
            right.members.len(),
        ))
    });
    pairs.sort_by(|left, right| {
        (
            left.canonical.content,
            left.corresponding.content,
            left.rule.id,
        )
            .cmp(&(
                right.canonical.content,
                right.corresponding.content,
                right.rule.id,
            ))
    });
    Ok(SemanticDetection {
        groups,
        pairs,
        units,
        candidates: candidates.stats,
        registered_observations,
        excluded_observations,
        unrepresentable_units,
        verified_pairs,
        disabled_pairs,
        grouping,
    })
}

/// Build one pair finding from a verified relation the semantic grouping could
/// not express as a cohesive group.
fn semantic_pair_from_indices(
    units: &[SemanticUnitGraph],
    verified: VerifiedSemanticPair,
) -> SemanticPair {
    let left = units[verified.candidate.left].clone();
    let right = units[verified.candidate.right].clone();
    let pair_confidence = semantic_confidence(
        verified.matched.rule.confidence,
        left.confidence_evidence(),
        right.confidence_evidence(),
    );
    let (canonical, corresponding) = if (left.content, left.unit) <= (right.content, right.unit) {
        (left, right)
    } else {
        (right, left)
    };
    SemanticPair {
        semantic_confidence: pair_confidence,
        canonical,
        corresponding,
        rule: verified.matched.rule,
    }
}

/// Coverage of one unit by the closed operation registry.
///
/// A call the registry does not recognise cannot be assumed irrelevant, so it
/// lowers only confidence. It never changes candidate extraction or rule
/// matching: doing so would turn incomplete helper evidence into a different
/// semantic claim.
fn normalization_confidence(registered: usize, excluded: usize) -> f64 {
    let total = registered.saturating_add(excluded);
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        registered as f64 / total as f64
    }
}

/// Translate one semantic byte window into report coordinates using the
/// already-parsed token stream. Empty point spans retain their host unit's
/// location, which is the compatibility path for adapters without full
/// anchors; current compiler adapters always provide non-empty spans.
fn semantic_window_location(
    ir: &SyntaxIrFile,
    host: &StructuralUnit,
    range: ByteRange,
) -> (u32, u32, usize) {
    let tokens = ir
        .tokens
        .get(host.token_start..host.token_end)
        .unwrap_or_default();
    let mut matching = tokens
        .iter()
        .filter(|token| token.span.start_byte < range.end && range.start < token.span.end_byte);
    let Some(first) = matching.next() else {
        return (host.start_line, host.end_line, 0);
    };
    let mut end_line = first.span.start_line;
    let mut token_count = 1;
    for token in matching {
        end_line = token.span.start_line;
        token_count += 1;
    }
    (first.span.start_line, end_line, token_count)
}

/// Combine a rule's measured base confidence with non-authoritative coverage
/// evidence. Missing data-flow or CFG evidence is intentionally neutral: it
/// may adjust confidence but must never be required for a finding.
fn semantic_confidence(
    rule_confidence: f64,
    left: SemanticConfidenceEvidence<'_>,
    right: SemanticConfidenceEvidence<'_>,
) -> f64 {
    (rule_confidence
        * left.normalization.min(right.normalization)
        * interaction_confidence(left.interactions, right.interactions)
        * data_flow_confidence(left.data_flows, right.data_flows)
        * cfg_confidence(left.cfg_shape, right.cfg_shape))
    .min(1.0)
}

/// Apply one rule's confidence to the least-complete member of a cohesive
/// semantic group. Every relation was independently verified; coverage only
/// communicates how much registered evidence each graph retained.
fn semantic_group_confidence(rule_confidence: f64, members: &[SemanticUnitGraph]) -> f64 {
    let coverage = members
        .iter()
        .map(|member| member.normalization_confidence)
        .fold(1.0_f64, f64::min);
    let interactions = members
        .first()
        .map_or_else(BTreeSet::new, |member| member.interactions.clone());
    let interaction_confidence = members.iter().skip(1).fold(1.05_f64, |confidence, member| {
        confidence.min(interaction_confidence(&interactions, &member.interactions))
    });
    let data_flows = members
        .first()
        .map_or_else(BTreeSet::new, |member| member.data_flows.clone());
    let data_flow_confidence = members.iter().skip(1).fold(1.05_f64, |confidence, member| {
        confidence.min(data_flow_confidence(&data_flows, &member.data_flows))
    });
    let cfg = members.first().and_then(|member| member.cfg_shape);
    let cfg_confidence = members.iter().skip(1).fold(1.05_f64, |confidence, member| {
        confidence.min(cfg_confidence(cfg, member.cfg_shape))
    });
    (rule_confidence * coverage * interaction_confidence * data_flow_confidence * cfg_confidence)
        .min(1.0)
}

/// A matching non-empty interaction summary corroborates a finding; a
/// disagreement lowers only confidence. Missing evidence is deliberately
/// neutral, because an empty closed summary cannot prove a pure unit.
fn interaction_confidence(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() || right.is_empty() {
        1.0
    } else if left == right {
        1.05
    } else {
        0.85
    }
}

/// A matching non-empty direct def-use summary corroborates a finding. It is
/// deliberately symmetrical with effect evidence: unavailable or empty
/// evidence cannot rule a finding out or establish the absence of a flow.
fn data_flow_confidence(
    left: &BTreeSet<(String, String)>,
    right: &BTreeSet<(String, String)>,
) -> f64 {
    if left.is_empty() || right.is_empty() {
        1.0
    } else if left == right {
        1.05
    } else {
        0.85
    }
}

/// A matching compiler-produced CFG shape corroborates a registered match;
/// conflicting shapes lower confidence. A missing summary is neutral so that
/// helpers without `MirCfg` preserve the same set of findings.
fn cfg_confidence(left: Option<CfgShape>, right: Option<CfgShape>) -> f64 {
    match (left, right) {
        (Some(left), Some(right)) if left == right => 1.05,
        (Some(_), Some(_)) => 0.85,
        (None, _) | (_, None) => 1.0,
    }
}

/// Summarize only compiler blocks whose anchors overlap a registered semantic
/// window. Compiler-local block indices are reduced to counts, which are
/// comparable across the two language helpers but never become stable IDs.
fn semantic_window_cfg_shape(
    cfg: Option<&ControlFlowGraph>,
    file: &str,
    window: codehelion_core::semantic::SemanticSourceRange,
) -> Option<CfgShape> {
    let cfg = cfg?;
    let blocks: BTreeSet<u32> = cfg
        .blocks
        .iter()
        .enumerate()
        .filter_map(|(index, block)| {
            let range = &block.anchor.expansion;
            (range.file == file && range.start_byte < window.end && window.start < range.end_byte)
                .then(|| u32::try_from(index).ok())
                .flatten()
        })
        .collect();
    if blocks.is_empty() {
        return None;
    }
    let mut shape = CfgShape {
        blocks: u32::try_from(blocks.len()).unwrap_or(u32::MAX),
        flow_edges: 0,
        taken_edges: 0,
        not_taken_edges: 0,
        unwind_edges: 0,
        return_edges: 0,
    };
    for edge in &cfg.edges {
        if !blocks.contains(&edge.from) || !blocks.contains(&edge.to) {
            continue;
        }
        let counter = match edge.kind {
            EdgeKind::Flow => &mut shape.flow_edges,
            EdgeKind::Taken => &mut shape.taken_edges,
            EdgeKind::NotTaken => &mut shape.not_taken_edges,
            EdgeKind::Unwind => &mut shape.unwind_edges,
            EdgeKind::Return => &mut shape.return_edges,
        };
        *counter = counter.saturating_add(1);
    }
    Some(shape)
}

/// An interaction belongs to a fragment only when its closed resource node is
/// already part of that fragment's SOG window.
fn semantic_window_interactions(graph: &SemanticOperationGraph) -> BTreeSet<String> {
    graph
        .nodes
        .iter()
        .filter_map(|node| node.attributes.resource_kind.as_deref())
        .filter_map(|resource| match resource {
            "file" => Some("file_io".to_owned()),
            "lock" => Some("synchronization".to_owned()),
            _ => None,
        })
        .collect()
}

/// Retain only helper-reported direct receiver flows whose two written API
/// anchors fall inside this SOG window. The helper's endpoint format is local
/// to compiler IR v1; after range membership is established, only closed API
/// names remain as comparison evidence.
fn semantic_window_data_flows(
    summary: &DataFlowSummary,
    window: codehelion_core::semantic::SemanticSourceRange,
) -> BTreeSet<(String, String)> {
    summary
        .flows
        .iter()
        .filter_map(|(source, sink)| {
            let source = flow_endpoint_in_window(source, window)?;
            let sink = flow_endpoint_in_window(sink, window)?;
            Some((source.to_owned(), sink.to_owned()))
        })
        .collect()
}

/// Parse one helper-local `start:end:api` endpoint and return its API only
/// when its full written range belongs to `window`.
fn flow_endpoint_in_window(
    endpoint: &str,
    window: codehelion_core::semantic::SemanticSourceRange,
) -> Option<&str> {
    let (start, rest) = endpoint.split_once(':')?;
    let (end, api) = rest.split_once(':')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    (start >= window.start && end <= window.end).then_some(api)
}

/// Select the narrowest truthful scope for a semantic finding.
fn semantic_scope<'a>(
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
    analysis: &StructuralReport,
) -> CloneScope {
    if members
        .into_iter()
        .all(|member| analysis.units[member.unit].range == member.range)
    {
        CloneScope::Unit
    } else {
        CloneScope::Fragment
    }
}

/// Assign stable per-host occurrence ranks without making source positions an
/// input to a semantic content or group fingerprint.
fn semantic_member_ranks<'a>(members: impl IntoIterator<Item = &'a SemanticUnitGraph>) -> Vec<u32> {
    let members: Vec<_> = members.into_iter().collect();
    let mut ordered: Vec<_> = members.iter().enumerate().collect();
    ordered.sort_by_key(|(_, member)| (member.unit, member.range, member.content));
    let mut ranks = vec![0_u32; members.len()];
    let mut next_by_unit = BTreeMap::new();
    for (position, member) in ordered {
        let rank = next_by_unit.entry(member.unit).or_insert(0_u32);
        ranks[position] = *rank;
        *rank = rank.saturating_add(1);
    }
    ranks
}

/// Decode the full 256-bit `BuildVariant` identity that SOG stores as bytes.
fn semantic_variant_fingerprint(variant: &BuildVariant) -> Result<[u8; 32]> {
    let hex = variant.fingerprint();
    let mut bytes = [0_u8; 32];
    if hex.len() != bytes.len() * 2 {
        bail!("BuildVariant fingerprint {hex:?} is not 256-bit hex");
    }
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        let end = start + 2;
        *byte = u8::from_str_radix(&hex[start..end], 16)
            .with_context(|| format!("BuildVariant fingerprint {hex:?} is not hexadecimal"))?;
    }
    Ok(bytes)
}

/// What the compilers managed to say about the tree, as the report puts it.
///
/// The restarts are summed across the helpers, because a restart is trouble the
/// run had rather than trouble one program had: what a reader does with the
/// number is decide whether a thin result was the tree's fault.
fn coverage(asked: &semantic::Answers) -> report::CompilerCoverage {
    let mut unavailable: BTreeMap<String, u64> = BTreeMap::new();
    let mut answered = 0;
    let mut not_asked = 0;
    for answer in &asked.per_source {
        match answer {
            semantic::Answer::Analyzed { .. } => answered += 1,
            semantic::Answer::NotAsked { .. } => not_asked += 1,
            semantic::Answer::Unavailable { reason, .. } => {
                *unavailable.entry(reason.name().to_string()).or_default() += 1;
            }
        }
    }
    report::CompilerCoverage {
        answered,
        not_asked,
        unavailable,
        restarts: asked
            .helpers
            .iter()
            .map(|helper| helper.restarts)
            .fold(0, u32::saturating_add),
    }
}

/// Read and parse one source file, enforcing the per-file time ceiling.
///
/// As in Fast mode the ceiling is checked after the parser returns: the
/// discovery size ceiling bounds the input, so the check keeps an
/// unexpectedly slow file out of the results while the skipped count keeps it
/// visible.
fn parse_one(source: &SourceUnit, timeout: std::time::Duration) -> FileOutcome<ParsedSource> {
    let started = std::time::Instant::now();
    let Ok(bytes) = std::fs::read(&source.absolute_path) else {
        return FileOutcome::Unreadable;
    };
    let text = String::from_utf8_lossy(&bytes);
    let ir = match source.language {
        Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(&text),
        Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(&text),
        Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(&text),
    };
    if started.elapsed() > timeout {
        return FileOutcome::TimedOut;
    }
    let unaccounted_tokens = as_u64(ir.unaccounted_tokens());
    FileOutcome::Done(Box::new(ParsedSource {
        meta: SourceMeta {
            relative_path: source.relative_path.to_string_lossy().into_owned(),
            language: source.language,
            marker_lines: suppress::marker_lines(&text),
            lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
            diagnostics: ir.diagnostics.len(),
            unaccounted_tokens,
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
fn mark_test_modules(files: &[SourceMeta], irs: &mut [SyntaxIrFile]) {
    let inputs: Vec<test_code::ModuleFile<'_>> = files
        .iter()
        .zip(irs.iter())
        .map(|(file, ir)| test_code::ModuleFile {
            path: Path::new(&file.relative_path),
            language: file.language,
            tokens: &ir.tokens,
        })
        .collect();
    let in_suite = test_code::declared_test_modules(&inputs);
    drop(inputs);
    for (ir, marked) in irs.iter_mut().zip(in_suite) {
        ir.test_module = marked;
    }
}

/// Build the structural stage configuration from the effective scan
/// configuration. An overridden candidate ceiling applies to every candidate
/// stage, so one configured number bounds the whole funnel; left unset, each
/// stage keeps the default measured for it.
fn structural_config(cfg: &Config) -> StructuralConfig {
    let mut config = StructuralConfig::default();
    if let Some(cap) = cfg.limits.posting_cap {
        config.candidate.posting_cap = cap;
        config.near_match.posting_cap = cap;
        config.control_flow.posting_cap = cap;
    }
    if let Some(budget) = cfg.limits.pair_budget {
        config.candidate.pair_budget = budget;
        config.near_match.pair_budget = budget;
        config.control_flow.pair_budget = budget;
    }
    config.grouping.max_component = cfg.limits.max_component;
    config.literals = literal_norm(cfg.literal_normalization);
    config
}

/// Suppression rules together with the per-file evaluation they need.
struct StructuralRules {
    rules: suppress::Rules,
    files: Vec<suppress::FileSuppression>,
}

impl StructuralRules {
    /// The rule suppressing a whole group: present only when *every* member
    /// is suppressed. The canonical (first) member's rule is the one
    /// recorded.
    fn group_rule(
        &self,
        members: impl Iterator<Item = usize>,
        analysis: &StructuralReport,
        local_units: &[usize],
    ) -> Option<usize> {
        let mut first = None;
        for member in members {
            let unit = &analysis.units[member];
            let rule = self.rules.member_rule(
                &self.files[unit.file],
                unit.start_line,
                unit.end_line,
                Some(local_units[member]),
            )?;
            if first.is_none() {
                first = Some(rule);
            }
        }
        first
    }

    /// The rule suppressing a semantic finding: each partial window is judged
    /// at its own line range while retaining the host unit for symbol rules.
    fn semantic_rule<'a>(
        &self,
        members: impl Iterator<Item = &'a SemanticUnitGraph>,
        analysis: &StructuralReport,
        local_units: &[usize],
    ) -> Option<usize> {
        let mut first = None;
        for member in members {
            let unit = &analysis.units[member.unit];
            let rule = self.rules.member_rule(
                &self.files[unit.file],
                member.start_line,
                member.end_line,
                Some(local_units[member.unit]),
            )?;
            if first.is_none() {
                first = Some(rule);
            }
        }
        first
    }

    /// The rule hiding a whole duplicated run: present only when *every*
    /// occurrence is suppressed, evaluated at the occurrence's own line span
    /// inside its host unit.
    fn region_rule(
        &self,
        region: &StructuralRegion,
        analysis: &StructuralReport,
        local_units: &[usize],
    ) -> Option<usize> {
        let mut first = None;
        for occurrence in &region.occurrences {
            let unit = &analysis.units[occurrence.unit];
            let rule = self.rules.member_rule(
                &self.files[unit.file],
                occurrence.start_line,
                occurrence.end_line,
                Some(local_units[occurrence.unit]),
            )?;
            if first.is_none() {
                first = Some(rule);
            }
        }
        first
    }
}

/// Compile the suppression rules and evaluate every parsed file against them.
/// A file's units come from the analysed units, in the order the analysis
/// walked them, so an inline marker resolves to the same unit the findings
/// anchor to.
fn compile_rules(
    cfg: &Config,
    files: &[SourceMeta],
    analysis: &StructuralReport,
) -> Result<StructuralRules> {
    let any_markers = files.iter().any(|file| !file.marker_lines.is_empty());
    let rules = suppress::Rules::compile(&cfg.suppression, any_markers)?;
    let mut spans: Vec<Vec<suppress::UnitSpan<'_>>> = files.iter().map(|_| Vec::new()).collect();
    for unit in &analysis.units {
        spans[unit.file].push(suppress::UnitSpan {
            start_line: unit.start_line,
            end_line: unit.end_line,
            name: unit.name.as_deref(),
        });
    }
    let evaluated = files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            rules.evaluate_file(&file.relative_path, &file.marker_lines, &spans[index])
        })
        .collect();
    Ok(StructuralRules {
        rules,
        files: evaluated,
    })
}

/// Which suppression rule, if any, hides each reported finding.
struct SuppressionVerdicts {
    /// Parallel to the analysis's clone groups.
    groups: Vec<Option<usize>>,
    /// Parallel to the runs the report lists.
    regions: Vec<Option<usize>>,
    /// Parallel to the verified pairs no group could hold.
    pairs: Vec<Option<usize>>,
    /// Parallel to the registered restricted-semantic correspondences.
    semantic_pairs: Vec<Option<usize>>,
    /// Parallel to cohesive registered restricted-semantic groups.
    semantic_groups: Vec<Option<usize>>,
}

/// The presentation policy for this invocation after explicit CLI intent.
///
/// The configuration remains the source of every durable policy choice. The
/// flag only changes where a known predicate family appears in this one
/// report; it neither changes clone detection nor writes configuration back.
fn presentation_suppression(cfg: &Config, include_trivial: bool) -> config::Suppression {
    let mut presentation = cfg.suppression.clone();
    if include_trivial {
        presentation.boilerplate.trivial_body = CategoryAction::Report;
    }
    presentation
}

/// Evaluate the configured suppression against everything the report lists.
///
/// Every kind of finding is judged by the same rules read at its own
/// place in the code: a marker or a path glob is an instruction about where
/// code sits, and a run or a pair sits somewhere as much as a group does.
#[allow(
    clippy::too_many_lines,
    reason = "suppression precedence for each finding shape is intentionally visible in one audit boundary"
)]
fn evaluate_suppression(
    cfg: &Config,
    rules: &mut StructuralRules,
    analysis: &StructuralReport,
    regions: &ReportableRegions,
    semantic_groups: &[SemanticGroup],
    semantic_pairs: &[SemanticPair],
    variant: &BuildVariant,
) -> SuppressionVerdicts {
    let hidden = hidden_boilerplate(&mut rules.rules, &cfg.suppression.boilerplate, analysis);
    let hidden_width_family = hidden_width_family(&mut rules.rules, cfg, analysis);
    let hidden_test_code = hidden_test_code(&mut rules.rules, cfg, analysis, regions);
    let local_units = local_unit_indices(analysis);
    // Most specific rule first: a clone id names this exact group, a path or
    // symbol glob or an inline marker is an explicit instruction about where
    // the members sit, the test attribute is the source stating what the code
    // is, and a boilerplate category is the tool's judgement about its shape.
    let groups = analysis
        .groups
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            rules
                .rules
                .clone_id_rule(&analysis.details[index].fingerprint.to_hex())
                .or_else(|| rules.group_rule(group.members.iter().copied(), analysis, &local_units))
                .or_else(|| hidden_test_code.filter(|_| analysis.details[index].test_code))
                .or_else(|| {
                    analysis.details[index]
                        .boilerplate
                        .and_then(|category| hidden.get(&category).copied())
                })
                .or_else(|| hidden_width_family.filter(|_| analysis.details[index].width_family))
                .or_else(|| {
                    rules
                        .rules
                        .baseline_rule(&analysis.details[index].fingerprint.to_hex())
                })
        })
        .collect();
    let region_verdicts = regions
        .reported
        .iter()
        .map(|&index| {
            let region = &analysis.regions[index];
            rules
                .rules
                .clone_id_rule(&region.fingerprint.to_hex())
                .or_else(|| rules.region_rule(region, analysis, &local_units))
                .or_else(|| hidden_test_code.filter(|_| region_test_code(analysis, region)))
                .or_else(|| rules.rules.baseline_rule(&region.fingerprint.to_hex()))
        })
        .collect();
    let pairs = analysis
        .unrepresented
        .iter()
        .map(|pair| {
            rules
                .rules
                .clone_id_rule(&pair.fingerprint.to_hex())
                .or_else(|| rules.group_rule(pair.members.iter().copied(), analysis, &local_units))
                .or_else(|| {
                    hidden_test_code.filter(|_| {
                        pair.members
                            .iter()
                            .all(|&member| analysis.units[member].test_code)
                    })
                })
                .or_else(|| rules.rules.baseline_rule(&pair.fingerprint.to_hex()))
        })
        .collect();
    let semantic_pairs = semantic_pairs
        .iter()
        .map(|pair| {
            let fingerprint = stable_id::semantic_clone_group_fingerprint(
                variant,
                pair.rule.id,
                pair.rule.version,
                &[pair.canonical.content, pair.corresponding.content],
            );
            let members = [&pair.canonical, &pair.corresponding];
            rules
                .rules
                .clone_id_rule(&fingerprint.to_hex())
                .or_else(|| rules.semantic_rule(members.into_iter(), analysis, &local_units))
                .or_else(|| {
                    hidden_test_code.filter(|_| {
                        members
                            .iter()
                            .all(|member| analysis.units[member.unit].test_code)
                    })
                })
                .or_else(|| rules.rules.baseline_rule(&fingerprint.to_hex()))
        })
        .collect();
    let semantic_groups = semantic_groups
        .iter()
        .map(|group| {
            let fingerprint = stable_id::semantic_clone_group_fingerprint(
                variant,
                group.rule.id,
                group.rule.version,
                &group
                    .members
                    .iter()
                    .map(|member| member.content)
                    .collect::<Vec<_>>(),
            );
            let members = group.members.iter();
            rules
                .rules
                .clone_id_rule(&fingerprint.to_hex())
                .or_else(|| rules.semantic_rule(members.clone(), analysis, &local_units))
                .or_else(|| {
                    hidden_test_code.filter(|_| {
                        members
                            .clone()
                            .all(|member| analysis.units[member.unit].test_code)
                    })
                })
                .or_else(|| rules.rules.baseline_rule(&fingerprint.to_hex()))
        })
        .collect();
    SuppressionVerdicts {
        groups,
        regions: region_verdicts,
        pairs,
        semantic_pairs,
        semantic_groups,
    }
}

/// Register a suppression rule for every boilerplate category the policy
/// hides *and* this run actually produced, returning the rule index per
/// category.
///
/// A category with no group in this run registers no rule: the recorded rules
/// are the ones that did something.
fn hidden_boilerplate(
    rules: &mut suppress::Rules,
    policy: &BoilerplatePolicy,
    analysis: &StructuralReport,
) -> BTreeMap<Boilerplate, usize> {
    let mut hidden = BTreeMap::new();
    for category in Boilerplate::all() {
        if policy.action(category) != CategoryAction::Hide {
            continue;
        }
        if !analysis
            .details
            .iter()
            .any(|detail| detail.boilerplate == Some(category))
        {
            continue;
        }
        let index = rules.add_shape_rule(category.name(), "boilerplate shape");
        hidden.insert(category, index);
    }
    hidden
}

/// Register the rule hiding groups written once per integer width, when the
/// policy hides them *and* this run found one, returning the rule index.
///
/// Recorded under the same scope as a boilerplate shape. What the two have in
/// common is the part a reader needs: the tool judged the code's shape rather
/// than being told about it by a path, a marker or a baseline. That this one
/// reads the shape off the members' tokens instead of their trees is a detail
/// of how, and the reason on the row says which judgement it was.
fn hidden_width_family(
    rules: &mut suppress::Rules,
    cfg: &Config,
    analysis: &StructuralReport,
) -> Option<usize> {
    if cfg.suppression.width_family != CategoryAction::Hide {
        return None;
    }
    analysis
        .details
        .iter()
        .any(|detail| detail.width_family)
        .then(|| rules.add_shape_rule("width-family", "one routine per integer width"))
}

/// Register the rule hiding test-suite duplication, when the policy hides it
/// *and* this run found some, returning the rule index.
///
/// As with a boilerplate category, a rule that hid nothing is not recorded:
/// the rules kept are the ones that did something.
fn hidden_test_code(
    rules: &mut suppress::Rules,
    cfg: &Config,
    analysis: &StructuralReport,
    regions: &ReportableRegions,
) -> Option<usize> {
    if cfg.suppression.test_code != CategoryAction::Hide {
        return None;
    }
    let any_group = analysis.details.iter().any(|detail| detail.test_code);
    let any_run = regions
        .reported
        .iter()
        .any(|&index| region_test_code(analysis, &analysis.regions[index]));
    (any_group || any_run).then(|| rules.add_attribute_rule("test", "test code"))
}

/// Which duplicated runs the report lists, and how many it folded away.
struct ReportableRegions {
    /// Indices into the analysed regions, in analysis order.
    reported: Vec<usize>,
    /// Runs left out because a whole-unit group already covers them.
    folded: usize,
}

/// Select the duplicated runs worth listing beside the whole-unit groups.
///
/// A run whose occurrences sit one apiece in units that are *themselves* a
/// reported clone group says nothing the unit group does not already say:
/// "these functions are clones" implies "they share this stretch". Listing
/// both describes one duplication twice, and on real code most runs are of
/// this kind, so the runs that name a duplication no unit group reaches would
/// be buried. They are folded away and counted rather than silently dropped.
///
/// Three cases deliberately survive the fold, because no unit group implies
/// them: a run occurring more than once inside the same unit, a run whose host
/// units are not all members of one group, and a run inside a *gapped* group
/// small enough to name a place inside its hosts rather than restate them.
///
/// The last of those turns on the covering group being gapped. An exact group
/// says its members agree statement for statement, which already accounts for
/// every stretch inside them however short — so a run there is folded on the
/// same grounds as any other, without consulting its size.
fn reportable_regions(analysis: &StructuralReport) -> ReportableRegions {
    let mut member_of: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, group) in analysis.groups.groups.iter().enumerate() {
        for &member in &group.members {
            member_of.entry(member).or_default().push(index);
        }
    }
    // The class of a group holding every host, if one does. Among several, the
    // exact one decides: it is the stronger claim about the same units.
    let covering_class = |hosts: &BTreeSet<usize>| {
        let first = hosts.first()?;
        member_of
            .get(first)?
            .iter()
            .filter(|&&group| {
                hosts
                    .iter()
                    .all(|host| analysis.groups.groups[group].members.contains(host))
            })
            .map(|&group| analysis.groups.groups[group].clone_type)
            .min()
    };

    let mut reported = Vec::new();
    let mut folded = 0;
    for (index, region) in analysis.regions.iter().enumerate() {
        let hosts: BTreeSet<usize> = region
            .occurrences
            .iter()
            .map(|occurrence| occurrence.unit)
            .collect();
        let one_per_unit = hosts.len() == region.occurrences.len();
        let covered = (one_per_unit && hosts.len() > 1)
            .then(|| covering_class(&hosts))
            .flatten();
        match covered {
            Some(class) if class.is_exact() || !localizes(analysis, region) => folded += 1,
            _ => reported.push(index),
        }
    }
    ReportableRegions { reported, folded }
}

/// How much of a host unit a run may cover and still be said to point at a
/// place *inside* it: at most one part in this many. Above that share the run
/// is, near enough, the unit itself.
const LOCALIZING_SHARE_DIVISOR: usize = 2;

/// Whether every unit hosting a run is test code.
///
/// A run shared between a test and the code it exercises is duplication across
/// that boundary, which is the case worth surfacing, so one host outside the
/// suite is enough to keep the run out of the suite's ranking.
fn region_test_code(analysis: &StructuralReport, region: &StructuralRegion) -> bool {
    region
        .occurrences
        .iter()
        .all(|occurrence| analysis.units[occurrence.unit].test_code)
}

/// Whether a run names a place inside its hosts rather than restating them.
///
/// A unit group directs attention at whole units, so a run spanning most of
/// one adds nothing: the reader is already looking there. A run that is a
/// small part of *every* host is the opposite case — a gapped group says its
/// members are alike overall and says nothing about where they agree exactly,
/// so a short stretch they share verbatim is a finding the group cannot state
/// and the one that can be lifted out as it stands.
fn localizes(analysis: &StructuralReport, region: &StructuralRegion) -> bool {
    region.occurrences.iter().all(|occurrence| {
        let host = &analysis.units[occurrence.unit];
        let host_tokens = host.token_end.saturating_sub(host.token_start);
        let run_tokens = occurrence.token_end.saturating_sub(occurrence.token_start);
        run_tokens.saturating_mul(LOCALIZING_SHARE_DIVISOR) <= host_tokens
    })
}

/// Each unit's index within its own file, which is what the file-local
/// suppression evaluation indexes. Units come out of the analysis grouped by
/// file in walk order, so one pass assigns every local index.
fn local_unit_indices(analysis: &StructuralReport) -> Vec<usize> {
    let mut next: BTreeMap<usize, usize> = BTreeMap::new();
    analysis
        .units
        .iter()
        .map(|unit| {
            let slot = next.entry(unit.file).or_insert(0);
            let local = *slot;
            *slot += 1;
            local
        })
        .collect()
}

/// Everything the report and the snapshot are assembled from.
struct ReportInputs<'a> {
    root: &'a Path,
    db_path: &'a Path,
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

    /// The configured suppression rules that hid nothing this run, read off
    /// the rules that whole-unit groups and duplicated runs actually cited.
    fn unused_suppressions(&self) -> Vec<report::UnusedRule> {
        let used: BTreeSet<usize> = self
            .group_suppressed
            .iter()
            .chain(self.region_suppressed)
            .chain(self.pair_suppressed)
            .chain(self.semantic_pair_suppressed)
            .chain(self.semantic_group_suppressed)
            .filter_map(|rule| *rule)
            .collect();
        self.rules
            .unused(&used)
            .into_iter()
            .map(|row| report::UnusedRule {
                scope: row.scope.clone(),
                pattern: row.pattern.clone(),
            })
            .collect()
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
        let row = &self.rules.rows[rule];
        report::Suppression {
            kind: report::SuppressionKind::Rule,
            reason: None,
            scope: Some(row.scope.clone()),
            pattern: Some(row.pattern.clone()),
        }
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
fn build_groups(inputs: &ReportInputs<'_>) -> Vec<report::Group> {
    let mut entries: Vec<report::Group> = (0..inputs.analysis.groups.groups.len())
        .map(|index| build_group(inputs, index))
        // A run carries no boilerplate classification: the classifier reads
        // whole units, so no run is ever ranked down for its shape. Where it
        // sits is another matter — a run duplicated across a suite is the
        // suite's repetition as much as a duplicated test function is.
        .chain((0..inputs.regions.reported.len()).map(|index| build_region(inputs, index)))
        // A pair no group could hold says less per finding than a group does
        // — two members rather than a set — and there are more of them than
        // there are groups, so the policy ranks them down by default rather
        // than letting them crowd the top of the report.
        .chain(
            (0..inputs.analysis.unrepresented.len()).map(|index| build_split_pair(inputs, index)),
        )
        .chain((0..inputs.semantic_groups.len()).map(|index| build_semantic_group(inputs, index)))
        .chain((0..inputs.semantic_pairs.len()).map(|index| build_semantic_pair(inputs, index)))
        .collect();
    report::order(&mut entries, inputs.suppression, inputs.sort);
    entries
}

/// Turn one verified semantic relation left outside every cohesive group into
/// a split-pair restricted semantic finding.
fn build_semantic_pair(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let pair = &inputs.semantic_pairs[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        pair.rule.id,
        pair.rule.version,
        &[pair.canonical.content, pair.corresponding.content],
    );
    let members = [&pair.canonical, &pair.corresponding];
    let member_ranks = semantic_member_ranks(members.iter().copied());
    let node_mappings = (0..pair.canonical.graph.nodes.len())
        .filter_map(|index| {
            let index = u32::try_from(index).ok()?;
            Some(report::SemanticNodeMapping {
                corresponding_member: 1,
                canonical: index,
                corresponding: index,
            })
        })
        .collect();
    let mut group = report::ranked(
        report::Group {
            fingerprint: fingerprint.to_hex(),
            clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic
                .name()
                .to_string(),
            scope: semantic_scope(members.iter().copied(), inputs.analysis)
                .name()
                .to_string(),
            statements: None,
            confidence: pair.semantic_confidence,
            priority: report::Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: members
                .iter()
                .all(|member| inputs.analysis.units[member.unit].test_code),
            width_family: false,
            split_pair: true,
            suppressed: inputs.semantic_pair_suppressed[index].map(|rule| inputs.suppression(rule)),
            baseline: None,
            semantic: Some(report::SemanticEvidence {
                schema_version: pair.canonical.graph.schema_version.clone(),
                rules: vec![report::SemanticRuleEvidence {
                    id: pair.rule.id.to_string(),
                    version: pair.rule.version,
                    confidence: pair.semantic_confidence,
                }],
                graphs: vec![
                    pair.canonical.graph.clone(),
                    pair.corresponding.graph.clone(),
                ],
                node_mappings,
            }),
            members: members
                .iter()
                .enumerate()
                .map(|(position, member)| {
                    let unit = &inputs.analysis.units[member.unit];
                    let file = &inputs.files[unit.file];
                    report::Member {
                        finding_id: stable_id::finding_id(
                            &fingerprint,
                            Some(&unit.fingerprint),
                            member_ranks[position],
                        )
                        .to_hex(),
                        content: member.content.to_hex(),
                        file: file.relative_path.clone(),
                        language: file.language.name().to_string(),
                        start_line: member.start_line,
                        end_line: member.end_line,
                        unit: unit.name.as_deref().map(ToString::to_string),
                        boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                        tokens: u64::try_from(member.token_count).unwrap_or(u64::MAX),
                        canonical: position == 0,
                    }
                })
                .collect(),
        },
        &inputs.weights,
        inputs.min_clone_tokens,
    );
    group.priority.semantic_confidence = Some(pair.semantic_confidence);
    group
}

/// Turn one complete-linkage semantic group into a restricted semantic
/// finding. Each mapping names the corresponding member explicitly so a
/// multi-member group remains explainable after it leaves the scan process.
fn build_semantic_group(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let semantic_group = &inputs.semantic_groups[index];
    let fingerprint = stable_id::semantic_clone_group_fingerprint(
        inputs.variant,
        semantic_group.rule.id,
        semantic_group.rule.version,
        &semantic_group
            .members
            .iter()
            .map(|member| member.content)
            .collect::<Vec<_>>(),
    );
    let node_mappings = semantic_node_mappings(&semantic_group.canonical, &semantic_group.members);
    let member_ranks = semantic_member_ranks(semantic_group.members.iter());
    let mut group = report::ranked(
        report::Group {
            fingerprint: fingerprint.to_hex(),
            clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic
                .name()
                .to_string(),
            scope: semantic_scope(semantic_group.members.iter(), inputs.analysis)
                .name()
                .to_string(),
            statements: None,
            confidence: semantic_group.semantic_confidence,
            priority: report::Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: semantic_group
                .members
                .iter()
                .all(|member| inputs.analysis.units[member.unit].test_code),
            width_family: false,
            split_pair: false,
            suppressed: inputs.semantic_group_suppressed[index]
                .map(|rule| inputs.suppression(rule)),
            baseline: None,
            semantic: Some(report::SemanticEvidence {
                schema_version: semantic_group.canonical.graph.schema_version.clone(),
                rules: vec![report::SemanticRuleEvidence {
                    id: semantic_group.rule.id.to_string(),
                    version: semantic_group.rule.version,
                    confidence: semantic_group.semantic_confidence,
                }],
                graphs: semantic_group
                    .members
                    .iter()
                    .map(|member| member.graph.clone())
                    .collect(),
                node_mappings,
            }),
            members: semantic_group
                .members
                .iter()
                .enumerate()
                .map(|(position, member)| {
                    let unit = &inputs.analysis.units[member.unit];
                    let file = &inputs.files[unit.file];
                    report::Member {
                        finding_id: stable_id::finding_id(
                            &fingerprint,
                            Some(&unit.fingerprint),
                            member_ranks[position],
                        )
                        .to_hex(),
                        content: member.content.to_hex(),
                        file: file.relative_path.clone(),
                        language: file.language.name().to_string(),
                        start_line: member.start_line,
                        end_line: member.end_line,
                        unit: unit.name.as_ref().map(ToString::to_string),
                        boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                        tokens: u64::try_from(member.token_count).unwrap_or(u64::MAX),
                        canonical: position == 0,
                    }
                })
                .collect(),
        },
        &inputs.weights,
        inputs.min_clone_tokens,
    );
    group.priority.semantic_confidence = Some(semantic_group.semantic_confidence);
    group
}

/// Produce explicit canonical-to-member node mappings for an entire cohesive
/// group. Rules admitted to grouping retain aligned fixed SOG sequences.
fn semantic_node_mappings(
    canonical: &SemanticUnitGraph,
    members: &[SemanticUnitGraph],
) -> Vec<report::SemanticNodeMapping> {
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
                    Some(report::SemanticNodeMapping {
                        corresponding_member: u32::try_from(member).ok()?,
                        canonical: node,
                        corresponding: node,
                    })
                })
        })
        .collect()
}

/// The structural pipeline's pass counts, stage by stage.
///
/// The run forks after candidate extraction: whole units go to verification
/// and grouping, while the statement windows that seeded the candidates are
/// folded back into the maximal runs they describe and confirmed against the
/// tokens they cover. The confirmed-run counts therefore continue the seed
/// line, not the verified-pair line.
#[allow(
    clippy::too_many_lines,
    reason = "the report deliberately presents the entire cross-mode funnel in one ordered definition"
)]
fn funnel(
    stats: &structural::StructuralStats,
    semantic: &SemanticDetection,
) -> Vec<report::FunnelStage> {
    let near = &stats.near_match;
    let grouping = &stats.grouping;
    let maximal = &stats.maximal;
    let mut stages = vec![
        report::FunnelStage::new("units", as_u64(stats.units)),
        report::FunnelStage::new("indexed fragments", as_u64(stats.candidate.fragments))
            .dropping("high_frequency", as_u64(stats.candidate.stop_fingerprints))
            .dropping(
                "high_frequency_postings",
                as_u64(stats.candidate.stop_postings),
            ),
        report::FunnelStage::new("exact seed pairs", as_u64(stats.candidate.candidate_pairs))
            .dropping(
                "pair_budget",
                as_u64(
                    stats
                        .candidate
                        .available_pairs
                        .saturating_sub(stats.candidate.candidate_pairs),
                ),
            ),
        report::FunnelStage::new("near-match pairs", as_u64(near.candidate_pairs))
            .dropping("too_few_shingles", as_u64(near.skipped_small))
            .dropping("crowded_bucket", as_u64(near.stop_buckets))
            .dropping("length_ratio", as_u64(near.filtered_by_size))
            .dropping("estimated_jaccard", as_u64(near.filtered_by_jaccard)),
        report::FunnelStage::new(
            "control-flow pairs",
            as_u64(stats.control_flow.candidate_pairs),
        )
        .dropping(
            "skeleton_too_small",
            as_u64(stats.control_flow.skipped_shallow),
        )
        .dropping("common_skeleton", as_u64(stats.control_flow.stop_skeletons))
        .dropping(
            "common_skeleton_postings",
            as_u64(stats.control_flow.stop_postings),
        )
        .dropping("length_ratio", as_u64(stats.control_flow.filtered_by_size)),
        report::FunnelStage::new("unit pairs", as_u64(stats.unit_pairs))
            .dropping("nested", as_u64(stats.nested_pairs))
            .dropping("conditional_arms", as_u64(stats.alternative_pairs))
            .dropping("divergent_shapes", as_u64(stats.divergent_shape_pairs)),
        report::FunnelStage::new("verified pairs", as_u64(stats.verified_pairs))
            .dropping("no_group_holds_both", as_u64(stats.unrepresented_pairs))
            .dropping("a_group_says_it_already", as_u64(stats.described_pairs))
            .dropping("the_ceiling_cut_the_set", as_u64(stats.severed_pairs)),
        report::FunnelStage::new("components", as_u64(grouping.components)),
        report::FunnelStage::new("unit groups", as_u64(grouping.groups))
            .dropping("outside_the_medoid", as_u64(grouping.medoid_ejections))
            .dropping("linkage_split", as_u64(grouping.linkage_splits))
            .dropping("left_alone", as_u64(grouping.singletons)),
        report::FunnelStage::new(
            "run seeds",
            as_u64(maximal.seeds.saturating_sub(maximal.divergent_extent)),
        )
        .dropping("divergent_extent", as_u64(maximal.divergent_extent)),
        report::FunnelStage::new("folded runs", as_u64(maximal.regions))
            .dropping("below_minimum", as_u64(maximal.below_minimum))
            .dropping("self_overlapping", as_u64(maximal.self_overlapping))
            .dropping("contained", as_u64(maximal.absorbed)),
        report::FunnelStage::new("duplicated runs", as_u64(maximal.shared)),
        report::FunnelStage::new("joined runs", as_u64(stats.region_merged)),
        report::FunnelStage::new("confirmed runs", as_u64(stats.regions))
            .dropping("unshared_content", as_u64(stats.region_singletons))
            .dropping("overlapping_occurrence", as_u64(stats.region_overlapping))
            .dropping("adjoining_occurrence", as_u64(stats.region_adjoining))
            .dropping("subsumed", as_u64(stats.region_subsumed)),
    ];
    let candidates = &semantic.candidates;
    stages.extend([
        report::FunnelStage::new(
            "semantic API observations",
            as_u64(semantic.registered_observations)
                .saturating_add(as_u64(semantic.excluded_observations)),
        )
        .dropping(
            "outside_registered_vocabulary",
            as_u64(semantic.excluded_observations),
        ),
        report::FunnelStage::new("semantic graphs", as_u64(candidates.graphs))
            .dropping("ineligible", as_u64(candidates.ineligible_graphs))
            .dropping(
                "no_registered_operations",
                as_u64(semantic.unrepresentable_units),
            ),
        report::FunnelStage::new("semantic candidate pairs", as_u64(candidates.pairs_emitted))
            .dropping("high_frequency", as_u64(candidates.oversized_buckets))
            .dropping("pair_budget", as_u64(candidates.pairs_budget_dropped)),
        report::FunnelStage::new("semantic verified pairs", as_u64(semantic.verified_pairs))
            .dropping("rule_disabled", as_u64(semantic.disabled_pairs)),
        report::FunnelStage::new(
            "semantic pairs represented by groups",
            as_u64(semantic.grouping.grouped_pairs),
        ),
        report::FunnelStage::new("restricted semantic groups", as_u64(semantic.groups.len()))
            .dropping(
                "invalid_grouping_input",
                as_u64(semantic.grouping.invalid_pairs),
            ),
        report::FunnelStage::new("restricted semantic pairs", as_u64(semantic.pairs.len()))
            .dropping(
                "no_group_holds_both",
                as_u64(semantic.grouping.ungrouped_pairs),
            )
            .dropping(
                "the_ceiling_cut_the_set",
                as_u64(semantic.grouping.ceiling_severed_pairs),
            ),
    ]);
    stages
}

/// Assemble the report model both output formats render from.
fn build_report(
    inputs: &ReportInputs<'_>,
    run_id: i64,
    stored: &SummaryRow,
    groups: Vec<report::Group>,
) -> Report {
    let variant = inputs.variant;

    Report {
        schema_version: report::SCHEMA_VERSION,
        run: report::RunInfo {
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
            run_id,
        },
        summary: build_summary(inputs, stored, &groups),
        groups,
    }
}

/// What the run reported about itself beyond the groups it found, in the shape
/// the audit database stores.
///
/// Built before the snapshot is written and read back out of it by
/// [`build_summary`], so the recorded run and the printed report carry one set
/// of numbers rather than two derivations that happen to agree.
fn summary_row(
    inputs: &ReportInputs<'_>,
    discovered: &DiscoveryReport,
    baseline_digest: Option<String>,
) -> SummaryRow {
    let stats = &inputs.analysis.stats;
    let tokens = as_u64(inputs.irs.iter().map(|ir| ir.tokens.len()).sum::<usize>());
    let unparsed = report::UnparsedCounts::new(
        inputs.files.iter().map(|file| file.unaccounted_tokens),
        tokens,
    );
    SummaryRow {
        lines: inputs.files.iter().map(|file| file.lines).sum(),
        tokens,
        lexer_diagnostics: as_u64(inputs.files.iter().map(|file| file.diagnostics).sum()),
        unparsed: Some(UnparsedRow {
            files: unparsed.files,
            tokens: unparsed.tokens,
        }),
        excluded_generated: as_u64(discovered.suppressed_generated.len()),
        excluded_by_glob: as_u64(inputs.glob_excluded),
        excluded_skipped: discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
        folded_runs: as_u64(inputs.regions.folded),
        subsumed_runs: as_u64(stats.region_subsumed),
        split_components: as_u64(stats.grouping.oversized_components),
        // Any candidate stage exhausting its budget makes the result
        // potentially incomplete.
        pair_budget_exhausted: stats.candidate.budget_exhausted
            || stats.near_match.budget_exhausted
            || stats.control_flow.budget_exhausted
            || inputs.semantic_detection.candidates.pairs_budget_dropped > 0,
        baseline_digest,
        funnel: report::stored_funnel(&funnel(stats, inputs.semantic_detection)),
        unused_suppressions: report::stored_rules(&inputs.unused_suppressions()),
    }
}

/// The summary block of the report: everything the run measured, counted off
/// the assembled entries and the stored row so the totals cannot disagree with
/// the listing or with the database.
fn build_summary(
    inputs: &ReportInputs<'_>,
    stored: &SummaryRow,
    groups: &[report::Group],
) -> report::Summary {
    let count = |language: Language| {
        as_u64(
            inputs
                .files
                .iter()
                .filter(|file| file.language == language)
                .count(),
        )
    };
    let files = report::FileCounts {
        total: as_u64(inputs.files.len()),
        rust: count(Language::Rust),
        c: count(Language::C),
        cpp: count(Language::Cpp),
    };
    report::restored(files, stored, groups)
}

/// One group of the report model, with its similarity evidence and its
/// suppression cause resolved.
fn build_group(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.analysis.groups.groups[index];
    let detail = &inputs.analysis.details[index];
    let suppressed = inputs.group_suppressed[index].map(|rule| inputs.suppression(rule));
    report::ranked(
        report::Group {
            fingerprint: detail.fingerprint.to_hex(),
            clone_type: group.clone_type.name().to_string(),
            scope: CloneScope::Unit.name().to_string(),
            statements: None,
            confidence: group.min_pairwise,
            priority: report::Priority::unranked(),
            similarity: Some(similarity(group, detail)),
            identifier_jaccard: Some(detail.identifier_jaccard),
            body_materiality: Some(report::BodyMateriality {
                has_loop: detail.body_materiality.has_loop,
                has_dynamic_allocation: detail.body_materiality.has_dynamic_allocation,
                call_count: detail.body_materiality.call_count,
            }),
            boilerplate: detail
                .boilerplate
                .map(|category| category.name().to_string()),
            test_code: detail.test_code,
            width_family: detail.width_family,
            suppressed,
            baseline: None,
            split_pair: false,
            semantic: None,
            members: group
                .members
                .iter()
                .zip(ranks_within_host(member_hosts(
                    &inputs.analysis.units,
                    &group.members,
                )))
                .enumerate()
                .map(|(position, (&member, rank))| {
                    let unit = &inputs.analysis.units[member];
                    let file = &inputs.files[unit.file];
                    report::Member {
                        finding_id: stable_id::finding_id(
                            &detail.fingerprint,
                            Some(&unit.fingerprint),
                            rank,
                        )
                        .to_hex(),
                        content: unit.content.to_hex(),
                        file: file.relative_path.clone(),
                        language: file.language.name().to_string(),
                        start_line: unit.start_line,
                        end_line: unit.end_line,
                        unit: unit.name.as_deref().map(ToString::to_string),
                        boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                        tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start))
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

/// A split pair's occurrences with the canonical instance first.
///
/// [`VerifiedPair::members`] is in unit-index order and has to stay that way —
/// membership is answered by binary search over it — while a group lists its
/// canonical instance first and the audit database records whichever it was
/// handed first as the canonical one. Ordering here is what keeps the report
/// and the recorded rows saying the same thing about the same pair.
fn pair_members(pair: &VerifiedPair) -> Vec<usize> {
    let mut members = vec![pair.canonical];
    members.extend(pair.members.iter().filter(|&&m| m != pair.canonical));
    members
}

/// One verified clone relation that no group could hold, as a report entry.
///
/// It is shaped exactly like a group, because that is what it is: a set whose
/// every member is a copy of every other. What sets it apart is that its
/// members appear in other findings too, which `split_pair` says outright.
/// Where the same two contents recur across the tree the entry carries every
/// occurrence of both, since that is one relation observed many times rather
/// than many relations.
fn build_split_pair(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let pair = &inputs.analysis.unrepresented[index];
    let suppressed = inputs.pair_suppressed[index].map(|rule| inputs.suppression(rule));
    let members = &pair_members(pair);
    report::ranked(
        report::Group {
            fingerprint: pair.fingerprint.to_hex(),
            clone_type: pair.class.name().to_string(),
            scope: CloneScope::Unit.name().to_string(),
            statements: None,
            confidence: pair.similarity,
            priority: report::Priority::unranked(),
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: members
                .iter()
                .all(|&member| inputs.analysis.units[member].test_code),
            // Read off the group's medoid, which a split pair does not have:
            // it exists because no group could hold both its members.
            width_family: false,
            suppressed,
            baseline: None,
            split_pair: true,
            semantic: None,
            members: members
                .iter()
                .zip(ranks_within_host(member_hosts(
                    &inputs.analysis.units,
                    members,
                )))
                .enumerate()
                .map(|(position, (&member, rank))| {
                    let unit = &inputs.analysis.units[member];
                    let file = &inputs.files[unit.file];
                    report::Member {
                        finding_id: stable_id::finding_id(
                            &pair.fingerprint,
                            Some(&unit.fingerprint),
                            rank,
                        )
                        .to_hex(),
                        content: unit.content.to_hex(),
                        file: file.relative_path.clone(),
                        language: file.language.name().to_string(),
                        start_line: unit.start_line,
                        end_line: unit.end_line,
                        unit: unit.name.as_deref().map(ToString::to_string),
                        boilerplate: unit.boilerplate.map(|shape| shape.name().to_string()),
                        tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start))
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

/// One duplicated run as a report entry.
///
/// The occurrences are runs of statements, so each is anchored at its own line
/// span and names the unit it sits in; the units themselves are usually not
/// clones of each other, which is the whole point of reporting the run.
fn build_region(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = ranks_within_host(occurrence_hosts(&inputs.analysis.units, region));
    report::ranked(
        report::Group {
            fingerprint: region.fingerprint.to_hex(),
            clone_type: region.clone_type.name().to_string(),
            scope: CloneScope::Fragment.name().to_string(),
            statements: Some(u64::from(region.statements)),
            confidence: REGION_SIMILARITY,
            priority: report::Priority::unranked(),
            // Confirmed by content equality, not scored across dimensions: there
            // is no breakdown to report.
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            // Boilerplate is classified over whole units; a run inside one carries
            // no such classification.
            boilerplate: None,
            test_code: region_test_code(inputs.analysis, region),
            // Runs inside two units say nothing about how the units differ.
            width_family: false,
            suppressed: inputs.region_suppressed[index].map(|rule| inputs.suppression(rule)),
            baseline: None,
            split_pair: false,
            semantic: None,
            members: region
                .occurrences
                .iter()
                .zip(&ranks)
                .enumerate()
                .map(|(position, (occurrence, &rank))| {
                    let unit = &inputs.analysis.units[occurrence.unit];
                    let file = &inputs.files[occurrence.file];
                    report::Member {
                        finding_id: stable_id::finding_id(
                            &region.fingerprint,
                            Some(&unit.fingerprint),
                            rank,
                        )
                        .to_hex(),
                        content: occurrence.content.to_hex(),
                        file: file.relative_path.clone(),
                        language: file.language.name().to_string(),
                        start_line: occurrence.start_line,
                        end_line: occurrence.end_line,
                        unit: unit.name.as_deref().map(ToString::to_string),
                        boilerplate: None,
                        tokens: u64::try_from(
                            occurrence.token_end.saturating_sub(occurrence.token_start),
                        )
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

/// Rank of each occurrence within its host, in occurrence order.
///
/// A finding is told apart from its siblings by its host's fingerprint plus
/// its rank within that host, so the rank has to count per *fingerprint* and
/// not per host: a unit fingerprint is raw content, so the same function
/// copied unchanged into eight files carries one fingerprint across all eight,
/// and counting per host would hand all eight occurrences rank zero and one
/// identifier between them. Counting per fingerprint also keeps the case the
/// rank was introduced for — one run duplicated twice inside a single unit —
/// since those two share a host and therefore a fingerprint.
fn ranks_within_host(hosts: impl IntoIterator<Item = UnitFingerprint>) -> Vec<u32> {
    let mut next: BTreeMap<UnitFingerprint, u32> = BTreeMap::new();
    hosts
        .into_iter()
        .map(|host| {
            let slot = next.entry(host).or_insert(0);
            let rank = *slot;
            *slot = slot.saturating_add(1);
            rank
        })
        .collect()
}

/// The host fingerprints of a group's members, in member order.
fn member_hosts<'a>(
    units: &'a [StructuralUnit],
    members: &'a [usize],
) -> impl Iterator<Item = UnitFingerprint> + 'a {
    members.iter().map(|&member| units[member].fingerprint)
}

/// The host fingerprints of a duplicated run's occurrences, in occurrence
/// order.
fn occurrence_hosts<'a>(
    units: &'a [StructuralUnit],
    region: &'a StructuralRegion,
) -> impl Iterator<Item = UnitFingerprint> + 'a {
    region
        .occurrences
        .iter()
        .map(|occurrence| units[occurrence.unit].fingerprint)
}

/// A group's reported similarity: the medoid-to-member breakdown of its
/// *weakest* member, paired with the group's cohesion.
///
/// One breakdown is reported rather than an average so that every number
/// stays a real measurement of a real pair. The weakest member is the
/// conservative choice: it is the evidence a reader should judge the group
/// by.
fn weakest_breakdown(detail: &GroupDetail) -> &SimilarityBreakdown {
    detail
        .member_breakdowns
        .iter()
        .skip(1)
        .min_by(|a, b| a.composite.total_cmp(&b.composite))
        .unwrap_or(&detail.member_breakdowns[0])
}

fn similarity(group: &StructuralGroup, detail: &GroupDetail) -> report::Similarity {
    let breakdown = weakest_breakdown(detail);
    report::Similarity {
        weight_version: WEIGHT_VERSION.to_string(),
        lexical: breakdown.lexical,
        structural: breakdown.structural,
        control_flow: breakdown.control_flow,
        type_similarity: breakdown.type_similarity,
        api: breakdown.api,
        composite: breakdown.composite,
        min_pairwise: group.min_pairwise,
        confidence_band: Some(group.confidence.name().to_string()),
    }
}

/// The `(component, version)` pairs recorded with every structural snapshot.
/// The frontend versions are the structural parsers', which is what the
/// fingerprints were derived under.
///
/// What a difference in any of them costs a recorded result is weighed by
/// [`codehelion_core::compat`] rather than assumed from being listed: the
/// grouping rules and the ranking recipe are here because they can be seen in
/// a result, not because they move an identifier.
pub(crate) fn detector_versions(weights: Weights, literals: LiteralNorm) -> Vec<(String, String)> {
    vec![
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        (
            "literals".to_string(),
            ContentNorm::Normalized(literals).label().to_string(),
        ),
        ("grouping".to_string(), GROUPING_VERSION.to_string()),
        ("ranking".to_string(), weights.recipe()),
        (
            "normalization".to_string(),
            NORMALIZATION_VERSION.to_string(),
        ),
        ("features".to_string(), FEATURE_SCHEMA_VERSION.to_string()),
        ("verify-weights".to_string(), WEIGHT_VERSION.to_string()),
        ("boilerplate".to_string(), BOILERPLATE_VERSION.to_string()),
        ("test-code".to_string(), TEST_CODE_VERSION.to_string()),
        ("sog-schema".to_string(), SOG_SCHEMA_VERSION.to_string()),
        (
            "semantic-candidate-index".to_string(),
            SEMANTIC_CANDIDATE_INDEX_VERSION.to_string(),
        ),
        (
            "semantic-windowing".to_string(),
            SEMANTIC_WINDOWING_VERSION.to_string(),
        ),
        (
            "semantic-rule-registry".to_string(),
            SEMANTIC_RULE_REGISTRY_VERSION.to_string(),
        ),
        (
            "frontend.rust".to_string(),
            codehelion_frontend_rust::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.c".to_string(),
            codehelion_frontend_c::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
        (
            "frontend.cpp".to_string(),
            codehelion_frontend_cpp::ir::STRUCTURAL_FRONTEND_VERSION.to_string(),
        ),
    ]
}

/// Assemble and persist the snapshot; returns the recorded run id.
fn record(
    cfg: &Config,
    inputs: &ReportInputs<'_>,
    ranked: &[report::Group],
    files: Vec<FileRow>,
    summary: &SummaryRow,
    asked: Option<&semantic::Answers>,
    replace_existing: bool,
) -> Result<i64> {
    let (units, groups) = snapshot_rows(inputs, ranked)?;
    let mut store = open_store(inputs.db_path)?;
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let detector_versions = detector_versions(
        cfg.priority.weights(),
        literal_norm(cfg.literal_normalization),
    );
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
        started_at: inputs.started_at,
        finished_at: inputs.finished_at,
        variant: inputs.variant,
        min_clone_tokens: cfg.min_clone_tokens,
        detector_versions: &detector_versions,
        suppressions: inputs.rules.rows.clone(),
        files,
        units,
        groups,
        features: Vec::new(),
        compiler_helpers,
        compiler_units,
        summary: summary.clone(),
    };
    store
        .record_snapshot_part(&snapshot, replace_existing)
        .map_err(Into::into)
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
fn snapshot_rows(
    inputs: &ReportInputs<'_>,
    ranked: &[report::Group],
) -> Result<(Vec<UnitRow>, Vec<GroupRow>)> {
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
    Ok((units, groups))
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
    Ok(GroupRow {
        fingerprint,
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        member_scope: semantic_scope(members.iter().copied(), inputs.analysis),
        statements: None,
        test_code: members
            .iter()
            .all(|member| inputs.analysis.units[member.unit].test_code),
        split_pair: true,
        score: pair.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(
            inputs.unit_tokens(canonical_unit),
            inputs.literals,
        ),
        suppress_reason: inputs.semantic_pair_suppressed[index]
            .map(|rule| inputs.rules.rows[rule].pattern.clone()),
        boilerplate: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        width_family: false,
        suppressed_by: inputs.semantic_pair_suppressed[index],
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        similarity: None,
        semantic: Some(SemanticEvidenceRow {
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
        }),
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
    })
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
    Ok(GroupRow {
        fingerprint,
        clone_type: codehelion_core::clone_class::CloneClass::RestrictedSemantic,
        member_scope: semantic_scope(group.members.iter(), inputs.analysis),
        statements: None,
        test_code: group
            .members
            .iter()
            .all(|member| inputs.analysis.units[member.unit].test_code),
        split_pair: false,
        score: group.semantic_confidence,
        entropy_bits: engine::content_entropy_bits(
            inputs.unit_tokens(canonical_unit),
            inputs.literals,
        ),
        suppress_reason: inputs.semantic_group_suppressed[index]
            .map(|rule| inputs.rules.rows[rule].pattern.clone()),
        boilerplate: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        width_family: false,
        suppressed_by: inputs.semantic_group_suppressed[index],
        priority: recorded_ranking(ranking, &fingerprint.to_hex())?,
        similarity: None,
        semantic: Some(SemanticEvidenceRow {
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
        }),
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
    })
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
    Ok(GroupRow {
        fingerprint: detail.fingerprint,
        clone_type: group.clone_type,
        member_scope: CloneScope::Unit,
        statements: None,
        test_code: detail.test_code,
        split_pair: false,
        score: group.min_pairwise,
        entropy_bits: engine::content_entropy_bits(inputs.unit_tokens(medoid), inputs.literals),
        // The structural funnel marks no noise category yet.
        suppress_reason: None,
        boilerplate: detail.boilerplate,
        width_family: detail.width_family,
        suppressed_by: inputs.group_suppressed[index],
        priority: recorded_ranking(ranking, &detail.fingerprint.to_hex())?,
        similarity: Some(breakdown_row(group, detail)),
        identifier_jaccard: Some(detail.identifier_jaccard),
        has_loop: Some(detail.body_materiality.has_loop),
        has_dynamic_allocation: Some(detail.body_materiality.has_dynamic_allocation),
        call_count: Some(detail.body_materiality.call_count),
        semantic: None,
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
    })
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
    Ok(GroupRow {
        fingerprint: pair.fingerprint,
        clone_type: pair.class,
        member_scope: CloneScope::Unit,
        statements: None,
        test_code: pair
            .members
            .iter()
            .all(|&member| inputs.analysis.units[member].test_code),
        split_pair: true,
        score: pair.similarity,
        entropy_bits: engine::content_entropy_bits(inputs.unit_tokens(canonical), inputs.literals),
        suppress_reason: None,
        boilerplate: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        width_family: false,
        suppressed_by: inputs.pair_suppressed[index],
        priority: recorded_ranking(ranking, &pair.fingerprint.to_hex())?,
        // The pair's evidence is the judge's verdict on it, which grouping did
        // not re-run against a medoid, so there is no per-dimension row to
        // record without inventing one.
        similarity: None,
        semantic: None,
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
    })
}

fn region_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
    ranking: &BTreeMap<&str, &report::Priority>,
) -> Result<GroupRow> {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = ranks_within_host(occurrence_hosts(&inputs.analysis.units, region));
    let canonical = region
        .occurrences
        .first()
        .map_or_else(Vec::new, |occurrence| {
            inputs.region_tokens(occurrence).to_vec()
        });
    Ok(GroupRow {
        fingerprint: region.fingerprint,
        clone_type: region.clone_type,
        member_scope: CloneScope::Fragment,
        statements: Some(region.statements),
        test_code: region_test_code(inputs.analysis, region),
        split_pair: false,
        score: REGION_SIMILARITY,
        entropy_bits: engine::content_entropy_bits(&canonical, inputs.literals),
        suppress_reason: None,
        boilerplate: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        width_family: false,
        suppressed_by: inputs.region_suppressed[index],
        priority: recorded_ranking(ranking, &region.fingerprint.to_hex())?,
        similarity: None,
        semantic: None,
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
    })
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CategoryAction, Compilers, Config, CrossLanguageCandidateInput, ExecutionPolicy, Language,
        LanguageSelection, SandboxRequest, ScanArgs, SemanticCandidateConfig,
        SemanticOperationGraph, StructuralConfig, enabled_cross_language_matches,
        extract_cross_language_candidates, presentation_suppression, run_with, semantic_sandbox,
        structural_config, verify_cross_language_candidates,
    };
    use crate::cli::{Format, Mode, SortAxis};
    use codehelion_core::semantic::{OperationAttributes, OperationKind, OperationNode};
    use std::path::PathBuf;

    #[test]
    fn include_trivial_overrides_only_this_invocations_presentation_policy() {
        let config = Config::default();
        assert_eq!(
            config.suppression.boilerplate.trivial_body,
            CategoryAction::RankDown
        );
        let presentation = presentation_suppression(&config, true);
        assert_eq!(
            presentation.boilerplate.trivial_body,
            CategoryAction::Report
        );
        assert_eq!(
            config.suppression.boilerplate.trivial_body,
            CategoryAction::RankDown,
            "the flag does not change the persisted configuration"
        );
    }

    /// Whether a helper is installed is a property of the machine, so what is
    /// fixed here is the pairing: without one, the message names the programs
    /// to install rather than the mode that was asked for; with one, the run
    /// knows which compiler answered.
    #[test]
    fn a_run_that_needs_a_compiler_says_which_program_supplies_it() {
        match Compilers::found(&ExecutionPolicy::deny_all(), SandboxRequest::unrestricted()) {
            Err(error) => {
                let text = format!("{error:#}");
                assert!(
                    text.contains(codehelion_core::doctor::RUST_HELPER.binary),
                    "{text}"
                );
            }
            Ok(compilers) => {
                for helper in &compilers.installed {
                    assert!(
                        !helper.greeting.toolchains.is_empty(),
                        "a helper that answered says what will do the analysing"
                    );
                }
            }
        }
    }

    #[test]
    fn untrusted_semantic_requires_an_enforceable_memory_limit() {
        let args = ScanArgs {
            sort: SortAxis::default(),
            min_identifier_jaccard: None,
            path: PathBuf::from("."),
            mode: Mode::Semantic,
            format: Format::Text,
            output: None,
            config: None,
            no_ignore: false,
            jobs: None,
            db: None,
            baseline: None,
            baseline_mode: crate::cli::BaselineMode::Suppress,
            allow_execution: None,
            compare_build_variants: false,
            compare_languages: false,
            show_suppressed: false,
            include_trivial: false,
            include_vendored: false,
            verbose: false,
            fail_on_findings: false,
            untrusted: true,
        };
        let error = semantic_sandbox(&args).expect_err("portable build cannot enforce it");
        assert!(
            format!("{error:#}").contains("OS memory containment is unavailable"),
            "{error:#}"
        );
    }

    /// A helper that reads none of the languages the tree holds has nothing to
    /// answer about, and a run that counted it would file its results under a
    /// compiler that never saw the project — giving one tree two identities
    /// depending on what happens to be installed beside the scanner.
    #[test]
    fn a_helper_that_reads_nothing_in_this_tree_is_not_part_of_the_run() {
        let Ok(compilers) =
            Compilers::found(&ExecutionPolicy::deny_all(), SandboxRequest::unrestricted())
        else {
            return;
        };
        let rust_only = LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        };
        for helper in compilers.at_work(rust_only) {
            assert!(
                helper.component.analyses.contains(&Language::Rust),
                "{} was asked about a tree it reads nothing in",
                helper.component.name
            );
        }
    }

    /// Nothing to scan is not the same as nothing to scan it with. A tree with
    /// no sources gives every helper nothing to do, and refusing there would
    /// report an empty directory as a machine missing a compiler.
    #[test]
    fn an_empty_tree_is_not_reported_as_a_missing_compiler() {
        let dir = tempfile::tempdir().unwrap();
        let args = ScanArgs {
            sort: SortAxis::default(),
            min_identifier_jaccard: None,
            path: dir.path().to_path_buf(),
            mode: Mode::Semantic,
            format: Format::Text,
            output: None,
            config: None,
            no_ignore: false,
            jobs: None,
            db: Some(dir.path().join("audit.db")),
            baseline: None,
            baseline_mode: crate::cli::BaselineMode::Suppress,
            allow_execution: None,
            compare_build_variants: false,
            compare_languages: false,
            show_suppressed: false,
            include_trivial: false,
            include_vendored: false,
            verbose: false,
            fail_on_findings: false,
            untrusted: false,
        };
        let Ok(compilers) =
            Compilers::found(&ExecutionPolicy::deny_all(), SandboxRequest::unrestricted())
        else {
            return;
        };
        let mut out = Vec::new();
        run_with(&args, &mut out, Some(&compilers)).expect("an empty tree scans");
    }

    /// Structural pairs statement fragments where Fast pairs token windows, and
    /// the two need different ceilings. Reading one number from the
    /// configuration for both would hand this mode a limit chosen for the other
    /// — which is how a ceiling meant as a safety valve becomes a silent cut.
    #[test]
    fn an_unset_ceiling_leaves_every_stage_at_its_own_default() {
        let config = structural_config(&Config::default());
        let defaults = StructuralConfig::default();
        assert_eq!(config.candidate.posting_cap, defaults.candidate.posting_cap);
        assert_eq!(config.candidate.pair_budget, defaults.candidate.pair_budget);
        assert_eq!(
            config.near_match.posting_cap,
            defaults.near_match.posting_cap
        );
        assert_eq!(
            config.control_flow.pair_budget,
            defaults.control_flow.pair_budget
        );
    }

    /// A ceiling that is set bounds the whole funnel, not one stage of it.
    #[test]
    fn a_configured_ceiling_reaches_every_candidate_stage() {
        let cfg = Config {
            limits: crate::config::Limits {
                posting_cap: Some(9),
                pair_budget: Some(11),
                ..crate::config::Limits::default()
            },
            ..Config::default()
        };
        let config = structural_config(&cfg);
        for cap in [
            config.candidate.posting_cap,
            config.near_match.posting_cap,
            config.control_flow.posting_cap,
        ] {
            assert_eq!(cap, 9);
        }
        for budget in [
            config.candidate.pair_budget,
            config.near_match.pair_budget,
            config.control_flow.pair_budget,
        ] {
            assert_eq!(budget, 11);
        }
    }

    #[test]
    fn semantic_candidate_cuts_are_visible_in_the_shared_funnel() {
        let detection = super::SemanticDetection {
            groups: Vec::new(),
            pairs: Vec::new(),
            units: Vec::new(),
            candidates: codehelion_core::semantic::SemanticCandidateStats {
                graphs: 8,
                ineligible_graphs: 2,
                buckets: 3,
                oversized_buckets: 1,
                pairs_available: 9,
                pairs_budget_dropped: 4,
                pairs_emitted: 5,
            },
            registered_observations: 8,
            excluded_observations: 6,
            unrepresentable_units: 2,
            verified_pairs: 3,
            disabled_pairs: 1,
            grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
        };
        let funnel = super::funnel(
            &codehelion_core::structural::StructuralStats::default(),
            &detection,
        );
        let candidate = funnel
            .iter()
            .find(|stage| stage.stage == "semantic candidate pairs")
            .expect("semantic candidate stage");
        assert_eq!(candidate.passed, 5);
        assert!(
            candidate
                .dropped
                .iter()
                .any(|drop| drop.cause == "pair_budget" && drop.count == 4)
        );
        let observations = funnel
            .iter()
            .find(|stage| stage.stage == "semantic API observations")
            .expect("semantic observation stage");
        assert_eq!(observations.passed, 14);
        assert!(
            observations
                .dropped
                .iter()
                .any(|drop| drop.cause == "outside_registered_vocabulary" && drop.count == 6)
        );
        let graphs = funnel
            .iter()
            .find(|stage| stage.stage == "semantic graphs")
            .expect("semantic graph stage");
        assert!(
            graphs
                .dropped
                .iter()
                .any(|drop| drop.cause == "no_registered_operations" && drop.count == 2)
        );
        let verified = funnel
            .iter()
            .find(|stage| stage.stage == "semantic verified pairs")
            .expect("semantic verification stage");
        assert!(
            verified
                .dropped
                .iter()
                .any(|drop| drop.cause == "rule_disabled" && drop.count == 1)
        );
    }

    #[test]
    fn incomplete_normalization_lowers_confidence_without_affecting_matching() {
        assert!((super::normalization_confidence(3, 0) - 1.0).abs() < f64::EPSILON);
        assert!((super::normalization_confidence(0, 2) - 0.0).abs() < f64::EPSILON);
        let empty_interactions = std::collections::BTreeSet::new();
        let empty_data_flows = std::collections::BTreeSet::new();
        assert!(
            (super::semantic_confidence(
                0.7,
                super::SemanticConfidenceEvidence {
                    normalization: 1.0,
                    interactions: &empty_interactions,
                    data_flows: &empty_data_flows,
                    cfg_shape: None,
                },
                super::SemanticConfidenceEvidence {
                    normalization: 0.5,
                    interactions: &empty_interactions,
                    data_flows: &empty_data_flows,
                    cfg_shape: None,
                },
            ) - 0.35)
                .abs()
                < f64::EPSILON
        );
        let file = std::collections::BTreeSet::from(["file_io".to_owned()]);
        let lock = std::collections::BTreeSet::from(["synchronization".to_owned()]);
        assert!((super::interaction_confidence(&file, &file) - 1.05).abs() < f64::EPSILON);
        assert!((super::interaction_confidence(&file, &lock) - 0.85).abs() < f64::EPSILON);
        assert!(
            (super::interaction_confidence(&file, &std::collections::BTreeSet::new()) - 1.0).abs()
                < f64::EPSILON
        );
        let filter_map = std::collections::BTreeSet::from([(
            "rust::Iterator::filter".to_owned(),
            "rust::Iterator::map".to_owned(),
        )]);
        let map_filter = std::collections::BTreeSet::from([(
            "rust::Iterator::map".to_owned(),
            "rust::Iterator::filter".to_owned(),
        )]);
        assert!(
            (super::data_flow_confidence(&filter_map, &filter_map) - 1.05).abs() < f64::EPSILON
        );
        assert!(
            (super::data_flow_confidence(&filter_map, &map_filter) - 0.85).abs() < f64::EPSILON
        );
        assert!(
            (super::data_flow_confidence(&filter_map, &std::collections::BTreeSet::new()) - 1.0)
                .abs()
                < f64::EPSILON
        );
        let straight = super::CfgShape {
            blocks: 2,
            flow_edges: 1,
            taken_edges: 0,
            not_taken_edges: 0,
            unwind_edges: 0,
            return_edges: 0,
        };
        let branch = super::CfgShape {
            taken_edges: 1,
            not_taken_edges: 1,
            ..straight
        };
        assert!(
            (super::cfg_confidence(Some(straight), Some(straight)) - 1.05).abs() < f64::EPSILON
        );
        assert!((super::cfg_confidence(Some(straight), Some(branch)) - 0.85).abs() < f64::EPSILON);
        assert!((super::cfg_confidence(Some(straight), None) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compiler_cfg_is_reduced_to_the_overlapping_semantic_window() {
        let anchor = |start_byte, end_byte| {
            codehelion_helper::ir::Anchor::written_here(codehelion_helper::ir::SourceRange {
                file: "src/lib.rs".to_string(),
                start_byte,
                end_byte,
                start_line: 1,
            })
        };
        let cfg = codehelion_helper::ir::ControlFlowGraph {
            blocks: vec![
                codehelion_helper::ir::BasicBlock {
                    anchor: anchor(10, 20),
                    length: 2,
                },
                codehelion_helper::ir::BasicBlock {
                    anchor: anchor(20, 30),
                    length: 1,
                },
                codehelion_helper::ir::BasicBlock {
                    anchor: anchor(40, 50),
                    length: 1,
                },
            ],
            edges: vec![
                codehelion_helper::ir::Edge {
                    from: 0,
                    to: 1,
                    kind: codehelion_helper::ir::EdgeKind::Flow,
                },
                codehelion_helper::ir::Edge {
                    from: 1,
                    to: 2,
                    kind: codehelion_helper::ir::EdgeKind::Taken,
                },
            ],
        };
        assert_eq!(
            super::semantic_window_cfg_shape(
                Some(&cfg),
                "src/lib.rs",
                codehelion_core::semantic::SemanticSourceRange { start: 10, end: 30 },
            ),
            Some(super::CfgShape {
                blocks: 2,
                flow_edges: 1,
                taken_edges: 0,
                not_taken_edges: 0,
                unwind_edges: 0,
                return_edges: 0,
            })
        );
        assert!(
            super::semantic_window_cfg_shape(
                Some(&cfg),
                "src/lib.rs",
                codehelion_core::semantic::SemanticSourceRange { start: 30, end: 40 },
            )
            .is_none()
        );
    }

    #[test]
    fn direct_data_flow_is_scoped_to_its_semantic_window() {
        let summary = codehelion_helper::ir::DataFlowSummary {
            computed: true,
            flows: vec![
                (
                    "10:16:rust::Iterator::filter".to_owned(),
                    "17:20:rust::Iterator::map".to_owned(),
                ),
                (
                    "40:46:rust::Iterator::filter".to_owned(),
                    "47:50:rust::Iterator::map".to_owned(),
                ),
            ],
        };
        let first = super::semantic_window_data_flows(
            &summary,
            codehelion_core::semantic::SemanticSourceRange { start: 0, end: 30 },
        );
        assert_eq!(
            first,
            std::collections::BTreeSet::from([(
                "rust::Iterator::filter".to_owned(),
                "rust::Iterator::map".to_owned(),
            )])
        );
        assert!(
            super::semantic_window_data_flows(
                &summary,
                codehelion_core::semantic::SemanticSourceRange { start: 21, end: 39 },
            )
            .is_empty()
        );
    }

    #[test]
    fn a_disabled_cross_language_rule_cannot_reach_the_comparison_report() {
        let graph = |language, variant| {
            SemanticOperationGraph::new(
                language,
                variant,
                vec![OperationNode {
                    kind: OperationKind::Validate,
                    attributes: OperationAttributes {
                        fallible_kind: Some(codehelion_core::semantic::FallibleKind::Option),
                        ..OperationAttributes::default()
                    },
                }],
                Vec::new(),
            )
            .expect("closed optional validation graph")
        };
        let inputs = vec![
            CrossLanguageCandidateInput {
                comparison_partition: [1; 16],
                graph: graph(Language::Rust, [2; 32]),
            },
            CrossLanguageCandidateInput {
                comparison_partition: [1; 16],
                graph: graph(Language::Cpp, [3; 32]),
            },
        ];
        let candidates =
            extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
        let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
        assert_eq!(verified.len(), 1);

        let config = Config::from_toml(
            "[semantic]\ndisabled = [\"cross-language-optional-validation-v1\"]\n",
        )
        .expect("registered cross-language rule is configurable");
        assert!(enabled_cross_language_matches(verified, &config).is_empty());
    }
}
