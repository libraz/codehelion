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
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_core::boilerplate::{BOILERPLATE_VERSION, Boilerplate};
use codehelion_core::clone_class::CloneScope;
use codehelion_core::discovery::{
    BuildVariant, ContentHash, DiscoveryReport, Language, LanguageSelection, NORMALIZATION_VERSION,
    SourceUnit,
};
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::features::FEATURE_SCHEMA_VERSION;
use codehelion_core::frontend::Token;
use codehelion_core::grouping::{GROUPING_VERSION, StructuralGroup};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::priority::Weights;
use codehelion_core::stable_id::{self, ContentNorm, FP_SCHEMA_VERSION, UnitFingerprint};
use codehelion_core::structural::{
    self, GroupDetail, RegionOccurrence, StructuralConfig, StructuralRegion, StructuralReport,
    StructuralUnit, VerifiedPair,
};
use codehelion_core::test_code::{self, TEST_CODE_VERSION};
use codehelion_core::verify::{SimilarityBreakdown, WEIGHT_VERSION};
use codehelion_store::snapshot::{
    FileRow, GroupOrigin, GroupRow, MemberRow, PriorityRow, SimilarityBreakdownRow, Snapshot,
    SummaryRow, UnitRow, UnparsedRow,
};

use super::{
    FileOutcome, ScanBaseline, as_u64, database_path, discover_sources, effective_jobs,
    filter_globs, literal_norm, map_sources, open_store, rfc3339_now, write_report,
};

use crate::Outcome;
use crate::cli::ScanArgs;
use crate::config::{self, BoilerplatePolicy, CategoryAction, Config};
use crate::report::{self, Report};
use crate::suppress;

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

/// Execute `codehelion scan` in Structural mode.
///
/// # Errors
///
/// Returns an error when the scan path, configuration or globs are invalid,
/// when the audit database cannot be opened or written, or when report output
/// fails. Per-file problems (unreadable or malformed sources) are counted and
/// reported instead of failing the scan.
pub fn run(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    let started_at = rfc3339_now();
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        bail!("scan path {} is not a directory", root.display());
    }
    let cfg = config::load(args.config.as_deref(), &root)?.config;
    let jobs = effective_jobs(args.jobs, cfg.jobs)?;

    let mut discovered = discover_sources(&root, &cfg, args.no_ignore)?;
    let sources = std::mem::take(&mut discovered.units);
    let (sources, glob_excluded) = filter_globs(&cfg, sources)?;

    // Discovery reports the Fast variant; the results belong to the
    // Structural one, and the two never share a fingerprint. The header
    // grammar carries over unchanged: it decided which frontend read every
    // `.h` below, so it describes these results just as it does Fast's.
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: cfg.languages.rust,
            c: cfg.languages.c,
            cpp: cfg.languages.cpp,
        },
        discovered.header_language,
    );
    let db_path = database_path(&root, args.db.as_deref(), &cfg);
    if let Some(model) = crate::scan::reusable(args, &cfg, &root, &db_path, &variant, &sources)? {
        write_report(args, out, &model)?;
        return Ok(crate::scan::outcome(args, &model));
    }

    let timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (parsed, unreadable, timed_out) =
        map_sources(&sources, jobs, |source| parse_one(source, timeout))?;
    let (files, mut irs): (Vec<SourceMeta>, Vec<SyntaxIrFile>) = parsed
        .into_iter()
        .map(|source| (source.meta, source.ir))
        .unzip();
    mark_test_modules(&files, &mut irs);

    let analysis = structural::analyze(&irs, &variant, &structural_config(&cfg));

    let mut rules = compile_rules(&cfg, &files, &analysis)?;
    let baseline = crate::scan::load_baseline(
        args.baseline.as_deref(),
        &mut rules.rules,
        &variant,
        &detector_versions(
            cfg.priority.weights(),
            literal_norm(cfg.literal_normalization),
        ),
    )?;
    let regions = reportable_regions(&analysis);
    let suppressed = evaluate_suppression(&cfg, &mut rules, &analysis, &regions);

    let changes = crate::scan::tree_changes(&db_path, &root, &variant, &sources)?;
    let finished_at = rfc3339_now();
    let mut inputs = ReportInputs {
        root: &root,
        db_path: &db_path,
        started_at: &started_at,
        finished_at: &finished_at,
        variant: &variant,
        files: &files,
        irs: &irs,
        analysis: &analysis,
        rules: &rules.rules,
        group_suppressed: &suppressed.groups,
        regions: &regions,
        region_suppressed: &suppressed.regions,
        suppression: &cfg.suppression,
        pair_suppressed: &suppressed.pairs,
        literals: literal_norm(cfg.literal_normalization),
        glob_excluded,
        unreadable,
        timed_out,
        changes,
        audit: None,
        weights: cfg.priority.weights(),
        min_clone_tokens: u64::from(cfg.min_clone_tokens),
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
    let (run_id, audit) = record(
        &cfg,
        &inputs,
        &groups,
        crate::scan::file_rows(&sources),
        &stored,
    )?;
    inputs.audit = audit;
    let mut model = build_report(&inputs, run_id, &stored, groups);
    // Counted against the assembled report rather than the raw analysis: a
    // stale entry is one whose duplication this run does not list.
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| crate::scan::baseline_status(baseline, &model.groups));
    write_report(args, out, &model)?;
    Ok(crate::scan::outcome(args, &model))
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
}

/// Evaluate the configured suppression against everything the report lists.
///
/// The three kinds of finding are judged by the same rules read at their own
/// place in the code: a marker or a path glob is an instruction about where
/// code sits, and a run or a pair sits somewhere as much as a group does.
fn evaluate_suppression(
    cfg: &Config,
    rules: &mut StructuralRules,
    analysis: &StructuralReport,
    regions: &ReportableRegions,
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
    SuppressionVerdicts {
        groups,
        regions: region_verdicts,
        pairs,
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
    /// Literal strategy the group content is scored under.
    literals: LiteralNorm,
    glob_excluded: usize,
    unreadable: u64,
    timed_out: u64,
    /// What moved since the previous scan of this tree, when comparable.
    changes: Option<report::TreeChanges>,
    audit: Option<report::AuditSummary>,
    /// How the run weighs the priority measures against one another.
    weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    min_clone_tokens: u64,
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
/// entries last, then priority descending, then fingerprint ascending, so
/// every view is stable across reruns.
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
        .collect();
    report::order(&mut entries, inputs.suppression);
    entries
}

/// The structural pipeline's pass counts, stage by stage.
///
/// The run forks after candidate extraction: whole units go to verification
/// and grouping, while the statement windows that seeded the candidates are
/// folded back into the maximal runs they describe and confirmed against the
/// tokens they cover. The confirmed-run counts therefore continue the seed
/// line, not the verified-pair line.
fn funnel(stats: &structural::StructuralStats) -> Vec<report::FunnelStage> {
    let near = &stats.near_match;
    let grouping = &stats.grouping;
    let maximal = &stats.maximal;
    vec![
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
    ]
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
            reused: false,
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
            || stats.control_flow.budget_exhausted,
        baseline_digest,
        funnel: report::stored_funnel(&funnel(stats)),
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
    let mut summary = report::restored(files, stored, groups);
    summary.changes = inputs.changes;
    summary.audit.clone_from(&inputs.audit);
    summary
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
            boilerplate: detail
                .boilerplate
                .map(|category| category.name().to_string()),
            test_code: detail.test_code,
            width_family: detail.width_family,
            suppressed,
            split_pair: false,
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
            boilerplate: None,
            test_code: members
                .iter()
                .all(|&member| inputs.analysis.units[member].test_code),
            // Read off the group's medoid, which a split pair does not have:
            // it exists because no group could hold both its members.
            width_family: false,
            suppressed,
            split_pair: true,
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
            // Boilerplate is classified over whole units; a run inside one carries
            // no such classification.
            boilerplate: None,
            test_code: region_test_code(inputs.analysis, region),
            // Runs inside two units say nothing about how the units differ.
            width_family: false,
            suppressed: inputs.region_suppressed[index].map(|rule| inputs.suppression(rule)),
            split_pair: false,
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
) -> Result<(i64, Option<report::AuditSummary>)> {
    let (units, mut groups) = snapshot_rows(inputs, ranked)?;
    let mut store = open_store(inputs.db_path)?;
    let audit =
        crate::scan::attach_history(&store, inputs.root, inputs.variant, &units, &mut groups)?;
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
        variant: inputs.variant,
        min_clone_tokens: cfg.min_clone_tokens,
        detector_versions: &detector_versions,
        suppressions: inputs.rules.rows.clone(),
        files,
        units,
        groups,
        features: Vec::new(),
        summary: summary.clone(),
    };
    Ok((store.record_snapshot(&snapshot)?, audit))
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
    let groups = (0..inputs.analysis.groups.groups.len())
        .map(|index| unit_group_row(inputs, index, &host_index, &ranking))
        .chain(regions.into_iter().map(Ok))
        .chain(split_pairs.into_iter().map(Ok))
        .collect::<Result<Vec<_>>>()?;
    Ok((units, groups))
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
        history: GroupOrigin::unconnected(&detail.fingerprint),
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
        history: GroupOrigin::unconnected(&pair.fingerprint),
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
        width_family: false,
        suppressed_by: inputs.pair_suppressed[index],
        priority: recorded_ranking(ranking, &pair.fingerprint.to_hex())?,
        // The pair's evidence is the judge's verdict on it, which grouping did
        // not re-run against a medoid, so there is no per-dimension row to
        // record without inventing one.
        similarity: None,
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
        history: GroupOrigin::unconnected(&region.fingerprint),
        clone_type: region.clone_type,
        member_scope: CloneScope::Fragment,
        statements: Some(region.statements),
        test_code: region_test_code(inputs.analysis, region),
        split_pair: false,
        score: REGION_SIMILARITY,
        entropy_bits: engine::content_entropy_bits(&canonical, inputs.literals),
        suppress_reason: None,
        boilerplate: None,
        width_family: false,
        suppressed_by: inputs.region_suppressed[index],
        priority: recorded_ranking(ranking, &region.fingerprint.to_hex())?,
        similarity: None,
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
    use super::{Config, StructuralConfig, structural_config};

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
}
