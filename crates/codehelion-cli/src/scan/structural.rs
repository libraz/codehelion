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
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{
    BuildVariant, ContentHash, DiscoveryReport, Language, LanguageSelection, NORMALIZATION_VERSION,
    SourceUnit,
};
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::features::FEATURE_SCHEMA_VERSION;
use codehelion_core::frontend::Token;
use codehelion_core::grouping::StructuralGroup;
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::stable_id::{self, FP_SCHEMA_VERSION};
use codehelion_core::structural::{
    self, GroupDetail, RegionOccurrence, StructuralConfig, StructuralRegion, StructuralReport,
    StructuralUnit,
};
use codehelion_core::verify::{SimilarityBreakdown, WEIGHT_VERSION};
use codehelion_store::snapshot::{GroupRow, MemberRow, SimilarityBreakdownRow, Snapshot, UnitRow};

use super::{
    FileOutcome, database_path, discover_sources, effective_jobs, filter_globs, literal_norm,
    map_sources, open_store, rfc3339_now, write_report,
};
use crate::Outcome;
use crate::cli::ScanArgs;
use crate::config::{self, BoilerplateAction, BoilerplatePolicy, Config};
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
    let timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (parsed, unreadable, timed_out) =
        map_sources(&sources, jobs, |source| parse_one(source, timeout))?;
    let (files, irs): (Vec<SourceMeta>, Vec<SyntaxIrFile>) = parsed
        .into_iter()
        .map(|source| (source.meta, source.ir))
        .unzip();

    // Discovery reports the Fast variant; the results belong to the
    // Structural one, and the two never share a fingerprint.
    let variant = BuildVariant::structural(LanguageSelection {
        rust: cfg.languages.rust,
        c: cfg.languages.c,
        cpp: cfg.languages.cpp,
    });
    let analysis = structural::analyze(&irs, &variant, &structural_config(&cfg));

    let mut rules = compile_rules(&cfg, &files, &analysis)?;
    let hidden = hidden_boilerplate(&mut rules.rules, &cfg.suppression.boilerplate, &analysis);
    let local_units = local_unit_indices(&analysis);
    // Most specific rule first: a clone id names this exact group, a path or
    // symbol glob or an inline marker is an explicit instruction about where
    // the members sit, and a boilerplate category is a judgement about their
    // shape.
    let group_suppressed: Vec<Option<usize>> = analysis
        .groups
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            rules
                .rules
                .clone_id_rule(&analysis.details[index].fingerprint.to_hex())
                .or_else(|| {
                    rules.group_rule(group.members.iter().copied(), &analysis, &local_units)
                })
                .or_else(|| {
                    analysis.details[index]
                        .boilerplate
                        .and_then(|category| hidden.get(&category).copied())
                })
        })
        .collect();
    let regions = reportable_regions(&analysis);
    // A duplicated run is suppressed by the same rules a whole unit is, read
    // at the run's own line span rather than its host unit's: a marker or a
    // path glob is an instruction about a place in the code, and a run has
    // its own place.
    let region_suppressed: Vec<Option<usize>> = regions
        .reported
        .iter()
        .map(|&index| {
            let region = &analysis.regions[index];
            rules
                .rules
                .clone_id_rule(&region.fingerprint.to_hex())
                .or_else(|| rules.region_rule(region, &analysis, &local_units))
        })
        .collect();

    let db_path = database_path(&root, args.db.as_deref(), &cfg);
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
        rules: &rules.rules,
        group_suppressed: &group_suppressed,
        regions: &regions,
        region_suppressed: &region_suppressed,
        boilerplate: &cfg.suppression.boilerplate,
        literals: literal_norm(cfg.literal_normalization),
        glob_excluded,
        unreadable,
        timed_out,
    };
    let run_id = record(&cfg, &inputs)?;
    let model = build_report(&inputs, run_id, &discovered);
    write_report(args, out, &model)?;

    let visible = model
        .groups
        .iter()
        .filter(|group| group.suppressed.is_none())
        .count();
    if args.fail_on_findings && visible > 0 {
        Ok(Outcome::FindingsPresent)
    } else {
        Ok(Outcome::Success)
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
    FileOutcome::Done(Box::new(ParsedSource {
        meta: SourceMeta {
            relative_path: source.relative_path.to_string_lossy().into_owned(),
            language: source.language,
            marker_lines: suppress::marker_lines(&text),
            lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
            diagnostics: ir.diagnostics.len(),
        },
        ir,
    }))
}

/// Build the structural stage configuration from the effective scan
/// configuration: the candidate ceilings apply to both candidate stages, so
/// one configured budget bounds the whole funnel.
fn structural_config(cfg: &Config) -> StructuralConfig {
    let mut config = StructuralConfig::default();
    config.candidate.posting_cap = cfg.limits.posting_cap;
    config.candidate.pair_budget = cfg.limits.pair_budget;
    config.near_match.posting_cap = cfg.limits.posting_cap;
    config.near_match.pair_budget = cfg.limits.pair_budget;
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
        if policy.action(category) != BoilerplateAction::Hide {
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
/// units are not all members of one group, and a run small enough to name a
/// place inside its hosts rather than restate them.
fn reportable_regions(analysis: &StructuralReport) -> ReportableRegions {
    let mut member_of: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, group) in analysis.groups.groups.iter().enumerate() {
        for &member in &group.members {
            member_of.entry(member).or_default().push(index);
        }
    }
    let covers = |hosts: &BTreeSet<usize>| {
        let Some(first) = hosts.first() else {
            return false;
        };
        member_of.get(first).is_some_and(|groups| {
            groups.iter().any(|&group| {
                hosts
                    .iter()
                    .all(|host| analysis.groups.groups[group].members.contains(host))
            })
        })
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
        if one_per_unit && hosts.len() > 1 && covers(&hosts) && !localizes(analysis, region) {
            folded += 1;
        } else {
            reported.push(index);
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
    /// What the report does with each recognised boilerplate shape.
    boilerplate: &'a BoilerplatePolicy,
    /// Literal strategy the group content is scored under.
    literals: LiteralNorm,
    glob_excluded: usize,
    unreadable: u64,
    timed_out: u64,
}

impl ReportInputs<'_> {
    /// The tokens one analysed unit covers, in its own file.
    fn unit_tokens(&self, unit: &StructuralUnit) -> &[Token] {
        let tokens = &self.irs[unit.file].tokens;
        let end = unit.token_end.min(tokens.len());
        let start = unit.token_start.min(end);
        &tokens[start..end]
    }

    /// Ranking value, computed exactly as the Fast path computes it: largest
    /// member size × extra instances × similarity. The inputs are always
    /// reported alongside; the collapsed number never replaces them.
    fn priority(&self, group: &StructuralGroup) -> f64 {
        let size = u32::try_from(self.largest_member_tokens(group)).unwrap_or(u32::MAX);
        let extra = u32::try_from(group.members.len().saturating_sub(1)).unwrap_or(u32::MAX);
        f64::from(size) * f64::from(extra) * group.min_pairwise
    }

    /// Whether a group is reported below every group that carries behaviour,
    /// because its shape is boilerplate the policy ranks down.
    fn ranked_down(&self, index: usize) -> bool {
        self.analysis.details[index]
            .boilerplate
            .is_some_and(|category| {
                self.boilerplate.action(category) == BoilerplateAction::RankDown
            })
    }

    /// Token count of the group's largest member.
    fn largest_member_tokens(&self, group: &StructuralGroup) -> usize {
        group
            .members
            .iter()
            .map(|&member| {
                let unit = &self.analysis.units[member];
                unit.token_end.saturating_sub(unit.token_start)
            })
            .max()
            .unwrap_or(0)
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

/// Token count of the longest occurrence of a duplicated run.
fn largest_occurrence_tokens(region: &StructuralRegion) -> usize {
    region
        .occurrences
        .iter()
        .map(|occurrence| occurrence.token_end.saturating_sub(occurrence.token_start))
        .max()
        .unwrap_or(0)
}

/// Ranking value of a duplicated run, on the same scale as a unit-scope
/// group's: largest occurrence × extra occurrences × similarity.
fn region_priority(region: &StructuralRegion) -> f64 {
    let size = u32::try_from(largest_occurrence_tokens(region)).unwrap_or(u32::MAX);
    let extra = u32::try_from(region.occurrences.len().saturating_sub(1)).unwrap_or(u32::MAX);
    f64::from(size) * f64::from(extra) * REGION_SIMILARITY
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
/// boilerplate last, then priority descending, then fingerprint ascending, so
/// every view is stable across reruns.
///
/// Duplicated units and duplicated runs share one ranking. They describe the
/// code differently, and each entry says which it is, but they compete for
/// the same attention and a reader wants the biggest duplication first
/// whichever shape it has.
fn build_groups(inputs: &ReportInputs<'_>) -> Vec<report::Group> {
    let mut entries: Vec<(bool, report::Group)> = (0..inputs.analysis.groups.groups.len())
        .map(|index| (inputs.ranked_down(index), build_group(inputs, index)))
        // A run carries no boilerplate classification: the classifier reads
        // whole units, so no run is ever ranked down for its shape.
        .chain((0..inputs.regions.reported.len()).map(|index| (false, build_region(inputs, index))))
        .collect();
    entries.sort_by(|(a_ranked_down, a), (b_ranked_down, b)| {
        a_ranked_down
            .cmp(b_ranked_down)
            .then_with(|| b.priority.value.total_cmp(&a.priority.value))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    entries.into_iter().map(|(_, group)| group).collect()
}

/// Assemble the report model both output formats render from.
fn build_report(inputs: &ReportInputs<'_>, run_id: i64, discovered: &DiscoveryReport) -> Report {
    let as_u64 = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    let count = |language: Language| {
        as_u64(
            inputs
                .files
                .iter()
                .filter(|file| file.language == language)
                .count(),
        )
    };
    // Counted off the report entries rather than the analysis, so the summary
    // cannot disagree with what the views list.
    let groups = build_groups(inputs);
    let count_class = |class: CloneClass| {
        as_u64(
            groups
                .iter()
                .filter(|g| g.clone_type == class.name())
                .count(),
        )
    };
    let variant = inputs.variant;
    let stats = &inputs.analysis.stats;

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
                normalization_version: variant.normalization_version,
                fingerprint: variant.fingerprint(),
            },
            detector_versions: detector_versions()
                .into_iter()
                .map(|(component, version)| report::DetectorVersion { component, version })
                .collect(),
            database: inputs.db_path.display().to_string(),
            run_id,
        },
        summary: report::Summary {
            files: report::FileCounts {
                total: as_u64(inputs.files.len()),
                rust: count(Language::Rust),
                c: count(Language::C),
                cpp: count(Language::Cpp),
            },
            lines: inputs.files.iter().map(|file| file.lines).sum(),
            tokens: as_u64(inputs.irs.iter().map(|ir| ir.tokens.len()).sum::<usize>()),
            lexer_diagnostics: as_u64(inputs.files.iter().map(|file| file.diagnostics).sum()),
            excluded: report::ExcludedCounts {
                generated: as_u64(discovered.suppressed_generated.len()),
                by_glob: as_u64(inputs.glob_excluded),
                skipped: discovered.skipped.total() + inputs.unreadable + inputs.timed_out,
            },
            groups: report::GroupCounts {
                total: as_u64(groups.len()),
                type_1: count_class(CloneClass::Type1),
                type_2: count_class(CloneClass::Type2),
                type_3: count_class(CloneClass::Type3),
                fragment_scope: as_u64(
                    groups
                        .iter()
                        .filter(|group| group.scope == CloneScope::Fragment.name())
                        .count(),
                ),
                folded_runs: as_u64(inputs.regions.folded),
                subsumed_runs: as_u64(stats.region_subsumed),
            },
            suppressed: report::SuppressedCounts {
                // The funnel marks no group as noise yet; suppression here is
                // rule-driven only.
                noise: 0,
                by_rule: as_u64(
                    groups
                        .iter()
                        .filter(|group| group.suppressed.is_some())
                        .count(),
                ),
            },
            // Either candidate stage exhausting its budget makes the result
            // potentially incomplete.
            pair_budget_exhausted: stats.candidate.budget_exhausted
                || stats.near_match.budget_exhausted,
        },
        groups,
    }
}

/// One group of the report model, with its similarity evidence and its
/// suppression cause resolved.
fn build_group(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let group = &inputs.analysis.groups.groups[index];
    let detail = &inputs.analysis.details[index];
    let suppressed = inputs.group_suppressed[index].map(|rule| inputs.suppression(rule));
    report::Group {
        fingerprint: detail.fingerprint.to_hex(),
        clone_type: group.clone_type.name().to_string(),
        scope: CloneScope::Unit.name().to_string(),
        statements: None,
        confidence: group.min_pairwise,
        priority: report::Priority {
            value: inputs.priority(group),
            largest_member_tokens: u64::try_from(inputs.largest_member_tokens(group))
                .unwrap_or(u64::MAX),
            extra_instances: u64::try_from(group.members.len().saturating_sub(1))
                .unwrap_or(u64::MAX),
            similarity: group.min_pairwise,
        },
        similarity: Some(similarity(group, detail)),
        boilerplate: detail
            .boilerplate
            .map(|category| category.name().to_string()),
        suppressed,
        members: group
            .members
            .iter()
            .enumerate()
            .map(|(position, &member)| {
                let unit = &inputs.analysis.units[member];
                let file = &inputs.files[unit.file];
                report::Member {
                    finding_id: stable_id::finding_id(
                        &detail.fingerprint,
                        Some(&unit.fingerprint),
                        0,
                    )
                    .to_hex(),
                    file: file.relative_path.clone(),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    unit: unit.name.as_deref().map(ToString::to_string),
                    tokens: u64::try_from(unit.token_end.saturating_sub(unit.token_start))
                        .unwrap_or(u64::MAX),
                    canonical: position == 0,
                }
            })
            .collect(),
    }
}

/// One duplicated run as a report entry.
///
/// The occurrences are runs of statements, so each is anchored at its own line
/// span and names the unit it sits in; the units themselves are usually not
/// clones of each other, which is the whole point of reporting the run.
fn build_region(inputs: &ReportInputs<'_>, index: usize) -> report::Group {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = occurrence_ranks(region);
    report::Group {
        fingerprint: region.fingerprint.to_hex(),
        clone_type: region.clone_type.name().to_string(),
        scope: CloneScope::Fragment.name().to_string(),
        statements: Some(u64::from(region.statements)),
        confidence: REGION_SIMILARITY,
        priority: report::Priority {
            value: region_priority(region),
            largest_member_tokens: u64::try_from(largest_occurrence_tokens(region))
                .unwrap_or(u64::MAX),
            extra_instances: u64::try_from(region.occurrences.len().saturating_sub(1))
                .unwrap_or(u64::MAX),
            similarity: REGION_SIMILARITY,
        },
        // Confirmed by content equality, not scored across dimensions: there
        // is no breakdown to report.
        similarity: None,
        // Boilerplate is classified over whole units; a run inside one carries
        // no such classification.
        boilerplate: None,
        suppressed: inputs.region_suppressed[index].map(|rule| inputs.suppression(rule)),
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
                    file: file.relative_path.clone(),
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
    }
}

/// Rank of each occurrence within its host unit, in occurrence order.
///
/// A run can occur twice inside one unit — a stretch duplicated within the
/// same function — and a finding identifier is derived from the group and the
/// host unit, so the rank is what keeps the two identifiers apart.
fn occurrence_ranks(region: &StructuralRegion) -> Vec<u32> {
    let mut next: BTreeMap<usize, u32> = BTreeMap::new();
    region
        .occurrences
        .iter()
        .map(|occurrence| {
            let slot = next.entry(occurrence.unit).or_insert(0);
            let rank = *slot;
            *slot = slot.saturating_add(1);
            rank
        })
        .collect()
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
fn detector_versions() -> Vec<(String, String)> {
    vec![
        ("fp-schema".to_string(), FP_SCHEMA_VERSION.to_string()),
        (
            "normalization".to_string(),
            NORMALIZATION_VERSION.to_string(),
        ),
        ("features".to_string(), FEATURE_SCHEMA_VERSION.to_string()),
        ("verify-weights".to_string(), WEIGHT_VERSION.to_string()),
        ("boilerplate".to_string(), BOILERPLATE_VERSION.to_string()),
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
fn record(cfg: &Config, inputs: &ReportInputs<'_>) -> Result<i64> {
    let (units, groups) = snapshot_rows(inputs);
    let config_hash = ContentHash::of(cfg.to_toml()?.as_bytes());
    let detector_versions = detector_versions();
    let root_path = inputs.root.to_string_lossy();
    let snapshot = Snapshot {
        root_path: &root_path,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: config_hash.as_str(),
        started_at: inputs.started_at,
        finished_at: inputs.finished_at,
        variant: inputs.variant,
        detector_versions: &detector_versions,
        suppressions: inputs.rules.rows.clone(),
        units,
        groups,
        features: Vec::new(),
    };
    let mut store = open_store(inputs.db_path)?;
    Ok(store.record_snapshot(&snapshot)?)
}

/// Turn the analysis into store rows. Every unit that hosts a member is
/// written once, even when it appears in several groups. A unit-scope
/// member's host is the unit it *is*; a duplicated run's host is the unit it
/// sits inside, which is a different unit for each occurrence and usually not
/// a clone of the others.
fn snapshot_rows(inputs: &ReportInputs<'_>) -> (Vec<UnitRow>, Vec<GroupRow>) {
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
        .map(|index| region_row(inputs, index, &host_index))
        .collect::<Vec<_>>();
    let groups = inputs
        .analysis
        .groups
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let detail = &inputs.analysis.details[index];
            let medoid = &inputs.analysis.units[group.canonical];
            GroupRow {
                fingerprint: detail.fingerprint,
                clone_type: group.clone_type,
                member_scope: CloneScope::Unit,
                test_code: detail.test_code,
                score: group.min_pairwise,
                entropy_bits: engine::content_entropy_bits(
                    inputs.unit_tokens(medoid),
                    inputs.literals,
                ),
                // The structural funnel marks no noise category yet.
                suppress_reason: None,
                boilerplate: detail.boilerplate,
                suppressed_by: inputs.group_suppressed[index],
                final_priority: inputs.priority(group),
                similarity: Some(breakdown_row(group, detail)),
                members: group
                    .members
                    .iter()
                    .map(|&member| {
                        let unit = &inputs.analysis.units[member];
                        let file = &inputs.files[unit.file];
                        MemberRow {
                            content: unit.content,
                            finding: stable_id::finding_id(
                                &detail.fingerprint,
                                Some(&unit.fingerprint),
                                0,
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
            }
        })
        .chain(regions)
        .collect();
    (units, groups)
}

/// One duplicated run as a store row. Its entropy is measured over the
/// canonical occurrence's own tokens, not its host unit's: the run is the
/// content the group is about.
fn region_row(
    inputs: &ReportInputs<'_>,
    index: usize,
    host_index: &BTreeMap<usize, usize>,
) -> GroupRow {
    let region = &inputs.analysis.regions[inputs.regions.reported[index]];
    let ranks = occurrence_ranks(region);
    let canonical = region
        .occurrences
        .first()
        .map_or_else(Vec::new, |occurrence| {
            inputs.region_tokens(occurrence).to_vec()
        });
    GroupRow {
        fingerprint: region.fingerprint,
        clone_type: region.clone_type,
        member_scope: CloneScope::Fragment,
        test_code: region_test_code(inputs.analysis, region),
        score: REGION_SIMILARITY,
        entropy_bits: engine::content_entropy_bits(&canonical, inputs.literals),
        suppress_reason: None,
        boilerplate: None,
        suppressed_by: inputs.region_suppressed[index],
        final_priority: region_priority(region),
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
    }
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
