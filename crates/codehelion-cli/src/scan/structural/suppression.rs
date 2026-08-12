//! Structural scan classification, suppression, and reportable-region selection.

use super::{
    BTreeMap, BTreeSet, Boilerplate, BoilerplatePolicy, BuildVariant, CategoryAction, Config,
    Context, Path, RegionOccurrence, ReportInputs, Result, SemanticGroup, SemanticPair,
    SemanticUnitGraph, SourceMeta, SourceTokenSpan, StructuralConfig, StructuralRegion,
    StructuralReport, StructuralUnit, SyntaxIrFile, TestCodeEvidence, as_u64, config, literal_norm,
    semantic_group_member_fingerprints, shared, stable_id, structural, suppress, test_code,
};

pub(super) fn mark_test_modules(files: &[SourceMeta], irs: &mut [SyntaxIrFile]) {
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

/// Add configured path evidence after structural analysis has classified
/// source markers, without involving paths in detection or grouping.
pub(super) fn mark_test_paths(
    cfg: &Config,
    files: &[SourceMeta],
    analysis: &mut StructuralReport,
) -> Result<()> {
    let paths = crate::scan::build_globset(&cfg.suppression.test_paths)
        .context("in suppression test-paths")?;
    let matched: Vec<bool> = files
        .iter()
        .map(|file| {
            paths
                .as_ref()
                .is_some_and(|globs| globs.is_match(&file.relative_path))
        })
        .collect();
    analysis.apply_test_path_evidence(&matched);
    Ok(())
}

/// Build the structural stage configuration from the effective scan
/// configuration. An overridden candidate ceiling applies to every candidate
/// stage, so one configured number bounds the whole funnel; left unset, each
/// stage keeps the default measured for it.
pub(super) fn structural_config(cfg: &Config) -> StructuralConfig {
    let mut config = StructuralConfig {
        min_clone_tokens: cfg.min_clone_tokens,
        ..StructuralConfig::default()
    };
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
    if let Some(delta) = cfg.limits.near_miss_delta {
        config.near_match.near_miss_delta = delta;
    }
    if let Some(cap) = cfg.limits.near_miss_cap {
        config.near_match.near_miss_cap = cap;
    }
    config.grouping.max_component = cfg.limits.max_component;
    if let Some(budget) = cfg.limits.verification_budget {
        config.verification_budget = budget;
    }
    if let Some(cells) = cfg.limits.max_alignment_cells {
        config.verify.max_alignment_cells = cells;
    }
    if let Some(budget) = cfg.limits.sibling_candidate_budget {
        config.siblings.candidate_budget = budget;
    }
    if let Some(cap) = cfg.limits.sibling_per_group_cap {
        config.siblings.per_group_cap = cap;
    }
    if let Some(cap) = cfg.limits.sibling_total_cap {
        config.siblings.total_cap = cap;
    }
    if let Some(budget) = cfg.limits.signature_sibling_candidate_budget {
        config.signature_siblings.candidate_budget = budget;
    }
    if let Some(cap) = cfg.limits.signature_sibling_per_group_cap {
        config.signature_siblings.per_group_cap = cap;
    }
    if let Some(cap) = cfg.limits.signature_sibling_total_cap {
        config.signature_siblings.total_cap = cap;
    }
    config.literals = literal_norm(cfg.literal_normalization);
    config
}

/// Suppression rules together with the per-file evaluation they need.
pub(super) struct StructuralRules {
    pub(super) rules: suppress::Rules,
    pub(super) files: Vec<suppress::FileSuppression>,
}

impl StructuralRules {
    /// The rule suppressing a whole group: present only when *every* member
    /// is suppressed. The canonical (first) member's rule is the one
    /// recorded.
    pub(super) fn group_rule(
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
    pub(super) fn semantic_rule<'a>(
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
    pub(super) fn region_rule(
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
pub(super) fn compile_rules(
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
pub(super) struct SuppressionVerdicts {
    /// Parallel to the analysis's clone groups.
    pub(super) groups: Vec<Option<usize>>,
    /// Parallel to the runs the report lists.
    pub(super) regions: Vec<Option<usize>>,
    /// Parallel to the verified pairs no group could hold.
    pub(super) pairs: Vec<Option<usize>>,
    /// Parallel to the registered restricted-semantic correspondences.
    pub(super) semantic_pairs: Vec<Option<usize>>,
    /// Parallel to cohesive registered restricted-semantic groups.
    pub(super) semantic_groups: Vec<Option<usize>>,
    /// Parallel to each owning group's supplemental siblings.
    pub(super) siblings: Vec<Vec<Option<usize>>>,
    /// Parallel to bounded near-match diagnostics.
    pub(super) near_misses: Vec<Option<usize>>,
}

/// The presentation policy for this invocation after explicit CLI intent.
///
/// The configuration remains the source of every durable policy choice. The
/// flag only changes where a known predicate family appears in this one
/// report; it neither changes clone detection nor writes configuration back.
pub(super) fn presentation_suppression(cfg: &Config, include_trivial: bool) -> config::Suppression {
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
pub(super) fn evaluate_suppression(
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
            shared::SuppressionPriority::first(|| {
                rules
                    .rules
                    .clone_id_rule(&analysis.details[index].fingerprint.to_hex())
            })
            .or_else(|| rules.group_rule(group.members.iter().copied(), analysis, &local_units))
            .or_else(|| hidden_test_code.filter(|_| analysis.details[index].test_code))
            .or_else(|| {
                unanimous_boilerplate(
                    group
                        .members
                        .iter()
                        .map(|&member| analysis.units[member].boilerplate),
                )
                .and_then(|category| hidden.get(&category).copied())
            })
            .or_else(|| hidden_width_family.filter(|_| analysis.details[index].width_family))
            .or_else(|| {
                rules.rules.baseline_rule(
                    &analysis.details[index].fingerprint.to_hex(),
                    as_u64(group.members.len()),
                )
            })
            .finish()
        })
        .collect();
    let region_verdicts = regions
        .reported
        .iter()
        .map(|&index| {
            let region = &analysis.regions[index];
            shared::SuppressionPriority::first(|| {
                rules.rules.clone_id_rule(&region.fingerprint.to_hex())
            })
            .or_else(|| rules.region_rule(region, analysis, &local_units))
            .or_else(|| hidden_test_code.filter(|_| region_test_code(analysis, region)))
            .or_else(|| {
                rules.rules.baseline_rule(
                    &region.fingerprint.to_hex(),
                    as_u64(region.occurrences.len()),
                )
            })
            .finish()
        })
        .collect();
    let pairs = analysis
        .unrepresented
        .iter()
        .map(|pair| {
            shared::SuppressionPriority::first(|| {
                rules.rules.clone_id_rule(&pair.fingerprint.to_hex())
            })
            .or_else(|| rules.group_rule(pair.members.iter().copied(), analysis, &local_units))
            .or_else(|| {
                hidden_test_code.filter(|_| {
                    pair.members
                        .iter()
                        .all(|&member| analysis.units[member].test_code)
                })
            })
            .or_else(|| {
                pair_shape_suppression(
                    unanimous_boilerplate(
                        pair.members
                            .iter()
                            .map(|&member| analysis.units[member].boilerplate),
                    ),
                    pair.width_family,
                    &hidden,
                    hidden_width_family,
                )
            })
            .or_else(|| {
                rules
                    .rules
                    .baseline_rule(&pair.fingerprint.to_hex(), as_u64(pair.members.len()))
            })
            .finish()
        })
        .collect();
    let semantic_pairs = semantic_pairs
        .iter()
        .map(|pair| {
            let members = [&pair.canonical, &pair.corresponding];
            let fingerprint = stable_id::semantic_clone_group_fingerprint(
                variant,
                pair.rule.id,
                pair.rule.version,
                &semantic_group_member_fingerprints(members, analysis),
            );
            shared::SuppressionPriority::first(|| rules.rules.clone_id_rule(&fingerprint.to_hex()))
                .or_else(|| rules.semantic_rule(members.into_iter(), analysis, &local_units))
                .or_else(|| {
                    hidden_test_code.filter(|_| {
                        members
                            .iter()
                            .all(|member| analysis.units[member.unit].test_code)
                    })
                })
                .or_else(|| rules.rules.baseline_rule(&fingerprint.to_hex(), 2))
                .finish()
        })
        .collect();
    let semantic_groups = semantic_groups
        .iter()
        .map(|group| {
            let fingerprint = stable_id::semantic_clone_group_fingerprint(
                variant,
                group.rule.id,
                group.rule.version,
                &semantic_group_member_fingerprints(group.members.iter(), analysis),
            );
            let members = group.members.iter();
            shared::SuppressionPriority::first(|| rules.rules.clone_id_rule(&fingerprint.to_hex()))
                .or_else(|| rules.semantic_rule(members.clone(), analysis, &local_units))
                .or_else(|| {
                    hidden_test_code.filter(|_| {
                        members
                            .clone()
                            .all(|member| analysis.units[member.unit].test_code)
                    })
                })
                .or_else(|| {
                    rules
                        .rules
                        .baseline_rule(&fingerprint.to_hex(), as_u64(group.members.len()))
                })
                .finish()
        })
        .collect();
    let siblings = analysis
        .siblings
        .iter()
        .map(|siblings| {
            let detail = &analysis.details[siblings.group];
            let member_count = as_u64(analysis.groups.groups[siblings.group].members.len());
            siblings
                .siblings
                .iter()
                .map(|sibling| {
                    let unit = &analysis.units[sibling.unit];
                    let finding =
                        stable_id::finding_id(&detail.fingerprint, Some(&unit.fingerprint), 0);
                    shared::SuppressionPriority::first(|| {
                        rules.rules.clone_id_rule(&finding.to_hex())
                    })
                    .or_else(|| {
                        rules.group_rule(std::iter::once(sibling.unit), analysis, &local_units)
                    })
                    .or_else(|| hidden_test_code.filter(|_| unit.test_code))
                    .or_else(|| {
                        unit.boilerplate
                            .and_then(|category| hidden.get(&category).copied())
                    })
                    .or_else(|| {
                        rules
                            .rules
                            .baseline_rule(&detail.fingerprint.to_hex(), member_count)
                    })
                    .finish()
                })
                .collect()
        })
        .collect();
    let near_misses = analysis
        .near_misses
        .iter()
        .map(|near_miss| {
            let members = [near_miss.a, near_miss.b];
            shared::SuppressionPriority::first(|| {
                rules.group_rule(members.into_iter(), analysis, &local_units)
            })
            .or_else(|| {
                hidden_test_code.filter(|_| {
                    members
                        .iter()
                        .all(|&member| analysis.units[member].test_code)
                })
            })
            .or_else(|| {
                unanimous_boilerplate(
                    members
                        .iter()
                        .map(|&member| analysis.units[member].boilerplate),
                )
                .and_then(|category| hidden.get(&category).copied())
            })
            .finish()
        })
        .collect();
    SuppressionVerdicts {
        groups,
        regions: region_verdicts,
        pairs,
        semantic_pairs,
        semantic_groups,
        siblings,
        near_misses,
    }
}

/// The structural classifications that hide a split pair, in the same order
/// as a normal group: a concrete boilerplate shape is more specific than the
/// relation-level width-family observation.
pub(super) fn pair_shape_suppression(
    boilerplate: Option<Boilerplate>,
    width_family: bool,
    hidden_boilerplate: &BTreeMap<Boilerplate, usize>,
    hidden_width_family: Option<usize>,
) -> Option<usize> {
    boilerplate
        .and_then(|category| hidden_boilerplate.get(&category).copied())
        .or_else(|| hidden_width_family.filter(|_| width_family))
}

/// Register a suppression rule for every boilerplate category the policy
/// hides *and* this run actually produced, returning the rule index per
/// category.
///
/// A category with no group in this run registers no rule: the recorded rules
/// are the ones that did something.
pub(super) fn hidden_boilerplate(
    rules: &mut suppress::Rules,
    policy: &BoilerplatePolicy,
    analysis: &StructuralReport,
) -> BTreeMap<Boilerplate, usize> {
    let mut hidden = BTreeMap::new();
    for category in Boilerplate::all() {
        if policy.action(category) != CategoryAction::Hide {
            continue;
        }
        if !analysis.groups.groups.iter().any(|group| {
            unanimous_boilerplate(
                group
                    .members
                    .iter()
                    .map(|&member| analysis.units[member].boilerplate),
            ) == Some(category)
        }) && !analysis.unrepresented.iter().any(|pair| {
            unanimous_boilerplate(
                pair.members
                    .iter()
                    .map(|&member| analysis.units[member].boilerplate),
            ) == Some(category)
        }) && !analysis.siblings.iter().any(|siblings| {
            siblings
                .siblings
                .iter()
                .any(|sibling| analysis.units[sibling.unit].boilerplate == Some(category))
        }) && !analysis.near_misses.iter().any(|near_miss| {
            unanimous_boilerplate(
                [near_miss.a, near_miss.b]
                    .into_iter()
                    .map(|member| analysis.units[member].boilerplate),
            ) == Some(category)
        }) {
            continue;
        }
        let index = rules.add_shape_rule(category.name(), "boilerplate shape");
        hidden.insert(category, index);
    }
    hidden
}

/// The boilerplate category every member of a finding shares.
///
/// A dominant category remains useful evidence for ranking, but hiding a
/// finding is stronger: one non-boilerplate member is enough to keep the
/// duplicated behaviour visible.
pub(super) fn unanimous_boilerplate(
    categories: impl IntoIterator<Item = Option<Boilerplate>>,
) -> Option<Boilerplate> {
    let mut categories = categories.into_iter();
    let category = categories.next()??;
    categories
        .all(|member| member == Some(category))
        .then_some(category)
}

/// Register the rule hiding groups written once per integer width, when the
/// policy hides them *and* this run found one, returning the rule index.
///
/// Recorded under the same scope as a boilerplate shape. What the two have in
/// common is the part a reader needs: the tool judged the code's shape rather
/// than being told about it by a path, a marker or a baseline. That this one
/// reads the shape off the members' tokens instead of their trees is a detail
/// of how, and the reason on the row says which judgement it was.
pub(super) fn hidden_width_family(
    rules: &mut suppress::Rules,
    cfg: &Config,
    analysis: &StructuralReport,
) -> Option<usize> {
    if cfg.suppression.width_family != CategoryAction::Hide {
        return None;
    }
    (analysis.details.iter().any(|detail| detail.width_family)
        || analysis.unrepresented.iter().any(|pair| pair.width_family))
    .then(|| rules.add_shape_rule("width-family", "one routine per integer width"))
}

/// Register the rule hiding test-suite duplication, when the policy hides it
/// *and* this run found some, returning the rule index.
///
/// As with a boilerplate category, a rule that hid nothing is not recorded:
/// the rules kept are the ones that did something.
pub(super) fn hidden_test_code(
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
    let any_sibling = analysis.siblings.iter().any(|siblings| {
        siblings
            .siblings
            .iter()
            .any(|sibling| analysis.units[sibling.unit].test_code)
    });
    let any_near_miss = analysis.near_misses.iter().any(|near_miss| {
        [near_miss.a, near_miss.b]
            .into_iter()
            .all(|member| analysis.units[member].test_code)
    });
    (any_group || any_run || any_sibling || any_near_miss)
        .then(|| rules.add_attribute_rule("test", "test code"))
}

/// Which duplicated runs the report lists, and how many it folded away.
pub(super) struct ReportableRegions {
    /// Indices into the analysed regions, in analysis order.
    pub(super) reported: Vec<usize>,
    /// Runs left out because a whole-unit group already covers them.
    pub(super) folded: usize,
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
pub(super) fn reportable_regions(analysis: &StructuralReport) -> ReportableRegions {
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
pub(super) fn region_test_code(analysis: &StructuralReport, region: &StructuralRegion) -> bool {
    region_test_code_evidence(analysis, region).is_some()
}

/// Aggregate the evidence for a group of structural units.
///
/// The same rule serves unit groups, fragment runs, split pairs, and semantic
/// findings: every member must be test code, marker takes precedence, and
/// only an all-path group says `path`.
pub(super) fn aggregate_test_code_evidence(
    analysis: &StructuralReport,
    members: impl IntoIterator<Item = usize>,
) -> Option<TestCodeEvidence> {
    test_code::aggregate_evidence(
        members
            .into_iter()
            .map(|member| analysis.units[member].test_code_evidence),
    )
}

/// Aggregate evidence for one duplicated statement run.
pub(super) fn region_test_code_evidence(
    analysis: &StructuralReport,
    region: &StructuralRegion,
) -> Option<TestCodeEvidence> {
    aggregate_test_code_evidence(
        analysis,
        region.occurrences.iter().map(|occurrence| occurrence.unit),
    )
}

/// Raw identifier agreement between the first reported run occurrence and the
/// remaining occurrences.
///
/// A run is already an exact normalized match. This is therefore triage-only
/// proxy evidence for a possible shared refactoring target, not a similarity
/// score and not an input to detection or grouping.
pub(super) fn region_identifier_jaccard(
    inputs: &ReportInputs<'_>,
    region: &StructuralRegion,
) -> f64 {
    region.occurrences.first().map_or(1.0, |canonical| {
        structural::span_identifier_jaccard(
            inputs.irs,
            region_token_span(canonical),
            region.occurrences.iter().skip(1).map(region_token_span),
        )
    })
}

pub(super) const fn unit_token_span(unit: &StructuralUnit) -> SourceTokenSpan {
    SourceTokenSpan::new(unit.file, unit.token_start, unit.token_end)
}

const fn region_token_span(occurrence: &RegionOccurrence) -> SourceTokenSpan {
    SourceTokenSpan::new(
        occurrence.file,
        occurrence.token_start,
        occurrence.token_end,
    )
}

/// Whether a run names a place inside its hosts rather than restating them.
///
/// A unit group directs attention at whole units, so a run spanning most of
/// one adds nothing: the reader is already looking there. A run that is a
/// small part of *every* host is the opposite case — a gapped group says its
/// members are alike overall and says nothing about where they agree exactly,
/// so a short stretch they share verbatim is a finding the group cannot state
/// and the one that can be lifted out as it stands.
pub(super) fn localizes(analysis: &StructuralReport, region: &StructuralRegion) -> bool {
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
pub(super) fn local_unit_indices(analysis: &StructuralReport) -> Vec<usize> {
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
