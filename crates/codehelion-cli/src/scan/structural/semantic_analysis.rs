//! Semantic partitioning, compiler-evidence resolution, and confidence composition.

use super::{
    BTreeMap, BTreeSet, BuildConfiguration, BuildVariant, ByteRange, CfgShape, CloneScope,
    CompileCommandSelector, Config, Context, ControlFlowGraph, DataFlowSummary, DiscoveryReport,
    EdgeKind, Installed, Language, LanguageSelection, Path, PathBuf, Result,
    SemanticCandidateStats, SemanticConfidenceEvidence, SemanticDetection, SemanticGroup,
    SemanticGroupingStats, SemanticGroupingUnit, SemanticOperationGraph, SemanticPair,
    SemanticUnitGraph, SourceMeta, SourceUnit, StructuralReport, StructuralUnit, SyntaxIrFile,
    VerifiedSemanticPair, bail, extract_registered_candidates, group_verified_semantic_pairs,
    path_key, registered_semantic_windows, semantic, stable_id, structural,
    verify_registered_candidates,
};

/// What a file's compiler answer is looked up under.
///
/// The same rule the file's own metadata was named by, because that metadata
/// is what does the looking up. Naming the two sides separately is how a file
/// comes to be present on both sides and found on neither: on Windows one
/// spelling separates with a backslash and the other with a slash, and every
/// unit is then skipped as unanswered — a scan that reports itself semantic,
/// answers about every file, and produces no finding a compiler contributed.
fn answered_by_file<'a>(
    sources: &'a [SourceUnit],
    asked: &'a semantic::Answers,
) -> BTreeMap<String, (&'a SourceUnit, &'a semantic::Answer)> {
    sources
        .iter()
        .zip(&asked.per_source)
        .map(|(source, answer)| (path_key(&source.relative_path), (source, answer)))
        .collect()
}

pub(super) struct SemanticPartition {
    pub(super) variant: BuildVariant,
    pub(super) sources: Vec<SourceUnit>,
    pub(super) commands: BTreeMap<PathBuf, CompileCommandSelector>,
}

impl SemanticPartition {
    /// This partition as the analysis reads it.
    pub(super) fn program(&self) -> SemanticProgram<'_> {
        SemanticProgram {
            variant: &self.variant,
            sources: &self.sources,
            commands: &self.commands,
        }
    }
}

/// One independently analysed program.
///
/// A tree that no compilation database splits is one program too, so the
/// single-partition run describes itself the same way rather than through a
/// parallel pipeline of its own.
#[derive(Clone, Copy)]
pub(super) struct SemanticProgram<'a> {
    pub(super) variant: &'a BuildVariant,
    pub(super) sources: &'a [SourceUnit],
    pub(super) commands: &'a BTreeMap<PathBuf, CompileCommandSelector>,
}

/// Every independently analysed program a semantic run splits the tree into.
///
/// One place decides what a program is, so every source the globs kept ends in
/// exactly the partitions that can speak for it: a header belongs to the
/// translation units that give it meaning, and when no command names any of
/// them it belongs to the no-build partition rather than to nothing at all.
pub(super) fn semantic_partitions(
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
    cfg: &Config,
    asking: Option<&[&Installed]>,
    root: &Path,
    helper_timeout: std::time::Duration,
) -> Result<Vec<SemanticPartition>> {
    let compiler_version = clang_toolchain(asking);
    let mut partitions = cpp_partitions(discovered, sources, cfg, compiler_version.as_deref());
    // Command partitions each hold every header. Without one, no partition
    // does, so the no-build partition takes them.
    let headers_unclaimed = partitions.is_empty();
    if let Some(unconfigured) = unconfigured_cpp_partition(discovered, sources, headers_unclaimed) {
        partitions.push(unconfigured);
    }
    if let Some(rust) = rust_partition(
        sources,
        asking,
        discovered.header_language,
        root,
        helper_timeout,
    )? {
        partitions.push(rust);
    }
    partitions.sort_by_cached_key(|partition| partition.variant.fingerprint());
    Ok(partitions)
}

/// Split a C/C++ scan by the exact command-derived build variant.
///
pub(super) fn cpp_partitions(
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
            let mut command_build = first.build();
            command_build.compiler_version = compiler_version.map(ToString::to_string);
            let build = BuildConfiguration::Cpp(Box::new(command_build));
            let mut commands = BTreeMap::new();
            let entry_paths: BTreeSet<PathBuf> = entries
                .iter()
                .map(|entry| {
                    codehelion_core::paths::canonical(&entry.file)
                        .unwrap_or_else(|_| entry.file.clone())
                })
                .collect();
            for entry in entries {
                let (file, directory, arguments) = entry.selector_fields();
                let path = codehelion_core::paths::canonical(&entry.file)
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
///
/// `unclaimed_headers` says whether this partition is also the only home the
/// tree's headers have. A header is analysed under the translation units that
/// give it meaning, so a run with command partitions leaves them there; a run
/// with none would otherwise read no header at all and account for none, and
/// the same tree scanned structurally would report more files with nothing
/// saying why.
pub(super) fn unconfigured_cpp_partition(
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
    unclaimed_headers: bool,
) -> Option<SemanticPartition> {
    let configured: BTreeSet<PathBuf> =
        discovered
            .compile_commands
            .as_ref()
            .map_or_else(BTreeSet::new, |database| {
                database
                    .entries
                    .iter()
                    .map(|entry| {
                        codehelion_core::paths::canonical(&entry.file)
                            .unwrap_or_else(|_| entry.file.clone())
                    })
                    .collect()
            });
    let selected: Vec<SourceUnit> = sources
        .iter()
        .filter(|source| {
            matches!(source.language, Language::C | Language::Cpp)
                && (unclaimed_headers || !source.is_header)
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
pub(super) fn clang_toolchain(asking: Option<&[&Installed]>) -> Option<String> {
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
pub(super) fn rust_partition(
    sources: &[SourceUnit],
    asking: Option<&[&Installed]>,
    headers: Language,
    root: &Path,
    timeout: std::time::Duration,
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
        .map(|helper| helper.build(root, timeout))
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
pub(super) fn ask_about(
    asking: &[&Installed],
    sources: &[SourceUnit],
    variant: &BuildVariant,
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    read_boundary: Option<&Path>,
    timeout: std::time::Duration,
) -> semantic::Answers {
    let backends: Vec<semantic::Backend<'_>> = asking
        .iter()
        .map(|helper| semantic::Backend {
            program: &helper.program,
            analyzes: helper.component.analyses,
            permitted: &helper.permitted,
            sandbox: helper.sandbox,
            read_boundary,
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
pub(super) fn resolve(
    asking: Option<&[&Installed]>,
    sources: &[SourceUnit],
    files: &[SourceMeta],
    variant: &BuildVariant,
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    read_boundary: Option<&Path>,
    timeout: std::time::Duration,
) -> (Option<semantic::Answers>, structural::ResolvedTypes) {
    let asked =
        asking.map(|asking| ask_about(asking, sources, variant, commands, read_boundary, timeout));
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
pub(super) fn resolved_types(
    asked: &semantic::Answers,
    sources: &[SourceUnit],
    files: &[SourceMeta],
) -> structural::ResolvedTypes {
    let answered = answered_by_file(sources, asked);
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
                        semantic::resolution_for(ir, &spelling),
                    ))
                })
                .unwrap_or_default()
        })
        .collect();
    structural::ResolvedTypes::per_file_with_semantic_normalization(
        resolved.iter().map(|(types, _, _)| types.clone()).collect(),
        resolved.iter().map(|(_, apis, _)| apis.clone()).collect(),
        resolved.into_iter().map(|(_, _, names)| names).collect(),
    )
}

/// Normalize compiler-resolved calls within each parser-owned unit and match
/// only the pairs selected by the bounded core-owned SOG index.
#[allow(
    clippy::too_many_lines,
    reason = "the adapter keeps compiler answers, range ownership, and bounded matching in one auditable boundary"
)]
pub(super) fn registered_semantic_pairs(
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
            units_without_registered_operations: 0,
            units_no_registered_rule_claimed: 0,
            verified_pairs: 0,
            disabled_pairs: 0,
            grouping: SemanticGroupingStats::default(),
        });
    };
    let variant_fingerprint = semantic_variant_fingerprint(variant)?;
    let answered = answered_by_file(sources, asked);
    let mut units = Vec::new();
    let mut registered_observations = 0_usize;
    let mut excluded_observations = 0_usize;
    // A unit reaches no semantic window for one of two reasons, and they send
    // whoever is looking into a thin run to different places: the compiler
    // resolved nothing the registry recognizes inside it, or it did and no
    // registered rule claimed what it found. The first is a gap in what the
    // helper was asked about, the second a gap in the rules.
    let mut units_without_registered_operations = 0_usize;
    let mut units_no_registered_rule_claimed = 0_usize;
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
            units_without_registered_operations =
                units_without_registered_operations.saturating_add(1);
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
            units_no_registered_rule_claimed = units_no_registered_rule_claimed.saturating_add(1);
        }
        let Some(syntax_ir) = irs.get(unit.file) else {
            continue;
        };
        for mut window in windows {
            let range = ByteRange {
                start: usize::try_from(window.source_range.start)
                    .context("semantic source range start exceeds this platform")?,
                end: usize::try_from(window.source_range.end)
                    .context("semantic source range end exceeds this platform")?,
            };
            let (start_line, end_line, token_count) =
                semantic_window_location(syntax_ir, unit, range);
            if let Some(structure_fingerprint) =
                semantic_window_structure_fingerprint(variant, syntax_ir, unit, range)
            {
                for node in &mut window.graph.nodes {
                    node.attributes.structure_fingerprint = Some(structure_fingerprint);
                }
            }
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
                occurrence_rank: 0,
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
    assign_semantic_occurrence_ranks(&mut units, analysis);
    // Every normalized window is compared, without consulting the clone-size
    // floor. A window is a closed semantic claim rather than a source
    // fragment: it spans the operations the compiler resolved, so its token
    // count measures the distance between two anchors and not the size of the
    // logic the rule matched. A registered pipeline written as one chained
    // expression is a handful of tokens wide by construction, and the labelled
    // corpora that admit each rule label exactly those single-line fragments.
    // The floor still decides what Fast and Structural report, where a token
    // count does describe the finding.
    let graphs: Vec<_> = units.iter().map(|unit| unit.graph.clone()).collect();
    let stages = crate::scan::runtime::stage_limits(cfg);
    let candidates = extract_registered_candidates(&graphs, stages.pairing.semantic_candidates());
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
        group_verified_semantic_pairs(&grouping_units, &enabled, &stages.grouping.grouping());
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
        units_without_registered_operations,
        units_no_registered_rule_claimed,
        verified_pairs,
        disabled_pairs,
        grouping,
    })
}

/// Build one pair finding from a verified relation the semantic grouping could
/// not express as a cohesive group.
pub(super) fn semantic_pair_from_indices(
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
pub(super) fn normalization_confidence(registered: usize, excluded: usize) -> f64 {
    let total = registered.saturating_add(excluded);
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        registered as f64 / total as f64
    }
}

/// Produce conservative source-structure evidence for one semantic window.
///
/// Byte ranges locate the already parsed tokens but do not enter the digest;
/// the resulting value is stable when the same window moves in its file.
fn semantic_window_structure_fingerprint(
    variant: &BuildVariant,
    ir: &SyntaxIrFile,
    host: &StructuralUnit,
    range: ByteRange,
) -> Option<[u8; 16]> {
    let tokens = semantic_window_tokens(ir, host, range);
    (!tokens.is_empty()).then(|| {
        stable_id::semantic_structure_fingerprint(
            variant,
            &stable_id::FileContext {
                frontend_version: ir.frontend_version,
                language: ir.language,
            },
            tokens,
        )
    })
}

/// Return the contiguous parsed tokens covered by a semantic source window.
fn semantic_window_tokens<'a>(
    ir: &'a SyntaxIrFile,
    host: &StructuralUnit,
    range: ByteRange,
) -> &'a [codehelion_core::frontend::Token] {
    let end = host.token_end.min(ir.tokens.len());
    let start = host.token_start.min(end);
    let tokens = &ir.tokens[start..end];
    let first = tokens.partition_point(|token| token.span.end_byte <= range.start);
    let last = tokens.partition_point(|token| token.span.start_byte < range.end);
    &tokens[first.min(last)..last]
}

/// Translate one semantic byte window into report coordinates using the
/// already-parsed token stream. Empty point spans retain their host unit's
/// location, which is the compatibility path for adapters without full
/// anchors; current compiler adapters always provide non-empty spans.
pub(super) fn semantic_window_location(
    ir: &SyntaxIrFile,
    host: &StructuralUnit,
    range: ByteRange,
) -> (u32, u32, usize) {
    let mut matching = semantic_window_tokens(ir, host, range).iter();
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
pub(super) fn semantic_confidence(
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
pub(super) fn semantic_group_confidence(
    rule_confidence: f64,
    members: &[SemanticUnitGraph],
) -> f64 {
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
pub(super) fn interaction_confidence(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
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
pub(super) fn data_flow_confidence(
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
pub(super) fn cfg_confidence(left: Option<CfgShape>, right: Option<CfgShape>) -> f64 {
    match (left, right) {
        (Some(left), Some(right)) if left == right => 1.05,
        (Some(_), Some(_)) => 0.85,
        (None, _) | (_, None) => 1.0,
    }
}

/// Summarize only compiler blocks whose anchors overlap a registered semantic
/// window. Compiler-local block indices are reduced to counts, which are
/// comparable across the two language helpers but never become stable IDs.
pub(super) fn semantic_window_cfg_shape(
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
pub(super) fn semantic_window_interactions(graph: &SemanticOperationGraph) -> BTreeSet<String> {
    graph
        .nodes
        .iter()
        .filter_map(|node| node.attributes.resource_kind.as_deref())
        .filter_map(codehelion_helper::ir::resource_interaction)
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod window_interaction_tests {
    use super::{BTreeSet, SemanticOperationGraph, semantic_window_interactions};
    use codehelion_core::discovery::Language;
    use codehelion_core::semantic::{OperationAttributes, OperationKind, OperationNode};

    fn acquires(resource_kind: &str) -> OperationNode {
        OperationNode {
            kind: OperationKind::AcquireResource,
            attributes: OperationAttributes {
                resource_kind: Some(resource_kind.to_owned()),
                ..OperationAttributes::default()
            },
        }
    }

    /// A resource kind the shared vocabulary does not list contributes nothing,
    /// rather than an interaction guessed from its spelling.
    #[test]
    fn a_resource_kind_outside_the_closed_vocabulary_names_no_interaction() {
        let graph = SemanticOperationGraph::new(
            Language::Rust,
            [0; 32],
            vec![
                acquires("file"),
                acquires("lock"),
                acquires("socket"),
                acquires("File"),
            ],
            Vec::new(),
        )
        .expect("resource acquisitions alone form a valid graph");

        assert_eq!(
            semantic_window_interactions(&graph),
            BTreeSet::from(["file_io".to_owned(), "synchronization".to_owned()])
        );
    }
}

/// Retain only helper-reported direct receiver flows whose two written API
/// anchors fall inside this SOG window. The helper's endpoint format is local
/// to compiler IR v1; after range membership is established, only closed API
/// names remain as comparison evidence.
pub(super) fn semantic_window_data_flows(
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
pub(super) fn flow_endpoint_in_window(
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
pub(super) fn semantic_scope<'a>(
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
pub(super) fn semantic_member_ranks<'a>(
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
) -> Vec<u32> {
    members
        .into_iter()
        .map(|member| member.occurrence_rank)
        .collect()
}

/// Derive one occurrence rank per window before grouping so every consumer uses
/// the same position-independent identity for the same semantic window.
///
/// A window is discriminated by what content says about it: the host unit it
/// sits in and its own normalized content. Nothing about where it sits enters
/// the ordering, so a doc comment added to one file — which moves every byte
/// offset after it, and used to swap two windows' ranks and with them their
/// finding ids — leaves every rank where it was. Windows that content cannot
/// separate at all keep the order they were extracted in, which is the last
/// discrimination available once host and content have agreed.
fn assign_semantic_occurrence_ranks(units: &mut [SemanticUnitGraph], analysis: &StructuralReport) {
    let discriminators: Vec<stable_id::OccurrenceDiscriminator> = units
        .iter()
        .map(|member| {
            stable_id::OccurrenceDiscriminator::of_unit(&analysis.units[member.unit].fingerprint)
                .and(stable_id::OccurrenceDiscriminator::of_fragment(
                    &member.content,
                ))
        })
        .collect();
    for (member, rank) in units
        .iter_mut()
        .zip(stable_id::occurrence_ranks(&discriminators))
    {
        member.occurrence_rank = rank;
    }
}

#[cfg(test)]
#[allow(clippy::default_trait_access, clippy::expect_used)]
mod occurrence_rank_tests {
    use super::{
        ByteRange, SemanticOperationGraph, SemanticUnitGraph, StructuralReport, StructuralUnit,
        assign_semantic_occurrence_ranks, stable_id,
    };
    use codehelion_core::discovery::Language;
    use codehelion_core::frontend::UnitKind;
    use codehelion_core::grouping::{GroupingConfig, group};
    use codehelion_core::structural::StructuralStats;

    fn make_unit(file: usize, fingerprint: stable_id::UnitFingerprint) -> StructuralUnit {
        StructuralUnit {
            file,
            kind: UnitKind::Function,
            range: ByteRange { start: 0, end: 100 },
            start_line: 1,
            end_line: 10,
            token_start: 0,
            token_end: 10,
            name: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            fingerprint,
            content: stable_id::FragmentFingerprint::from_bytes([11; 16]),
            normalized_content: stable_id::FragmentFingerprint::from_bytes([12; 16]),
        }
    }

    /// Three windows over two host identities: the first two units are content
    /// identical, so they share a host fingerprint and their windows share a
    /// rank sequence; the third has a host of its own.
    fn analysis_of_two_identical_hosts() -> StructuralReport {
        let host = stable_id::UnitFingerprint::from_bytes([7; 16]);
        let other_host = stable_id::UnitFingerprint::from_bytes([8; 16]);
        StructuralReport {
            units: vec![
                make_unit(0, host),
                make_unit(1, host),
                make_unit(2, other_host),
            ],
            groups: group(&[], &[], &GroupingConfig::default()),
            regions: Vec::new(),
            details: Vec::new(),
            unrepresented: Vec::new(),
            siblings: Vec::new(),
            near_misses: Vec::new(),
            stats: StructuralStats::default(),
        }
    }

    /// One window per unit, each at the byte range it is given.
    fn windows_at(ranges: [ByteRange; 3]) -> Vec<SemanticUnitGraph> {
        let content = stable_id::FragmentFingerprint::from_bytes([9; 16]);
        let graph = SemanticOperationGraph::new(Language::Rust, [0; 32], Vec::new(), Vec::new())
            .expect("empty graph is valid");
        ranges
            .into_iter()
            .enumerate()
            .map(|(unit, range)| SemanticUnitGraph {
                unit,
                occurrence_rank: 0,
                range,
                start_line: 1,
                end_line: 2,
                token_count: 2,
                graph: graph.clone(),
                content,
                normalization_confidence: 1.0,
                interactions: Default::default(),
                data_flows: Default::default(),
                cfg_shape: None,
            })
            .collect()
    }

    fn ranked(windows: &mut [SemanticUnitGraph], analysis: &StructuralReport) -> Vec<u32> {
        assign_semantic_occurrence_ranks(windows, analysis);
        windows
            .iter()
            .map(|window| window.occurrence_rank)
            .collect()
    }

    #[test]
    fn identical_hosts_from_different_units_get_distinct_semantic_ranks() {
        let analysis = analysis_of_two_identical_hosts();
        let mut windows = windows_at([
            ByteRange { start: 40, end: 50 },
            ByteRange { start: 10, end: 20 },
            ByteRange { start: 10, end: 20 },
        ]);

        let ranks = ranked(&mut windows, &analysis);

        assert_eq!(ranks, vec![0, 1, 0]);
        let identities: std::collections::BTreeSet<_> = windows
            .iter()
            .map(|window| {
                stable_id::semantic_occurrence_fingerprint(
                    window.content,
                    &analysis.units[window.unit].fingerprint,
                    window.occurrence_rank,
                )
            })
            .collect();
        assert_eq!(
            identities.len(),
            3,
            "windows that share a host and a content still identify apart"
        );
    }

    /// Adding a doc comment to one file moves every byte offset after it. That
    /// is not a change to any window's content or to the unit hosting it, so no
    /// window's rank — and so no semantic finding id — may move with it.
    #[test]
    fn a_comment_added_to_one_file_moves_no_semantic_occurrence_rank() {
        let analysis = analysis_of_two_identical_hosts();
        let mut before = windows_at([
            ByteRange { start: 40, end: 50 },
            ByteRange { start: 10, end: 20 },
            ByteRange { start: 10, end: 20 },
        ]);
        // The second file gains a comment above its window, pushing that window
        // past its twin in byte order.
        let mut after = windows_at([
            ByteRange { start: 40, end: 50 },
            ByteRange {
                start: 910,
                end: 920,
            },
            ByteRange { start: 10, end: 20 },
        ]);

        assert_eq!(
            ranked(&mut before, &analysis),
            ranked(&mut after, &analysis)
        );
    }
}

/// Convert semantic windows into occurrence-qualified inputs for a group ID.
pub(super) fn semantic_group_member_fingerprints<'a>(
    members: impl IntoIterator<Item = &'a SemanticUnitGraph>,
    analysis: &StructuralReport,
) -> Vec<stable_id::FragmentFingerprint> {
    members
        .into_iter()
        .map(|member| {
            stable_id::semantic_occurrence_fingerprint(
                member.content,
                &analysis.units[member.unit].fingerprint,
                member.occurrence_rank,
            )
        })
        .collect()
}

/// Decode the full 256-bit `BuildVariant` identity that SOG stores as bytes.
pub(super) fn semantic_variant_fingerprint(variant: &BuildVariant) -> Result<[u8; 32]> {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use codehelion_core::discovery::{ContentHash, TargetKind};

    use super::{Language, SourceUnit, answered_by_file, path_key, semantic};

    fn source(relative: &str) -> SourceUnit {
        SourceUnit {
            relative_path: PathBuf::from(relative),
            absolute_path: PathBuf::from("/w").join(relative),
            language: Language::Cpp,
            is_header: false,
            content_hash: ContentHash::of(b""),
            source_bytes: Vec::new().into(),
            byte_len: 0,
            package: None,
            crate_name: None,
            target_kind: TargetKind::Library,
        }
    }

    /// The name a compiler's answer is filed under is the name the file's own
    /// metadata carries. Naming the two sides separately is how a file comes to
    /// be present on both and found on neither.
    #[test]
    fn an_answer_is_filed_under_the_name_the_file_is_looked_up_by() {
        let sources = [source("src/range_loop.cpp"), source("include/calls.hpp")];
        let asked = semantic::Answers {
            helpers: Vec::new(),
            per_source: sources
                .iter()
                .map(|source| semantic::Answer::NotAsked {
                    unit: codehelion_helper::ir::UnitRef {
                        unit: String::new(),
                        file: source.absolute_path.display().to_string(),
                        variant: String::new(),
                    },
                    reason: codehelion_helper::ir::Unavailability::NotSupported,
                })
                .collect(),
        };

        let answered = answered_by_file(&sources, &asked);

        for source in &sources {
            assert!(
                answered.contains_key(&path_key(&source.relative_path)),
                "{} is not filed under the name its metadata carries",
                source.relative_path.display()
            );
        }
    }
}
