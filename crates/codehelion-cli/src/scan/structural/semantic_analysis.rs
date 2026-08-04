//! Semantic partitioning, compiler-evidence resolution, and confidence composition.

use super::{
    BTreeMap, BTreeSet, BuildConfiguration, BuildVariant, ByteRange, CfgShape, CloneScope,
    CompileCommandSelector, Config, Context, ControlFlowGraph, DataFlowSummary, DiscoveryReport,
    EdgeKind, GroupingConfig, Installed, Language, LanguageSelection, Path, PathBuf, Result,
    SemanticCandidateConfig, SemanticCandidateStats, SemanticConfidenceEvidence, SemanticDetection,
    SemanticGroup, SemanticGroupingStats, SemanticGroupingUnit, SemanticOperationGraph,
    SemanticPair, SemanticUnitGraph, SourceMeta, SourceUnit, StructuralReport, StructuralUnit,
    SyntaxIrFile, VerifiedSemanticPair, bail, extract_registered_candidates,
    group_verified_semantic_pairs, registered_semantic_windows, semantic, stable_id, structural,
    verify_registered_candidates,
};

pub(super) struct SemanticPartition {
    pub(super) variant: BuildVariant,
    pub(super) sources: Vec<SourceUnit>,
    pub(super) commands: BTreeMap<PathBuf, CompileCommandSelector>,
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
pub(super) fn unconfigured_cpp_partition(
    discovered: &DiscoveryReport,
    sources: &[SourceUnit],
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
    assign_semantic_occurrence_ranks(&mut units);
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

/// Derive one host-local occurrence rank before grouping so every consumer
/// uses the same position-independent identity for the same semantic window.
fn assign_semantic_occurrence_ranks(units: &mut [SemanticUnitGraph]) {
    let mut ordered: Vec<_> = units
        .iter()
        .enumerate()
        .map(|(index, member)| (index, member.unit, member.range, member.content))
        .collect();
    ordered.sort_by_key(|(_, unit, range, content)| (*unit, *range, *content));
    let mut next_by_unit = BTreeMap::new();
    for (index, unit, _, _) in ordered {
        let rank = next_by_unit.entry(unit).or_insert(0_u32);
        units[index].occurrence_rank = *rank;
        *rank = rank.saturating_add(1);
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
