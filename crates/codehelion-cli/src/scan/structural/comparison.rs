//! Cross-build-variant and cross-language semantic comparisons.

use super::{
    BTreeSet, BuildVariant, Config, Context, CrossComparisonUnit, CrossLanguageCandidateInput,
    CrossLanguageComparisonSnapshot, CrossLanguageComparisonUnit, CrossLanguageSemanticGroupRow,
    CrossLanguageSemanticMemberRow, CrossVariantComparisonSnapshot, CrossVariantGroupRow,
    CrossVariantMemberRow, CrossVariantUnit, DiscoveryReport, Installed, Language,
    PartitionOutcome, Path, Report, ReportInputs, Result, ScanArgs, ScanBaseline,
    SemanticCandidateConfig, SemanticDetection, SemanticPartition, SourceMeta, SourceUnit,
    StructuralReport, SyntaxIrFile, as_u64, build_groups, build_report, compile_rules, coverage,
    detector_versions, evaluate_suppression, extract_cross_language_candidates, literal_norm,
    map_sources, mark_test_modules, mark_test_paths, open_store, parse_one,
    presentation_suppression, record, registered_semantic_pairs, report, reportable_regions,
    resolve, rfc3339_now, semantic_confidence, stable_id, structural, structural_config,
    summary_row, suppress, verify_cross_language_candidates,
};

/// The normal partitions are the source of truth for whether a comparison
/// could start. An absent status therefore never means an empty comparison.
pub(super) fn cross_variant_comparison_not_run(
    reports: &[Report],
) -> report::CrossVariantComparisonNotRun {
    let mut origin_variants: Vec<String> = reports
        .iter()
        .map(|report| report.run.build_variant.fingerprint.clone())
        .collect();
    origin_variants.sort_unstable();
    origin_variants.dedup();
    let reason = if origin_variants.len() < 2 {
        "fewer than two build-variant partitions were available"
    } else {
        "fewer than two build-variant partitions supplied whole units eligible for exact comparison"
    };
    report::CrossVariantComparisonNotRun {
        status: "not_run".to_string(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        reason: reason.to_string(),
        origin_variants,
    }
}

/// Execute and record one semantic partition.
///
/// The parser is intentionally run per partition for now. It never executes
/// target code, and keeping its products private to the partition makes it
/// impossible for a future resolved-type refinement to accidentally reconnect
/// clone grouping across build variants.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run_semantic_partition(
    args: &ScanArgs,
    cfg: &Config,
    guardrails: Option<&report::Guardrails>,
    jobs: usize,
    root: &Path,
    db_path: &Path,
    configuration: &report::ConfigurationInfo,
    started_at: &str,
    shared_discovery: Option<&DiscoveryReport>,
    sources: &[SourceUnit],
    glob_excluded: usize,
    asking: Option<&[&Installed]>,
    partition: &SemanticPartition,
) -> Result<PartitionOutcome> {
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
    let mut analysis =
        structural::analyze_resolved(&irs, &partition.variant, &structural_config(cfg), &resolved);
    mark_test_paths(cfg, &files, &mut analysis)?;
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
    let matched_rules: BTreeSet<usize> = rules
        .files
        .iter()
        .flat_map(suppress::FileSuppression::matched_rules)
        .collect();
    let baseline = crate::scan::load_baseline(
        args.baseline.as_deref(),
        args.baseline_mode,
        &mut rules.rules,
        &partition.variant,
        &detector_versions(literal_norm(cfg.literal_normalization)),
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
        configuration,
        started_at,
        finished_at: &finished_at,
        variant: &partition.variant,
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
    let groups = build_groups(&inputs);
    let stored = summary_row(
        &inputs,
        shared_discovery,
        baseline.as_ref().map(ScanBaseline::digest),
        guardrails,
    );
    let run_id = record(
        cfg,
        &inputs,
        &groups,
        crate::scan::file_rows(sources),
        &stored,
        asked.as_ref(),
        false,
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

pub(super) fn maybe_cross_comparison_units(
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

pub(super) fn maybe_cross_language_comparison_units(
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

pub(super) fn copy_guardrails(guardrails: &report::Guardrails) -> report::Guardrails {
    report::Guardrails {
        profile: guardrails.profile.clone(),
        max_file_bytes: guardrails.max_file_bytes,
        parse_timeout_ms: guardrails.parse_timeout_ms,
        helper_timeout_ms: guardrails.helper_timeout_ms,
        posting_cap: guardrails.posting_cap,
        pair_budget: guardrails.pair_budget,
        max_component: guardrails.max_component,
    }
}

/// Retain C/C++ units from one completed partition for an explicitly requested
/// comparison. The normal report owns neither this data nor its interpretation.
pub(super) fn cross_comparison_units(
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
pub(super) fn record_cross_variant_comparison(
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
pub(super) fn record_cross_language_comparison(
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
        funnel: cross_language_funnel(&candidates.stats),
        search_truncated: candidates.stats.oversized_buckets > 0
            || candidates.stats.pairs_budget_dropped > 0,
        groups: report_groups,
    }))
}

/// Candidate accounting for an opt-in cross-language comparison.
///
/// Bucket and pair drops use separate stages because their counts have
/// different units. Keeping them distinct stops a member ceiling from reading
/// as a number of unexamined pairs.
pub(super) fn cross_language_funnel(
    stats: &codehelion_core::semantic::CrossLanguageCandidateStats,
) -> Vec<report::FunnelStage> {
    vec![
        report::FunnelStage::new("cross-language graphs", as_u64(stats.graphs))
            .dropping("ineligible", as_u64(stats.ineligible_graphs)),
        report::FunnelStage::new(
            "cross-language candidate buckets",
            as_u64(stats.buckets.saturating_sub(stats.oversized_buckets)),
        )
        .dropping("bucket_member_cap", as_u64(stats.oversized_buckets)),
        report::FunnelStage::new(
            "cross-language candidate pairs",
            as_u64(stats.pairs_emitted),
        )
        .dropping("pair_budget", as_u64(stats.pairs_budget_dropped)),
    ]
}

/// Keep only opt-in cross-language rule applications enabled for this project.
///
/// The candidate index remains independent of configuration for complete,
/// deterministic accounting; this policy boundary decides only whether an
/// already explained correspondence may become a reported finding.
pub(super) fn enabled_cross_language_matches(
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
