//! Cross-build-variant and cross-language semantic comparisons.

use super::{
    BTreeSet, BuildVariant, Config, Context, CrossComparisonUnit, CrossLanguageCandidateInput,
    CrossLanguageComparisonSnapshot, CrossLanguageComparisonUnit, CrossLanguageSemanticGroupRow,
    CrossLanguageSemanticMemberRow, CrossVariantComparisonSnapshot, CrossVariantGroupRow,
    CrossVariantMemberRow, CrossVariantUnit, DiscoveryReport, Installed, Language,
    PartitionOutcome, Path, Report, ReportInputs, Result, ScanArgs, ScanBaseline,
    SemanticDetection, SemanticProgram, SourceMeta, StructuralReport, SyntaxIrFile, as_u64,
    build_groups, build_report, compile_rules, coverage, detector_versions, directory_partitions,
    evaluate_suppression, extract_cross_language_candidates, literal_norm, map_sources,
    mark_test_modules, mark_test_paths, parse_one, path_key, presentation_suppression, record,
    registered_semantic_pairs, remove_signature_sibling_funnel_stage, report, reportable_regions,
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

/// Everything one program is analysed under, whether the run holds one or
/// several.
///
/// The context is built once per invocation. A partitioned run and a run over
/// the whole tree then take the same path with the same values, so a change to
/// what a program's report carries cannot reach one of them and miss the other.
#[derive(Clone, Copy)]
pub(super) struct ProgramContext<'a> {
    pub(super) args: &'a ScanArgs,
    pub(super) cfg: &'a Config,
    pub(super) guardrails: Option<&'a report::Guardrails>,
    pub(super) jobs: usize,
    pub(super) root: &'a Path,
    pub(super) db_path: &'a Path,
    pub(super) configuration: &'a report::ConfigurationInfo,
    pub(super) started_at: &'a str,
    /// The helpers this run asks about its sources, if any.
    pub(super) asking: Option<&'a [&'a Installed]>,
    pub(super) glob_excluded: usize,
    /// The analysis a failure here belongs to.
    pub(super) mode: crate::cli::Mode,
    /// Whether this program is the whole run. It then records a complete
    /// snapshot of its own and may stand in for a compatible predecessor;
    /// otherwise it stages a part that the invocation commits with the others.
    pub(super) whole_run: bool,
}

/// Execute and record one program.
///
/// The parser is intentionally run per partition for now. It never executes
/// target code, and keeping its products private to the partition makes it
/// impossible for a future resolved-type refinement to accidentally reconnect
/// clone grouping across build variants.
#[allow(clippy::too_many_lines)]
pub(super) fn run_program(
    ctx: &ProgramContext<'_>,
    shared_discovery: Option<&DiscoveryReport>,
    program: SemanticProgram<'_>,
) -> Result<PartitionOutcome> {
    let ProgramContext {
        args,
        cfg,
        guardrails,
        jobs,
        root,
        db_path,
        configuration,
        started_at,
        asking,
        glob_excluded,
        mode,
        whole_run,
    } = *ctx;
    let sources = program.sources;
    let analysis_began = std::time::Instant::now();
    let replay_database = args
        .db
        .is_some()
        .then(|| crate::scan::spelled_for_a_command(db_path));
    let timeout = std::time::Duration::from_millis(cfg.limits.parse_timeout_ms);
    let (parsed, unreadable, timed_out) = map_sources(sources, jobs, |source| {
        parse_one(source, cfg.limits.max_file_bytes, timeout)
    })
    .map_err(|error| crate::analysis_failure(mode, error))?;
    let (files, mut irs): (Vec<SourceMeta>, Vec<SyntaxIrFile>) = parsed
        .into_iter()
        .map(|source| (source.meta, source.ir))
        .unzip();
    mark_test_modules(&files, &mut irs);

    let (asked, resolved) = resolve(
        asking,
        sources,
        &files,
        program.variant,
        program.commands,
        args.untrusted.then_some(root),
        std::time::Duration::from_millis(cfg.limits.helper_timeout_ms),
    );
    let structural_cfg = structural_config(cfg);
    let mut analysis = if args.siblings_by_signature {
        let directory_partitions = directory_partitions(&files);
        structural::analyze_resolved_with_context(
            &irs,
            program.variant,
            &structural_cfg,
            &resolved,
            &directory_partitions,
        )
    } else {
        structural::analyze_resolved(&irs, program.variant, &structural_cfg, &resolved)
    };
    mark_test_paths(cfg, &files, &mut analysis)?;
    let semantic = registered_semantic_pairs(
        asked.as_ref(),
        sources,
        &files,
        &irs,
        &analysis,
        program.variant,
        cfg,
    )
    .map_err(|error| crate::analysis_failure(mode, error))?;
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
        program.variant,
        &detector_versions(
            literal_norm(cfg.literal_normalization),
            cfg.entropy_ratio_floor,
            asked.as_ref(),
        ),
        cfg.min_clone_tokens,
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
        program.variant,
    );
    let finished_at = rfc3339_now();
    let analysis_took = analysis_began.elapsed();
    let inputs = ReportInputs {
        root,
        db_path,
        replay_database: replay_database.as_deref(),
        configuration,
        started_at,
        finished_at: &finished_at,
        variant: program.variant,
        files: &files,
        irs: &irs,
        analysis: &analysis,
        semantic_groups: &semantic.groups,
        semantic_pairs: &semantic.pairs,
        semantic_detection: &semantic,
        compiler_answers: asked.as_ref(),
        rules: &rules.rules,
        matched_rules: &matched_rules,
        group_suppressed: &suppressed.groups,
        regions: &regions,
        region_suppressed: &suppressed.regions,
        suppression: &presentation_cfg.suppression,
        pair_suppressed: &suppressed.pairs,
        semantic_pair_suppressed: &suppressed.semantic_pairs,
        semantic_group_suppressed: &suppressed.semantic_groups,
        sibling_suppressed: &suppressed.siblings,
        near_miss_suppressed: &suppressed.near_misses,
        entropy_ratio_floor: cfg.entropy_ratio_floor,
        literals: literal_norm(cfg.literal_normalization),
        glob_excluded,
        unreadable,
        timed_out,
        weights: cfg.priority.weights(),
        min_clone_tokens: u64::from(cfg.min_clone_tokens),
        sort: args.sort.axis(),
        reuse_allowed: whole_run && !args.no_reuse,
        untrusted: args.untrusted,
        siblings_by_signature: args.siblings_by_signature,
    };
    let normalized = build_groups(&inputs)?;
    let groups = normalized.groups;
    let identity_collapsed = normalized.identity_collapsed;
    let mut stored = summary_row(
        &inputs,
        shared_discovery,
        baseline.as_ref().map(ScanBaseline::digest),
        guardrails,
    );
    if !args.siblings_by_signature {
        remove_signature_sibling_funnel_stage(&mut stored);
    }
    report::append_stored_identity_stage(&mut stored.funnel, groups.len(), identity_collapsed);
    let mut model = build_report(&inputs, None, &stored, groups);
    model.run.reused = false;
    model.summary.changes = None;
    model.summary.guardrails = guardrails.map(copy_guardrails);
    model.summary.compiler = asked.as_ref().map(coverage);
    model.summary.baseline = baseline
        .as_ref()
        .map(|baseline| crate::scan::apply_baseline(baseline, &mut model.groups));
    model.refresh_supplemental_summary();
    let comparison_units =
        maybe_cross_comparison_units(args, program.variant, &files, &irs, &analysis);
    let cross_language_units =
        maybe_cross_language_comparison_units(args, program.variant, &files, &analysis, &semantic);
    let recording_began = std::time::Instant::now();
    let record_result = record(
        cfg,
        &inputs,
        &model.groups,
        crate::scan::file_rows(sources),
        &stored,
        asked.as_ref(),
        whole_run,
    );
    let recording_took = recording_began.elapsed();
    let (recording_error, staged, reuse_key) = match record_result {
        Ok(recorded) => {
            model.run.run_id = Some(recorded.run_id);
            model.run.reused = recorded.reused;
            model.run.timings = Some(report::RunTimings {
                analysis: analysis_took,
                recording: (!recorded.reused).then_some(recording_took),
            });
            model.summary.changes = recorded.changes;
            (None, recorded.staged, Some(recorded.reuse_key))
        }
        Err(error) => {
            model.run.timings = Some(report::RunTimings {
                analysis: analysis_took,
                recording: None,
            });
            (Some(error), None, None)
        }
    };
    let outcome = crate::scan::outcome(args, &model);
    Ok(PartitionOutcome {
        outcome,
        report: model,
        comparison_units,
        cross_language_units,
        recording_error,
        staged,
        reuse_key,
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
                occurrence: stable_id::semantic_occurrence_fingerprint(
                    semantic_unit.content,
                    &unit.fingerprint,
                    semantic_unit.occurrence_rank,
                ),
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
        verification_budget: guardrails.verification_budget,
        max_alignment_cells: guardrails.max_alignment_cells,
        near_miss_delta: guardrails.near_miss_delta,
        near_miss_cap: guardrails.near_miss_cap,
        sibling_candidate_budget: guardrails.sibling_candidate_budget,
        sibling_per_group_cap: guardrails.sibling_per_group_cap,
        sibling_total_cap: guardrails.sibling_total_cap,
        signature_sibling_candidate_budget: guardrails.signature_sibling_candidate_budget,
        signature_sibling_per_group_cap: guardrails.signature_sibling_per_group_cap,
        signature_sibling_total_cap: guardrails.signature_sibling_total_cap,
        signature_sibling_max_units_per_signature: guardrails
            .signature_sibling_max_units_per_signature,
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

/// Prepared cross-build comparison kept alive until the normal partition
/// finalizer commits every staged snapshot.
pub(super) struct PreparedCrossVariant {
    pub root_path: String,
    pub comparison_id: stable_id::CrossVariantComparisonId,
    pub policy_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub origins: Vec<String>,
    pub groups: Vec<CrossVariantGroupRow>,
    pub report: report::CrossVariantComparison,
}

impl PreparedCrossVariant {
    pub(super) fn snapshot(&self) -> CrossVariantComparisonSnapshot<'_> {
        CrossVariantComparisonSnapshot {
            root_path: &self.root_path,
            comparison_id: self.comparison_id,
            policy_version: &self.policy_version,
            started_at: &self.started_at,
            finished_at: &self.finished_at,
            origins: &self.origins,
            groups: &self.groups,
        }
    }
}

/// Directly compare the completed C/C++ partitions without persisting yet.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the preparation boundary remains fallible as comparison preparation grows"
)]
pub(super) fn prepare_cross_variant_comparison(
    root: &Path,
    started_at: &str,
    units: &[CrossComparisonUnit],
) -> Result<Option<PreparedCrossVariant>> {
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
                    member_id: member.id,
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
    let root_path = path_key(root);
    let report = report::CrossVariantComparison {
        policy_version: stable_id::CROSS_VARIANT_POLICY_VERSION.to_string(),
        comparison_id: comparison.id.to_hex(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        origin_variants: comparison.origin_variants.clone(),
        groups: comparison
            .groups
            .iter()
            .map(|group| report::CrossVariantGroup {
                id: group.id.to_hex(),
                clone_type: group.clone_type.name().to_string(),
                members: group
                    .members
                    .iter()
                    .map(|member| report::CrossVariantMember {
                        origin_variant: member.origin_variant.clone(),
                        language: member.language.name().to_string(),
                        file: crate::scan::display_path(&member.file_path),
                        start_line: member.start_line,
                        end_line: member.end_line,
                        name: member.name.clone(),
                        token_count: member.token_count,
                    })
                    .collect(),
            })
            .collect(),
    };
    Ok(Some(PreparedCrossVariant {
        root_path,
        comparison_id: comparison.id,
        policy_version: stable_id::CROSS_VARIANT_POLICY_VERSION.to_string(),
        started_at: started_at.to_string(),
        finished_at,
        origins: comparison.origin_variants,
        groups,
        report,
    }))
}

/// Prepared Rust-to-C++ comparison kept alive until all semantic partitions
/// have been finalized.
pub(super) struct PreparedCrossLanguage {
    pub root_path: String,
    pub comparison_id: stable_id::CrossLanguageComparisonId,
    pub policy_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub origins: Vec<String>,
    pub groups: Vec<CrossLanguageSemanticGroupRow>,
    pub report: report::CrossLanguageComparison,
}

impl PreparedCrossLanguage {
    pub(super) fn snapshot(&self) -> CrossLanguageComparisonSnapshot<'_> {
        CrossLanguageComparisonSnapshot {
            root_path: &self.root_path,
            comparison_id: self.comparison_id,
            policy_version: &self.policy_version,
            started_at: &self.started_at,
            finished_at: &self.finished_at,
            origins: &self.origins,
            groups: &self.groups,
        }
    }
}

/// Directly compare the completed Rust and C++ semantic partitions without
/// persisting yet.
#[allow(
    clippy::too_many_lines,
    reason = "the comparison boundary constructs report and persistence evidence together"
)]
pub(super) fn prepare_cross_language_comparison(
    root: &Path,
    started_at: &str,
    units: &[CrossLanguageComparisonUnit],
    cfg: &Config,
) -> Result<Option<PreparedCrossLanguage>> {
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
    let candidates = extract_cross_language_candidates(
        &inputs,
        crate::scan::runtime::stage_limits(cfg)
            .pairing
            .semantic_candidates(),
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
            &[left.occurrence, right.occurrence],
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
                    member_id: stable_id::cross_language_member_id(
                        &group_id,
                        &unit.origin_variant,
                        &unit.occurrence,
                    ),
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
                    file: crate::scan::display_path(&unit.file_path),
                    start_line: unit.start_line,
                    end_line: unit.end_line,
                    name: unit.name.clone(),
                    graph: unit.graph.clone(),
                })
                .collect(),
        });
    }
    let finished_at = rfc3339_now();
    let root_path = path_key(root);
    let report = report::CrossLanguageComparison {
        policy_version: stable_id::CROSS_LANGUAGE_POLICY_VERSION.to_string(),
        comparison_id: comparison_id.to_hex(),
        comparison_kind: "restricted-semantic-rust-cpp-pipelines".to_string(),
        origin_variants: origins.clone(),
        funnel: cross_language_funnel(&candidates.stats),
        search_truncated: candidates.stats.oversized_buckets > 0
            || candidates.stats.pairs_budget_dropped > 0,
        groups: report_groups,
    };
    Ok(Some(PreparedCrossLanguage {
        root_path,
        comparison_id,
        policy_version: stable_id::CROSS_LANGUAGE_POLICY_VERSION.to_string(),
        started_at: started_at.to_string(),
        finished_at,
        origins,
        groups: store_groups,
        report,
    }))
}

/// Describe an explicitly requested Rust-to-C++ comparison that lacked one
/// of its required source-language inputs.
pub(super) fn cross_language_comparison_not_run(
    reports: &[Report],
    units: &[CrossLanguageComparisonUnit],
) -> report::CrossLanguageComparisonNotRun {
    let mut origin_variants: Vec<_> = reports
        .iter()
        .map(|report| report.run.build_variant.fingerprint.clone())
        .collect();
    origin_variants.sort_unstable();
    origin_variants.dedup();
    let has_rust = units.iter().any(|unit| unit.language == Language::Rust);
    let has_cpp = units.iter().any(|unit| unit.language == Language::Cpp);
    let reason = match (has_rust, has_cpp) {
        (false, false) => "no eligible Rust or C++ semantic windows were available".to_string(),
        (false, true) => "no eligible Rust semantic windows were available".to_string(),
        (true, false) => "no eligible C++ semantic windows were available".to_string(),
        (true, true) => "fewer than two origin build variants were available".to_string(),
    };
    report::CrossLanguageComparisonNotRun {
        status: "not_run".to_string(),
        comparison_kind: "registered-rust-cpp-semantic".to_string(),
        reason,
        origin_variants,
    }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod posting_ceiling_tests {
    use super::{
        BTreeSet, BuildVariant, Config, CrossLanguageComparisonUnit, Language, Path,
        prepare_cross_language_comparison, report, stable_id,
    };
    use codehelion_core::discovery::LanguageSelection;
    use codehelion_core::semantic::{
        FallibleKind, OperationAttributes, OperationKind, OperationNode, SemanticOperationGraph,
    };

    /// Three comparable units whose graphs share one candidate bucket: two Rust
    /// and one C++, so a ceiling of two members leaves that bucket over it while
    /// the default ceiling admits it. Each origin reads the tree under its own
    /// build variant, which is what makes a pair across two of them comparable.
    fn one_bucket_of_three() -> Vec<CrossLanguageComparisonUnit> {
        [
            ("origin-a", 7, Language::Rust, "src/left.rs"),
            ("origin-b", 8, Language::Rust, "src/right.rs"),
            ("origin-b", 8, Language::Cpp, "cpp/right.cpp"),
        ]
        .into_iter()
        .map(|(origin_variant, origin_seed, language, file_path)| {
            let graph = SemanticOperationGraph::new(
                language,
                [origin_seed; 32],
                vec![OperationNode {
                    kind: OperationKind::Validate,
                    attributes: OperationAttributes {
                        fallible_kind: Some(FallibleKind::Option),
                        ..OperationAttributes::default()
                    },
                }],
                Vec::new(),
            )
            .expect("closed optional validation graph");
            let variant = BuildVariant::structural(LanguageSelection::default(), language);
            CrossLanguageComparisonUnit {
                origin_variant: origin_variant.to_owned(),
                language,
                file_path: file_path.to_owned(),
                start_line: 1,
                end_line: 3,
                name: None,
                occurrence: stable_id::semantic_fragment_fingerprint(&variant, &graph),
                graph,
                normalization_confidence: 1.0,
                interactions: BTreeSet::new(),
                data_flows: BTreeSet::new(),
                cfg_shape: None,
            }
        })
        .collect()
    }

    /// Buckets the member ceiling refused, as this comparison accounted for them.
    fn buckets_over_the_ceiling(funnel: &[report::FunnelStage]) -> u64 {
        funnel
            .iter()
            .filter(|stage| stage.stage == "cross-language candidate buckets")
            .flat_map(|stage| &stage.dropped)
            .filter(|drop| drop.cause == "bucket_member_cap")
            .map(|drop| drop.count)
            .sum()
    }

    fn comparison(cfg: &Config) -> report::CrossLanguageComparison {
        prepare_cross_language_comparison(
            Path::new("/tree"),
            "2026-01-01T00:00:00Z",
            &one_bucket_of_three(),
            cfg,
        )
        .expect("the comparison prepares")
        .expect("two origins holding both languages compare")
        .report
    }

    /// The cross-language index is one of the bucket paths a run's stated
    /// posting ceiling governs, so it takes that ceiling from the stage mapping
    /// the reported guardrail is read from rather than from a width of its own.
    /// A ceiling written into this call site instead would leave the bucket
    /// paired at a width no configuration can lower.
    #[test]
    fn the_cross_language_index_cuts_at_the_configured_posting_ceiling() {
        let cfg = Config::from_toml("[limits]\nposting-cap = 2\n")
            .expect("a posting ceiling is configurable");
        let stated = crate::scan::runtime::stage_limits(&cfg)
            .pairing
            .semantic_candidates();
        assert_eq!(stated.max_bucket_members, 2);

        let cut = comparison(&cfg);
        assert_eq!(buckets_over_the_ceiling(&cut.funnel), 1);
        assert!(cut.search_truncated);
        assert!(cut.groups.is_empty());
    }

    /// The same tree under no configured ceiling pairs the bucket, which is what
    /// makes the cut above a consequence of the stated number.
    #[test]
    fn the_cross_language_index_pairs_the_same_bucket_under_the_default_ceiling() {
        let cfg = Config::default();
        let admitted = comparison(&cfg);
        assert_eq!(buckets_over_the_ceiling(&admitted.funnel), 0);
        assert!(!admitted.search_truncated);
        assert!(!admitted.groups.is_empty());
    }
}
