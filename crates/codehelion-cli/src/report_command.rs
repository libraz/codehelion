//! Replaying recorded scans and explaining stored findings.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module exposes command helpers to crate-local tests"
)]

use super::{
    Context, DetailFormat, ExplainArgs, FULL_ID_CHARS, IdKind, IdMatch, Outcome, Path, PathBuf,
    ReportArgs, Result, RunOrigin, Store, Write, bail, config, fingerprint_hex, report,
    resolve_db_at, scan, suppress,
};

pub(crate) fn report_command(args: &ReportArgs, out: &mut impl Write) -> Result<Outcome> {
    let (resolved_config, path) = report_database(args)?;
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = Store::open(&path)?;
    let run = store
        .run_summary(args.run)?
        .with_context(|| format!("no recorded run {} in {}", args.run, path.display()))?;
    store.ensure_completed_run(run.id)?;
    let finished_at = run
        .finished_at
        .as_deref()
        .context("the selected run did not complete and cannot be reported")?;
    let origin = store.run_origin(run.id)?;
    let variant = store
        .build_variant(&origin.variant_fingerprint)?
        .context("the selected run has no stored build variant")?;
    let summary_row = store
        .run_summary_row(run.id)?
        .context("the selected run has no stored summary")?;
    let mut groups = recorded_groups(&store, run.id)?;
    let sort = args.sort.axis();
    report::order(&mut groups, &resolved_config.config.suppression, sort);
    let compiler = store
        .run_compiler_coverage(run.id)?
        .map(restored_compiler_coverage);
    let ranking = recorded_ranking(&origin.detector_versions)?;
    let analysis_mode = run.analysis_mode.clone();
    let mut model = report::Report {
        schema_version: report::SCHEMA_VERSION,
        run: report::RunInfo {
            tool_version: run.tool_version,
            mode: run.analysis_mode,
            root: run.root_path,
            configuration: recorded_configuration(&origin)?,
            started_at: run.started_at,
            finished_at: finished_at.to_string(),
            build_variant: report::BuildVariantInfo {
                mode: variant.analysis_mode,
                languages: variant
                    .languages
                    .as_deref()
                    .map_or_else(Vec::new, |languages| {
                        languages
                            .split(',')
                            .filter(|language| !language.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    }),
                headers: variant.header_language.filter(|header| !header.is_empty()),
                normalization_version: u32::try_from(origin.normalization_version)
                    .context("stored normalization version does not fit the report")?,
                fingerprint: variant.fingerprint,
            },
            detector_versions: origin
                .detector_versions
                .iter()
                .filter(|(component, _)| component != "ranking")
                .map(|(component, version)| report::DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            ranking,
            database: path.display().to_string(),
            run_id: run.id,
        },
        summary: report::Summary {
            compiler,
            ..report::restored(&summary_row, &groups, &analysis_mode)
        },
        groups,
    };
    scan::hydrate_artifact_savings(&store, run.id, &mut model.groups)?;
    scan::write_report_options(
        scan::ReportOutput {
            format: args.format,
            output: args.output.as_deref(),
            force: args.force,
            verbose: args.verbose,
            show_suppressed: args.show_suppressed,
            sort,
            min_identifier_jaccard: args.min_identifier_jaccard,
        },
        out,
        &model,
    )?;
    Ok(Outcome::Success)
}

/// Restore configuration provenance without letting the current configuration
/// overwrite what the recorded run actually used.
pub(crate) fn recorded_configuration(origin: &RunOrigin) -> Result<report::ConfigurationInfo> {
    Ok(report::ConfigurationInfo {
        source: origin.config_source.clone(),
        path: origin.config_path.clone(),
        min_clone_tokens: u32::try_from(origin.min_clone_tokens)
            .context("stored minimum clone length does not fit the report")?,
    })
}

/// Rebuild each recorded group with the priority saved beside it.
pub(crate) fn recorded_groups(store: &Store, run_id: i64) -> Result<Vec<report::Group>> {
    store
        .run_groups(run_id)?
        .into_iter()
        .map(|group| {
            let priority = store
                .run_group_priority(run_id, &group.fingerprint_hex)?
                .with_context(|| {
                    format!(
                        "recorded run {run_id} has no saved priority for clone group {}",
                        group.fingerprint_hex
                    )
                })?;
            recorded_group(group, &priority)
        })
        .collect()
}

/// Resolve the configuration that also supplies a recorded report's view
/// policy, together with its local database path.
pub(crate) fn report_database(args: &ReportArgs) -> Result<(config::ResolvedConfig, PathBuf)> {
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let path = scan::database_path(&root, args.db.as_deref(), &resolved_config, false)?;
    Ok((resolved_config, path))
}

/// Turn the normalised compiler rows' aggregate back into report metadata.
///
/// Compiler coverage belongs in its own tables because one source unit can
/// carry a full compiler IR, not merely a count. Reading the aggregate here
/// keeps `report --run` faithful without copying it into a second source of
/// truth.
pub(crate) fn restored_compiler_coverage(
    coverage: codehelion_store::compiler::CompilerCoverage,
) -> report::CompilerCoverage {
    let build_script_refused = coverage
        .unavailable
        .get("requires_execution")
        .copied()
        .unwrap_or(0);
    let execution_refusals = codehelion_core::execution::ExecutionPolicy::deny_all()
        .refusal(codehelion_core::execution::Execution::BuildScript)
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
        answered: coverage.answered,
        not_asked: coverage.not_asked,
        unavailable: coverage.unavailable,
        execution_refusals,
        restarts: coverage.restarts.unwrap_or(0),
    }
}

/// Rebuild a report group from exactly the values a snapshot persisted.
pub(crate) fn recorded_group(
    group: codehelion_store::query::StoredGroup,
    priority: &codehelion_store::query::StoredPriority,
) -> Result<report::Group> {
    let stored_suppression = group.suppressed_by;
    let suppress_reason = group.suppress_reason;
    let count = |value: i64| u64::try_from(value).unwrap_or(0);
    let line = |value: Option<i64>| u32::try_from(value.unwrap_or(0)).unwrap_or(0);
    let identifier_jaccard = group.identifier_jaccard;
    let api_similarity = group
        .similarity
        .as_ref()
        .and_then(|similarity| similarity.api);
    let body_materiality = match (
        group.has_loop,
        group.has_dynamic_allocation,
        group.call_count.and_then(|count| u64::try_from(count).ok()),
    ) {
        (Some(has_loop), Some(has_dynamic_allocation), Some(call_count)) => {
            Some(report::BodyMateriality {
                has_loop,
                has_dynamic_allocation,
                call_count,
            })
        }
        _ => None,
    };
    Ok(report::Group {
        fingerprint: group.fingerprint_hex,
        clone_type: group.clone_type,
        scope: group.member_scope,
        statements: group.statements.map(count),
        confidence: group.score,
        entropy_bits: group.entropy_bits,
        priority: recorded_priority_for_report(
            priority,
            group.score,
            identifier_jaccard,
            api_similarity,
            body_materiality,
        )?,
        identifier_jaccard,
        body_materiality,
        similarity: group.similarity.map(|stored| report::Similarity {
            weight_version: stored.weight_version,
            lexical: stored.lexical,
            structural: stored.structural,
            control_flow: stored.control_flow,
            type_similarity: stored.type_similarity,
            api: stored.api,
            composite: stored.composite,
            min_pairwise: stored.min_pairwise,
            confidence_band: stored.confidence_band,
        }),
        boilerplate: group.boilerplate,
        test_code: group.test_code,
        test_code_evidence: group.test_code_evidence,
        width_family: group.width_family,
        split_pair: group.split_pair,
        suppressed: recorded_suppression(suppress_reason, stored_suppression),
        // A recorded run is re-rendered on its own; a baseline is something a
        // scan is given, and nothing about it is stored with the snapshot.
        baseline: None,
        semantic: group.semantic.map(|evidence| report::SemanticEvidence {
            schema_version: evidence.schema_version,
            rules: vec![report::SemanticRuleEvidence {
                id: evidence.rule_id,
                version: evidence.rule_version,
                confidence: evidence.rule_confidence,
            }],
            graphs: evidence.graphs,
            node_mappings: evidence
                .node_mappings
                .into_iter()
                .map(|mapping| report::SemanticNodeMapping {
                    corresponding_member: mapping.corresponding_member,
                    canonical: mapping.canonical,
                    corresponding: mapping.corresponding,
                })
                .collect(),
        }),
        artifact_savings: Vec::new(),
        members: group
            .members
            .into_iter()
            .map(|member| report::Member {
                finding_id: member.finding_hex,
                content: member.content_hex,
                file: member.file_path,
                language: member.language,
                start_line: line(member.start_line),
                end_line: line(member.end_line),
                unit: member.unit_name,
                boilerplate: member.boilerplate,
                tokens: count(member.token_count),
                canonical: member.is_canonical,
            })
            .collect(),
    })
}

/// Convert the ranking values saved with one group without re-applying rules.
pub(crate) fn recorded_priority_for_report(
    stored: &codehelion_store::query::StoredPriority,
    similarity: f64,
    identifier_jaccard: Option<f64>,
    api_similarity: Option<f64>,
    body_materiality: Option<report::BodyMateriality>,
) -> Result<report::Priority> {
    let count = |value: i64| u64::try_from(value).unwrap_or(0);
    Ok(report::Priority {
        value: stored.final_priority,
        clone_confidence: stored.clone_confidence,
        maintenance_risk: stored
            .maintenance_risk
            .context("recorded priority is missing maintenance risk")?,
        refactoring_difficulty: stored
            .refactoring_difficulty
            .context("recorded priority is missing refactoring difficulty")?,
        semantic_confidence: stored.semantic_confidence,
        source_artifact_confidence: stored.source_artifact_confidence,
        savings_confidence: stored.savings_confidence,
        inputs: report::PriorityInputs {
            smallest_member_tokens: count(stored.facts.smallest_member_tokens),
            largest_member_tokens: count(stored.facts.largest_member_tokens),
            instances: count(stored.facts.instances),
            similarity,
            files: count(stored.facts.files),
            directories: count(stored.facts.directories),
            languages: count(stored.facts.languages),
            min_clone_tokens: count(
                stored
                    .facts
                    .min_clone_tokens
                    .context("recorded priority is missing the clone-length floor")?,
            ),
            identifier_jaccard,
            api_similarity,
            has_loop: body_materiality.map(|body| body.has_loop),
            has_dynamic_allocation: body_materiality.map(|body| body.has_dynamic_allocation),
            call_count: body_materiality.map(|body| body.call_count),
            churn: None,
            ownership_spread: None,
        },
    })
}

/// Rebuild the suppression label that the snapshot recorded for one group.
pub(crate) fn recorded_suppression(
    reason: Option<String>,
    rule: Option<codehelion_store::query::StoredSuppressionRef>,
) -> Option<report::Suppression> {
    reason.map_or_else(
        || {
            rule.map(|rule| report::Suppression {
                kind: report::SuppressionKind::Rule,
                reason: rule.reason,
                scope: Some(rule.scope),
                pattern: Some(rule.pattern),
                active: rule.active,
            })
        },
        |reason| {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some(reason),
                scope: None,
                pattern: None,
                active: None,
            })
        },
    )
}

/// Recover the recorded ranking weights from their persisted recipe.
pub(crate) fn recorded_ranking(detectors: &[(String, String)]) -> Result<report::RankingInfo> {
    let recipe = detectors
        .iter()
        .find_map(|(component, version)| (component == "ranking").then_some(version))
        .context("the selected run has no stored ranking recipe")?;
    let (with_risk, ease) = recipe
        .rsplit_once("-ease")
        .context("stored ranking recipe has no ease weight")?;
    let (_, risk) = with_risk
        .rsplit_once("-risk")
        .context("stored ranking recipe has no maintenance-risk weight")?;
    Ok(report::RankingInfo {
        recipe: recipe.clone(),
        maintenance_risk: risk
            .parse()
            .context("stored ranking maintenance-risk weight is invalid")?,
        refactoring_ease: ease
            .parse()
            .context("stored ranking refactoring-ease weight is invalid")?,
    })
}

/// Look up one recorded id and print what it identifies.
///
/// An id names one of three things: an occurrence of a clone group, a clone
/// group itself, or a group from an explicit cross-language comparison. The
/// kind is decided by looking the id up rather than by its shape, and an
/// abbreviation is accepted wherever it names exactly one of them — the
/// report prints group ids in full, and retyping thirty-two hex digits to ask
/// about what is on the screen is a break in the trail the ids exist to keep.
pub(crate) fn explain(args: &ExplainArgs, out: &mut impl Write) -> Result<Outcome> {
    let path = resolve_db_at(&args.path, args.db.as_deref(), args.config.as_deref())?;
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = Store::open(&path)?;
    let found = resolve_id(&store, &args.finding_id, &path)?;
    match found.kind {
        IdKind::Occurrence => explain_occurrence(&store, &found.id, args, out),
        IdKind::CloneGroup => explain_clone_group(&store, &found.id, &path, args, out),
        IdKind::CrossLanguageGroup => explain_cross_language_group(&store, &found.id, args, out),
    }
}

/// Turn what the caller typed into the one recorded id it names.
///
/// # Errors
///
/// Fails when the text is not an id at all, when nothing recorded starts with
/// it, and when more than one thing does — the last listing the candidates,
/// because the answer is to type more of one of them.
pub(crate) fn resolve_id(store: &Store, typed: &str, path: &Path) -> Result<IdMatch> {
    let prefix = typed.to_ascii_lowercase();
    if !prefix.chars().all(|c| c.is_ascii_hexdigit()) || prefix.len() > FULL_ID_CHARS {
        bail!("{typed} is not an id: ids are up to {FULL_ID_CHARS} hexadecimal digits");
    }
    if prefix.len() < suppress::MIN_CLONE_ID_CHARS {
        bail!(
            "{typed} is too short to identify one thing; give at least {} of the {FULL_ID_CHARS} digits",
            suppress::MIN_CLONE_ID_CHARS
        );
    }
    the_one(typed, store.ids_starting_with(&prefix)?, path)
}

/// The single id `matches` names, or why it does not name one.
///
/// Separated from the lookup so that both unwelcome answers can be tested:
/// forcing two recorded ids to share eight hex digits is not something a
/// fixture can arrange.
pub(crate) fn the_one(typed: &str, mut matches: Vec<IdMatch>, path: &Path) -> Result<IdMatch> {
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => bail!(
            "no finding, clone group or cross-language comparison group with id {typed} in {}",
            path.display()
        ),
        _ => {
            let listed: Vec<String> = matches
                .iter()
                .map(|found| format!("{} {}", found.kind.label(), found.id))
                .collect();
            bail!(
                "{typed} names {} things; give more of one of them: {}",
                matches.len(),
                listed.join(", ")
            )
        }
    }
}

/// Print one clone group as the report lists it, with every member.
pub(crate) fn explain_clone_group(
    store: &Store,
    fingerprint: &str,
    path: &Path,
    args: &ExplainArgs,
    out: &mut impl Write,
) -> Result<Outcome> {
    let Some(found) = store.group(fingerprint)? else {
        bail!("no clone group with id {fingerprint} in {}", path.display());
    };
    let priority = store
        .run_group_priority(found.run_id, fingerprint)?
        .with_context(|| format!("clone group {fingerprint} was recorded without a ranking"))?;
    let detail = report::CloneGroupDetail {
        database: path.display().to_string(),
        group: recorded_group(found.group, &priority)?,
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        DetailFormat::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

/// Print one group from an explicit cross-language comparison.
///
/// Comparison-domain groups stay outside normal scan snapshots, baselines and
/// savings, so they render their own detail rather than a report group.
pub(crate) fn explain_cross_language_group(
    store: &Store,
    group_id: &str,
    args: &ExplainArgs,
    out: &mut impl Write,
) -> Result<Outcome> {
    let group = store
        .cross_language_group(group_id)?
        .with_context(|| format!("cross-language comparison group {group_id} went missing"))?;
    let detail = report::CrossLanguageGroupDetail {
        group_id: group.group_id_hex,
        comparison_id: group.comparison_id_hex,
        policy_version: group.policy_version,
        root_path: group.root_path,
        origin_variants: group.origin_variants,
        rule_id: group.rule_id,
        rule_version: group.rule_version,
        semantic_confidence: group.semantic_confidence,
        correspondence_ids: group.correspondence_ids,
        members: group
            .members
            .into_iter()
            .map(|member| report::CrossLanguageGroupMemberDetail {
                origin_variant: member.origin_variant,
                language: member.language,
                file: member.file_path,
                start_line: member.start_line,
                end_line: member.end_line,
                unit: member.unit_name,
                graph: member.graph,
            })
            .collect(),
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        DetailFormat::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

/// Print one occurrence of a clone group, with what the run recorded about the
/// group it belongs to.
#[allow(
    clippy::too_many_lines,
    reason = "one occurrence's complete detail, assembled in one place"
)]
pub(crate) fn explain_occurrence(
    store: &Store,
    finding_id: &str,
    args: &ExplainArgs,
    out: &mut impl Write,
) -> Result<Outcome> {
    let occurrence = store
        .occurrence(finding_id)?
        .with_context(|| format!("occurrence {finding_id} went missing"))?;
    let source_artifact_mappings = store
        .artifact_fragment_mappings(finding_id)?
        .into_iter()
        .map(|mapping| report::SourceArtifactMappingDetail {
            artifact_analysis_id: mapping.analysis_id,
            artifact_symbol_fingerprint: fingerprint_hex(mapping.artifact_symbol_fingerprint),
            source_build_variant_fingerprint: fingerprint_hex(
                mapping.source_build_variant_fingerprint,
            ),
            artifact_build_variant_fingerprint: fingerprint_hex(mapping.build_variant_fingerprint),
            confidence: mapping.confidence.to_string(),
            evidence: mapping.evidence,
            attributed_bytes: mapping.attributed_bytes,
        })
        .collect();
    let clone_group_savings = store
        .clone_group_savings(occurrence.scan_run_id, &occurrence.group_fingerprint_hex)?
        .into_iter()
        .map(|(artifact_analysis_id, savings)| {
            Ok(report::CloneGroupSavingsDetail {
                artifact_analysis_id,
                source_build_variant_fingerprint: fingerprint_hex(
                    savings.source_build_variant_fingerprint,
                ),
                artifact_build_variant_fingerprint: fingerprint_hex(
                    savings.artifact_build_variant_fingerprint,
                ),
                duplicated_bytes: savings.duplicated_bytes,
                estimated_refactor_savings_bytes: savings.estimated_refactor_savings_bytes,
                mapping_confidence: savings.mapping_confidence.to_string(),
                clone_confidence: savings.clone_confidence,
                model_confidence: savings.model_confidence.to_string(),
                savings_confidence: savings.savings_confidence.to_string(),
                model_schema_version: savings.model_schema_version,
                assumptions: serde_json::from_str(&savings.assumptions_json)
                    .context("parsing persisted structured savings assumptions")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let line = |value: Option<i64>| u32::try_from(value.unwrap_or(0)).unwrap_or(0);
    let detail = report::FindingDetail {
        member: report::Member {
            finding_id: occurrence.member.finding_hex,
            content: occurrence.member.content_hex,
            file: occurrence.member.file_path,
            language: occurrence.member.language,
            start_line: line(occurrence.member.start_line),
            end_line: line(occurrence.member.end_line),
            unit: occurrence.member.unit_name,
            boilerplate: occurrence.member.boilerplate,
            tokens: u64::try_from(occurrence.member.token_count).unwrap_or(0),
            canonical: occurrence.member.is_canonical,
        },
        group: report::GroupRef {
            fingerprint: occurrence.group_fingerprint_hex,
            clone_type: occurrence.clone_type,
            scope: occurrence.member_scope,
            confidence: occurrence.score,
            entropy_bits: occurrence.entropy_bits,
            priority: occurrence.priority.as_ref().map(recorded_priority),
            members: u64::try_from(occurrence.member_count).unwrap_or(0),
            boilerplate: occurrence.boilerplate,
            test_code: occurrence.test_code,
            test_code_evidence: occurrence.test_code_evidence,
            split_pair: occurrence.split_pair,
            similarity: occurrence.similarity.map(|stored| report::Similarity {
                weight_version: stored.weight_version,
                lexical: stored.lexical,
                structural: stored.structural,
                control_flow: stored.control_flow,
                type_similarity: stored.type_similarity,
                api: stored.api,
                composite: stored.composite,
                min_pairwise: stored.min_pairwise,
                confidence_band: stored.confidence_band,
            }),
            semantic: occurrence
                .semantic
                .map(|evidence| report::SemanticEvidence {
                    schema_version: evidence.schema_version,
                    rules: vec![report::SemanticRuleEvidence {
                        id: evidence.rule_id,
                        version: evidence.rule_version,
                        confidence: evidence.rule_confidence,
                    }],
                    graphs: evidence.graphs,
                    node_mappings: evidence
                        .node_mappings
                        .into_iter()
                        .map(|mapping| report::SemanticNodeMapping {
                            corresponding_member: mapping.corresponding_member,
                            canonical: mapping.canonical,
                            corresponding: mapping.corresponding,
                        })
                        .collect(),
                }),
            suppressed: recorded_suppression(occurrence.suppress_reason, occurrence.suppression),
        },
        scan_run: occurrence.scan_run_id,
        source_artifact_mappings,
        clone_group_savings,
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        DetailFormat::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

/// A stored ranking as the detail view shows it.
///
/// A count that will not fit is reported at the ceiling rather than wrapping:
/// a group with more occurrences than a `u64` can hold is past anything the
/// derivation would say about it anyway.
pub(crate) fn recorded_priority(
    stored: &codehelion_store::query::StoredPriority,
) -> report::RecordedPriority {
    let count = |value: i64| u64::try_from(value).unwrap_or(u64::MAX);
    report::RecordedPriority {
        value: stored.final_priority,
        clone_confidence: stored.clone_confidence,
        maintenance_risk: stored.maintenance_risk,
        refactoring_difficulty: stored.refactoring_difficulty,
        semantic_confidence: stored.semantic_confidence,
        source_artifact_confidence: stored.source_artifact_confidence,
        savings_confidence: stored.savings_confidence,
        inputs: report::RecordedInputs {
            smallest_member_tokens: count(stored.facts.smallest_member_tokens),
            largest_member_tokens: count(stored.facts.largest_member_tokens),
            instances: count(stored.facts.instances),
            files: count(stored.facts.files),
            directories: count(stored.facts.directories),
            languages: count(stored.facts.languages),
            min_clone_tokens: stored.facts.min_clone_tokens.map(count),
        },
    }
}
