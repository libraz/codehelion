//! Resolving a typed identifier to one recorded finding and writing its
//! detail document.

use super::recorded::{recorded_group, recorded_priority, recorded_sibling, recorded_suppression};
use super::{
    Context, DetailFormat, ExplainArgs, FULL_ID_CHARS, IdKind, IdMatch, Outcome, Path, Result,
    RunOrigin, Store, Write, bail, fingerprint_hex, report, resolve_db_at, scan, suppress,
};

/// Look up one recorded id and print what it identifies.
///
/// An id names an occurrence, an ordinary clone group, or a group from an
/// explicit cross-language or cross-build-variant comparison. The kind is
/// decided by looking the id up rather than by its shape, and an
/// abbreviation is accepted wherever it names exactly one of them — the
/// report prints group ids in full, and retyping thirty-two hex digits to ask
/// about what is on the screen is a break in the trail the ids exist to keep.
pub(crate) fn explain(args: &ExplainArgs, out: &mut impl Write) -> Result<Outcome> {
    let path = resolve_db_at(
        scan::DatabaseUse::Reading,
        &args.path,
        args.db.as_deref(),
        args.config.as_deref(),
        args.untrusted,
    )?;
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = scan::open_recorded_store(&path)?;
    let found = resolve_id(&store, &args.finding_id, &path)?;
    match found.kind {
        IdKind::Occurrence => explain_occurrence(&store, &found.id, args, out),
        IdKind::CloneGroup => explain_clone_group(&store, &found.id, &path, args, out),
        IdKind::Sibling => explain_sibling(&store, &found.id, args, out),
        IdKind::CrossLanguageGroup => explain_cross_language_group(&store, &found.id, args, out),
        IdKind::CrossVariantGroup => explain_cross_variant_group(&store, &found.id, args, out),
    }
}

/// Write one standalone detail in the format `explain` was asked for.
///
/// Each detail states different facts and renders them its own way, but which
/// of the two formats a reader gets — and that either one is a success — is one
/// decision, so it is made once for every detail whose text view takes no
/// further options.
fn write_detail(
    args: &ExplainArgs,
    out: &mut impl Write,
    json: impl FnOnce() -> serde_json::Result<String>,
    text: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> Result<Outcome> {
    match args.format {
        DetailFormat::Json => write!(out, "{}", json()?)?,
        DetailFormat::Text => text(out)?,
    }
    Ok(Outcome::Success)
}

/// Print one supplemental sibling finding without promoting it to membership.
pub(crate) fn explain_sibling(
    store: &Store,
    finding_id: &str,
    args: &ExplainArgs,
    out: &mut impl Write,
) -> Result<Outcome> {
    let found = store
        .sibling(finding_id)?
        .with_context(|| format!("sibling finding {finding_id} went missing"))?;
    let detail = report::SiblingDetail {
        scan_run: found.run_id,
        group_fingerprint: found.group_fingerprint_hex,
        sibling: recorded_sibling(&found.sibling),
    };
    write_detail(
        args,
        out,
        || detail.to_json(),
        |mut out| detail.render_text(&mut out),
    )
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
            "no finding or clone/comparison group with id {typed} in {}",
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

/// Print one group from an explicit cross-build-variant comparison.
pub(crate) fn explain_cross_variant_group(
    store: &Store,
    group_id: &str,
    args: &ExplainArgs,
    out: &mut impl Write,
) -> Result<Outcome> {
    let group = store
        .cross_variant_group(group_id)?
        .with_context(|| format!("cross-build-variant comparison group {group_id} went missing"))?;
    let detail = report::CrossVariantGroupDetail {
        group_id: group.group_id_hex,
        comparison_id: group.comparison_id_hex,
        policy_version: group.policy_version,
        root_path: scan::display_path(&group.root_path),
        origin_variants: group.origin_variants,
        clone_type: group.clone_type,
        members: group
            .members
            .into_iter()
            .map(|member| report::CrossVariantGroupMemberDetail {
                origin_variant: member.origin_variant,
                language: member.language,
                file: scan::display_path(&member.file_path),
                start_line: member.start_line,
                end_line: member.end_line,
                unit: member.unit_name,
                token_count: member.token_count,
            })
            .collect(),
    };
    write_detail(
        args,
        out,
        || detail.to_json(),
        |mut out| detail.render_text(&mut out),
    )
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
    let origin = store.run_origin(found.run_id)?;
    let (latest_scan_run, present_in_latest_run) =
        latest_comparable_run(store, &origin, &found.group.fingerprint_hex)?;
    let mut group = recorded_group(found.group, &priority)?;
    scan::hydrate_artifact_savings(store, found.run_id, std::slice::from_mut(&mut group))?;
    // Resolved rather than remembered: the run this one was compared with is
    // recoverable from what it agreed with that run on, so a lookup explains
    // the decision the same way the report that made it did.
    if let Some(predecessor) = store.preceding_compatible_run(found.run_id)? {
        scan::hydrate_group_identity(
            store,
            found.run_id,
            predecessor,
            std::slice::from_mut(&mut group),
        )?;
    }
    let detail = report::CloneGroupDetail {
        database: path.display().to_string(),
        scan_run: origin.id,
        analysis_mode: origin.analysis_mode,
        build_variant: origin.variant_fingerprint,
        latest_scan_run,
        present_in_latest_run,
        group,
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        // `explain` writes to standard output alone, so the terminal test
        // `auto` makes is the right one without an `--output` to consult.
        DetailFormat::Text => {
            detail.render_text(args.decoration.resolve(), args.color.enabled(true), out)?;
        }
    }
    Ok(Outcome::Success)
}

/// The newest run a group's own run can be compared with, and whether that run
/// still records the group.
///
/// Only runs over the same root, in the same analysis mode and under the same
/// build variant are comparable, so a group found under one set of conditions
/// is never reported as gone on the strength of a run made under another.
/// Both answers are `None` when the found run is the only comparable one:
/// there is then no later scan whose silence could mean anything.
fn latest_comparable_run(
    store: &Store,
    origin: &RunOrigin,
    fingerprint_hex: &str,
) -> Result<(Option<i64>, Option<bool>)> {
    let comparable = store.comparable_run_count(
        &origin.root_path,
        &origin.analysis_mode,
        &origin.variant_fingerprint,
    )?;
    if comparable < 2 {
        return Ok((None, None));
    }
    let Some(latest) = store.latest_run_for_variant(
        &origin.root_path,
        &origin.analysis_mode,
        &origin.variant_fingerprint,
    )?
    else {
        return Ok((None, None));
    };
    let present = store.run_holds_group(latest.id, fingerprint_hex)?;
    Ok((Some(latest.id), Some(present)))
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
        root_path: scan::display_path(&group.root_path),
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
                file: scan::display_path(&member.file_path),
                start_line: member.start_line,
                end_line: member.end_line,
                unit: member.unit_name,
                graph: member.graph,
            })
            .collect(),
    };
    write_detail(
        args,
        out,
        || detail.to_json(),
        |mut out| detail.render_text(&mut out),
    )
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
                mapping.source_build_variant_fingerprint.as_bytes(),
            ),
            artifact_build_variant_fingerprint: fingerprint_hex(
                mapping.build_variant_fingerprint.as_bytes(),
            ),
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
                    savings.source_build_variant_fingerprint.as_bytes(),
                ),
                artifact_build_variant_fingerprint: fingerprint_hex(
                    savings.artifact_build_variant_fingerprint.as_bytes(),
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
            file: scan::display_path(&occurrence.member.file_path),
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
