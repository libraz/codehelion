//! Rebuilding one report model from what the store recorded.

use super::{Context, Result, RunOrigin, Store, report, scan};

pub(super) fn recorded_build_variant_settings(
    settings: &[codehelion_store::query::StoredSetting],
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> {
    let mut grouped = std::collections::BTreeMap::new();
    for setting in settings {
        grouped
            .entry(setting.language.clone())
            .or_insert_with(std::collections::BTreeMap::new)
            .entry(setting.name.clone())
            .or_insert_with(Vec::new)
            .push((setting.position, setting.value.clone()));
    }
    grouped
        .into_iter()
        .map(|(language, names)| {
            let names = names
                .into_iter()
                .map(|(name, mut values)| {
                    values.sort_unstable_by_key(|(position, _)| *position);
                    (name, values.into_iter().map(|(_, value)| value).collect())
                })
                .collect();
            (language, names)
        })
        .collect()
}

/// Restore supplemental sibling evidence from the dedicated `SQLite` table.
/// It remains outside the ranked group list, exactly as a fresh scan presents
/// it, so re-rendering cannot promote a sibling into primary membership.
pub(super) fn recorded_siblings(
    groups: &[codehelion_store::query::StoredGroup],
) -> Vec<report::GroupSiblings> {
    groups
        .iter()
        .filter(|group| !group.siblings.is_empty())
        .map(|group| report::GroupSiblings {
            group_fingerprint: group.fingerprint_hex.clone(),
            siblings: group.siblings.iter().map(recorded_sibling).collect(),
        })
        .collect()
}

pub(super) fn recorded_sibling(
    sibling: &codehelion_store::query::StoredSibling,
) -> report::Sibling {
    report::Sibling {
        clone_type: sibling.clone_type.clone(),
        confidence_band: sibling.confidence_band.clone(),
        basis: sibling.basis.clone(),
        signature: sibling.signature.clone(),
        signature_units: sibling
            .signature_units
            .and_then(|units| u64::try_from(units).ok()),
        similarity: report::SiblingSimilarity {
            weight_version: sibling.weight_version.clone(),
            lexical: sibling.lexical,
            structural: sibling.structural,
            control_flow: sibling.control_flow,
            type_similarity: sibling.type_similarity,
            api: sibling.api,
            composite: sibling.composite,
        },
        member: report::Member {
            finding_id: sibling.member.finding_hex.clone(),
            content: sibling.member.content_hex.clone(),
            file: scan::display_path(&sibling.member.file_path),
            language: sibling.member.language.clone(),
            start_line: u32::try_from(sibling.member.start_line.unwrap_or(0)).unwrap_or(0),
            end_line: u32::try_from(sibling.member.end_line.unwrap_or(0)).unwrap_or(0),
            unit: sibling.member.unit_name.clone(),
            boilerplate: sibling.member.boilerplate.clone(),
            tokens: u64::try_from(sibling.member.token_count).unwrap_or(0),
            canonical: false,
        },
        suppressed: recorded_suppression(None, sibling.suppressed_by.clone()),
    }
}

/// Restore run-scoped near-match diagnostics without reinterpreting them as
/// findings or attaching them to a primary clone group.
pub(super) fn recorded_near_misses(
    near_misses: &[codehelion_store::query::StoredNearMiss],
) -> Vec<report::NearMiss> {
    near_misses
        .iter()
        .map(|near_miss| report::NearMiss {
            estimated_jaccard: near_miss.estimated_jaccard,
            left: recorded_near_miss_unit(&near_miss.left),
            right: recorded_near_miss_unit(&near_miss.right),
            suppressed: recorded_suppression(None, near_miss.suppressed_by.clone()),
        })
        .collect()
}

/// Convert one stored source-unit anchor to the public near-miss shape.
fn recorded_near_miss_unit(
    unit: &codehelion_store::query::StoredNearMissUnit,
) -> report::NearMissUnit {
    report::NearMissUnit {
        unit_fingerprint: unit.fingerprint_hex.clone(),
        language: unit.language.clone(),
        file: scan::display_path(&unit.file_path),
        start_line: u32::try_from(unit.start_line.unwrap_or(0)).unwrap_or(0),
        end_line: u32::try_from(unit.end_line.unwrap_or(0)).unwrap_or(0),
        unit: unit.unit_name.clone(),
        tokens: u64::try_from(unit.token_count).unwrap_or(0),
    }
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

/// What the newest recorded seam run says, beside the generation before it.
///
/// One reader for a fresh scan and for a replay: the counts are read back
/// rather than recomputed, and two derivations of one comparison would disagree
/// the moment either of them changed. `root_path` is the key runs are recorded
/// under, which [`scan::path_key`] produces from a canonical root.
///
/// A delta is reported only where the previous run under the same settings
/// carried the same seam. A seam written into the ledger since then has no
/// earlier generation, and subtracting against nothing would report the
/// ledger's growth as movement in the code.
///
/// # Errors
///
/// Returns any underlying database error.
pub(crate) fn recorded_seam(store: &Store, root_path: &str) -> Result<Option<report::SeamReport>> {
    let Some(latest) = store.latest_seam_run(root_path)? else {
        return Ok(None);
    };
    let previous = store.preceding_seam_run(root_path, latest.id, &latest.run.settings_digest)?;
    let count = |value: i64| u64::try_from(value).unwrap_or(0);
    let seams = latest
        .run
        .entries
        .iter()
        .map(|entry| {
            let earlier = previous.as_ref().and_then(|previous| {
                previous
                    .run
                    .entries
                    .iter()
                    .find(|candidate| candidate.seam_id == entry.seam_id)
            });
            report::ReportedSeam {
                id: entry.seam_id.clone(),
                note: entry.note.clone(),
                asymmetric_changes: count(entry.asymmetric_changes),
                breaches: count(entry.breaches),
                last_breach: entry.last_breach.clone(),
                findings: count(entry.findings),
                asymmetric_changes_since: earlier.map(|earlier| {
                    entry
                        .asymmetric_changes
                        .saturating_sub(earlier.asymmetric_changes)
                }),
                breaches_since: earlier
                    .map(|earlier| entry.breaches.saturating_sub(earlier.breaches)),
                findings_since: earlier
                    .map(|earlier| entry.findings.saturating_sub(earlier.findings)),
            }
        })
        .collect();
    Ok(Some(report::SeamReport {
        seam_run_id: latest.id,
        settings_digest: latest.run.settings_digest.clone(),
        first_commit: latest.run.first_commit.clone(),
        last_commit: latest.run.last_commit.clone(),
        commits: count(latest.run.commit_count),
        since_seam_run_id: previous.as_ref().map(|previous| previous.id),
        seams,
    }))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::items_after_test_module,
    reason = "the command's private reconstruction helpers remain adjacent to their public callers"
)]
mod tests {
    use super::*;

    #[test]
    fn stored_variant_settings_restore_the_language_and_sequence_order() {
        let stored = vec![
            codehelion_store::query::StoredSetting {
                language: "cpp".to_string(),
                name: "includes".to_string(),
                position: 1,
                value: "generated".to_string(),
            },
            codehelion_store::query::StoredSetting {
                language: "cpp".to_string(),
                name: "includes".to_string(),
                position: 0,
                value: "include".to_string(),
            },
            codehelion_store::query::StoredSetting {
                language: "cpp".to_string(),
                name: "compiler".to_string(),
                position: 0,
                value: "clang++".to_string(),
            },
        ];

        assert_eq!(
            recorded_build_variant_settings(&stored),
            std::collections::BTreeMap::from([(
                String::from("cpp"),
                std::collections::BTreeMap::from([
                    (String::from("compiler"), vec![String::from("clang++")]),
                    (
                        String::from("includes"),
                        vec![String::from("include"), String::from("generated")],
                    ),
                ]),
            )])
        );
    }

    #[test]
    fn recorded_near_misses_reconstruct_as_run_scoped_diagnostics() {
        let stored = codehelion_store::query::StoredNearMiss {
            estimated_jaccard: 0.28,
            left: codehelion_store::query::StoredNearMissUnit {
                fingerprint_hex: "a1".repeat(16),
                language: "rust".to_string(),
                file_path: "src/left.rs".to_string(),
                start_line: Some(10),
                end_line: Some(24),
                token_count: 48,
                unit_name: Some("left_candidate".to_string()),
            },
            right: codehelion_store::query::StoredNearMissUnit {
                fingerprint_hex: "b2".repeat(16),
                language: "rust".to_string(),
                file_path: "src/right.rs".to_string(),
                start_line: Some(31),
                end_line: Some(46),
                token_count: 51,
                unit_name: Some("right_candidate".to_string()),
            },
            suppressed_by: Some(codehelion_store::query::StoredSuppressionRef {
                scope: "path_glob".to_string(),
                pattern: "vendor/**".to_string(),
                reason: Some("vendored sources".to_string()),
                active: Some(true),
            }),
        };

        let restored = recorded_near_misses(&[stored]);
        assert_eq!(restored.len(), 1);
        assert!((restored[0].estimated_jaccard - 0.28).abs() < f64::EPSILON);
        assert_eq!(restored[0].left.file, "src/left.rs");
        assert_eq!(restored[0].right.file, "src/right.rs");
        assert_eq!(restored[0].left.unit.as_deref(), Some("left_candidate"));
        let suppression = restored[0]
            .suppressed
            .as_ref()
            .expect("stored suppression is replayed");
        assert_eq!(suppression.pattern.as_deref(), Some("vendor/**"));
    }
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
    // Read off the reason a file went unasked about, which is where a refused
    // execution is counted: the run reports the refusal with the permission
    // that lifts it, and a replay that could not find the count would drop the
    // one line saying what to do about it.
    let build_script_refused = coverage
        .not_asked_reasons
        .get(codehelion_helper::ir::Unavailability::RequiresExecution.name())
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
        not_asked_reasons: coverage.not_asked_reasons,
        unavailable: coverage.unavailable,
        diagnostics: coverage.diagnostics,
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
        identity: None,
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
        // Settled from the run's whole set of findings once it is loaded, the
        // same way a scan settles it once its own set is complete. Deriving it
        // rather than storing it is what keeps a replay from disagreeing with
        // the scan it replays.
        narrower_cut_of: None,
        ranked_down: false,
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
                file: scan::display_path(&member.file_path),
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
