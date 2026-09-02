//! Restoring a report summary from what the store recorded, and the labels
//! that say why a finding is hidden.

use super::funnel::{FunnelDrop, FunnelStage, search_truncated, stored_identity_collapsed};
use crate::report::{
    ExcludedCounts, FileCounts, Group, GroupCounts, Guardrails, Summary, SuppressedCounts,
    UnparsedCounts,
};
use crate::suppress::{CLONE_ID_SCOPE, VENDORED_SCOPE, multi_match_clone_ids};
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_store::snapshot::{GuardrailsRow, SummaryRow, UnusedRuleRow};
use serde::Serialize;

impl Guardrails {
    /// Record the concrete resource ceilings an untrusted invocation used.
    ///
    /// `Limits::clamp_to_untrusted` first materialises the optional pairing
    /// limits. The profile is still supplied as a defensive fallback so this
    /// renderer cannot ever claim a zero or missing effective ceiling.
    ///
    /// `enforced` decides which ceilings this run states at all. A ceiling the
    /// selected mode never consults is left absent rather than filled in: a
    /// number printed beside the ones that fired reads as a bound the run
    /// worked under, and a reader who then lowered it would be adjusting a
    /// stage this mode does not run.
    /// Every ceiling stated, as a mode whose stages take all of them reports
    /// them. Only tests reach for this shorthand; a scan states the ceilings
    /// its own mode enforces and nothing else.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn untrusted(
        limits: &crate::config::Limits,
        profile: &codehelion_core::execution::Limits,
    ) -> Self {
        Self::untrusted_under(
            limits,
            profile,
            crate::scan::runtime::enforced_ceilings(crate::cli::Mode::Structural),
        )
    }

    /// The same ceilings, holding back the ones `enforced` says this run's
    /// stages never consult.
    #[must_use]
    pub(crate) fn untrusted_under(
        limits: &crate::config::Limits,
        profile: &codehelion_core::execution::Limits,
        enforced: crate::scan::runtime::EnforcedCeilings,
    ) -> Self {
        use crate::scan::runtime::Ceiling;
        let verification = enforced.holds(Ceiling::Verification);
        let grouping = enforced.holds(Ceiling::Grouping);
        let near_match = enforced.holds(Ceiling::NearMatch);
        let siblings = enforced.holds(Ceiling::Siblings);
        Self {
            profile: "untrusted".to_string(),
            max_file_bytes: limits.max_file_bytes,
            parse_timeout_ms: limits.parse_timeout_ms,
            helper_timeout_ms: limits.helper_timeout_ms,
            posting_cap: limits.posting_cap.unwrap_or(profile.posting_cap),
            pair_budget: limits.pair_budget.unwrap_or(profile.max_candidates),
            verification_budget: verification.then(|| {
                limits
                    .verification_budget
                    .unwrap_or(profile.verification_budget)
            }),
            max_alignment_cells: verification.then(|| {
                limits
                    .max_alignment_cells
                    .unwrap_or(profile.max_alignment_cells)
            }),
            near_miss_delta: near_match.then(|| {
                limits.near_miss_delta.unwrap_or_else(|| {
                    codehelion_core::near_match::NearMatchConfig::default().near_miss_delta
                })
            }),
            near_miss_cap: near_match.then(|| {
                limits.near_miss_cap.unwrap_or_else(|| {
                    codehelion_core::near_match::NearMatchConfig::default().near_miss_cap
                })
            }),
            sibling_candidate_budget: siblings.then(|| {
                limits.sibling_candidate_budget.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().candidate_budget
                })
            }),
            sibling_per_group_cap: siblings.then(|| {
                limits.sibling_per_group_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().per_group_cap
                })
            }),
            sibling_total_cap: siblings.then(|| {
                limits.sibling_total_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().total_cap
                })
            }),
            signature_sibling_candidate_budget: siblings.then(|| {
                limits
                    .signature_sibling_candidate_budget
                    .unwrap_or_else(|| {
                        codehelion_core::structural::SignatureSiblingConfig::default()
                            .candidate_budget
                    })
            }),
            signature_sibling_per_group_cap: siblings.then(|| {
                limits.signature_sibling_per_group_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SignatureSiblingConfig::default().per_group_cap
                })
            }),
            signature_sibling_total_cap: siblings.then(|| {
                limits.signature_sibling_total_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SignatureSiblingConfig::default().total_cap
                })
            }),
            signature_sibling_max_units_per_signature: siblings.then(|| {
                limits
                    .signature_sibling_max_units_per_signature
                    .unwrap_or_else(|| {
                        codehelion_core::structural::SignatureSiblingConfig::default()
                            .max_units_per_signature
                    })
            }),
            max_component: grouping.then_some(limits.max_component),
        }
    }
}

impl From<&GuardrailsRow> for Guardrails {
    fn from(row: &GuardrailsRow) -> Self {
        let count =
            |value: Option<u64>| value.map(|value| usize::try_from(value).unwrap_or(usize::MAX));
        Self {
            profile: row.profile.clone(),
            max_file_bytes: row.max_file_bytes,
            parse_timeout_ms: row.parse_timeout_ms,
            helper_timeout_ms: row.helper_timeout_ms,
            posting_cap: usize::try_from(row.posting_cap).unwrap_or(usize::MAX),
            pair_budget: usize::try_from(row.pair_budget).unwrap_or(usize::MAX),
            verification_budget: count(row.verification_budget),
            max_alignment_cells: count(row.max_alignment_cells),
            near_miss_delta: row.near_miss_delta_bits.map(f64::from_bits),
            near_miss_cap: count(row.near_miss_cap),
            sibling_candidate_budget: count(row.sibling_candidate_budget),
            sibling_per_group_cap: count(row.sibling_per_group_cap),
            sibling_total_cap: count(row.sibling_total_cap),
            signature_sibling_candidate_budget: count(row.signature_sibling_candidate_budget),
            signature_sibling_per_group_cap: count(row.signature_sibling_per_group_cap),
            signature_sibling_total_cap: count(row.signature_sibling_total_cap),
            signature_sibling_max_units_per_signature: count(
                row.signature_sibling_max_units_per_signature,
            ),
            max_component: count(row.max_component),
        }
    }
}

/// The rules that hid nothing, in the shape the audit database stores them.
///
/// A rule that covered several groups is left out: it hid something, and the
/// report derives that notice from the groups themselves on every path.
#[must_use]
pub fn stored_rules(rules: &[UnusedRule]) -> Vec<UnusedRuleRow> {
    rules
        .iter()
        .filter(|rule| rule.matched == 0)
        .map(|rule| UnusedRuleRow {
            scope: rule.scope.clone(),
            pattern: rule.pattern.clone(),
        })
        .collect()
}

/// The configured clone ids this report shows covering more than one group.
///
/// Read off the groups rather than counted beside the rules, because a clone
/// id outranks every other suppression rule in every mode: a group its prefix
/// covers is hidden by it and cites it, so the report itself holds the count.
/// That also makes a replayed run say what the scan said, since the groups a
/// run recorded carry the rule each of them was hidden by.
fn clone_ids_covering_several_groups(groups: &[Group]) -> Vec<UnusedRule> {
    let cited = groups.iter().filter_map(|group| {
        let suppression = group.suppressed.as_ref()?;
        if suppression.scope.as_deref() != Some(CLONE_ID_SCOPE) {
            return None;
        }
        suppression.pattern.as_deref()
    });
    multi_match_clone_ids(cited)
        .into_iter()
        .map(|(pattern, matched)| UnusedRule {
            scope: CLONE_ID_SCOPE.to_string(),
            pattern,
            matched,
        })
        .collect()
}

/// The summary a stored row and the groups it belongs to describe together.
///
/// Everything a group carries is counted off `groups` and everything else is
/// read from `stored`; nothing is held in both places. What a run measured
/// about its comparisons — the tree changes, the audit states, what a baseline
/// hid — is left absent here, because those are statements about *this*
/// invocation rather than about the recorded run.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "restoration keeps every persisted summary field visible beside its source"
)]
pub fn restored(stored: &SummaryRow, groups: &[Group], analysis_mode: &str) -> Summary {
    let count = |predicate: &dyn Fn(&Group) -> bool| {
        u64::try_from(groups.iter().filter(|group| predicate(group)).count()).unwrap_or(u64::MAX)
    };
    let suppressed_as = |kind: SuppressionKind| {
        count(&|group| {
            group
                .suppressed
                .as_ref()
                .is_some_and(|suppression| suppression.kind == kind)
        })
    };
    let funnel: Vec<FunnelStage> = stored
        .funnel
        .iter()
        .map(|stage| FunnelStage {
            stage: stage.name.clone(),
            passed: stage.passed,
            dropped: stage
                .dropped
                .iter()
                .map(|drop| FunnelDrop {
                    cause: drop.cause.clone(),
                    count: drop.count,
                })
                .collect(),
        })
        .collect();
    let search_truncated = search_truncated(&funnel);
    Summary {
        top_churn: None,
        files: FileCounts {
            total: stored.analyzed_files.total,
            rust: stored.analyzed_files.rust,
            c: stored.analyzed_files.c,
            cpp: stored.analyzed_files.cpp,
        },
        lines: stored.lines,
        tokens: stored.tokens,
        lexer_diagnostics: stored.lexer_diagnostics,
        unparsed: stored
            .unparsed
            .map(|row| UnparsedCounts::from_counts(row.files, row.tokens, stored.tokens)),
        excluded: ExcludedCounts {
            generated: stored.excluded_generated,
            by_glob: stored.excluded_by_glob,
            skipped: stored.excluded_skipped,
            too_large: stored.excluded_too_large,
            oversized_metadata: stored.excluded_oversized_metadata,
            binary: stored.excluded_binary,
            unreadable: stored.excluded_unreadable,
            symlinks: stored.excluded_symlinks,
            walk_errors: stored.excluded_walk_errors,
            timed_out: stored.excluded_timed_out,
            language_excluded: stored.excluded_language,
            symlink_files: stored.excluded_symlink_files,
            symlink_directories: stored.excluded_symlink_directories,
        },
        baseline: None,
        changes: None,
        guardrails: stored.guardrails.as_ref().map(Guardrails::from),
        // Nor this: what a compiler answered belongs to the run that asked
        // it, and this report is a recorded run read back.
        compiler: None,
        groups: GroupCounts {
            total: u64::try_from(groups.len()).unwrap_or(u64::MAX),
            type_1: count(&|group| group.clone_type == CloneClass::Type1.name()),
            type_2: count(&|group| group.clone_type == CloneClass::Type2.name()),
            type_3: count(&|group| group.clone_type == CloneClass::Type3.name()),
            restricted_semantic: count(&|group| {
                group.clone_type == CloneClass::RestrictedSemantic.name()
            }),
            fragment_scope: count(&|group| group.scope == CloneScope::Fragment.name()),
            folded_runs: stored.folded_runs,
            subsumed_runs: stored.subsumed_runs,
            test_code: count(&|group| group.test_code),
        },
        suppressed: SuppressedCounts {
            noise: suppressed_as(SuppressionKind::Noise),
            by_rule: suppressed_as(SuppressionKind::Rule),
            vendored: count(&|group| {
                group
                    .suppressed
                    .as_ref()
                    .and_then(|cause| cause.scope.as_deref())
                    == Some(VENDORED_SCOPE)
            }),
        },
        // Supplemental rows are assembled outside the persisted summary row;
        // the report envelope fills these from the final vectors after mode
        // specific assembly (and replay does the same after hydration).
        siblings: 0,
        near_misses: 0,
        unmeasured_in_this_mode: unmeasured_in_this_mode(analysis_mode),
        unused_suppressions: stored
            .unused_suppressions
            .iter()
            .map(|rule| UnusedRule {
                scope: rule.scope.clone(),
                pattern: rule.pattern.clone(),
                matched: 0,
            })
            .chain(clone_ids_covering_several_groups(groups))
            .collect(),
        unapplied_suppression_policies: unapplied_suppression_policies(analysis_mode),
        funnel,
        split_components: stored.split_components,
        common_signatures_skipped: stored.common_signatures_skipped,
        largest_skipped_signature_units: stored.largest_skipped_signature_units,
        pair_budget_exhausted: stored.pair_budget_exhausted,
        search_truncated,
        identity_collapsed: stored_identity_collapsed(&stored.funnel),
    }
}

/// Configured suppression policies that a given analysis mode cannot apply.
///
/// This is derived from the mode rather than stored in the summary row: the
/// limitation is a property of the frontend, and a replay must present the
/// same limitation as the original report.
#[must_use]
pub fn unapplied_suppression_policies(analysis_mode: &str) -> Vec<String> {
    if analysis_mode == "fast" {
        [
            "suppression.boilerplate",
            "suppression.test-code",
            "suppression.width-family",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    }
}

/// Measurements unavailable in one analysis mode.
///
/// This is derived from the mode rather than stored in the summary row so a
/// replay carries the same contract as the source run. Fast intentionally
/// leaves all four Structural supplemental measures out.
#[must_use]
pub fn unmeasured_in_this_mode(analysis_mode: &str) -> Vec<String> {
    if analysis_mode == "fast" {
        [
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    }
}

/// One configured suppression rule a report has to name.
///
/// Either the rule matched nothing, or — for a clone id, whose whole purpose
/// is to name one duplication — its prefix currently covers several groups.
/// Both are a rule doing something other than what it says.
#[derive(Debug, Serialize)]
pub struct UnusedRule {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`).
    pub scope: String,
    /// The pattern as configured.
    pub pattern: String,
    /// How many groups the rule covers: `0` for a rule that hid nothing, and
    /// the number of groups for a clone id whose prefix covers more than one.
    pub matched: u64,
}

impl UnusedRule {
    /// One-line rendering for the text views, matching how a rule that *did*
    /// match is named.
    #[must_use]
    pub fn label(&self) -> String {
        match self.scope.as_str() {
            "path_glob" => format!("path glob {:?}", self.pattern),
            "symbol_pattern" => format!("symbol glob {:?}", self.pattern),
            CLONE_ID_SCOPE => format!("clone id {}", self.pattern),
            scope => format!("{scope} {:?}", self.pattern),
        }
    }
}

/// How the run composed its ranking.
///
/// A run-level setting rather than a per-group one, and reported because two
/// reports ordered under different weights are different orderings of the same
/// findings, which nothing else in the document would say.
#[derive(Debug, Clone, Serialize)]
pub struct RankingInfo {
    /// Version of the ranking rules together with the weights applied.
    pub recipe: String,
    /// Weight given to what keeping the copies in step costs.
    pub maintenance_risk: u32,
    /// Weight given to how cheap the duplication would be to remove.
    pub refactoring_ease: u32,
}

/// Which mechanism suppressed a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    /// The engine marked the group as noise.
    Noise,
    /// A configured or inline suppression rule matched every member.
    Rule,
}

/// Why a group is hidden from default reports.
#[derive(Debug, Clone, Serialize)]
pub struct Suppression {
    /// The suppressing mechanism.
    pub kind: SuppressionKind,
    /// Engine noise category or suppression-rule judgement, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression-rule scope, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Suppression-rule pattern, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Whether the stored rule was active, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{UnusedRule, restored};
    use crate::report::ranking::fixtures::hidden_by_clone_id;
    use crate::report::{TextOptions, tests::sample_report};
    use crate::suppress::CLONE_ID_SCOPE;
    use codehelion_store::snapshot::SummaryRow;

    #[test]
    fn a_clone_id_hiding_more_than_the_group_it_names_is_reported_with_the_count() {
        // Two groups whose ids share the configured prefix: the id was written
        // about one duplication and now hides a second nobody judged.
        let groups = vec![
            hidden_by_clone_id(&format!("0123abcd{}", "11".repeat(12)), "0123abcd"),
            hidden_by_clone_id(&format!("0123abcd{}", "22".repeat(12)), "0123abcd"),
        ];

        let summary = restored(&SummaryRow::default(), &groups, "fast");
        let covering: Vec<&UnusedRule> = summary
            .unused_suppressions
            .iter()
            .filter(|rule| rule.matched > 1)
            .collect();
        assert_eq!(covering.len(), 1);
        assert_eq!(covering[0].scope, CLONE_ID_SCOPE);
        assert_eq!(covering[0].pattern, "0123abcd");
        assert_eq!(covering[0].matched, 2);

        // The machine surface carries the count beside the rule.
        let value = serde_json::to_value(&summary).unwrap();
        assert_eq!(value["unused_suppressions"][0]["matched"], 2);

        // And so does the text one, where a reader meets it.
        let mut report = sample_report();
        report.summary.unused_suppressions = summary.unused_suppressions;
        let mut buffer = Vec::new();
        report
            .render_notes(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.contains(
                "note: 1 suppression rule(s) hide more than the one group they name: \
                 clone id 0123abcd (2 groups)"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_clone_id_that_still_names_one_group_is_left_alone() {
        let groups = vec![
            hidden_by_clone_id(&format!("0123abcd{}", "11".repeat(12)), "0123abcd"),
            hidden_by_clone_id(&format!("9999beef{}", "22".repeat(12)), "9999beef"),
        ];

        let summary = restored(&SummaryRow::default(), &groups, "fast");
        assert!(summary.unused_suppressions.is_empty());
    }
}
