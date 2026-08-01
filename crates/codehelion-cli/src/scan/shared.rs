//! Mode-independent assembly for source-scan reports and snapshots.
//!
//! Fast and Structural produce different evidence, but the public and durable
//! envelopes must evolve together. Constructors here own the common shape;
//! each mode fills only the evidence it actually measured.

use std::collections::BTreeSet;

use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::stable_id::CloneGroupFingerprint;
use codehelion_store::snapshot::{
    FileCountsRow, GroupRow, GuardrailsRow, MemberRow, PriorityRow, SummaryRow, UnparsedRow,
};

use crate::report::{self, Report};
use crate::suppress;

/// Inputs whose storage shape is identical for every source-analysis mode.
pub(super) struct SummaryInputs {
    pub analyzed_files: FileCountsRow,
    pub lines: u64,
    pub tokens: u64,
    pub lexer_diagnostics: u64,
    pub unparsed: Option<UnparsedRow>,
    pub excluded_generated: u64,
    pub excluded_by_glob: u64,
    pub excluded_too_large: u64,
    pub excluded_binary: u64,
    pub excluded_unreadable: u64,
    pub excluded_symlinks: u64,
    pub excluded_walk_errors: u64,
    pub excluded_timed_out: u64,
    pub guardrails: Option<GuardrailsRow>,
    pub excluded_skipped: u64,
    pub folded_runs: u64,
    pub subsumed_runs: u64,
    pub split_components: u64,
    pub pair_budget_exhausted: bool,
    pub baseline_digest: Option<String>,
    pub funnel: Vec<report::FunnelStage>,
    pub unused_suppressions: Vec<report::UnusedRule>,
}

/// Build the one persisted summary shape shared by every source mode.
pub(super) fn summary(inputs: SummaryInputs) -> SummaryRow {
    SummaryRow {
        analyzed_files: inputs.analyzed_files,
        lines: inputs.lines,
        tokens: inputs.tokens,
        lexer_diagnostics: inputs.lexer_diagnostics,
        unparsed: inputs.unparsed,
        excluded_generated: inputs.excluded_generated,
        excluded_by_glob: inputs.excluded_by_glob,
        excluded_too_large: inputs.excluded_too_large,
        excluded_binary: inputs.excluded_binary,
        excluded_unreadable: inputs.excluded_unreadable,
        excluded_symlinks: inputs.excluded_symlinks,
        excluded_walk_errors: inputs.excluded_walk_errors,
        excluded_timed_out: inputs.excluded_timed_out,
        guardrails: inputs.guardrails,
        excluded_skipped: inputs.excluded_skipped,
        folded_runs: inputs.folded_runs,
        subsumed_runs: inputs.subsumed_runs,
        split_components: inputs.split_components,
        pair_budget_exhausted: inputs.pair_budget_exhausted,
        baseline_digest: inputs.baseline_digest,
        funnel: report::stored_funnel(&inputs.funnel),
        unused_suppressions: report::stored_rules(&inputs.unused_suppressions),
    }
}

/// Assemble the common public report envelope after a mode has ranked groups.
pub(super) fn report(
    run: report::RunInfo,
    stored: &SummaryRow,
    groups: Vec<report::Group>,
    analysis_mode: &str,
) -> Report {
    Report {
        schema_version: report::SCHEMA_VERSION,
        run,
        summary: report::restored(stored, &groups, analysis_mode),
        groups,
    }
}

/// Fields every public group has before mode-specific evidence is attached.
pub(super) struct ReportGroupCore {
    pub fingerprint: String,
    pub clone_type: CloneClass,
    pub scope: CloneScope,
    pub statements: Option<u64>,
    pub confidence: f64,
    pub entropy_bits: f64,
    pub members: Vec<report::Member>,
}

/// Create a public group with neutral values for evidence the mode did not measure.
pub(super) fn report_group(core: ReportGroupCore) -> report::Group {
    report::Group {
        fingerprint: core.fingerprint,
        clone_type: core.clone_type.name().to_string(),
        scope: core.scope.name().to_string(),
        statements: core.statements,
        confidence: core.confidence,
        entropy_bits: core.entropy_bits,
        priority: report::Priority::unranked(),
        similarity: None,
        identifier_jaccard: None,
        body_materiality: None,
        boilerplate: None,
        test_code: false,
        test_code_evidence: None,
        width_family: false,
        suppressed: None,
        baseline: None,
        split_pair: false,
        semantic: None,
        artifact_savings: Vec::new(),
        members: core.members,
    }
}

/// Fields every persisted group has before mode-specific evidence is attached.
pub(super) struct StoredGroupCore {
    pub fingerprint: CloneGroupFingerprint,
    pub clone_type: CloneClass,
    pub scope: CloneScope,
    pub statements: Option<u32>,
    pub score: f64,
    pub entropy_bits: f64,
    pub suppressed_by: Option<usize>,
    pub priority: PriorityRow,
    pub members: Vec<MemberRow>,
}

/// Create a persisted group with neutral values for unavailable evidence.
pub(super) fn stored_group(core: StoredGroupCore) -> GroupRow {
    GroupRow {
        fingerprint: core.fingerprint,
        clone_type: core.clone_type,
        member_scope: core.scope,
        test_code: false,
        test_code_evidence: None,
        split_pair: false,
        score: core.score,
        entropy_bits: core.entropy_bits,
        suppress_reason: None,
        boilerplate: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        width_family: false,
        statements: core.statements,
        suppressed_by: core.suppressed_by,
        priority: core.priority,
        similarity: None,
        semantic: None,
        members: core.members,
    }
}

/// Short-circuiting suppression selection in explicit most-specific-first order.
pub(super) struct SuppressionPriority(Option<usize>);

impl SuppressionPriority {
    pub(super) fn first(candidate: impl FnOnce() -> Option<usize>) -> Self {
        Self(candidate())
    }

    pub(super) fn or_else(mut self, candidate: impl FnOnce() -> Option<usize>) -> Self {
        if self.0.is_none() {
            self.0 = candidate();
        }
        self
    }

    pub(super) const fn finish(self) -> Option<usize> {
        self.0
    }
}

/// Render a matched configured rule with the same vocabulary in every mode.
pub(super) fn rule_suppression(rules: &suppress::Rules, rule: usize) -> report::Suppression {
    let row = &rules.rows[rule];
    report::Suppression {
        kind: report::SuppressionKind::Rule,
        reason: row.reason.clone(),
        scope: Some(row.scope.clone()),
        pattern: Some(row.pattern.clone()),
        active: Some(true),
    }
}

/// Resolve the unused-rule report from every selector and winning verdict.
pub(super) fn unused_suppressions(
    rules: &suppress::Rules,
    used: impl IntoIterator<Item = usize>,
) -> Vec<report::UnusedRule> {
    let used: BTreeSet<usize> = used.into_iter().collect();
    rules
        .unused(&used)
        .into_iter()
        .map(|row| report::UnusedRule {
            scope: row.scope.clone(),
            pattern: row.pattern.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use codehelion_core::clone_class::{CloneClass, CloneScope};
    use codehelion_core::stable_id::CloneGroupFingerprint;
    use codehelion_store::snapshot::PriorityRow;

    use super::{
        ReportGroupCore, StoredGroupCore, SuppressionPriority, report_group, stored_group,
    };

    #[test]
    fn suppression_priority_stops_after_the_first_match() {
        let later_calls = Cell::new(0);
        let selected = SuppressionPriority::first(|| None)
            .or_else(|| Some(7))
            .or_else(|| {
                later_calls.set(later_calls.get() + 1);
                Some(11)
            })
            .finish();

        assert_eq!(selected, Some(7));
        assert_eq!(later_calls.get(), 0);
    }

    #[test]
    fn common_group_shapes_leave_mode_specific_evidence_unknown() {
        let public = report_group(ReportGroupCore {
            fingerprint: "01".repeat(16),
            clone_type: CloneClass::Type1,
            scope: CloneScope::Unit,
            statements: None,
            confidence: 1.0,
            entropy_bits: 2.0,
            members: Vec::new(),
        });
        assert_eq!(public.clone_type, "type-1");
        assert_eq!(public.scope, "unit");
        assert!(public.similarity.is_none());
        assert!(public.body_materiality.is_none());
        assert!(public.semantic.is_none());
        assert!(public.artifact_savings.is_empty());

        let stored = stored_group(StoredGroupCore {
            fingerprint: CloneGroupFingerprint::from_bytes([1; 16]),
            clone_type: CloneClass::Type1,
            scope: CloneScope::Unit,
            statements: None,
            score: 1.0,
            entropy_bits: 2.0,
            suppressed_by: None,
            priority: PriorityRow {
                clone_confidence: 1.0,
                maintenance_risk: 0.0,
                refactoring_difficulty: 0.0,
                final_priority: 1.0,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            members: Vec::new(),
        });
        assert_eq!(stored.member_scope, CloneScope::Unit);
        assert!(stored.similarity.is_none());
        assert!(stored.semantic.is_none());
        assert!(stored.identifier_jaccard.is_none());
    }

    #[test]
    fn fast_and_structural_cannot_redeclare_the_shared_envelopes() {
        for (pipeline, source) in [
            ("fast", include_str!("../scan.rs")),
            ("structural", include_str!("structural.rs")),
        ] {
            let lines = source.lines().map(str::trim_start).collect::<Vec<_>>();
            assert!(
                !lines.contains(&"report::Group {"),
                "{pipeline} redeclared the public group envelope"
            );
            assert!(
                !lines.contains(&"SummaryRow {"),
                "{pipeline} redeclared the summary storage envelope"
            );
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains("| GroupRow {") || line.contains("Ok(GroupRow {")),
                "{pipeline} redeclared the group storage envelope"
            );
        }
    }
}
