//! Mode-independent assembly for source-scan reports and snapshots.
//!
//! Fast and Structural produce different evidence, but the public and durable
//! envelopes must evolve together. Constructors here own the common shape;
//! each mode fills only the evidence it actually measured.

use std::collections::BTreeSet;

use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::engine::Instance;
use codehelion_core::stable_id::{self, CloneGroupFingerprint, MemberIds, OccurrenceDiscriminator};
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
    pub excluded_oversized_metadata: u64,
    pub excluded_binary: u64,
    pub excluded_unreadable: u64,
    pub excluded_symlinks: u64,
    pub excluded_walk_errors: u64,
    pub excluded_timed_out: u64,
    pub excluded_language: u64,
    pub excluded_symlink_files: u64,
    pub excluded_symlink_directories: u64,
    pub guardrails: Option<GuardrailsRow>,
    pub excluded_skipped: u64,
    pub folded_runs: u64,
    pub subsumed_runs: u64,
    pub split_components: u64,
    pub common_signatures_skipped: u64,
    pub largest_skipped_signature_units: u64,
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
        excluded_oversized_metadata: inputs.excluded_oversized_metadata,
        excluded_binary: inputs.excluded_binary,
        excluded_unreadable: inputs.excluded_unreadable,
        excluded_symlinks: inputs.excluded_symlinks,
        excluded_walk_errors: inputs.excluded_walk_errors,
        excluded_timed_out: inputs.excluded_timed_out,
        excluded_language: inputs.excluded_language,
        excluded_symlink_files: inputs.excluded_symlink_files,
        excluded_symlink_directories: inputs.excluded_symlink_directories,
        guardrails: inputs.guardrails,
        excluded_skipped: inputs.excluded_skipped,
        folded_runs: inputs.folded_runs,
        subsumed_runs: inputs.subsumed_runs,
        split_components: inputs.split_components,
        common_signatures_skipped: inputs.common_signatures_skipped,
        largest_skipped_signature_units: inputs.largest_skipped_signature_units,
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
        siblings: Vec::new(),
        near_misses: Vec::new(),
    }
}

/// One occurrence of a group's content, with the group's nomination resolved.
///
/// Only [`nominated_occurrences`] produces these, so every view of a group
/// reads its member order and its canonical mark off one decision instead of
/// arranging its own.
pub(super) struct Occurrence<'a> {
    /// Where the occurrence sits, as the detector anchored it.
    pub instance: &'a Instance,
    /// The occurrence's position-free identifiers.
    pub ids: &'a MemberIds,
    /// Whether the group keeps this copy rather than counting it duplicated.
    pub canonical: bool,
}

/// Put a group's occurrences in the one order every view of it lists them in:
/// the canonical member first.
///
/// The canonical member is the copy duplication accounting keeps rather than
/// counts as duplicated, so which occurrence carries the mark decides how a
/// group's duplicated bytes are attributed. Where every member shares one
/// content, nothing about the code separates them and the nomination falls to
/// the members' position-free identities. It must not fall to the order the
/// occurrences arrived in: that order follows the walk, and a file rename would
/// then move the reported byte count of code nobody edited.
///
/// The public report and the recorded snapshot are two views of one verdict, so
/// both take their member list from here; a second nomination on either side is
/// a second verdict, and the two would disagree as soon as they were derived
/// differently. Where similarity already picked a representative — a Structural
/// group's medoid — the occurrences arrive nominated and this is not used.
pub(super) fn nominated_occurrences<'a>(
    occurrences: impl IntoIterator<Item = (&'a Instance, &'a MemberIds)>,
) -> Vec<Occurrence<'a>> {
    let mut occurrences: Vec<Occurrence<'a>> = occurrences
        .into_iter()
        .map(|(instance, ids)| Occurrence {
            instance,
            ids,
            canonical: false,
        })
        .collect();
    let discriminators: Vec<OccurrenceDiscriminator> = occurrences
        .iter()
        .map(|occurrence| {
            OccurrenceDiscriminator::of_fragment(&occurrence.ids.content)
                .and(OccurrenceDiscriminator::of_finding(&occurrence.ids.finding))
        })
        .collect();
    if let Some(index) = stable_id::canonical_occurrence(&discriminators)
        && let Some(head) = occurrences.get_mut(..=index)
    {
        head.rotate_right(1);
    }
    if let Some(canonical) = occurrences.first_mut() {
        canonical.canonical = true;
    }
    occurrences
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
        // A scan cannot know this until the run is recorded and compared
        // with its predecessor, so it is filled in afterwards.
        identity: None,
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
        // Which findings sit inside which is a question about the run's
        // whole set, so it is settled once the set is complete rather than
        // guessed at while one member of it is being built.
        narrower_cut_of: None,
        ranked_down: false,
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
    pub ranked_down: bool,
    pub priority: PriorityRow,
    pub members: Vec<MemberRow>,
}

/// Create a persisted group with neutral values for unavailable evidence.
pub(super) fn stored_group(core: StoredGroupCore) -> GroupRow {
    GroupRow {
        fingerprint: core.fingerprint,
        history: codehelion_store::snapshot::GroupOrigin::unconnected(&core.fingerprint),
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
        ranked_down: core.ranked_down,
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
            matched: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use codehelion_core::clone_class::{CloneClass, CloneScope};
    use codehelion_core::engine::Instance;
    use codehelion_core::stable_id::{
        CloneGroupFingerprint, FindingId, FragmentFingerprint, MemberIds,
    };
    use codehelion_store::snapshot::PriorityRow;

    use super::{
        ReportGroupCore, StoredGroupCore, SuppressionPriority, nominated_occurrences, report_group,
        stored_group,
    };

    fn instance(file: usize) -> Instance {
        Instance {
            file,
            token_start: 0,
            token_end: 1,
            start_line: 1,
            end_line: 1,
            unit: None,
        }
    }

    /// Two occurrences of one content, told apart only by their finding ids.
    fn member_ids(finding: u8) -> MemberIds {
        MemberIds {
            content: FragmentFingerprint::from_bytes([7; 16]),
            finding: FindingId::from_bytes([finding; 16]),
        }
    }

    #[test]
    fn the_nomination_does_not_follow_the_order_occurrences_arrive_in() {
        let instances = [instance(0), instance(1)];
        let ids = [member_ids(1), member_ids(2)];

        let forward = nominated_occurrences(instances.iter().zip(&ids));
        let reversed = nominated_occurrences(instances.iter().rev().zip(ids.iter().rev()));

        // One of the two arrival orders leads with the occurrence the
        // identities do not nominate, so agreeing on a canonical at all means
        // the list was rearranged rather than taken as it came.
        assert_eq!(
            forward.first().map(|occurrence| occurrence.ids.finding),
            reversed.first().map(|occurrence| occurrence.ids.finding),
        );
        for nominated in [&forward, &reversed] {
            let marked: Vec<usize> = nominated
                .iter()
                .enumerate()
                .filter(|(_, occurrence)| occurrence.canonical)
                .map(|(position, _)| position)
                .collect();
            assert_eq!(marked, vec![0], "exactly the first occurrence is marked");
            let findings: std::collections::BTreeSet<FindingId> = nominated
                .iter()
                .map(|occurrence| occurrence.ids.finding)
                .collect();
            assert_eq!(findings.len(), 2, "no occurrence is lost or repeated");
        }
    }

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
            ranked_down: false,
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
