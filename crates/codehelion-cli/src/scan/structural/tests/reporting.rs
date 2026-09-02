//! What the report and its shared funnel say about a finished run.

use super::{detector_versions, report};
use codehelion_core::discovery::{
    AnalysisMode, BuildVariant, DiscoveryReport, Language, LanguageSelection, SkipReport,
};
use codehelion_helper::ir::{CompilerIr, Unavailability, UnitRef};
use std::path::PathBuf;

#[test]
fn shared_discovery_exclusions_belong_to_one_semantic_partition() {
    let discovery = DiscoveryReport {
        units: Vec::new(),
        build_variant: BuildVariant::structural(LanguageSelection::default(), Language::Cpp),
        header_language: Language::Cpp,
        packages: Vec::new(),
        suppressed_generated: vec![PathBuf::from("src/generated.cpp")],
        skipped: SkipReport {
            too_large: 2,
            binary: 3,
            unreadable: 5,
            language_excluded: 0,
            symlinks: 7,
            symlink_files: 0,
            symlink_directories: 0,
            symlink_unresolved: 0,
            oversized_metadata: 0,
            walk_errors: 11,
        },
        compile_commands: None,
        compile_commands_error: None,
    };

    let first = super::discovery_exclusions(Some(&discovery), 13);
    assert_eq!(first.generated, 1);
    assert_eq!(first.by_glob, 13);
    assert_eq!(first.skipped, 28);

    let later = super::discovery_exclusions(None, 13);
    assert_eq!(later, super::DiscoveryExclusions::default());
}

#[test]
fn semantic_detector_versions_are_sorted_and_deduplicate_answered_ir_schemas() {
    let first_unit = UnitRef {
        unit: "first".to_string(),
        file: "src/lib.rs".to_string(),
        variant: "debug".to_string(),
    };
    let second_unit = UnitRef {
        unit: "second".to_string(),
        file: "src/lib.rs".to_string(),
        variant: "debug".to_string(),
    };
    let mut first = CompilerIr::empty(first_unit.clone());
    first.schema_version = "compiler-ir-v2".to_string();
    let mut duplicate = CompilerIr::empty(second_unit.clone());
    duplicate.schema_version = "compiler-ir-v2".to_string();
    let mut other = CompilerIr::empty(second_unit);
    other.schema_version = "compiler-ir-v1".to_string();
    let answers = crate::semantic::Answers {
        helpers: Vec::new(),
        per_source: vec![
            crate::semantic::Answer::Analyzed {
                helper: 0,
                ir: Box::new(first),
            },
            crate::semantic::Answer::Unavailable {
                helper: None,
                unit: first_unit,
                reason: Unavailability::NoBuildInformation,
                diagnostics: Vec::new(),
            },
            crate::semantic::Answer::Analyzed {
                helper: 0,
                ir: Box::new(duplicate),
            },
            crate::semantic::Answer::Analyzed {
                helper: 0,
                ir: Box::new(other),
            },
        ],
    };

    let versions = detector_versions(
        codehelion_core::engine::LiteralNorm::Full,
        0.6,
        Some(&answers),
    );
    assert!(versions.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(
        versions
            .iter()
            .filter(|(component, _)| component == "compiler_ir")
            .collect::<Vec<_>>(),
        vec![
            &("compiler_ir".to_string(), "compiler-ir-v1".to_string()),
            &("compiler_ir".to_string(), "compiler-ir-v2".to_string()),
        ]
    );
    assert!(
        detector_versions(codehelion_core::engine::LiteralNorm::Full, 0.6, None)
            .iter()
            .all(|(component, _)| component != "compiler_ir")
    );
}

#[test]
fn semantic_candidate_cuts_are_visible_in_the_shared_funnel() {
    let detection = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats {
            graphs: 8,
            ineligible_graphs: 2,
            buckets: 3,
            oversized_buckets: 1,
            pairs_available: 9,
            pairs_budget_dropped: 4,
            pairs_emitted: 5,
        },
        registered_observations: 8,
        excluded_observations: 6,
        units_without_registered_operations: 2,
        units_no_registered_rule_claimed: 3,
        verified_pairs: 3,
        disabled_pairs: 1,
        grouping: codehelion_core::semantic::SemanticGroupingStats {
            verified_pairs: 2,
            duplicate_pairs: 0,
            invalid_pairs: 0,
            grouped_pairs: 2,
            ungrouped_pairs: 0,
            ceiling_severed_pairs: 0,
            groups: 1,
        },
    };
    let funnel = super::funnel(
        &codehelion_core::structural::StructuralStats::default(),
        &detection,
        0,
        0,
        AnalysisMode::Semantic,
    );
    let candidate = funnel
        .iter()
        .find(|stage| stage.stage == "semantic candidate pairs")
        .expect("semantic candidate stage");
    assert_eq!(candidate.passed, 5);
    assert!(
        candidate
            .dropped
            .iter()
            .any(|drop| drop.cause == "pair_budget" && drop.count == 4)
    );
    let buckets = funnel
        .iter()
        .find(|stage| stage.stage == "semantic candidate buckets")
        .expect("semantic bucket stage");
    assert_eq!(buckets.passed, 2);
    assert!(
        buckets
            .dropped
            .iter()
            .any(|drop| drop.cause == "bucket_member_cap" && drop.count == 1)
    );
    assert!(
        candidate
            .dropped
            .iter()
            .all(|drop| drop.cause != "overshared_values"),
        "the pair stage does not mislabel omitted buckets as pairs"
    );
    let observations = funnel
        .iter()
        .find(|stage| stage.stage == "semantic API observations")
        .expect("semantic observation stage");
    assert_eq!(observations.passed, 14);
    assert!(
        observations
            .dropped
            .iter()
            .any(|drop| drop.cause == "outside_registered_vocabulary" && drop.count == 6)
    );
    let verified = funnel
        .iter()
        .find(|stage| stage.stage == "semantic verified pairs")
        .expect("semantic verification stage");
    assert!(
        verified
            .dropped
            .iter()
            .any(|drop| drop.cause == "rule_disabled" && drop.count == 1)
    );
}

#[test]
fn a_unit_that_reached_no_window_says_which_of_the_two_reasons_it_was() {
    let detection = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats {
            graphs: 8,
            ineligible_graphs: 2,
            ..codehelion_core::semantic::SemanticCandidateStats::default()
        },
        registered_observations: 8,
        excluded_observations: 6,
        // Two units in which the registry recognized nothing the compiler
        // resolved, and three that held registered operations no rule claimed.
        units_without_registered_operations: 2,
        units_no_registered_rule_claimed: 3,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(
        &codehelion_core::structural::StructuralStats::default(),
        &detection,
        0,
        0,
        AnalysisMode::Semantic,
    );
    let graphs = funnel
        .iter()
        .find(|stage| stage.stage == "semantic graphs")
        .expect("semantic graph stage");
    assert_eq!(
        graphs.passed, 6,
        "the ineligible graphs are dropped from the value, not counted inside it"
    );
    for (cause, count) in [
        ("ineligible", 2),
        ("no_registered_operations", 2),
        ("no_registered_rule_matched", 3),
    ] {
        assert!(
            graphs
                .dropped
                .iter()
                .any(|drop| drop.cause == cause && drop.count == count),
            "{cause} names one condition of its own"
        );
    }
    assert!(
        graphs
            .dropped
            .iter()
            .all(|drop| drop.cause != "below_min_clone_tokens"),
        "a registered semantic window is admitted on its rule, not on a token floor"
    );
}

#[test]
fn no_semantic_pair_is_counted_as_both_carried_and_dropped() {
    // Grouping was handed seven relations: one it could not read, one that
    // restated another, and five it judged. Two of the five reached a group;
    // of the three that did not, one was severed by the component ceiling and
    // two were weighed and declined.
    let grouping = codehelion_core::semantic::SemanticGroupingStats {
        verified_pairs: 5,
        duplicate_pairs: 1,
        invalid_pairs: 1,
        grouped_pairs: 2,
        ungrouped_pairs: 3,
        ceiling_severed_pairs: 1,
        groups: 1,
    };
    let detection = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        // Two of the nine the verifier accepted name a rule this run turned
        // off, so seven reached grouping.
        verified_pairs: 9,
        disabled_pairs: 2,
        grouping,
    };
    let funnel = super::funnel(
        &codehelion_core::structural::StructuralStats::default(),
        &detection,
        0,
        0,
        AnalysisMode::Semantic,
    );
    let stage = |name: &str| {
        funnel
            .iter()
            .find(|stage| stage.stage == name)
            .expect("semantic stage")
    };
    let total = |stage: &report::FunnelStage| {
        stage
            .dropped
            .iter()
            .fold(stage.passed, |sum, drop| sum + drop.count)
    };

    let verified = stage("semantic verified pairs");
    assert_eq!(verified.passed, 7);
    assert_eq!(
        total(verified),
        9,
        "every accepted relation is accounted for"
    );

    let grouped = stage("semantic pairs represented by groups");
    assert_eq!(grouped.passed, 2);
    assert_eq!(
        total(grouped),
        7,
        "every relation grouping was given is accounted for"
    );
    for (cause, count) in [
        ("invalid_grouping_input", 1),
        ("duplicate_relation", 1),
        ("no_group_holds_both", 2),
        ("the_ceiling_cut_the_set", 1),
    ] {
        assert!(
            grouped
                .dropped
                .iter()
                .any(|drop| drop.cause == cause && drop.count == count),
            "{cause} is stated where the relation reached no group"
        );
    }

    // The pair findings are those same ungrouped relations written out, so
    // restating why they reached no group here would count each of them twice.
    assert!(stage("restricted semantic pairs").dropped.is_empty());
    assert!(stage("restricted semantic groups").dropped.is_empty());
}

#[test]
fn verification_budget_is_visible_as_search_truncation() {
    let stats = codehelion_core::structural::StructuralStats {
        unit_pairs: 12,
        verification_budget_dropped: 7,
        verified_pairs: 3,
        ..codehelion_core::structural::StructuralStats::default()
    };
    let semantic = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Semantic);
    let verified = funnel
        .iter()
        .find(|stage| stage.stage == "verified pairs")
        .expect("verified pair stage");
    assert_eq!(verified.passed, 3);
    assert!(
        verified
            .dropped
            .iter()
            .any(|drop| drop.cause == "verification_budget" && drop.count == 7)
    );
    assert!(report::search_truncated(&funnel));
}

#[test]
fn candidate_pass_budgets_are_visible_in_the_shared_funnel() {
    let stats = codehelion_core::structural::StructuralStats {
        near_match: codehelion_core::near_match::NearMatchStats {
            budget_exhausted: true,
            budget_dropped: 3,
            ..codehelion_core::near_match::NearMatchStats::default()
        },
        control_flow: codehelion_core::control_flow::ControlFlowStats {
            budget_exhausted: true,
            budget_dropped: 6,
            ..codehelion_core::control_flow::ControlFlowStats::default()
        },
        ..codehelion_core::structural::StructuralStats::default()
    };
    let semantic = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Semantic);
    for (stage_name, dropped) in [("near-match pairs", 3), ("control-flow pairs", 6)] {
        let stage = funnel
            .iter()
            .find(|stage| stage.stage == stage_name)
            .expect("candidate stage");
        assert!(
            stage
                .dropped
                .iter()
                .any(|drop| drop.cause == "pair_budget" && drop.count == dropped)
        );
    }
    assert!(report::search_truncated(&funnel));
}

#[test]
fn unit_group_funnel_counts_final_members_not_refinement_moves() {
    let stats = codehelion_core::structural::StructuralStats {
        grouping: codehelion_core::grouping::GroupingStats {
            units: 6,
            groups: 2,
            medoid_ejections: 3,
            linkage_splits: 2,
            singletons: 2,
            ..codehelion_core::grouping::GroupingStats::default()
        },
        ..codehelion_core::structural::StructuralStats::default()
    };
    let semantic = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Semantic);
    let grouped = funnel
        .iter()
        .find(|stage| stage.stage == "grouped units")
        .expect("grouped-unit stage");
    assert_eq!(grouped.passed, 4);
    assert_eq!(grouped.dropped.len(), 1);
    assert_eq!(grouped.dropped[0].cause, "left_alone");
    assert_eq!(grouped.dropped[0].count, 2);
}

/// A funnel row is read by comparing what it carried with what it set aside,
/// which only means anything when both count the same kind of thing. One run
/// holds many occurrences, so occurrence reasons stated against a run count can
/// exceed it and say nothing a reader can act on.
#[test]
fn run_and_occurrence_drops_are_counted_where_the_value_shares_their_unit() {
    // One reported run holding two occurrences. Confirmation set five
    // occurrences aside on the way, and two whole runs left through reasons
    // about runs.
    let stats = codehelion_core::structural::StructuralStats {
        regions: 1,
        region_occurrences: 2,
        region_singletons: 2,
        region_unresolved: 1,
        region_overlapping: 1,
        region_adjoining: 1,
        region_folded: 1,
        region_subsumed: 1,
        below_min_clone_token_regions: 1,
        ..codehelion_core::structural::StructuralStats::default()
    };
    let semantic = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Structural);
    let stage = |name: &str| {
        funnel
            .iter()
            .find(|stage| stage.stage == name)
            .expect("run stage")
    };

    let runs = stage("confirmed runs");
    assert_eq!(runs.passed, 1);
    assert_eq!(
        runs.dropped
            .iter()
            .map(|drop| drop.cause.as_str())
            .collect::<Vec<_>>(),
        vec!["same_content", "subsumed", "below_min_clone_tokens"],
        "a run row states only what happened to whole runs"
    );

    let occurrences = stage("run occurrences");
    assert_eq!(occurrences.passed, 2);
    assert_eq!(
        occurrences
            .dropped
            .iter()
            .map(|drop| (drop.cause.as_str(), drop.count))
            .collect::<Vec<_>>(),
        vec![
            ("unshared_content", 2),
            ("unresolved_occurrence", 1),
            ("overlapping_occurrence", 1),
            ("adjoining_occurrence", 1),
        ],
    );
}

/// A mode that never asks a compiler anything has no answer about registered
/// semantic duplication. Reporting the stages at zero would read as one.
#[test]
fn a_mode_that_asks_no_compiler_reports_no_semantic_funnel_stages() {
    let stats = codehelion_core::structural::StructuralStats::default();
    let semantic = super::SemanticDetection {
        groups: Vec::new(),
        pairs: Vec::new(),
        units: Vec::new(),
        candidates: codehelion_core::semantic::SemanticCandidateStats::default(),
        registered_observations: 0,
        excluded_observations: 0,
        units_without_registered_operations: 0,
        units_no_registered_rule_claimed: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };

    let structural = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Structural);
    assert!(
        structural
            .iter()
            .all(|stage| !stage.stage.contains("semantic")),
        "a structural run reports no stage it never ran"
    );
    assert!(
        structural.iter().any(|stage| stage.stage == "unit pairs"),
        "the stages this mode does run remain"
    );

    let semantic_funnel = super::funnel(&stats, &semantic, 0, 0, AnalysisMode::Semantic);
    assert!(
        semantic_funnel
            .iter()
            .any(|stage| stage.stage == "semantic verified pairs"),
        "a semantic run reports the stages it ran"
    );
}
