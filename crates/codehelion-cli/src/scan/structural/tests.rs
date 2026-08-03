use super::{
    CategoryAction, Compilers, Config, CrossLanguageCandidateInput, ExecutionPolicy, Language,
    LanguageSelection, SandboxRequest, ScanArgs, SemanticCandidateConfig, SemanticOperationGraph,
    StructuralConfig, VerifiedPair, copy_guardrails, coverage, enabled_cross_language_matches,
    extract_cross_language_candidates, helper_timeout, installed_helper, pair_shape_suppression,
    presentation_suppression, report, run_with, semantic_sandbox, structural_config,
    unanimous_boilerplate, unavailable_execution_message, verify_cross_language_candidates,
};
use super::{SourceMeta, compile_rules, evaluate_suppression, reportable_regions};
use crate::cli::{Format, Mode, SortAxis};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, DiscoveryReport, SkipReport};
use codehelion_core::doctor::{CLANG_HELPER, Greeting, HelperFacts, HelperState, RUST_HELPER};
use codehelion_core::semantic::{OperationAttributes, OperationKind, OperationNode};
use codehelion_core::stable_id::CloneGroupFingerprint;
use codehelion_core::stable_id::{FragmentFingerprint, UnitFingerprint};
use codehelion_core::structural::{
    BodyMateriality, GroupDetail, GroupSiblings, StructuralNearMiss, StructuralReport,
    StructuralSibling, StructuralUnit,
};
use codehelion_core::verify::{Confidence, SimilarityBreakdown};
use codehelion_core::{
    frontend::UnitKind,
    grouping::{GroupingConfig, GroupingUnit, SimilarityEdge, group as group_units},
    ir::ByteRange,
};
use codehelion_helper::ir::{Unavailability, UnitRef};
use std::collections::BTreeMap;
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
fn include_trivial_overrides_only_this_invocations_presentation_policy() {
    let config = Config::default();
    assert_eq!(
        config.suppression.boilerplate.trivial_body,
        CategoryAction::RankDown
    );
    let presentation = presentation_suppression(&config, true);
    assert_eq!(
        presentation.boilerplate.trivial_body,
        CategoryAction::Report
    );
    assert_eq!(
        config.suppression.boilerplate.trivial_body,
        CategoryAction::RankDown,
        "the flag does not change the persisted configuration"
    );
}

#[test]
fn hiding_boilerplate_requires_every_member_to_share_its_category() {
    let category = Boilerplate::TrivialBody;
    assert_eq!(
        unanimous_boilerplate([Some(category), Some(category)]),
        Some(category)
    );
    assert_eq!(
        unanimous_boilerplate([Some(category), None]),
        None,
        "a non-boilerplate member remains a visible finding"
    );
}

#[test]
fn sibling_ranks_continue_after_primary_members_with_the_same_fingerprint() {
    let repeated = UnitFingerprint::from_bytes([1; 16]);
    let distinct = UnitFingerprint::from_bytes([2; 16]);

    assert_eq!(
        super::reporting::ranks_after(
            [repeated, repeated, distinct],
            [repeated, repeated, distinct],
        ),
        vec![2, 3, 1]
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the closed primary, sibling, and near-miss fixture keeps every suppression input visible"
)]
fn supplemental_diagnostics_apply_path_suppression_like_primary_findings() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::Rust);
    let units = (0..5)
        .map(|index| StructuralUnit {
            file: index,
            kind: UnitKind::Function,
            range: ByteRange { start: 0, end: 1 },
            start_line: 1,
            end_line: 1,
            token_start: 0,
            token_end: 1,
            name: Some(format!("unit_{index}").as_str().into()),
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            fingerprint: UnitFingerprint::from_bytes([u8::try_from(index + 1).unwrap(); 16]),
            content: FragmentFingerprint::from_bytes([u8::try_from(index + 11).unwrap(); 16]),
            normalized_content: FragmentFingerprint::from_bytes(
                [u8::try_from(index + 21).unwrap(); 16],
            ),
        })
        .collect::<Vec<_>>();
    let grouping_units = units
        .iter()
        .map(|unit| GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect::<Vec<_>>();
    let groups = group_units(
        &grouping_units,
        &[SimilarityEdge {
            a: 0,
            b: 1,
            similarity: 1.0,
            breakdown: None,
            class: CloneClass::Type1,
            confidence: Confidence::High,
        }],
        &GroupingConfig::default(),
    );
    let perfect = SimilarityBreakdown {
        lexical: 1.0,
        structural: 1.0,
        control_flow: None,
        type_similarity: None,
        api: None,
        composite: 1.0,
    };
    let analysis = StructuralReport {
        units,
        groups,
        regions: Vec::new(),
        details: vec![GroupDetail {
            fingerprint: CloneGroupFingerprint::from_bytes([42; 16]),
            member_breakdowns: vec![perfect, perfect],
            cohesion_breakdown: perfect,
            identifier_jaccard: 1.0,
            body_materiality: BodyMateriality {
                has_loop: false,
                has_dynamic_allocation: false,
                call_count: 0,
            },
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
        }],
        unrepresented: Vec::new(),
        siblings: vec![GroupSiblings {
            group: 0,
            siblings: vec![StructuralSibling {
                unit: 2,
                clone_type: CloneClass::Type3,
                confidence: Confidence::Low,
                breakdown: perfect,
            }],
        }],
        near_misses: vec![StructuralNearMiss {
            a: 3,
            b: 4,
            estimated_jaccard: 0.25,
        }],
        stats: codehelion_core::structural::StructuralStats::default(),
    };
    let files = [
        "src/a.rs",
        "src/b.rs",
        "vendor/sibling.rs",
        "vendor/left.rs",
        "vendor/right.rs",
    ]
    .into_iter()
    .map(|relative_path| SourceMeta {
        relative_path: relative_path.to_string(),
        language: Language::Rust,
        marker_lines: Vec::new(),
        lines: 1,
        diagnostics: 0,
        unaccounted_tokens: 0,
        depth_truncated: false,
    })
    .collect::<Vec<_>>();
    let mut config = Config::default();
    config.suppression.paths = vec!["vendor/**".to_string()];
    config.suppression.vendored_paths.clear();
    let mut rules = compile_rules(&config, &files, &analysis).expect("compile path rule");
    let regions = reportable_regions(&analysis);
    let verdicts =
        evaluate_suppression(&config, &mut rules, &analysis, &regions, &[], &[], &variant);

    assert_eq!(verdicts.groups, vec![None]);
    assert!(verdicts.siblings[0][0].is_some());
    assert!(verdicts.near_misses[0].is_some());
}

#[test]
fn build_description_uses_the_configured_helper_timeout() {
    let mut config = Config::default();
    config.limits.helper_timeout_ms = 17;
    assert_eq!(
        helper_timeout(&config),
        std::time::Duration::from_millis(17)
    );
}

#[test]
fn split_pair_shape_suppression_keeps_group_precedence() {
    let pair = VerifiedPair {
        members: vec![0, 1],
        canonical: 0,
        fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
        similarity: 0.9,
        breakdown: None,
        class: CloneClass::Type2,
        confidence: Confidence::High,
        boilerplate: Some(Boilerplate::MacroRepetition),
        width_family: true,
    };
    let hidden = BTreeMap::from([(Boilerplate::MacroRepetition, 3)]);
    assert_eq!(
        pair_shape_suppression(pair.boilerplate, pair.width_family, &hidden, Some(4)),
        Some(3)
    );

    let only_width = VerifiedPair {
        boilerplate: None,
        ..pair
    };
    assert_eq!(
        pair_shape_suppression(
            only_width.boilerplate,
            only_width.width_family,
            &hidden,
            Some(4)
        ),
        Some(4)
    );
}

#[test]
fn a_dominant_split_pair_shape_is_ranked_but_not_hidden() {
    let category = Boilerplate::MacroRepetition;
    let dominant = unanimous_boilerplate([
        Some(category),
        Some(category),
        Some(category),
        Some(category),
        None,
    ]);
    let hidden = BTreeMap::from([(category, 3)]);

    assert_eq!(dominant, None);
    assert_eq!(pair_shape_suppression(dominant, false, &hidden, None), None);
}

/// Whether a helper is installed is a property of the machine, so what is
/// fixed here is the pairing: without one, the message names the programs
/// to install rather than the mode that was asked for; with one, the run
/// knows which compiler answered.
#[test]
fn a_run_that_needs_a_compiler_says_which_program_supplies_it() {
    match Compilers::found(
        &ExecutionPolicy::deny_all(),
        SandboxRequest::unrestricted(),
        &crate::config::Helpers::default(),
    ) {
        Err(error) => {
            let text = format!("{error:#}");
            assert!(text.contains(RUST_HELPER.binary), "{text}");
        }
        Ok(compilers) => {
            for helper in &compilers.installed {
                assert!(
                    !helper.greeting.toolchains.is_empty(),
                    "a helper that answered says what will do the analysing"
                );
            }
        }
    }
}

#[test]
fn a_silent_optional_helper_does_not_block_an_answering_helper() {
    let policy = ExecutionPolicy::deny_all();
    let sandbox = SandboxRequest::unrestricted();
    let rust = installed_helper(
        RUST_HELPER,
        HelperFacts {
            path: PathBuf::from("/tool/codehelion-backend-rust"),
            state: HelperState::Answered(Greeting {
                version: "1.0.0".to_owned(),
                protocol: 2,
                toolchains: vec!["rust-analyzer".to_owned()],
                capabilities: vec!["types".to_owned()],
                executes: Vec::new(),
            }),
        },
        &policy,
        sandbox,
    );
    let clang = installed_helper(
        CLANG_HELPER,
        HelperFacts {
            path: PathBuf::from("/tool/codehelion-backend-clang"),
            state: HelperState::Silent("protocol mismatch".to_owned()),
        },
        &policy,
        sandbox,
    );

    assert!(rust.is_some());
    assert!(clang.is_none());
}

#[test]
fn an_unimplemented_execution_class_is_not_described_as_a_missing_helper() {
    let message =
        unavailable_execution_message(codehelion_core::execution::Execution::ProceduralMacro);
    assert!(message.contains("not implemented"), "{message}");
    assert!(message.contains("only build-script"), "{message}");
    assert!(!message.contains("no helper installed"), "{message}");
}

#[test]
fn denied_build_scripts_keep_their_cost_and_exact_permission() {
    let answers = crate::semantic::Answers {
        helpers: Vec::new(),
        per_source: vec![crate::semantic::Answer::Unavailable {
            helper: None,
            unit: UnitRef {
                unit: "generated".to_string(),
                file: "build.rs".to_string(),
                variant: "host".to_string(),
            },
            reason: Unavailability::RequiresExecution,
            diagnostics: Vec::new(),
        }],
    };

    let compiler = coverage(&answers);

    assert_eq!(compiler.unavailable["requires_execution"], 1);
    assert_eq!(compiler.execution_refusals.len(), 1);
    let refusal = &compiler.execution_refusals[0];
    assert_eq!(refusal.execution, "build-script");
    assert_eq!(refusal.files, 1);
    assert!(refusal.cost.contains("build script"), "{refusal:?}");
    assert_eq!(
        refusal.permission_argument,
        "--allow-execution=build-script"
    );
    assert!(refusal.message.contains(&refusal.permission_argument));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn untrusted_semantic_requires_an_enforceable_memory_limit() {
    let args = ScanArgs {
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: PathBuf::from("."),
        mode: Mode::Semantic,
        format: Format::Text,
        output: None,
        force: false,
        config: None,
        helpers: Vec::new(),
        no_ignore: false,
        follow_links: false,
        compile_commands: None,
        jobs: None,
        db: None,
        baseline: None,
        baseline_mode: crate::cli::BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: false,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        show_near_misses: false,
        include_trivial: false,
        no_reuse: false,
        include_vendored: false,
        view: crate::cli::ViewArgs::default(),
        fail_on_findings: false,
        untrusted: true,
    };
    let error = semantic_sandbox(&args).expect_err("portable build cannot enforce it");
    assert!(
        format!("{error:#}").contains("OS memory containment is unavailable"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn untrusted_semantic_requires_a_linux_memory_limit() {
    let args = ScanArgs {
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: PathBuf::from("."),
        mode: Mode::Semantic,
        format: Format::Text,
        output: None,
        force: false,
        config: None,
        helpers: Vec::new(),
        no_ignore: false,
        follow_links: false,
        compile_commands: None,
        jobs: None,
        db: None,
        baseline: None,
        baseline_mode: crate::cli::BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: false,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        show_near_misses: false,
        include_trivial: false,
        no_reuse: false,
        include_vendored: false,
        view: crate::cli::ViewArgs::default(),
        fail_on_findings: false,
        untrusted: true,
    };
    let request = semantic_sandbox(&args).expect("Linux can enforce the requested ceiling");
    assert_eq!(
        request.max_memory_bytes(),
        codehelion_core::execution::Limits::untrusted().max_subprocess_bytes
    );
}

/// A helper that reads none of the languages the tree holds has nothing to
/// answer about, and a run that counted it would file its results under a
/// compiler that never saw the project — giving one tree two identities
/// depending on what happens to be installed beside the scanner.
#[test]
fn a_helper_that_reads_nothing_in_this_tree_is_not_part_of_the_run() {
    let Ok(compilers) = Compilers::found(
        &ExecutionPolicy::deny_all(),
        SandboxRequest::unrestricted(),
        &crate::config::Helpers::default(),
    ) else {
        return;
    };
    let rust_only = LanguageSelection {
        rust: true,
        c: false,
        cpp: false,
    };
    for helper in compilers.at_work(rust_only) {
        assert!(
            helper.component.analyses.contains(&Language::Rust),
            "{} was asked about a tree it reads nothing in",
            helper.component.name
        );
    }
}

/// Nothing to scan is not the same as nothing to scan it with. A tree with
/// no sources gives every helper nothing to do, and refusing there would
/// report an empty directory as a machine missing a compiler.
#[test]
fn an_empty_tree_is_not_reported_as_a_missing_compiler() {
    let dir = tempfile::tempdir().unwrap();
    let args = ScanArgs {
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: dir.path().to_path_buf(),
        mode: Mode::Semantic,
        format: Format::Text,
        output: None,
        force: false,
        config: None,
        helpers: Vec::new(),
        no_ignore: false,
        follow_links: false,
        compile_commands: None,
        jobs: None,
        db: Some(dir.path().join("audit.db")),
        baseline: None,
        baseline_mode: crate::cli::BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: false,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        show_near_misses: false,
        include_trivial: false,
        include_vendored: false,
        view: crate::cli::ViewArgs::default(),
        no_reuse: false,
        fail_on_findings: false,
        untrusted: false,
    };
    let Ok(compilers) = Compilers::found(
        &ExecutionPolicy::deny_all(),
        SandboxRequest::unrestricted(),
        &crate::config::Helpers::default(),
    ) else {
        return;
    };
    let mut out = Vec::new();
    run_with(&args, &mut out, Some(&compilers)).expect("an empty tree scans");
}

/// Structural pairs statement fragments where Fast pairs token windows, and
/// the two need different ceilings. Reading one number from the
/// configuration for both would hand this mode a limit chosen for the other
/// — which is how a ceiling meant as a safety valve becomes a silent cut.
#[test]
fn an_unset_ceiling_leaves_every_stage_at_its_own_default() {
    let config = structural_config(&Config::default());
    let defaults = StructuralConfig::default();
    assert_eq!(config.min_clone_tokens, defaults.min_clone_tokens);
    assert_eq!(config.candidate.posting_cap, defaults.candidate.posting_cap);
    assert_eq!(config.candidate.pair_budget, defaults.candidate.pair_budget);
    assert_eq!(
        config.near_match.posting_cap,
        defaults.near_match.posting_cap
    );
    assert_eq!(
        config.control_flow.pair_budget,
        defaults.control_flow.pair_budget
    );
}

/// A ceiling that is set bounds the whole funnel, not one stage of it.
#[test]
fn a_configured_ceiling_reaches_every_candidate_stage() {
    let cfg = Config {
        min_clone_tokens: 37,
        limits: crate::config::Limits {
            posting_cap: Some(9),
            pair_budget: Some(11),
            verification_budget: Some(13),
            max_alignment_cells: Some(17),
            ..crate::config::Limits::default()
        },
        ..Config::default()
    };
    let config = structural_config(&cfg);
    assert_eq!(config.min_clone_tokens, 37);
    for cap in [
        config.candidate.posting_cap,
        config.near_match.posting_cap,
        config.control_flow.posting_cap,
    ] {
        assert_eq!(cap, 9);
    }
    for budget in [
        config.candidate.pair_budget,
        config.near_match.pair_budget,
        config.control_flow.pair_budget,
    ] {
        assert_eq!(budget, 11);
    }
    assert_eq!(config.verification_budget, 13);
    assert_eq!(config.verify.max_alignment_cells, 17);
}

#[test]
fn partitioned_reports_copy_every_untrusted_guardrail() {
    let profile = codehelion_core::execution::Limits::untrusted();
    let mut limits = crate::config::Limits::default();
    limits.clamp_to_untrusted(&profile);
    let guardrails = report::Guardrails::untrusted(&limits, &profile);
    assert_eq!(
        serde_json::to_value(copy_guardrails(&guardrails)).unwrap(),
        serde_json::to_value(guardrails).unwrap()
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
        unrepresentable_units: 2,
        verified_pairs: 3,
        disabled_pairs: 1,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(
        &codehelion_core::structural::StructuralStats::default(),
        &detection,
        0,
        0,
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
            .all(|drop| drop.cause != "high_frequency"),
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
    let graphs = funnel
        .iter()
        .find(|stage| stage.stage == "semantic graphs")
        .expect("semantic graph stage");
    assert_eq!(
        graphs.passed, 2,
        "unrepresentable parser units share the graph-stage denominator"
    );
    assert!(
        graphs
            .dropped
            .iter()
            .any(|drop| drop.cause == "no_registered_operations" && drop.count == 2)
    );
    assert!(
        graphs
            .dropped
            .iter()
            .all(|drop| drop.cause != "below_min_clone_tokens"),
        "a registered semantic window is admitted on its rule, not on a token floor"
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
        unrepresentable_units: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0);
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
        unrepresentable_units: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0);
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
        unrepresentable_units: 0,
        verified_pairs: 0,
        disabled_pairs: 0,
        grouping: codehelion_core::semantic::SemanticGroupingStats::default(),
    };
    let funnel = super::funnel(&stats, &semantic, 0, 0);
    let grouped = funnel
        .iter()
        .find(|stage| stage.stage == "grouped units")
        .expect("grouped-unit stage");
    assert_eq!(grouped.passed, 4);
    assert_eq!(grouped.dropped.len(), 1);
    assert_eq!(grouped.dropped[0].cause, "left_alone");
    assert_eq!(grouped.dropped[0].count, 2);
}

#[test]
fn incomplete_normalization_lowers_confidence_without_affecting_matching() {
    assert!((super::normalization_confidence(3, 0) - 1.0).abs() < f64::EPSILON);
    assert!((super::normalization_confidence(0, 2) - 0.0).abs() < f64::EPSILON);
    let empty_interactions = std::collections::BTreeSet::new();
    let empty_data_flows = std::collections::BTreeSet::new();
    assert!(
        (super::semantic_confidence(
            0.7,
            super::SemanticConfidenceEvidence {
                normalization: 1.0,
                interactions: &empty_interactions,
                data_flows: &empty_data_flows,
                cfg_shape: None,
            },
            super::SemanticConfidenceEvidence {
                normalization: 0.5,
                interactions: &empty_interactions,
                data_flows: &empty_data_flows,
                cfg_shape: None,
            },
        ) - 0.35)
            .abs()
            < f64::EPSILON
    );
    let file = std::collections::BTreeSet::from(["file_io".to_owned()]);
    let lock = std::collections::BTreeSet::from(["synchronization".to_owned()]);
    assert!((super::interaction_confidence(&file, &file) - 1.05).abs() < f64::EPSILON);
    assert!((super::interaction_confidence(&file, &lock) - 0.85).abs() < f64::EPSILON);
    assert!(
        (super::interaction_confidence(&file, &std::collections::BTreeSet::new()) - 1.0).abs()
            < f64::EPSILON
    );
    let filter_map = std::collections::BTreeSet::from([(
        "rust::Iterator::filter".to_owned(),
        "rust::Iterator::map".to_owned(),
    )]);
    let map_filter = std::collections::BTreeSet::from([(
        "rust::Iterator::map".to_owned(),
        "rust::Iterator::filter".to_owned(),
    )]);
    assert!((super::data_flow_confidence(&filter_map, &filter_map) - 1.05).abs() < f64::EPSILON);
    assert!((super::data_flow_confidence(&filter_map, &map_filter) - 0.85).abs() < f64::EPSILON);
    assert!(
        (super::data_flow_confidence(&filter_map, &std::collections::BTreeSet::new()) - 1.0).abs()
            < f64::EPSILON
    );
    let straight = super::CfgShape {
        blocks: 2,
        flow_edges: 1,
        taken_edges: 0,
        not_taken_edges: 0,
        unwind_edges: 0,
        return_edges: 0,
    };
    let branch = super::CfgShape {
        taken_edges: 1,
        not_taken_edges: 1,
        ..straight
    };
    assert!((super::cfg_confidence(Some(straight), Some(straight)) - 1.05).abs() < f64::EPSILON);
    assert!((super::cfg_confidence(Some(straight), Some(branch)) - 0.85).abs() < f64::EPSILON);
    assert!((super::cfg_confidence(Some(straight), None) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn compiler_cfg_is_reduced_to_the_overlapping_semantic_window() {
    let anchor = |start_byte, end_byte| {
        codehelion_helper::ir::Anchor::written_here(codehelion_helper::ir::SourceRange {
            file: "src/lib.rs".to_string(),
            start_byte,
            end_byte,
            start_line: 1,
        })
    };
    let cfg = codehelion_helper::ir::ControlFlowGraph {
        blocks: vec![
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(10, 20),
                length: 2,
            },
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(20, 30),
                length: 1,
            },
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(40, 50),
                length: 1,
            },
        ],
        edges: vec![
            codehelion_helper::ir::Edge {
                from: 0,
                to: 1,
                kind: codehelion_helper::ir::EdgeKind::Flow,
            },
            codehelion_helper::ir::Edge {
                from: 1,
                to: 2,
                kind: codehelion_helper::ir::EdgeKind::Taken,
            },
        ],
    };
    assert_eq!(
        super::semantic_window_cfg_shape(
            Some(&cfg),
            "src/lib.rs",
            codehelion_core::semantic::SemanticSourceRange { start: 10, end: 30 },
        ),
        Some(super::CfgShape {
            blocks: 2,
            flow_edges: 1,
            taken_edges: 0,
            not_taken_edges: 0,
            unwind_edges: 0,
            return_edges: 0,
        })
    );
    assert!(
        super::semantic_window_cfg_shape(
            Some(&cfg),
            "src/lib.rs",
            codehelion_core::semantic::SemanticSourceRange { start: 30, end: 40 },
        )
        .is_none()
    );
}

#[test]
fn direct_data_flow_is_scoped_to_its_semantic_window() {
    let summary = codehelion_helper::ir::DataFlowSummary {
        computed: true,
        flows: vec![
            (
                "10:16:rust::Iterator::filter".to_owned(),
                "17:20:rust::Iterator::map".to_owned(),
            ),
            (
                "40:46:rust::Iterator::filter".to_owned(),
                "47:50:rust::Iterator::map".to_owned(),
            ),
        ],
    };
    let first = super::semantic_window_data_flows(
        &summary,
        codehelion_core::semantic::SemanticSourceRange { start: 0, end: 30 },
    );
    assert_eq!(
        first,
        std::collections::BTreeSet::from([(
            "rust::Iterator::filter".to_owned(),
            "rust::Iterator::map".to_owned(),
        )])
    );
    assert!(
        super::semantic_window_data_flows(
            &summary,
            codehelion_core::semantic::SemanticSourceRange { start: 21, end: 39 },
        )
        .is_empty()
    );
}

#[test]
fn a_disabled_cross_language_rule_cannot_reach_the_comparison_report() {
    let graph = |language, variant| {
        SemanticOperationGraph::new(
            language,
            variant,
            vec![OperationNode {
                kind: OperationKind::Validate,
                attributes: OperationAttributes {
                    fallible_kind: Some(codehelion_core::semantic::FallibleKind::Option),
                    ..OperationAttributes::default()
                },
            }],
            Vec::new(),
        )
        .expect("closed optional validation graph")
    };
    let inputs = vec![
        CrossLanguageCandidateInput {
            comparison_partition: [1; 16],
            graph: graph(Language::Rust, [2; 32]),
        },
        CrossLanguageCandidateInput {
            comparison_partition: [1; 16],
            graph: graph(Language::Cpp, [3; 32]),
        },
    ];
    let candidates = extract_cross_language_candidates(&inputs, SemanticCandidateConfig::default());
    let verified = verify_cross_language_candidates(&inputs, &candidates.pairs);
    assert_eq!(verified.len(), 1);

    let config =
        Config::from_toml("[semantic]\ndisabled = [\"cross-language-optional-validation-v1\"]\n")
            .expect("registered cross-language rule is configurable");
    assert!(enabled_cross_language_matches(verified, &config).is_empty());
}

#[test]
fn cross_language_ceiling_drops_use_the_shared_truncation_funnel() {
    let stats = codehelion_core::semantic::CrossLanguageCandidateStats {
        graphs: 12,
        ineligible_graphs: 3,
        buckets: 4,
        oversized_buckets: 1,
        pairs_available: 20,
        pairs_budget_dropped: 7,
        pairs_emitted: 5,
    };
    let funnel = super::cross_language_funnel(&stats);
    assert!(report::search_truncated(&funnel));
    assert_eq!(funnel[1].passed, 3);
    assert_eq!(funnel[1].dropped[0].cause, "bucket_member_cap");
    assert_eq!(funnel[2].passed, 5);
    assert_eq!(funnel[2].dropped[0].cause, "pair_budget");
}
