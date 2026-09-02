//! Cross-build-variant and cross-language comparison.

use crate::cli::{Format, Mode, ScanArgs, SortAxis};
use crate::config::Config;
use crate::report;
use crate::scan::structural::comparison::{copy_guardrails, enabled_cross_language_matches};
use crate::scan::structural::helpers::Compilers;
use crate::scan::structural::run_with;
use codehelion_core::discovery::Language;
use codehelion_core::execution::ExecutionPolicy;
use codehelion_core::semantic::{
    CrossLanguageCandidateInput, OperationAttributes, OperationKind, OperationNode,
    SemanticCandidateConfig, SemanticOperationGraph, extract_cross_language_candidates,
    verify_cross_language_candidates,
};
use codehelion_helper::SandboxRequest;

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

/// A comparison the caller asked for says what became of it however many
/// programs the tree held. A report with no word about it cannot be told apart
/// from one that compared and found nothing.
#[test]
fn a_requested_language_comparison_says_it_did_not_run_on_a_single_program() {
    let dir = tempfile::tempdir().unwrap();
    let args = ScanArgs {
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: dir.path().to_path_buf(),
        mode: Mode::Semantic,
        format: Format::Json,
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
        compare_languages: true,
        show_suppressed: false,
        show_siblings: false,
        siblings_by_signature: false,
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
    run_with(&args, &mut out, Some(&compilers)).expect("a tree with one program scans");
    let rendered: serde_json::Value = serde_json::from_slice(&out).expect("the report is JSON");
    assert_eq!(
        rendered["cross_language_comparison_status"]["status"],
        serde_json::json!("not_run"),
        "a requested comparison that could not run is explicit"
    );
    assert!(
        rendered["partitions"].is_array(),
        "a run that answers about a comparison keeps the partitioned shape"
    );
}
