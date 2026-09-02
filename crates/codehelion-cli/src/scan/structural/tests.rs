use super::{
    CategoryAction, Compilers, Config, CrossLanguageCandidateInput, ExecutionPolicy, Language,
    LanguageSelection, SandboxRequest, ScanArgs, SemanticOperationGraph, StructuralConfig,
    VerifiedPair, copy_guardrails, coverage, detector_versions, enabled_cross_language_matches,
    extract_cross_language_candidates, helper_timeout, installed_helper, pair_shape_suppression,
    presentation_suppression, report, run_with, semantic_sandbox, structural_config,
    unanimous_boilerplate, unavailable_execution_message, verify_cross_language_candidates,
};
use super::{SourceMeta, compile_rules, evaluate_suppression, reportable_regions};
// Named here so the sibling test modules reach them as `super::`, the way the
// bodies moved out of this file already spell them.
use super::{
    CfgShape, DiscoveryExclusions, SemanticConfidenceEvidence, SemanticDetection, cfg_confidence,
    cross_language_funnel, data_flow_confidence, discovery_exclusions, funnel,
    interaction_confidence, normalization_confidence, semantic_confidence, semantic_partitions,
    semantic_window_cfg_shape, semantic_window_data_flows, unconfigured_cpp_partition,
};
use crate::cli::{Format, Mode, SortAxis};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::BuildVariant;
use codehelion_core::doctor::{CLANG_HELPER, Greeting, HelperFacts, HelperState, RUST_HELPER};
use codehelion_core::semantic::SemanticCandidateConfig;
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
fn directory_partitions_are_sorted_and_opaque() {
    let files = ["z/file.rs", "a/one.rs", "z/other.rs", "file.rs"]
        .into_iter()
        .map(|relative_path| SourceMeta {
            relative_path: relative_path.to_string(),
            directory_key: std::path::Path::new(relative_path)
                .parent()
                .map(crate::scan::path_key)
                .unwrap_or_default(),
            language: Language::Rust,
            marker_lines: Vec::new(),
            lines: 1,
            diagnostics: 0,
            unaccounted_tokens: 0,
            depth_truncated: false,
        })
        .collect::<Vec<_>>();
    let partitions = super::directory_partitions(&files);
    assert_eq!(partitions[0].index(), 2);
    assert_eq!(partitions[1].index(), 1);
    assert_eq!(partitions[2].index(), 2);
    assert_eq!(partitions[3].index(), 0);
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

/// The reuse key of one invocation, as each recording path builds it.
fn hash(
    cfg: &Config,
    rules: &crate::suppress::Rules,
    presentation: &crate::config::Suppression,
) -> String {
    crate::scan::reuse_config_hash(
        cfg,
        crate::scan::store::ReuseProfile {
            untrusted: false,
            siblings_by_signature: false,
            rules: &rules.rows,
            presentation,
        },
    )
    .expect("the key is built")
    .as_str()
    .to_string()
}

/// Two invocations may stand in for one another only when they would record
/// the same rows. What a run was told to do with a baseline, and the
/// presentation policy it ranked under, both change those rows without
/// changing the configuration the run is recorded under.
#[test]
fn the_reuse_key_separates_invocations_that_record_different_rows() {
    let cfg = Config::default();
    let mut suppressing = crate::suppress::Rules::compile(&cfg.suppression, false)
        .expect("the configured rules compile");
    suppressing.add_baseline("frozen.json", BTreeMap::new());
    let comparing = crate::suppress::Rules::compile(&cfg.suppression, false)
        .expect("the configured rules compile");

    let hidden = hash(&cfg, &suppressing, &cfg.suppression);
    let marked = hash(&cfg, &comparing, &cfg.suppression);
    assert_ne!(
        hidden, marked,
        "a baseline the run marks is not the same question as one it hides"
    );
    assert_eq!(
        hidden,
        hash(&cfg, &suppressing, &cfg.suppression),
        "the same invocation keeps one key"
    );
    assert_ne!(
        hash(&cfg, &comparing, &cfg.suppression),
        hash(&cfg, &comparing, &presentation_suppression(&cfg, true)),
        "a run that ranks trivial findings differently records different rows"
    );
}

mod comparison;
mod helpers;
mod reporting;
mod semantic_analysis;
mod suppression;
