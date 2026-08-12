//! Store integration: snapshot round-trips, crash atomicity, fingerprint
//! dedup across scans and unsupported-layout rejection — all against real `SQLite`
//! databases (in-memory and on-disk), never mocks.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{
    BuildConfiguration, BuildVariant, CppBuild, Language, LanguageSelection, RustBuild,
};
use codehelion_core::frontend::UnitKind;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, CrossLanguageComparisonId, CrossLanguageGroupId, CrossLanguageMemberId,
    CrossVariantComparisonId, CrossVariantGroupId, CrossVariantMemberId, FindingId,
    FragmentFingerprint, UnitFingerprint, group_lineage_id,
};
use codehelion_core::structural::SiblingBasis;
use codehelion_core::verify::Confidence;
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCorrelation,
    ArtifactAnalysisSnapshot,
};
use codehelion_store::query::{IdKind, IdMatch, StoredVariant};
use codehelion_store::snapshot::{
    AuditState, CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow,
    CrossLanguageSemanticMemberRow, CrossVariantComparisonSnapshot, CrossVariantGroupRow,
    CrossVariantMemberRow, FileRow, FunnelDropRow, FunnelStageRow, GroupOrigin, GroupRow,
    LineageAdoption, LineageParent, MemberRow, NearMissRow, PriorityRow, SemanticEvidenceRow,
    SemanticNodeMappingRow, SemanticOperationGraphRow, SiblingGroupRow, SiblingRow,
    SimilarityBreakdownRow, Snapshot, SummaryRow, SuppressionRuleRow, UnitRow, UnparsedRow,
    UnusedRuleRow,
};
use codehelion_store::{Store, StoreError};

const fn unit_fp(seed: u8) -> UnitFingerprint {
    UnitFingerprint::from_bytes([seed; 16])
}

const fn frag_fp(seed: u8) -> FragmentFingerprint {
    FragmentFingerprint::from_bytes([seed; 16])
}

const fn group_fp(seed: u8) -> CloneGroupFingerprint {
    CloneGroupFingerprint::from_bytes([seed; 16])
}

const fn finding(seed: u8) -> FindingId {
    FindingId::from_bytes([seed; 16])
}

fn semantic_graph_json(kind: &str) -> String {
    serde_json::json!({
        "schema_version": "sog-v1",
        "language": "c",
        "build_variant_fingerprint": vec![0_u8; 32],
        "nodes": [{
            "kind": kind,
            "attributes": {
                "type_tag": null,
                "api_names": [],
                "resource_kind": null,
                "fallible_kind": null,
                "direct_propagation": null
            }
        }],
        "edges": []
    })
    .to_string()
}

fn cross_language_graph_json(language: &str, kind: &str, api_name: &str, variant: u8) -> String {
    serde_json::json!({
        "schema_version": "sog-v1",
        "language": language,
        "build_variant_fingerprint": vec![variant; 32],
        "nodes": [{
            "kind": kind,
            "attributes": {
                "type_tag": null,
                "api_names": [api_name],
                "resource_kind": null,
                "fallible_kind": null,
                "direct_propagation": null
            }
        }],
        "edges": []
    })
    .to_string()
}

fn detector_versions() -> Vec<(String, String)> {
    vec![
        ("normalization".to_string(), "2".to_string()),
        ("frontend.rust".to_string(), "rust-lexer-v1".to_string()),
        ("fp-schema".to_string(), "fp-schema-v1".to_string()),
    ]
}

fn member_with_finding(
    content_seed: u8,
    finding_seed: u8,
    path: &str,
    host: Option<usize>,
) -> MemberRow {
    MemberRow {
        content: frag_fp(content_seed),
        finding: finding(finding_seed.wrapping_add(100)),
        language: Language::Rust,
        host_unit: host,
        boilerplate: None,
        file_path: path.to_string(),
        start_line: 10,
        end_line: 20,
        token_count: 42,
    }
}

fn sample_snapshot<'a>(
    variant: &'a BuildVariant,
    detectors: &'a [(String, String)],
) -> Snapshot<'a> {
    Snapshot {
        root_path: "/repo",
        tool_version: "0.1.0",
        config_hash: "cfg-hash",
        config_source: "root",
        config_path: Some("/repo/codehelion.toml"),
        started_at: "2026-07-24T00:00:00Z",
        finished_at: "2026-07-24T00:00:05Z",
        variant,
        min_clone_tokens: 20,
        detector_versions: detectors,
        units: vec![
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/a.rs".to_string(),
                start_line: 1,
                end_line: 9,
                token_count: 50,
            },
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/b.rs".to_string(),
                start_line: 3,
                end_line: 11,
                token_count: 50,
            },
        ],
        suppressions: Vec::new(),
        groups: vec![GroupRow {
            fingerprint: group_fp(9),
            history: GroupOrigin::unconnected(&group_fp(9)),
            clone_type: CloneClass::Type1,
            split_pair: false,
            member_scope: CloneScope::Unit,
            statements: None,
            identifier_jaccard: None,
            has_loop: None,
            has_dynamic_allocation: None,
            call_count: None,
            test_code: false,
            test_code_evidence: None,
            score: 1.0,
            entropy_bits: 4.2,
            suppress_reason: None,
            boilerplate: None,
            width_family: false,
            ranked_down: true,
            suppressed_by: None,
            priority: PriorityRow {
                clone_confidence: 0.81,
                maintenance_risk: 0.44,
                refactoring_difficulty: 0.27,
                final_priority: 0.52,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            similarity: None,
            semantic: None,
            members: vec![
                member_with_finding(1, 1, "src/a.rs", Some(0)),
                member_with_finding(1, 2, "src/b.rs", Some(1)),
            ],
        }],
        sibling_groups: Vec::new(),
        near_misses: Vec::new(),
        files: vec![
            FileRow {
                relative_path: "src/a.rs".to_string(),
                content_hash: "aa".repeat(32),
                language: Language::Rust,
                byte_len: 120,
            },
            FileRow {
                relative_path: "src/b.rs".to_string(),
                content_hash: "bb".repeat(32),
                language: Language::Rust,
                byte_len: 240,
            },
        ],
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: sample_summary(),
    }
}

/// A summary with every field distinguishable from every other, so a
/// round-trip that swaps two of them fails instead of passing.
fn sample_summary() -> SummaryRow {
    SummaryRow {
        analyzed_files: codehelion_store::snapshot::FileCountsRow {
            total: 12,
            rust: 6,
            c: 4,
            cpp: 2,
        },
        lines: 310,
        tokens: 1_400,
        lexer_diagnostics: 2,
        unparsed: Some(UnparsedRow {
            files: 1,
            tokens: 35,
        }),
        excluded_generated: 3,
        excluded_by_glob: 4,
        excluded_too_large: 1,
        excluded_binary: 1,
        excluded_unreadable: 1,
        excluded_symlinks: 2,
        excluded_walk_errors: 1,
        excluded_timed_out: 1,
        excluded_language: 2,
        excluded_symlink_files: 1,
        excluded_symlink_directories: 1,
        guardrails: Some(codehelion_store::snapshot::GuardrailsRow {
            profile: "untrusted".to_string(),
            max_file_bytes: 512,
            parse_timeout_ms: 20,
            helper_timeout_ms: 30,
            posting_cap: 40,
            pair_budget: 50,
            near_miss_delta_bits: 0.05_f64.to_bits(),
            near_miss_cap: 54,
            verification_budget: 55,
            max_alignment_cells: 56,
            sibling_candidate_budget: 51,
            sibling_per_group_cap: 52,
            sibling_total_cap: 53,
            signature_sibling_candidate_budget: 57,
            signature_sibling_per_group_cap: 58,
            signature_sibling_total_cap: 59,
            max_component: 60,
        }),
        excluded_skipped: 5,
        folded_runs: 6,
        subsumed_runs: 7,
        split_components: 8,
        pair_budget_exhausted: true,
        baseline_digest: Some("cc".repeat(32)),
        funnel: vec![
            FunnelStageRow {
                name: "tokens".to_string(),
                passed: 1_400,
                dropped: Vec::new(),
            },
            FunnelStageRow {
                name: "seed pairs".to_string(),
                passed: 12,
                dropped: vec![
                    FunnelDropRow {
                        cause: "pair_budget".to_string(),
                        count: 9,
                    },
                    FunnelDropRow {
                        cause: "high_frequency".to_string(),
                        count: 4,
                    },
                ],
            },
        ],
        unused_suppressions: vec![UnusedRuleRow {
            scope: "path_glob".to_string(),
            pattern: "vendor/**".to_string(),
        }],
    }
}

#[path = "store/build_variants.rs"]
mod build_variants;
#[path = "store/feature_and_run_metadata.rs"]
mod feature_and_run_metadata;
#[path = "store/semantic_snapshots.rs"]
mod semantic_snapshots;
#[path = "store/snapshot_atomicity.rs"]
mod snapshot_atomicity;
#[path = "store/snapshot_round_trip.rs"]
mod snapshot_round_trip;
