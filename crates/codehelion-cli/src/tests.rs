use super::report_command::*;
use super::*;
use crate::cli::{BaselineMode, SortAxis};
use codehelion_core::discovery::Language;
use codehelion_core::semantic::{
    OperationAttributes, OperationEdge, OperationEdgeKind, OperationKind, OperationNode,
    SemanticOperationGraph,
};
use codehelion_core::stable_id::{CrossLanguageComparisonId, CrossLanguageGroupId};
use codehelion_store::snapshot::{
    CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow, CrossLanguageSemanticMemberRow,
};

#[test]
fn comparison_and_presentation_flags_reject_unsupported_modes() {
    let mut args = ScanArgs {
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: PathBuf::from("."),
        mode: Mode::Fast,
        format: cli::Format::Text,
        output: None,
        force: false,
        config: None,
        no_ignore: false,
        jobs: None,
        db: None,
        baseline: None,
        baseline_mode: BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: true,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        include_trivial: false,
        include_vendored: false,
        verbose: false,
        fail_on_findings: false,
        untrusted: false,
    };
    let error = scan_command(&args, &mut Vec::new()).expect_err("mode must be semantic");
    assert!(format!("{error:#}").contains("--compare-build-variants requires --mode semantic"));

    args.compare_build_variants = false;
    args.compare_languages = true;
    let error = scan_command(&args, &mut Vec::new()).expect_err("mode must be semantic");
    assert!(format!("{error:#}").contains("--compare-languages requires --mode semantic"));

    args.mode = Mode::Structural;
    args.compare_languages = false;
    args.compare_build_variants = true;
    let error = scan_command(&args, &mut Vec::new()).expect_err("mode must be semantic");
    assert!(format!("{error:#}").contains("--compare-build-variants requires --mode semantic"));

    args.mode = Mode::Fast;
    args.compare_build_variants = false;
    args.include_trivial = true;
    let error = scan_command(&args, &mut Vec::new()).expect_err("mode must support the flag");
    assert!(
        format!("{error:#}")
            .contains("--include-trivial requires --mode structural or --mode semantic")
    );
}

#[test]
fn restored_compiler_coverage_keeps_each_outcome_distinct() {
    let coverage = codehelion_store::compiler::CompilerCoverage {
        answered: 4,
        not_asked: 2,
        unavailable: std::collections::BTreeMap::from([
            ("missing-helper".to_string(), 3),
            ("timeout".to_string(), 1),
        ]),
        restarts: Some(5),
    };
    let restored = restored_compiler_coverage(coverage);
    assert_eq!(restored.answered, 4);
    assert_eq!(restored.not_asked, 2);
    assert_eq!(restored.unavailable["missing-helper"], 3);
    assert_eq!(restored.unavailable["timeout"], 1);
    assert_eq!(restored.restarts, 5);
}

#[test]
fn an_id_naming_more_than_one_thing_lists_them_rather_than_picking() {
    let path = Path::new(".codehelion/audit.db");
    let candidates = vec![
        IdMatch {
            kind: IdKind::Occurrence,
            id: "aa11bb22cc33".to_string(),
        },
        IdMatch {
            kind: IdKind::CloneGroup,
            id: "aa11bb22dd44".to_string(),
        },
    ];

    let error = the_one("aa11bb22", candidates, path).expect_err("two things, not one");
    let text = format!("{error:#}");
    // Picking one would be a guess, and a guess about which finding
    // somebody is reading is worse than a question.
    assert!(text.contains("names 2 things"), "{text}");
    assert!(text.contains("finding aa11bb22cc33"), "{text}");
    assert!(text.contains("clone group aa11bb22dd44"), "{text}");

    let found = the_one(
        "aa11bb22cc33",
        vec![IdMatch {
            kind: IdKind::Occurrence,
            id: "aa11bb22cc33".to_string(),
        }],
        path,
    )
    .expect("one thing");
    assert_eq!(found.kind, IdKind::Occurrence);

    let error = the_one("aa11bb22", Vec::new(), path).expect_err("nothing recorded");
    assert!(format!("{error:#}").contains("no finding, clone group or"));
}

#[test]
fn explain_reads_a_cross_language_group_without_turning_it_into_a_finding() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    let graph = SemanticOperationGraph::new(
        Language::Rust,
        [1; 32],
        vec![
            OperationNode {
                kind: OperationKind::Source,
                attributes: OperationAttributes::default(),
            },
            OperationNode {
                kind: OperationKind::Collect,
                attributes: OperationAttributes::default(),
            },
        ],
        vec![OperationEdge {
            from: 0,
            to: 1,
            kind: OperationEdgeKind::Data,
        }],
    )
    .unwrap();
    let graph_json = serde_json::to_string(&graph).unwrap();
    let cpp_graph =
        SemanticOperationGraph::new(Language::Cpp, [2; 32], graph.nodes, graph.edges).unwrap();
    let cpp_graph_json = serde_json::to_string(&cpp_graph).unwrap();
    let origins = vec!["cpp-variant".to_string(), "rust-variant".to_string()];
    let groups = vec![CrossLanguageSemanticGroupRow {
        group_id: CrossLanguageGroupId::from_bytes([72; 16]),
        rule_id: "cross-language-sequence-pipeline-v1".to_string(),
        rule_version: 1,
        semantic_confidence: 0.55,
        correspondence_ids: vec!["sequence-map-v1".to_string()],
        members: vec![
            CrossLanguageSemanticMemberRow {
                origin_variant: "rust-variant".to_string(),
                language: Language::Rust,
                file_path: "rust/src/lib.rs".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v1".to_string(),
                graph_json,
            },
            CrossLanguageSemanticMemberRow {
                origin_variant: "cpp-variant".to_string(),
                language: Language::Cpp,
                file_path: "cpp/src/map.cpp".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v1".to_string(),
                graph_json: cpp_graph_json,
            },
        ],
    }];
    let comparison = CrossLanguageComparisonSnapshot {
        root_path: "/repo",
        comparison_id: CrossLanguageComparisonId::from_bytes([71; 16]),
        policy_version: "cross-language-semantic-v1",
        started_at: "2026-07-31T00:00:00Z",
        finished_at: "2026-07-31T00:00:01Z",
        origins: &origins,
        groups: &groups,
    };
    Store::open(&database)
        .unwrap()
        .record_cross_language_comparison(&comparison)
        .unwrap();

    let args = ExplainArgs {
        path: std::env::current_dir().unwrap(),
        config: None,
        finding_id: "48".repeat(16),
        format: DetailFormat::Text,
        db: Some(database),
    };
    let mut output = Vec::new();
    assert_eq!(explain(&args, &mut output).unwrap(), Outcome::Success);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("cross-language semantic group"));
    assert!(output.contains("sequence-map-v1"));
    assert!(output.contains("rust rust/src/lib.rs:3-6 (rust-variant)"));
}

#[test]
fn dispatch_doctor_writes_diagnostics() {
    let mut buffer = Vec::new();
    let outcome = dispatch(&Command::Doctor, &mut buffer).expect("dispatch should succeed");
    assert_eq!(outcome, Outcome::Success);
    let text = String::from_utf8(buffer).expect("output is utf-8");
    assert!(text.contains("codehelion"));
    assert!(text.contains(env!("CARGO_PKG_VERSION")));
    // The test binary runs from the cargo target directory.
    assert!(text.contains("install: local build"));
    let expected_sandbox = if cfg!(target_os = "linux") {
        "OS memory ceilings available; network and filesystem containment unavailable"
    } else {
        "OS memory, network, and filesystem containment unavailable"
    };
    assert!(text.contains(expected_sandbox));
    assert!(text.contains("artifacts:"));
    assert!(text.contains("wasm: available"));
    assert!(text.contains("restricted semantic rules: 12 enabled"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn interrogating_a_helper_honours_the_requested_containment() {
    let program = tempfile::NamedTempFile::new().expect("creating placeholder helper");
    let facts = interrogate(
        "placeholder-helper",
        Some(program.path()),
        codehelion_helper::SandboxRequest::require_memory_limit(4096),
    )
    .expect("configured file is considered for interrogation");
    let doctor::HelperState::Silent(why) = facts.state else {
        panic!("an unenforceable limit must stop before starting: {facts:?}");
    };
    assert!(
        why.contains("OS memory containment is unavailable"),
        "{why}"
    );
}

#[test]
fn install_channel_is_inferred_from_the_executable_location() {
    let channel = |path: &str| install_channel(Path::new(path));
    assert_eq!(
        channel("/opt/homebrew/Cellar/codehelion/0.1.0/bin/codehelion"),
        "homebrew"
    );
    assert_eq!(channel("/home/user/.linuxbrew/bin/codehelion"), "homebrew");
    assert_eq!(
        channel("/home/user/.cargo/bin/codehelion"),
        "cargo (crates.io)"
    );
    assert_eq!(
        channel("/venv/lib/python3.12/site-packages/codehelion/bin/codehelion"),
        "pypi"
    );
    assert_eq!(
        channel("/work/codehelion/target/release/codehelion"),
        "local build"
    );
    assert_eq!(
        channel("/work/codehelion/target/llvm-cov-target/debug/codehelion"),
        "local build"
    );
    assert_eq!(
        channel("/usr/local/bin/codehelion"),
        "standalone (archive or manual install)"
    );
}

#[test]
fn findings_outcome_maps_to_dedicated_exit_code() {
    assert_eq!(Outcome::Success.exit_code(), ExitCode::SUCCESS);
    assert_eq!(
        Outcome::FindingsPresent.exit_code(),
        ExitCode::from(EXIT_FINDINGS)
    );
}
