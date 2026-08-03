use super::report_command::*;
use super::*;
use crate::cli::{BaselineMode, SortAxis};
use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::Language;
use codehelion_core::semantic::{
    OperationAttributes, OperationEdge, OperationEdgeKind, OperationKind, OperationNode,
    SemanticOperationGraph,
};
use codehelion_core::stable_id::{
    CrossLanguageComparisonId, CrossLanguageGroupId, CrossLanguageMemberId,
    CrossVariantComparisonId, CrossVariantGroupId, CrossVariantMemberId,
};
use codehelion_store::snapshot::{
    CrossLanguageComparisonSnapshot, CrossLanguageSemanticGroupRow, CrossLanguageSemanticMemberRow,
    CrossVariantComparisonSnapshot, CrossVariantGroupRow, CrossVariantMemberRow,
};

#[test]
fn comparison_and_presentation_flags_reject_unsupported_modes() {
    let mut args = ScanArgs {
        helpers: Vec::new(),
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: PathBuf::from("."),
        mode: Mode::Fast,
        format: cli::Format::Text,
        output: None,
        force: false,
        config: None,
        no_ignore: false,
        follow_links: false,
        compile_commands: None,
        jobs: None,
        db: None,
        baseline: None,
        baseline_mode: BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: true,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        show_near_misses: false,
        include_trivial: false,
        include_vendored: false,
        view: cli::ViewArgs::default(),
        no_reuse: false,
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
        diagnostics: std::collections::BTreeMap::new(),
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
    assert!(format!("{error:#}").contains("no finding or clone/comparison group"));
}

#[test]
fn explain_reads_a_cross_variant_group_from_the_id_the_report_prints() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.db");
    let origins = vec!["debug-variant".to_string(), "release-variant".to_string()];
    let groups = vec![CrossVariantGroupRow {
        group_id: CrossVariantGroupId::from_bytes([80; 16]),
        clone_type: CloneClass::Type1,
        members: vec![
            CrossVariantMemberRow {
                member_id: CrossVariantMemberId::from_bytes([81; 16]),
                origin_variant: origins[0].clone(),
                language: Language::Cpp,
                file_path: "src/shared.cpp".to_string(),
                start_line: 3,
                end_line: 8,
                unit_name: Some("shared".to_string()),
                token_count: 24,
            },
            CrossVariantMemberRow {
                member_id: CrossVariantMemberId::from_bytes([82; 16]),
                origin_variant: origins[1].clone(),
                language: Language::Cpp,
                file_path: "src/shared.cpp".to_string(),
                start_line: 3,
                end_line: 8,
                unit_name: Some("shared".to_string()),
                token_count: 24,
            },
        ],
    }];
    let comparison = CrossVariantComparisonSnapshot {
        root_path: "/repo",
        comparison_id: CrossVariantComparisonId::from_bytes([79; 16]),
        policy_version: "cross-variant-exact-v1",
        started_at: "2026-08-03T00:00:00Z",
        finished_at: "2026-08-03T00:00:01Z",
        origins: &origins,
        groups: &groups,
    };
    Store::open(&database)
        .unwrap()
        .record_cross_variant_comparison(&comparison)
        .unwrap();

    let args = ExplainArgs {
        path: std::env::current_dir().unwrap(),
        config: None,
        finding_id: "50".repeat(16),
        format: DetailFormat::Json,
        db: Some(database),
        untrusted: false,
    };
    let mut output = Vec::new();
    assert_eq!(explain(&args, &mut output).unwrap(), Outcome::Success);
    let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(output["response_kind"], "cross_variant_group");
    assert_eq!(output["group_id"], "50".repeat(16));
    assert_eq!(output["comparison_id"], "4f".repeat(16));
    assert_eq!(output["members"].as_array().map(Vec::len), Some(2));
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
                member_id: CrossLanguageMemberId::from_bytes([73; 16]),
                origin_variant: "rust-variant".to_string(),
                language: Language::Rust,
                file_path: "rust/src/lib.rs".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v4".to_string(),
                graph_json,
            },
            CrossLanguageSemanticMemberRow {
                member_id: CrossLanguageMemberId::from_bytes([74; 16]),
                origin_variant: "cpp-variant".to_string(),
                language: Language::Cpp,
                file_path: "cpp/src/map.cpp".to_string(),
                start_line: 3,
                end_line: 6,
                unit_name: Some("map_values".to_string()),
                graph_schema_version: "sog-v4".to_string(),
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
        untrusted: false,
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
    let args = DoctorArgs {
        helpers: Vec::new(),
        path: std::env::current_dir().expect("current directory is available"),
        config: None,
        db: None,
        untrusted: false,
    };
    let outcome = dispatch(&Command::Doctor(args), &mut buffer).expect("dispatch should succeed");
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
    assert!(text.contains(
        "restricted semantic rules: 8 enabled; 4 cross-language rules require --compare-languages"
    ));
}

#[test]
fn database_metadata_errors_are_not_reported_as_absent() {
    let blocker = tempfile::NamedTempFile::new().expect("create non-directory path component");
    let database = blocker.path().join("audit.db");
    let error = database_storage_bytes(&database_files(&database))
        .expect_err("metadata under a file must remain an OS error");
    let source = error
        .downcast_ref::<io::Error>()
        .expect("the database metadata error is retained");
    assert_eq!(source.kind(), io::ErrorKind::NotADirectory);
}

#[test]
fn untrusted_reading_commands_confine_a_configured_database_but_not_explicit_db() {
    let repository = tempfile::tempdir().expect("create repository");
    let config = repository.path().join("untrusted.toml");
    std::fs::write(&config, "database = \"../outside.db\"").expect("write configuration");

    let error = resolve_db_at(repository.path(), None, Some(&config), true)
        .expect_err("untrusted configuration must not escape the selected repository");
    assert!(error.to_string().contains("`..` can escape"));

    let explicit = PathBuf::from("../operator-selected.db");
    assert_eq!(
        resolve_db_at(repository.path(), Some(&explicit), Some(&config), true)
            .expect("an explicit database remains an operator choice"),
        explicit
    );
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
