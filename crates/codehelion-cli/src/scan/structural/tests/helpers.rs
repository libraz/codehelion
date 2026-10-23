//! Which compiler helpers a run is given, and what it says when it has
//! none.

use super::*;

#[test]
fn build_description_uses_the_configured_helper_timeout() {
    let mut config = Config::default();
    config.limits.helper_timeout_ms = 17;
    assert_eq!(
        helper_timeout(&config.limits),
        std::time::Duration::from_millis(17)
    );
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
        helper_timeout(&Config::default().limits),
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

    // A refusal is not a helper that failed: the file went unasked about, and
    // what to do about it is the permission the refusal names.
    assert_eq!(compiler.not_asked, 1);
    assert_eq!(compiler.not_asked_reasons["requires_execution"], 1);
    assert!(compiler.unavailable.is_empty());
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
    let limits = helper_limits(&Config::default(), true);
    let error = semantic_sandbox(true, &limits).expect_err("portable build cannot enforce it");
    assert!(
        format!("{error:#}").contains("OS memory containment is unavailable"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn untrusted_semantic_requires_a_linux_memory_limit() {
    let limits = helper_limits(&Config::default(), true);
    let request = semantic_sandbox(true, &limits).expect("Linux can enforce the requested ceiling");
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
    let compilers = fixture_compilers();
    let rust_only = LanguageSelection {
        rust: true,
        c: false,
        cpp: false,
    };
    let at_work = compilers.at_work(rust_only);
    assert_eq!(at_work.len(), 1, "only the Rust helper reads this tree");
    for helper in at_work {
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
        siblings_by_signature: false,
        show_near_misses: false,
        include_trivial: false,
        include_vendored: false,
        view: crate::cli::ViewArgs::default(),
        no_reuse: false,
        fail_on_findings: false,
        untrusted: false,
    };
    let compilers = fixture_compilers();
    let mut out = Vec::new();
    run_with(&args, &mut out, Some(&compilers)).expect("an empty tree scans");
}

/// Both helpers described by fixture facts, so these cases run whatever is
/// installed on the machine.
fn fixture_compilers() -> Compilers {
    let answering = |component: codehelion_core::doctor::HelperComponent, path: &str| {
        installed_helper(
            component,
            HelperFacts {
                path: PathBuf::from(path),
                state: HelperState::Answered(Greeting {
                    version: "1.0.0".to_owned(),
                    protocol: 2,
                    toolchains: vec!["fixture".to_owned()],
                    capabilities: vec!["types".to_owned()],
                    executes: Vec::new(),
                }),
            },
            &ExecutionPolicy::deny_all(),
            SandboxRequest::unrestricted(),
        )
        .expect("an answering fixture helper is admitted")
    };
    Compilers {
        installed: vec![
            answering(RUST_HELPER, "/tool/codehelion-backend-rust"),
            answering(CLANG_HELPER, "/tool/codehelion-backend-clang"),
        ],
    }
}

/// Helpers read the tree's own files, so every semantic run hands them the
/// file ceiling the scanner reads the same tree under; an untrusted run hands
/// them the lowered one.
#[test]
fn helpers_are_held_to_the_scanners_file_ceiling() {
    let mut config = Config::default();
    config.limits.max_file_bytes = 4096;
    let trusted = semantic_sandbox(false, &helper_limits(&config, false))
        .expect("a trusted run needs no OS containment");
    assert_eq!(trusted.max_file_bytes(), Some(4096));
    assert_eq!(trusted.max_memory_bytes(), None);

    config.limits.max_file_bytes = u64::MAX;
    let untrusted = helper_limits(&config, true);
    assert_eq!(
        untrusted.max_file_bytes,
        codehelion_core::execution::Limits::untrusted().max_file_bytes
    );
}

#[test]
fn the_handshake_deadline_is_the_configured_helper_timeout() {
    let mut config = Config::default();
    config.limits.helper_timeout_ms = 60_000;
    assert_eq!(
        helper_timeout(&helper_limits(&config, false)),
        std::time::Duration::from_secs(60)
    );
    assert!(
        helper_timeout(&helper_limits(&config, true))
            <= codehelion_core::execution::Limits::untrusted().helper_timeout,
        "an untrusted run lowers the handshake deadline with the rest"
    );
}
