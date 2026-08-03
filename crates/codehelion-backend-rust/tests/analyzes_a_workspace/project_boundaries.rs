use super::*;

/// The baseline. Every category asserted here can be checked by opening the
/// fixture: `amount` is an `i64`, `label` is a `String`, and `labels` returns a
/// `Vec<String>`.
#[test]
fn a_plain_workspace_comes_back_with_types_a_reader_can_check() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
    assert_eq!(category_of(&ir, "amount"), TypeCategory::Integer);
    // A struct in the standard library, reported by its shape rather than as
    // the record it technically is: the category exists so that this and a C++
    // `std::string` are the same answer.
    assert_eq!(category_of(&ir, "label"), TypeCategory::Text);
    assert_eq!(category_of(&ir, "labels"), TypeCategory::Sequence);
    assert_eq!(category_of(&ir, "debits"), TypeCategory::Integer);
}

/// Closed standard API evidence is separate from the stable definition
/// identity, so a later cross-language rule never recovers meaning from an
/// arbitrary workspace method name.
#[test]
fn standard_iterator_calls_carry_closed_api_names() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    let names = ir
        .calls
        .iter()
        .filter_map(|call| call.api_name.as_deref())
        .collect::<Vec<_>>();
    assert!(names.contains(&"rust::Iterator::map"), "{names:?}");
    assert!(names.contains(&"rust::Iterator::collect"), "{names:?}");
    assert!(names.contains(&"rust::slice::iter"), "{names:?}");
}

/// The serialization rule is allowed only when the helper resolved both
/// standard APIs. A project method named `parse` or `to_string` cannot enter
/// this evidence path.
#[test]
fn standard_text_round_trip_calls_carry_closed_api_names() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    let names = ir
        .calls
        .iter()
        .filter_map(|call| call.api_name.as_deref())
        .collect::<Vec<_>>();
    assert!(names.contains(&"rust::ToString::to_string"), "{names:?}");
    assert!(names.contains(&"rust::str::parse"), "{names:?}");
}

/// The limited def-use summary must prove only a direct, compiler-resolved
/// iterator receiver chain. A binding between the calls is intentionally not
/// treated as the same fact: following bindings would be general data-flow.
#[test]
fn a_direct_filter_map_receiver_chain_is_recorded_without_following_bindings() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert!(ir.data_flow.computed);
    assert_eq!(ir.data_flow.flows.len(), 1, "{:?}", ir.data_flow.flows);
    let (source, sink) = &ir.data_flow.flows[0];
    assert!(source.ends_with(":rust::Iterator::filter"), "{source}");
    assert!(sink.ends_with(":rust::Iterator::map"), "{sink}");
}

/// Anchors have to point at the fixture's own text, since a fragment is cut
/// from a file and a finding anchored anywhere else is unusable.
#[test]
fn every_symbol_is_anchored_where_it_was_written() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert!(!ir.symbols.is_empty());
    for symbol in &ir.symbols {
        let anchor = &symbol.anchor.expansion;
        assert_eq!(anchor.file, "ledger/src/lib.rs", "{}", symbol.name);
        assert!(anchor.end_byte > anchor.start_byte, "{}", symbol.name);
        assert!(anchor.start_line >= 1, "{}", symbol.name);
        // Written where it stands: nothing here comes from a macro, and
        // claiming otherwise would put a definition nobody wrote at a place
        // somebody did.
        assert_eq!(symbol.anchor.definition, None, "{}", symbol.name);
    }
}

/// A crate whose types only exist after a build script has run cannot be
/// analysed without running it. Answering with whatever happens to resolve
/// would report a partial reading as a complete one.
#[test]
fn a_crate_that_needs_its_build_script_is_declined_by_name() {
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let unit = UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::RequiresExecution),
        Analysis::Done(ir) => panic!("analysed a crate it could not have read: {ir:?}"),
    }
}

/// And declining it has to leave no trace of having run it. The two are not the
/// same claim: a helper that ran the build script and then reported
/// `RequiresExecution` would pass the test above.
#[test]
fn declining_a_build_script_does_not_run_it() {
    let marker = codehelion_fixtures::execution_marker("build-script").unwrap();
    assert!(
        !marker.exists(),
        "{} existed before the helper was asked anything",
        marker.display()
    );
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let _ = analyze(&UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    });
    assert!(
        !marker.exists(),
        "{} appeared: the helper ran the fixture's build script",
        marker.display()
    );
}

/// The other half of refusing: permitted, the crate is analysed rather than
/// declined, and the script that was declined before has now run.
///
/// Against a copy, not the fixture. The fixture's marker is the evidence that
/// nothing in this checkout ran its build script, and a test that ran it in
/// place would spend that evidence to prove one thing about permission.
#[test]
fn permitting_a_build_script_runs_it_and_analyses_what_it_wrote() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("build-script");
    copy_fixture(&codehelion_fixtures::rust("build-script").unwrap(), &root);
    let marker = root.join(codehelion_fixtures::EXECUTION_MARKER);
    assert!(!marker.exists(), "the copy starts as the fixture does");

    let unit = UnitRef {
        // The crate, not the package: cargo's `generated-tables` is compiled
        // as `generated_tables`, and a unit is named by what the compiler
        // calls it.
        unit: "generated_tables".to_string(),
        file: root.join("src/lib.rs").display().to_string(),
        variant: "host".to_string(),
    };
    let mut helper = helper().permitting(vec![Execution::BuildScript]);
    let analysis = helper
        .analyze(&unit, &[Capability::Types])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");

    assert!(
        matches!(analysis, Analysis::Done(_)),
        "permitted, the crate is read rather than declined: {analysis:?}"
    );
    assert!(
        marker.exists(),
        "{} is missing: nothing ran, so permitting it bought nothing",
        marker.display()
    );
}

/// Copy a fixture's own files, and only those: a `target` directory left by an
/// earlier run would be carried into a tree whose whole point is that nothing
/// has been built in it yet.
fn copy_fixture(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the copy");
    for entry in std::fs::read_dir(from).expect("read the fixture") {
        let entry = entry.expect("read an entry");
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let source = entry.path();
        let destination = to.join(&name);
        if source.is_dir() {
            copy_fixture(&source, &destination);
        } else {
            std::fs::copy(&source, &destination).expect("copy a file");
        }
    }
}

/// One process, asked twice, must not answer differently the second time. The
/// workspace is cached between requests, and a cache that changed an answer
/// would be a cache that made results depend on what was asked before.
#[test]
fn asking_twice_in_one_process_gives_the_same_answer() {
    let target = unit("plain", "ledger", "ledger");
    let mut helper = helper();
    let first = helper.analyze(&target, &[Capability::Types]).unwrap();
    let second = helper.analyze(&target, &[Capability::Types]).unwrap();
    helper.shutdown().unwrap();
    assert_eq!(first, second);
}

/// What a run files its answers under, asked of the side that resolves it.
///
/// Both halves matter. The features name the package that enables them,
/// because two packages' features of one name are unrelated; the settings are
/// the compiler's own, so that the same source read for two targets is two
/// readings rather than one.
#[test]
fn a_project_says_which_features_it_is_read_with() {
    let described = describe(&codehelion_fixtures::rust("features").unwrap());
    assert_eq!(described.features, vec!["counters/default".to_string()]);
    assert!(
        described
            .cfgs
            .iter()
            .any(|cfg| cfg.starts_with("target_os")),
        "the compiler's own settings should be there: {:?}",
        described.cfgs
    );
}

/// A member can change a direct dependency's features without moving the
/// lockfile. Those flags alter the resolved program, so describing only the
/// member's own feature set would let two different readings share a variant.
#[test]
fn a_direct_dependency_feature_is_part_of_the_build_description() {
    let directory = tempfile::tempdir().expect("temporary workspace");
    let root = directory.path();
    std::fs::create_dir_all(root.join("app/src")).expect("create app source");
    std::fs::create_dir_all(root.join("support/src")).expect("create dependency source");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\", \"support\"]\nresolver = \"2\"\n",
    )
    .expect("write workspace manifest");
    let app_manifest = |features: &str| {
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
             [dependencies]\nsupport = {{ path = \"../support\"{features} }}\n"
        )
    };
    std::fs::write(root.join("app/Cargo.toml"), app_manifest(""))
        .expect("write app manifest without the dependency feature");
    std::fs::write(
        root.join("app/src/lib.rs"),
        "pub fn answer() -> u8 { 42 }\n",
    )
    .expect("write app source");
    std::fs::write(
        root.join("support/Cargo.toml"),
        "[package]\nname = \"support\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [features]\ndefault = [\"wide\"]\nwide = []\nextra = []\n",
    )
    .expect("write dependency manifest");
    std::fs::write(root.join("support/src/lib.rs"), "pub struct Support;\n")
        .expect("write dependency source");
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"support\",\n]\n\n[[package]]\nname = \"support\"\nversion = \"0.1.0\"\n",
    )
    .expect("write workspace lockfile");

    let without_extra = describe(root);
    assert!(
        !without_extra
            .features
            .iter()
            .any(|feature| feature == "support/extra"),
        "{without_extra:?}"
    );

    std::fs::write(
        root.join("app/Cargo.toml"),
        app_manifest(", features = [\"extra\"]"),
    )
    .expect("enable dependency feature");
    let with_extra = describe(root);
    assert!(
        with_extra
            .features
            .iter()
            .any(|feature| feature == "support/extra"),
        "{with_extra:?}"
    );
}

/// A tree with no project in it is described as having no build, which is not
/// the same as failing to describe it: every run over such a tree reads it the
/// same way, so an empty answer is the answer.
#[test]
fn a_tree_with_no_project_in_it_is_described_as_having_no_build() {
    let described = describe(Path::new("/nowhere/at/all"));
    assert_eq!(described, codehelion_helper::BuildDescription::default());
}

/// A described build always has settings — the target alone supplies dozens —
/// so the empty description above says what it says without a flag for it.
#[test]
fn a_project_that_enables_nothing_is_still_described_by_its_target() {
    let described = describe(&codehelion_fixtures::rust("plain").unwrap());
    assert!(described.features.is_empty(), "{:?}", described.features);
    assert!(!described.cfgs.is_empty());
}

fn describe(root: &Path) -> codehelion_helper::BuildDescription {
    let mut helper = helper();
    let described = helper.describe(root).expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    described
}

/// A unit nobody can place is refused rather than guessed at.
#[test]
fn a_unit_outside_any_project_is_reported_as_having_no_build_information() {
    let unit = UnitRef {
        unit: "nothing".to_string(),
        file: "/nowhere/at/all/src/lib.rs".to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::NoBuildInformation),
        Analysis::Done(ir) => panic!("analysed a project that is not there: {ir:?}"),
    }
}

/// A locked, offline metadata read must decline a dependency graph that Cargo
/// would otherwise create a lockfile for. The real helper is used because the
/// command invocation is the behavior under test.
#[test]
fn a_missing_lockfile_is_unavailable_without_creating_it() {
    let project = tempfile::tempdir().expect("temporary project");
    let source = project.path().join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"offline-lock-check\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest");
    std::fs::write(&source, "pub fn answer() -> u8 { 42 }\n").expect("source");

    let mut helper = helper();
    let result = helper
        .analyze(
            &UnitRef {
                unit: "offline_lock_check".to_owned(),
                file: source.display().to_string(),
                variant: "host".to_owned(),
            },
            &[Capability::Types],
        )
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");

    assert_eq!(
        result,
        Analysis::Missing(Unavailability::MetadataUnavailable)
    );
    assert!(
        !project.path().join("Cargo.lock").exists(),
        "metadata must not create a lockfile"
    );
}

/// A target repository cannot select a rustup toolchain for the helper. The
/// helper fixes its own installed sysroot before it reads this manifest, so an
/// unavailable channel is neither downloaded nor consulted.
#[test]
fn a_target_rust_toolchain_file_cannot_replace_the_helpers_toolchain() {
    let project = tempfile::tempdir().expect("temporary project");
    let source = project.path().join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source directory")).expect("create source");
    std::fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"fixed-helper-toolchain\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        project.path().join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"fixed-helper-toolchain\"\nversion = \"0.1.0\"\n",
    )
    .expect("lockfile");
    std::fs::write(
        project.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"codehelion-target-must-not-control-rustup\"\n",
    )
    .expect("target toolchain file");
    std::fs::write(&source, "pub fn answer() -> u8 { 42 }\n").expect("source");

    let mut helper = helper();
    helper
        .describe(project.path())
        .expect("the target toolchain file must not affect metadata");
    let result = helper
        .analyze(
            &UnitRef {
                unit: "fixed_helper_toolchain".to_owned(),
                file: source.display().to_string(),
                variant: "host".to_owned(),
            },
            &[Capability::Types],
        )
        .expect("the helper should answer with its fixed toolchain");
    helper.shutdown().expect("the helper should stop cleanly");

    assert!(matches!(result, Analysis::Done(_)));
}

/// One request names one source file. A helper may load the containing crate,
/// but it must not send declarations from sibling source files as though they
/// were an answer about the requested file.
#[test]
fn each_rust_request_contains_only_the_requested_files_symbols() {
    let project = tempfile::tempdir().expect("temporary project");
    let source = project.path().join("src");
    std::fs::create_dir_all(&source).expect("source directory");
    std::fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"per-file-ir\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        project.path().join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"per-file-ir\"\nversion = \"0.1.0\"\n",
    )
    .expect("lockfile");
    let root = source.join("lib.rs");
    let sibling = source.join("sibling.rs");
    std::fs::write(&root, "pub mod sibling;\npub fn root_only() {}\n").expect("root source");
    std::fs::write(&sibling, "pub fn sibling_only() {}\n").expect("sibling source");

    let mut helper = helper();
    let mut analyze_file = |file: &Path| {
        helper
            .analyze(
                &UnitRef {
                    unit: "per_file_ir".to_owned(),
                    file: file.display().to_string(),
                    variant: "host".to_owned(),
                },
                &[Capability::Types, Capability::NameResolution],
            )
            .expect("the helper should answer")
    };
    let root_ir = match analyze_file(&root) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("root source was unavailable: {reason:?}"),
    };
    let sibling_ir = match analyze_file(&sibling) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("sibling source was unavailable: {reason:?}"),
    };
    helper.shutdown().expect("the helper should stop cleanly");

    assert!(
        root_ir
            .symbols
            .iter()
            .any(|symbol| symbol.name == "root_only")
    );
    assert!(
        root_ir
            .symbols
            .iter()
            .all(|symbol| symbol.anchor.expansion.file == "src/lib.rs"),
        "root answer leaked another file: {:?}",
        root_ir.symbols
    );
    assert!(
        sibling_ir
            .symbols
            .iter()
            .any(|symbol| symbol.name == "sibling_only")
    );
    assert!(
        sibling_ir
            .symbols
            .iter()
            .all(|symbol| symbol.anchor.expansion.file == "src/sibling.rs"),
        "sibling answer leaked another file: {:?}",
        sibling_ir.symbols
    );
}
