use super::*;

/// Whether a compiler helper is installed is a property of the machine this
/// runs on, so what is fixed here is the pairing. Without one, the mode says
/// which program supplies it and stops — it does not answer without a compiler
/// and call the answer semantic. With one, the report says how much of the
/// tree the compiler could speak for, which is what tells a thin semantic run
/// apart from a tree with little duplication in it.
#[test]
fn semantic_mode_either_asks_a_compiler_or_says_which_one_is_missing() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "semantic"])
        .output()
        .expect("the scan should run");
    if output.status.success() {
        let text = String::from_utf8(output.stdout).expect("output is utf-8");
        assert!(text.contains("compiler: answered for"), "{text}");
    } else {
        let text = String::from_utf8(output.stderr).expect("output is utf-8");
        assert!(text.contains("codehelion-backend-rust"), "{text}");
    }
}

/// A scan rooted inside a workspace spells its files against that root, and
/// the compiler spells them against the workspace's. Matched on the scan's own
/// spelling the two never meet, and every file's types go missing without
/// anything saying so — the analysis says what it anchored against so the two
/// can be brought together instead.
#[test]
fn a_scan_below_the_workspace_root_still_gets_what_the_compiler_resolved() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("member/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("member/Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    // The second file is a declared module: a file no crate reaches is a file
    // the compiler resolves nothing in, which would leave the group scored the
    // way an unanchored one is and prove nothing about the anchoring.
    std::fs::write(
        root.join("member/src/lib.rs"),
        format!("mod other;\n\n{CHECKSUM_RS}"),
    )
    .unwrap();
    std::fs::write(root.join("member/src/other.rs"), CHECKSUM_RS).unwrap();

    let output = cmd()
        .current_dir(root.join("member"))
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("the scan should run");
    if !output.status.success() {
        // No helper on this machine, which the pairing test above covers.
        return;
    }
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(report["summary"]["compiler"]["answered"], 2);
    let types = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find_map(|group| group["similarity"]["type_similarity"].as_f64())
        .expect("a group scored on every dimension");
    assert!(
        (types - 1.0).abs() < f64::EPSILON,
        "two copies of one function agree on their types: {report}"
    );
}

/// Two readings of one tree under different features are two programs, and a
/// run has to file them apart. Nothing in the source text changes when a
/// feature is switched on — the manifest is not a file the scan reads — so a
/// run that took its identity from the tree alone would report the first
/// reading's findings as this one's, and the types the compiler resolved
/// differently would go unremarked.
#[test]
fn one_tree_read_with_different_features_is_not_reported_as_the_other() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    let manifest = |default: &str| {
        format!(
            "[workspace]\n\n[package]\nname = \"counters\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\npublish = false\n\n\
             [features]\ndefault = [{default}]\nwide = []\n"
        )
    };
    std::fs::write(root.join("Cargo.toml"), manifest("")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "#[cfg(feature = \"wide\")]\npub type Count = i64;\n\
         #[cfg(not(feature = \"wide\"))]\npub type Count = i16;\n\
         pub fn counted(values: &[Count]) -> Count { values.iter().sum() }\n",
    )
    .unwrap();

    let scan = || {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    // The same reading twice: reported from what was recorded, which is what
    // makes the third scan below say something.
    let again = scan().expect("the helper answered once, so it answers again");
    assert_eq!(again["run"]["reused"], serde_json::json!(true));

    std::fs::write(root.join("Cargo.toml"), manifest("\"wide\"")).unwrap();
    let widened = scan().expect("the helper answers");
    assert_ne!(
        widened["run"]["reused"],
        serde_json::json!(true),
        "{widened}"
    );
    assert_ne!(widened["run"]["run_id"], first["run"]["run_id"]);
}

/// A Cargo manifest can change a direct dependency's active features while the
/// lockfile stays byte-for-byte identical. The semantic variant must carry the
/// helper's resolved dependency feature set, or it would reuse findings for a
/// different program.
#[test]
fn a_direct_dependency_feature_change_gets_its_own_semantic_variant() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("app/src")).unwrap();
    std::fs::create_dir_all(root.join("support/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\", \"support\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    let app_manifest = |features: &str| {
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
             [dependencies]\nsupport = {{ path = \"../support\"{features} }}\n"
        )
    };
    std::fs::write(root.join("app/Cargo.toml"), app_manifest("")).unwrap();
    std::fs::write(
        root.join("app/src/lib.rs"),
        "pub fn answer() -> u8 { support::answer() }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("support/Cargo.toml"),
        "[package]\nname = \"support\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [features]\nextra = []\n",
    )
    .unwrap();
    std::fs::write(
        root.join("support/src/lib.rs"),
        "#[cfg(feature = \"extra\")]\npub fn answer() -> u8 { 2 }\n\
         #[cfg(not(feature = \"extra\"))]\npub fn answer() -> u8 { 1 }\n",
    )
    .unwrap();

    let scan = || {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    let lockfile_before = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    let again = scan().expect("the helper answered once, so it answers again");
    assert_eq!(again["run"]["reused"], serde_json::json!(true));

    std::fs::write(
        root.join("app/Cargo.toml"),
        app_manifest(", features = [\"extra\"]"),
    )
    .unwrap();
    let changed = scan().expect("the helper answers after a dependency feature changes");
    assert_eq!(
        std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default(),
        lockfile_before,
        "the lockfile cannot be the signal that keeps these runs apart"
    );
    assert_ne!(
        changed["run"]["reused"],
        serde_json::json!(true),
        "{changed}"
    );
    assert_ne!(changed["run"]["run_id"], first["run"]["run_id"]);
}

/// The three ways a permission would be granted and change nothing. Each is
/// refused with the sentence that says which, because a permission that was
/// accepted and dropped leaves somebody believing the thin answer they got is
/// what their project looks like.
#[test]
fn a_permission_that_could_not_take_effect_is_refused_rather_than_dropped() {
    let dir = fixture();
    let refused = |extra: &[&str]| {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", "."])
            .args(extra)
            .output()
            .expect("the scan should run");
        assert!(!output.status.success(), "{output:?}");
        String::from_utf8(output.stderr).expect("output is utf-8")
    };

    // A mode that runs nothing whatever it is told.
    let said = refused(&["--allow-execution=build-script"]);
    assert!(said.contains("fast"), "{said}");

    // A trust level that permits nothing, and a permission, in one command.
    let said = refused(&[
        "--mode",
        "semantic",
        "--untrusted",
        "--allow-execution=build-script",
    ]);
    assert!(said.contains("--untrusted"), "{said}");

    // A class nobody can grant, which somebody who misspelled one believes
    // they granted.
    let said = refused(&["--mode", "semantic", "--allow-execution=build-scripts"]);
    assert!(said.contains("build-script"), "{said}");
}

/// Permitting a build script changes two things at once, and both have to
/// hold. The crate stops being declined, which is what was asked for; and the
/// run is filed apart from the refused one, which is what stops the refused
/// run's findings from being handed back as this one's — nothing in the source
/// text differs between the two, so the identity is the only thing that can
/// tell them apart.
#[test]
fn a_run_allowed_to_build_reads_more_and_is_filed_apart_from_one_that_was_not() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\n\n[package]\nname = \"generated\"\nversion = \"0.1.0\"\n\
         edition = \"2021\"\npublish = false\nbuild = \"build.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("build.rs"),
        "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    \
         std::fs::write(std::path::Path::new(&out).join(\"table.rs\"), \
         \"pub const SIZES: [u32; 3] = [1, 2, 4];\\n\").unwrap();\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/table.rs\"));\n\
         pub fn largest() -> u32 { SIZES.iter().copied().max().unwrap_or(0) }\n",
    )
    .unwrap();

    let scan = |extra: &[&str]| {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .args(extra)
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(refused) = scan(&[]) else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    assert_eq!(
        refused["summary"]["compiler"]["unavailable"]["requires_execution"],
        serde_json::json!(1),
        "{refused}"
    );

    let permitted = scan(&["--allow-execution=build-script"]).expect("the helper answers");
    assert_eq!(
        permitted["summary"]["compiler"]["answered"],
        serde_json::json!(1),
        "{permitted}"
    );
    assert_ne!(permitted["run"]["reused"], serde_json::json!(true));
    assert_ne!(permitted["run"]["run_id"], refused["run"]["run_id"]);
}

/// A recorded semantic run is reported again like any other, and it has to
/// come back with the sentence that makes it semantic. Restored short — no
/// compiler line, or one claiming files nobody asked about were failures — a
/// thin run would read as a clean tree the second time it was reported.
#[test]
fn a_semantic_run_reported_again_still_says_what_the_compiler_answered() {
    let dir = fixture();
    let scan = || {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", "semantic", "--format", "json"])
            .output()
            .expect("the scan should run");
        output.status.success().then(|| {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("stdout is one JSON document")
        })
    };
    let Some(first) = scan() else {
        // No helper on this machine, which the pairing test above covers.
        return;
    };
    let second = scan().expect("the helper answered once, so it answers again");
    let first_partitions = first["partitions"].as_array().expect("semantic partitions");
    let second_partitions = second["partitions"]
        .as_array()
        .expect("semantic partitions");
    assert_eq!(second_partitions.len(), first_partitions.len());
    for (again, original) in second_partitions.iter().zip(first_partitions) {
        assert_eq!(again["run"]["reused"], serde_json::json!(true), "{again}");
        assert_eq!(again["run"]["run_id"], original["run"]["run_id"]);
        assert_eq!(
            again["summary"]["compiler"],
            original["summary"]["compiler"]
        );
        assert!(
            again["summary"]["compiler"].is_object(),
            "a semantic run says what a compiler answered: {again}"
        );
    }
}

/// The reuse path's own tests: a tree nobody touched is reported from the
/// recorded run rather than analysed again, and every input that could change
/// the answer defeats that.
mod reuse {
    use super::{cmd, fixture};
    use std::path::Path;

    /// Scan and parse, letting the reuse decision take its course.
    fn scan(root: &Path, extra: &[&str]) -> serde_json::Value {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--format", "json"])
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
    }

    fn reused(value: &serde_json::Value) -> bool {
        value["run"]["reused"] == serde_json::json!(true)
    }

    /// The report a reused run produces is the report an analysis produces:
    /// everything but the run's own metadata and what it says about *this*
    /// invocation's comparisons.
    fn findings(mut value: serde_json::Value) -> serde_json::Value {
        let run = value["run"].as_object_mut().expect("run object");
        for key in ["started_at", "finished_at", "run_id", "reused"] {
            run.remove(key);
        }
        let summary = value["summary"].as_object_mut().expect("summary object");
        for key in ["changes", "audit"] {
            summary.remove(key);
        }
        value
    }

    #[test]
    fn an_untouched_tree_is_reported_from_the_run_that_read_it() {
        let dir = fixture();
        let analysed = scan(dir.path(), &["--no-reuse"]);
        assert!(!reused(&analysed));

        let again = scan(dir.path(), &[]);
        assert!(reused(&again), "{again:#?}");
        assert_eq!(again["run"]["run_id"], analysed["run"]["run_id"]);
        assert_eq!(findings(again), findings(analysed));
    }

    #[test]
    fn reporting_a_run_again_records_no_second_run() {
        let dir = fixture();
        scan(dir.path(), &["--no-reuse"]);
        scan(dir.path(), &[]);
        scan(dir.path(), &[]);

        let store = super::open_store(dir.path());
        let latest = store.latest_run().unwrap().expect("a recorded run");
        assert_eq!(latest.id, 1, "the reused scans recorded nothing");
    }

    #[test]
    fn a_file_that_moved_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        std::fs::write(
            dir.path().join("src/new.rs"),
            "pub fn added() -> u8 { 1 }\n",
        )
        .unwrap();
        assert!(!reused(&scan(dir.path(), &[])));
    }

    #[test]
    fn a_changed_setting_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        assert!(reused(&scan(dir.path(), &[])));

        std::fs::write(
            dir.path().join("codehelion.toml"),
            "min-clone-tokens = 25\n",
        )
        .unwrap();
        assert!(!reused(&scan(dir.path(), &[])));
    }

    /// A baseline is not part of the configuration, so the run has to record
    /// which frozen set it was reported against: the same tree under two
    /// baselines is two different reports.
    #[test]
    fn a_different_frozen_set_is_analysed_again() {
        let dir = fixture();
        scan(dir.path(), &[]);
        cmd()
            .current_dir(dir.path())
            .args(["baseline", "create", "."])
            .assert()
            .success();

        let with = ["--baseline", "codehelion-baseline.json"];
        assert!(!reused(&scan(dir.path(), &with)), "a baseline came in");
        assert!(reused(&scan(dir.path(), &with)), "the same baseline again");
        assert!(!reused(&scan(dir.path(), &[])), "the baseline went away");
    }

    /// A mode is a different reading of the same bytes, so one mode's run says
    /// nothing about another's.
    #[test]
    fn another_mode_is_analysed_rather_than_answered_from_this_one() {
        let dir = fixture();
        scan(dir.path(), &[]);
        assert!(!reused(&scan(dir.path(), &["--mode", "structural"])));
        assert!(reused(&scan(dir.path(), &["--mode", "structural"])));
        assert!(
            reused(&scan(dir.path(), &[])),
            "the Fast run is still there"
        );
    }
}
