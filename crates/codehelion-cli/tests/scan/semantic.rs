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
        .args(["scan", ".", "--mode", "semantic", "-v"])
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

fn write_semantic_replay_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("src")).expect("fixture source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic_replay_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        r"
pub fn checksum_a(seed: u64, data: &[u64]) -> u64 {
    let mut total = seed;
    for item in data {
        total = total.wrapping_mul(31).wrapping_add(*item);
    }
    total
}

pub fn checksum_b(seed: u64, data: &[u64]) -> u64 {
    let mut total = seed;
    for item in data {
        total = total.wrapping_mul(31).wrapping_add(*item);
    }
    total
}

pub fn checksum_sibling(seed: u64, data: &[u64]) -> u64 {
    let mut total = seed;
    for item in data {
        total = total.wrapping_add(*item);
    }
    if total > 100 { total } else { 0 }
}
",
    )
    .expect("fixture source");
}

/// A semantic report rendered directly after the scan and one reconstructed
/// from its completed snapshot must expose the same persisted evidence. The
/// fixture supplies enough primary groups and supplemental siblings to make
/// detector-version and ordering drift observable here.
#[test]
fn a_semantic_fresh_report_matches_report_run_for_persisted_evidence() {
    let fixture = tempfile::tempdir().expect("semantic replay fixture");
    write_semantic_replay_fixture(fixture.path());
    let database = tempfile::tempdir().expect("database directory");
    let database_path = database.path().join("audit.db");
    let database_text = database_path.to_str().expect("database path is utf-8");
    let first = cmd()
        .current_dir(fixture.path())
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--siblings-by-signature",
            "--format",
            "json",
            "--no-reuse",
            "--db",
            database_text,
        ])
        .output()
        .expect("the semantic scan should run");
    if !first.status.success() {
        // The compiler helper is optional on a developer machine. The other
        // semantic tests cover the explicit missing-helper contract.
        return;
    }
    let fresh: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("fresh semantic output is one JSON document");
    let fresh = fresh["partitions"]
        .as_array()
        .and_then(|partitions| {
            partitions.iter().find(|partition| {
                partition["siblings"]
                    .as_array()
                    .is_some_and(|s| !s.is_empty())
            })
        })
        .unwrap_or(&fresh);
    assert!(
        fresh["siblings"]
            .as_array()
            .is_some_and(|siblings| !siblings.is_empty()),
        "the real semantic E2E fixture must retain sibling evidence"
    );
    assert_eq!(
        fresh["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([]),
        "Semantic mode must not claim Fast-only unmeasured values: {fresh}"
    );
    assert!(
        fresh["run"]["detector_versions"]
            .as_array()
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version["component"] == "compiler_ir")
            }),
        "a compiler-answering semantic run must name its IR schema detector"
    );
    let run_id = fresh["run"]["run_id"]
        .as_i64()
        .expect("fresh semantic output names its run");
    let run_text = run_id.to_string();
    let replayed = cmd()
        .current_dir(fixture.path())
        .args([
            "report",
            "--path",
            ".",
            "--run",
            &run_text,
            "--format",
            "json",
            "--db",
            database_text,
        ])
        .output()
        .expect("the recorded semantic run should replay");
    assert!(replayed.status.success(), "{replayed:?}");
    let replayed: serde_json::Value =
        serde_json::from_slice(&replayed.stdout).expect("replay is one JSON document");

    assert_eq!(
        fresh["run"]["detector_versions"], replayed["run"]["detector_versions"],
        "fresh and replayed semantic runs must name the same detector versions"
    );
    assert_eq!(fresh["siblings"], replayed["siblings"]);
    assert_eq!(fresh["groups"], replayed["groups"]);
    assert_eq!(fresh["summary"], replayed["summary"]);
    assert_eq!(fresh["near_misses"], replayed["near_misses"]);
    assert_eq!(
        replayed["summary"]["unmeasured_in_this_mode"],
        serde_json::json!([]),
        "Semantic replay must not claim Fast-only unmeasured values: {replayed}"
    );
}

/// A tree of registered pipelines that all normalize to the same shape, so the
/// semantic candidate index holds them in one bucket of `count` members.
fn write_pipeline_bucket_fixture(root: &Path, count: u64) {
    std::fs::create_dir_all(root.join("src")).expect("fixture source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"pipeline_bucket_fixture\"\nversion = \"0.1.0\"\n\
         edition = \"2024\"\npublish = false\n",
    )
    .expect("fixture manifest");
    // A dependency-free lock file: the helper reads a locked resolution and
    // will not write one into a tree it was only asked to read.
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n\
         [[package]]\nname = \"pipeline_bucket_fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("fixture lock file");
    let source = (0..count)
        .map(|remainder| {
            format!(
                "pub fn selects_{remainder}(values: &[u64]) -> Vec<u64> {{\n    \
                 values.iter().filter(|value| **value % {count} == {remainder}).\
                 map(|value| *value).collect()\n}}\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(root.join("src/lib.rs"), source).expect("fixture source");
}

/// One semantic scan of a tree, or `None` on a machine with no compiler
/// helper, which the missing-helper test above covers.
fn semantic_scan(root: &Path) -> Option<serde_json::Value> {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("the semantic scan should run");
    output
        .status
        .success()
        .then(|| serde_json::from_slice(&output.stdout).expect("stdout is one JSON document"))
}

/// What one funnel stage of a report passed on, and what it dropped for a cause.
fn funnel_stage(report: &serde_json::Value, stage: &str) -> (u64, u64) {
    let stage = report["summary"]["funnel"]
        .as_array()
        .expect("the report has a funnel")
        .iter()
        .find(|entry| entry["stage"] == stage)
        .expect("the funnel names every stage the run reached");
    let passed = stage["passed"]
        .as_u64()
        .expect("a stage counts what passed");
    let dropped = stage["dropped"]
        .as_array()
        .map(|drops| {
            drops
                .iter()
                .filter(|drop| drop["cause"] == "bucket_member_cap")
                .filter_map(|drop| drop["count"].as_u64())
                .sum()
        })
        .unwrap_or_default();
    (passed, dropped)
}

/// The posting ceiling a run is given is the width its semantic bucket index
/// cuts at. The registered-rule index is one of the bucket paths that ceiling
/// governs, so it takes the number from this run's stage ceilings; a width
/// written into the semantic call site instead would leave the configured
/// number inert, and this bucket would be paired however low it was set.
#[test]
fn a_semantic_run_cuts_its_buckets_at_the_posting_ceiling_it_was_given() {
    const CEILING: u64 = 2;

    let capped = tempfile::tempdir().expect("capped fixture");
    write_pipeline_bucket_fixture(capped.path(), CEILING + 1);
    std::fs::write(
        capped.path().join("codehelion.toml"),
        format!("[limits]\nposting-cap = {CEILING}\n"),
    )
    .expect("fixture configuration");
    let Some(report) = semantic_scan(capped.path()) else {
        return;
    };
    let (buckets, over_the_ceiling) = funnel_stage(&report, "semantic candidate buckets");
    assert_eq!(
        (buckets, over_the_ceiling),
        (0, 1),
        "the one bucket is wider than the stated ceiling and has to be dropped: {report}"
    );
    assert_eq!(
        funnel_stage(&report, "semantic candidate pairs").0,
        0,
        "a dropped bucket pairs nothing: {report}"
    );

    // The same tree with no ceiling stated, which leaves the stage at the width
    // measured for it. Without this a fixture that never formed a bucket at all
    // would read exactly like one the ceiling cut.
    let open = tempfile::tempdir().expect("uncapped fixture");
    write_pipeline_bucket_fixture(open.path(), CEILING + 1);
    let Some(report) = semantic_scan(open.path()) else {
        return;
    };
    let (buckets, over_the_ceiling) = funnel_stage(&report, "semantic candidate buckets");
    assert_eq!(
        (buckets, over_the_ceiling),
        (1, 0),
        "a bucket inside the stage's own width is kept: {report}"
    );
    assert!(
        funnel_stage(&report, "semantic candidate pairs").0 > 0,
        "the kept bucket pairs its members: {report}"
    );
}

/// The reuse path's own tests: a tree nobody touched is reported from the
/// recorded run rather than analysed again, and every input that could change
/// the answer defeats that.
mod reuse {
    use super::{cmd, fixture};
    use std::path::Path;

    /// Scan and parse, letting the reuse decision take its course.
    fn scan(root: &Path, extra: &[&str]) -> serde_json::Value {
        let mut args = vec!["scan", "."];
        if !extra.contains(&"--mode") {
            args.extend(["--mode", "semantic"]);
        }
        args.push("--format");
        args.push("json");
        let output = cmd()
            .current_dir(root)
            .args(args)
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
    }

    fn reused(value: &serde_json::Value) -> bool {
        value["partitions"].as_array().map_or_else(
            || value["run"]["reused"] == serde_json::json!(true),
            |partitions| {
                !partitions.is_empty()
                    && partitions
                        .iter()
                        .all(|partition| partition["run"]["reused"] == serde_json::json!(true))
            },
        )
    }

    fn run_ids(value: &serde_json::Value) -> Vec<serde_json::Value> {
        value["partitions"].as_array().map_or_else(
            || vec![value["run"]["run_id"].clone()],
            |partitions| {
                partitions
                    .iter()
                    .map(|partition| partition["run"]["run_id"].clone())
                    .collect()
            },
        )
    }

    fn strip_run_metadata(value: &mut serde_json::Value) {
        let run = value["run"].as_object_mut().expect("run object");
        for key in ["started_at", "finished_at", "run_id", "reused"] {
            run.remove(key);
        }
        let summary = value["summary"].as_object_mut().expect("summary object");
        for key in ["changes", "audit"] {
            summary.remove(key);
        }
    }

    /// The report a reused run produces is the report an analysis produces:
    /// everything but the run's own metadata and what it says about *this*
    /// invocation's comparisons.
    fn findings(mut value: serde_json::Value) -> serde_json::Value {
        if let Some(partitions) = value["partitions"].as_array_mut() {
            for partition in partitions {
                strip_run_metadata(partition);
            }
        } else {
            strip_run_metadata(&mut value);
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
        assert_eq!(run_ids(&again), run_ids(&analysed));
        assert_eq!(findings(again), findings(analysed));
    }

    #[test]
    fn reporting_a_run_again_records_no_second_run() {
        let dir = fixture();
        scan(dir.path(), &["--no-reuse"]);
        scan(dir.path(), &[]);
        scan(dir.path(), &[]);

        let store = super::open_store(dir.path());
        let recorded = store.table_count("scan_run").unwrap();
        assert!(recorded > 0, "a semantic partition was recorded");
        scan(dir.path(), &[]);
        assert_eq!(
            store.table_count("scan_run").unwrap(),
            recorded,
            "the reused scans recorded nothing"
        );
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
    /// baselines is two different reports, and neither run answers for the
    /// other.
    #[test]
    fn a_different_frozen_set_is_analysed_again() {
        let dir = fixture();
        let plain = scan(dir.path(), &[]);
        cmd()
            .current_dir(dir.path())
            .args(["baseline", "create", "."])
            .assert()
            .success();

        let with = ["--baseline", "codehelion-baseline.json"];
        assert!(!reused(&scan(dir.path(), &with)), "a baseline came in");
        let frozen = scan(dir.path(), &with);
        assert!(reused(&frozen), "the same baseline again");
        assert_ne!(
            run_ids(&frozen),
            run_ids(&plain),
            "a run reported against a baseline is not the run reported without one"
        );
        assert_eq!(
            run_ids(&scan(dir.path(), &[])),
            run_ids(&plain),
            "the baseline went away, and the run that read the same tree without one answers"
        );
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
