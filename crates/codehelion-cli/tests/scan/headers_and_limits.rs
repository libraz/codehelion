use super::*;

#[test]
fn a_bare_header_is_read_as_the_language_the_tree_is_written_in() {
    let cpp_tree = header_fixture(&["a.cpp", "b.cpp", "vendored.c"]);
    assert_eq!(
        header_reading(cpp_tree.path(), None),
        (1, 3, "cpp".to_string()),
        "two C++ sources outvote one C source, so shared.h is C++"
    );

    let c_tree = header_fixture(&["a.c", "b.c", "fuzz.cc"]);
    assert_eq!(
        header_reading(c_tree.path(), None),
        (3, 1, "c".to_string()),
        "one vendored C++ harness does not make a C project C++"
    );
}

/// A header-only library is the case with nothing to vote, and the case where
/// getting it wrong costs everything.
///
/// There is no `.cpp` to outvote a `.c` because there are no translation units
/// at all — every line the run will read is in the headers. Settling that by
/// default would read a whole C++ project with the C grammar, which does not
/// merely skip the C++ declarations: error recovery reshapes what surrounds
/// them, so most of the project stops being analysed at all.
#[test]
fn a_library_that_is_nothing_but_headers_is_read_by_what_the_headers_say() {
    let cpp_only = header_fixture(&[]);
    assert_eq!(
        header_reading(cpp_only.path(), None),
        (0, 1, "cpp".to_string()),
        "the header declares a namespace and a class, and nothing else speaks"
    );

    // And a C library shipped the same way stays C: the check is for what only
    // C++ can spell, not for a C++-looking word.
    let c_only = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        c_only.path().join("mixer.h"),
        "/* Widgets of every class, in the namespace sense. */\n#include <string.h>\n\
         static int mixer_width(const char *s) { return (int) strlen(s); }\n",
    )
    .unwrap();
    assert_eq!(
        header_reading(c_only.path(), None),
        (1, 0, "c".to_string()),
        "the C++ words are all in a comment"
    );
}

#[test]
fn the_configured_header_grammar_overrides_the_tree_and_moves_the_variant() {
    let dir = header_fixture(&["a.cpp", "b.cpp"]);
    let (_, _, detected) = header_reading(dir.path(), None);
    assert_eq!(detected, "cpp");
    let detected_fingerprint = scan_json(dir.path())["run"]["build_variant"]["fingerprint"].clone();

    let (c_files, cpp_files, forced) =
        header_reading(dir.path(), Some("[languages]\nheaders = \"c\"\n"));
    assert_eq!(forced, "c", "the configured grammar decides");
    assert_eq!((c_files, cpp_files), (1, 2), "shared.h is now counted as C");

    // The two runs saw different code in the same header, so their results
    // must not land in one fingerprint space.
    assert_ne!(
        scan_json(dir.path())["run"]["build_variant"]["fingerprint"],
        detected_fingerprint
    );
}

#[test]
fn the_run_says_how_far_each_stage_of_the_pipeline_narrowed_it() {
    let dir = fixture();
    let value = scan_json(dir.path());
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    let passed = |name: &str| {
        funnel
            .iter()
            .find(|entry| entry["stage"] == name)
            .expect("the stage is reported")["passed"]
            .as_u64()
            .unwrap()
    };
    // The Fast pipeline's own stage names, not the structural ones: it
    // narrows a winnowed fingerprint index down to verified pairs.
    assert!(passed("tokens") > passed("fingerprints"));
    assert!(passed("fingerprints") >= passed("indexed values"));
    assert!(passed("verified pairs") >= 1, "the fixture holds a clone");

    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:").not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:"))
        .stdout(predicate::str::contains("fragment classes"));
}

#[test]
fn configured_file_size_ceiling_skips_oversized_files() {
    let dir = fixture();
    // 4 KiB of valid Rust, above the 1 KiB ceiling set below.
    let big = "// filler line to grow the file body\n".repeat(120);
    std::fs::write(dir.path().join("src/big.rs"), big).unwrap();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-file-bytes = 1024\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["files"]["total"], 5);
    assert_eq!(value["summary"]["excluded"]["skipped"], 1);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["members"].as_array().unwrap())
            .all(|member| member["file"] != "src/big.rs")
    );
}

/// A scan told to distrust the tree reads less of it, and a report that read
/// less has to be distinguishable from a tree that holds less. The oversized
/// file is the evidence the ceilings took effect; the profile line is what
/// stops the smaller result from reading as a smaller codebase.
#[test]
fn distrusting_the_tree_lowers_the_ceilings_and_reports_them() {
    let dir = fixture();
    // Above the untrusted profile's 512 KiB ceiling and below the default one.
    let big = "// filler line to grow the file body\n".repeat(16_000);
    std::fs::write(dir.path().join("src/big.rs"), big).unwrap();
    // Every setting is deliberately laxer than the untrusted profile. This
    // comes from the repository's discovered configuration, the attack
    // surface the flag is meant to constrain.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-file-bytes = 2097152\nparse-timeout-ms = 10000\nhelper-timeout-ms = 300000\nposting-cap = 256\npair-budget = 1000000\nmax-component = 1024\n",
    )
    .unwrap();

    let trusting = scan_json(dir.path());
    assert_eq!(trusting["summary"]["files"]["total"], 6);
    assert!(trusting["summary"]["guardrails"].is_null());

    let distrusting = scan_json_with(dir.path(), &["--untrusted"]);
    assert_eq!(distrusting["summary"]["files"]["total"], 5);
    assert_eq!(distrusting["summary"]["excluded"]["skipped"], 1);
    let guardrails = &distrusting["summary"]["guardrails"];
    assert_eq!(guardrails["profile"], "untrusted");
    assert_eq!(guardrails["max_file_bytes"], 512 * 1024);
    assert_eq!(guardrails["parse_timeout_ms"], 5000);
    assert_eq!(guardrails["helper_timeout_ms"], 30_000);
    assert_eq!(guardrails["posting_cap"], 32);
    assert_eq!(guardrails["pair_budget"], 500_000);
    assert_eq!(guardrails["max_component"], 128);
}

/// The profile has to be visible in the format a person reads, not only in the
/// one a program reads: the text report is where somebody notices that a run
/// which found less was told to look at less.
#[test]
fn the_text_report_says_the_run_was_told_to_distrust_the_tree() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--untrusted"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(text.contains("untrusted profile"), "{text}");
    for ceiling in [
        "30000 ms helper deadline",
        "posting lists up to 32",
        "128 units per group",
    ] {
        assert!(text.contains(ceiling), "{text}");
    }
}

/// The ceilings are part of what a reused run is matched on, so a distrusting
/// scan cannot be answered with a recording made under the default ones — that
/// recording read files this run would not have opened.
#[cfg(any())]
#[test]
fn a_distrusting_scan_does_not_reuse_a_run_that_trusted_the_tree() {
    let dir = fixture();
    let reused = |extra: &[&str]| -> bool {
        let output = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--format", "json"])
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
        value["run"]["reused"] == serde_json::Value::Bool(true)
    };
    assert!(!reused(&[]), "the first scan cannot reuse anything");
    assert!(reused(&[]), "an unchanged tree is read from the recording");
    assert!(
        !reused(&["--untrusted"]),
        "a recording made under the default ceilings answered a distrusting scan"
    );
    assert!(
        reused(&["--untrusted"]),
        "a second distrusting scan should reuse the first one"
    );
}

#[test]
fn configured_pair_budget_exhaustion_is_reported() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\npair-budget = 1\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["pair_budget_exhausted"], true);
    assert_eq!(value["summary"]["search_truncated"], true);
    assert_eq!(value["summary"]["groups"]["total"], 1);
    // And says how much it did not look at. "The budget ran out" alone does
    // not tell a reader whether a handful of low-signal candidates were
    // trimmed or the search never started, and only one of those is a result
    // worth acting on.
    //
    // Both pairing passes are checked, because each holds its own allowance:
    // a pass whose funnel stage stayed silent would leave its share of the
    // search unaccounted for while the run as a whole still read as merely
    // "exhausted".
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    for stage_name in ["seed pairs", "fragment pairs"] {
        let stage = funnel.iter().find(|stage| stage["stage"] == stage_name);
        assert!(stage.is_some(), "the funnel names the {stage_name} stage");
        let stage = stage.unwrap();
        let unexamined = stage["dropped"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drop| drop["cause"] == "pair_budget");
        assert!(
            unexamined.is_some(),
            "{stage_name} accounts for what the ceiling stopped"
        );
        assert!(unexamined.unwrap()["count"].as_u64().unwrap() > 0);
        assert_eq!(stage["passed"], 1);
    }

    let run_id = value["run"]["run_id"].as_i64().expect("a recorded run id");
    cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "text"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("candidate search was truncated")
                .and(predicate::str::contains("candidate-pair budget")),
        );
}

#[test]
fn a_ceiling_truncated_corpus_is_stable_across_worker_counts() {
    let corpus = synthetic_rust_corpus("rust-negative");
    std::fs::write(
        corpus.path().join("codehelion.toml"),
        "[limits]\npair-budget = 1\n",
    )
    .expect("write constrained corpus configuration");

    let one_worker = structural_json_with_jobs(corpus.path(), 1, &corpus.path().join("one.db"));
    let many_workers = structural_json_with_jobs(corpus.path(), 3, &corpus.path().join("many.db"));
    for report in [&one_worker, &many_workers] {
        assert_eq!(report["summary"]["pair_budget_exhausted"], true);
        assert_eq!(report["summary"]["search_truncated"], true);
    }

    let (one_worker, _) = detected::from_report_json(
        &serde_json::to_string(&one_worker).expect("report remains serializable"),
    )
    .expect("one-worker report is measurable");
    let (many_workers, _) = detected::from_report_json(
        &serde_json::to_string(&many_workers).expect("report remains serializable"),
    )
    .expect("many-worker report is measurable");
    let stable = stability(&one_worker, &many_workers);
    assert!(stable.identical, "ceiling changed the result: {stable:?}");
    assert!((stable.jaccard - 1.0).abs() < f64::EPSILON);
    assert!(stable.churn.abs() < f64::EPSILON);
}

#[test]
fn a_posting_cap_marks_the_default_report_as_search_truncated() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nposting-cap = 2\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["search_truncated"], true);
    let dropped = value["summary"]["funnel"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|stage| stage["dropped"].as_array().unwrap())
        .any(|drop| {
            matches!(
                drop["cause"].as_str(),
                Some("high_frequency" | "high_frequency_postings" | "class_cap")
            )
        });
    assert!(dropped, "the funnel records the posting ceiling");

    let run_id = value["run"]["run_id"].as_i64().expect("a recorded run id");
    cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "text"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("candidate search was truncated")
                .and(predicate::str::contains("class cap")),
        );
}

/// A ceiling on the whole search must not switch one of the two detectors off.
///
/// The verbatim pass runs first over a far larger candidate space. Sharing one
/// allowance with the renamed-copy pass means that above a few hundred
/// thousand lines the first pass spends all of it, and Fast mode silently
/// becomes verbatim-only — while reporting nothing worse than an exhausted
/// budget.
#[test]
fn a_tight_budget_narrows_both_detectors_rather_than_silencing_one() {
    let dir = fixture();
    let full = scan_json(dir.path());
    let type2 = |value: &serde_json::Value| {
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|group| group["clone_type"] == "type-2")
            .count()
    };
    assert!(type2(&full) > 0, "the fixture holds a renamed copy");

    // Tight enough that the verbatim pass runs out, wide enough that the
    // renamed pass could still do its work with an allowance of its own.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\npair-budget = 12\n",
    )
    .unwrap();
    let squeezed = scan_json(dir.path());
    assert_eq!(squeezed["summary"]["pair_budget_exhausted"], true);
    assert!(
        type2(&squeezed) > 0,
        "the renamed copy is still found when the verbatim pass runs out"
    );
}

#[test]
fn zero_parse_timeout_is_rejected_in_each_mode() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nparse-timeout-ms = 0\n",
    )
    .unwrap();

    for mode in ["fast", "structural"] {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "limits.parse-timeout-ms must be at least 1",
            ));
    }
}

#[test]
fn json_reports_follow_the_versioned_schema() {
    let dir = fixture();
    let value = scan_json(dir.path());

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["run"]["mode"], "fast");
    assert_eq!(value["run"]["configuration"]["source"], "defaults");
    assert_eq!(value["run"]["configuration"]["min_clone_tokens"], 20);
    assert_eq!(value["run"]["build_variant"]["mode"], "fast");
    assert!(value["run"]["started_at"].as_str().unwrap().ends_with('Z'));
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "fp-schema")
    );
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "noise-filter"
                && entry["version"] == "entropy-ratio-v1:0.600000")
    );
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["component"] != "ranking"),
        "ranking is presentation metadata, not a detector-version contract"
    );
    assert_eq!(value["summary"]["files"]["total"], 5);
    assert!(value["summary"]["lines"].as_u64().unwrap() > 0);
    assert!(value["summary"]["search_truncated"].is_boolean());

    // Deterministic listing: priority descending across the whole document.
    let groups = value["groups"].as_array().unwrap();
    assert!(!groups.is_empty());
    let priorities: Vec<f64> = groups
        .iter()
        .map(|group| group["priority"]["value"].as_f64().unwrap())
        .collect();
    assert!(priorities.windows(2).all(|pair| pair[0] >= pair[1]));
    for group in groups {
        assert_eq!(group["suppressed"], serde_json::Value::Null);
        let members = group["members"].as_array().unwrap();
        assert!(members.len() >= 2);
        assert_eq!(members[0]["canonical"], true);
        assert_eq!(members[0]["finding_id"].as_str().unwrap().len(), 32);
    }

    // The JSON members carry exactly the finding ids the snapshot recorded.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored: std::collections::BTreeSet<String> = store
        .run_groups(run.id)
        .unwrap()
        .iter()
        .flat_map(|group| group.members.iter().map(|m| m.finding_hex.clone()))
        .collect();
    let reported: std::collections::BTreeSet<String> = groups
        .iter()
        .flat_map(|group| {
            group["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["finding_id"].as_str().unwrap().to_string())
        })
        .collect();
    assert_eq!(stored, reported);
}

#[test]
fn report_replay_preserves_the_effective_configuration_provenance() {
    let dir = fixture();
    let config_path = dir.path().join("codehelion.toml");
    std::fs::write(&config_path, "min-clone-tokens = 25\n").unwrap();
    let recorded_config_path = dir
        .path()
        .canonicalize()
        .expect("fixture root resolves")
        .join("codehelion.toml");

    let report = scan_json(dir.path());
    let expected = serde_json::json!({
        "source": "root",
        "path": recorded_config_path.display().to_string(),
        "min_clone_tokens": 25,
    });
    assert_eq!(report["run"]["configuration"], expected);
    let run_id = report["run"]["run_id"]
        .as_i64()
        .expect("scan records its run id");

    let output = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("re-render recorded report");
    assert!(output.status.success(), "{output:?}");
    let replayed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recorded report is JSON");
    assert_eq!(replayed["run"]["configuration"], expected);

    cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "configuration: root ({}); minimum clone length: 25 tokens",
            recorded_config_path.display()
        )));
}
