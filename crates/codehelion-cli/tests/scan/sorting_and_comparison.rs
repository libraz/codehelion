use super::*;

/// How to read one axis's measure off a reported group.
type Measure = fn(&serde_json::Value) -> f64;

/// What each `--sort` axis is called and how to read the measure it names off
/// a reported group, so a test can hold the report to the axis it asked for.
const AXES: [(&str, Measure); 4] = [
    ("priority", |group| {
        group["priority"]["value"].as_f64().expect("a value")
    }),
    ("identifier-jaccard", |group| {
        group["identifier_jaccard"].as_f64().expect("a measure")
    }),
    ("instances", |group| {
        group["priority"]["inputs"]["instances"]
            .as_f64()
            .expect("a count")
    }),
    ("duplicated-tokens", |group| {
        let members = group["members"].as_array().expect("members");
        let size = |member: &serde_json::Value| member["tokens"].as_f64().expect("a size");
        let total: f64 = members.iter().map(size).sum();
        let canonical = members
            .iter()
            .find(|member| member["canonical"] == true)
            .map_or(0.0, size);
        total - canonical
    }),
];

#[test]
fn fast_mode_refuses_unmeasured_identifier_jaccard_options() {
    let dir = fixture();

    for arguments in [
        vec!["scan", ".", "--sort", "identifier-jaccard"],
        vec!["scan", ".", "--min-identifier-jaccard", "0.7"],
    ] {
        cmd()
            .current_dir(dir.path())
            .args(arguments)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "requires --mode structural or --mode semantic",
            ));
    }
}

#[test]
fn fast_mode_refuses_structural_only_diagnostic_flags() {
    let dir = fixture();

    for flag in ["--show-siblings", "--show-near-misses"] {
        cmd()
            .current_dir(dir.path())
            .args(["scan", ".", flag])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "{flag} requires --mode structural or --mode semantic"
            )));
    }
}

/// What a group measures on one axis, in the order the report listed them.
///
/// Structural mode, because raw identifier agreement is measured on whole
/// units and a mode that does not read units has nothing to say about it.
fn axis_values(report: &serde_json::Value, measure: Measure) -> Vec<f64> {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(measure)
        .collect()
}

#[test]
fn every_sort_axis_orders_the_report_on_what_it_names() {
    let dir = fixture();
    let root = dir.path();

    for (axis, measure) in AXES {
        let report = scan_json_with(root, &["--mode", "structural", "--sort", axis]);
        let values = axis_values(&report, measure);
        assert!(values.len() > 1, "the fixture has something to order");
        assert!(
            values.windows(2).all(|pair| pair[0] >= pair[1]),
            "{axis} listed out of its own order: {values:?}"
        );
        // Nothing about the axis may change which findings there are.
        assert_eq!(
            group_ids(&report).len(),
            group_ids(&scan_json_with(root, &["--mode", "structural"])).len(),
            "the {axis} axis changed the findings rather than their order"
        );
    }
}

#[test]
fn the_chosen_axis_reorders_the_report_and_says_so_in_the_heading() {
    let dir = fixture();
    let root = dir.path();

    let by_priority = group_ids(&scan_json_with(root, &["--mode", "structural"]));
    let by_instances = group_ids(&scan_json_with(
        root,
        &["--mode", "structural", "--sort", "instances"],
    ));
    assert_ne!(
        by_priority, by_instances,
        "the fixture ranks these two axes differently, so the flag has to show"
    );
    // The same run again, because an order a reader cites has to survive a
    // rerun of the scan that produced it.
    assert_eq!(
        by_instances,
        group_ids(&scan_json_with(
            root,
            &["--mode", "structural", "--sort", "instances"],
        )),
    );

    cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "--sort", "instances"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sorted by instances"));
}

#[test]
fn a_recorded_run_can_be_read_back_on_another_axis() {
    let dir = fixture();
    let root = dir.path();
    let scanned = scan_json_with(root, &["--mode", "structural"]);
    let run_id = scanned["run"]["run_id"].as_i64().expect("a run id");

    let output = cmd()
        .current_dir(root)
        .args([
            "report",
            "--run",
            &run_id.to_string(),
            "--format",
            "json",
            "--sort",
            "instances",
        ])
        .output()
        .expect("reread the recorded run");
    assert!(output.status.success(), "{output:?}");
    let reread: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");

    let instances = AXES
        .iter()
        .find(|(axis, _)| *axis == "instances")
        .expect("the instances axis")
        .1;
    let values = axis_values(&reread, instances);
    assert!(
        values.windows(2).all(|pair| pair[0] >= pair[1]),
        "the recorded run came back out of the order it was asked for: {values:?}"
    );
    let mut listed = group_ids(&reread);
    let mut recorded = group_ids(&scanned);
    listed.sort();
    recorded.sort();
    assert_eq!(
        listed, recorded,
        "an axis is a way of reading the snapshot, not of changing it"
    );
}

#[test]
fn an_identifier_floor_narrows_the_listing_without_moving_a_count() {
    let dir = fixture();
    let root = dir.path();

    let listed = |extra: &[&str]| {
        let output = cmd()
            .current_dir(root)
            .args(["scan", ".", "--mode", "structural", "-vv"])
            .args(extra)
            .output()
            .expect("run scan");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).expect("text output")
    };
    let full = listed(&[]);
    let floored = listed(&["--min-identifier-jaccard", "0.9"]);

    let counted = |text: &str| {
        text.lines()
            .find(|line| line.contains(" groups (type-"))
            .expect("the group count")
            .to_string()
    };
    assert_eq!(
        counted(&full),
        counted(&floored),
        "a view chose what to list, so it may not restate what was found"
    );
    assert!(
        floored.contains("group(s) are not listed: raw identifier agreement below 0.90"),
        "what a floor left out has to be said: {floored}"
    );
    let structural = scan_json_with(root, &["--mode", "structural"]);
    let low_agreement: Vec<&str> = structural["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter_map(|group| {
            group["identifier_jaccard"]
                .as_f64()
                .filter(|agreement| *agreement < 0.9)
                .and_then(|_| group["fingerprint"].as_str())
        })
        .collect();
    assert!(
        !low_agreement.is_empty(),
        "the renamed copies supply low-agreement structural evidence"
    );
    assert!(
        low_agreement
            .iter()
            .any(|fingerprint| full.contains(fingerprint)),
        "the unfloored view lists low-agreement groups"
    );
    assert!(
        low_agreement
            .iter()
            .all(|fingerprint| !floored.contains(fingerprint)),
        "the renamed copies sit under the floor and should have gone: {floored}"
    );

    // Exports carry the findings rather than a reading of them.
    assert_eq!(
        group_ids(&scan_json_with(root, &["--mode", "structural"])),
        group_ids(&scan_json_with(
            root,
            &["--mode", "structural", "--min-identifier-jaccard", "0.9"],
        )),
    );
}

#[test]
fn comparing_against_a_baseline_names_what_went_and_what_took_its_place() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Both copies are reworked in step. The duplication has not been removed
    // and has not spread; it is the same two functions in the same two files.
    // Its content moved, though, and a group is identified by its content, so
    // this is one group gone and another arriving in its place.
    std::fs::write(root.join("src/a.rs"), CHECKSUM_REWORKED_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_REWORKED_RS).unwrap();

    let after = scan_json_with(
        root,
        &["--baseline", "baseline.json", "--baseline-mode", "compare"],
    );
    let status = &after["summary"]["baseline"];
    assert_eq!(status["mode"], "compare");
    assert_eq!(status["stale"], 1);
    assert_eq!(status["appeared"], 1);
    assert!(
        status["stale_tokens"].as_u64().expect("a count") > 0,
        "what went is measured in tokens, not only in groups"
    );
    assert!(status["appeared_tokens"].as_u64().expect("a count") > 0);

    // Compare mode hides nothing: a report with the known half missing cannot
    // answer what moved.
    let groups = after["groups"].as_array().expect("groups");
    assert!(groups.iter().all(|group| group["suppressed"].is_null()));

    let gone = status["gone"].as_array().expect("the entries that went");
    assert_eq!(gone.len(), 1);
    let arrived = groups
        .iter()
        .find(|group| group["baseline"]["state"] == "new")
        .expect("the group that took its place");
    // Without this the reader sees "1 new group" and reads it as duplication
    // they have just introduced.
    assert_eq!(
        arrived["baseline"]["derived_from"]["group"],
        gone[0]["group"]
    );
    assert_eq!(arrived["baseline"]["derived_from"]["shared_sites"], 2);
}

#[test]
fn duplication_written_somewhere_new_is_not_credited_to_what_went() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // The frozen pair goes, and an unrelated pair arrives in files nothing was
    // ever frozen over. Nothing stood where this stands, so nothing is claimed.
    std::fs::remove_file(root.join("src/b.rs")).unwrap();
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/d.rs"), FORMAT_RS).unwrap();

    let after = scan_json_with(
        root,
        &["--baseline", "baseline.json", "--baseline-mode", "compare"],
    );
    assert_eq!(after["summary"]["baseline"]["stale"], 1);
    assert_eq!(after["summary"]["baseline"]["appeared"], 1);
    let arrived = after["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| group["baseline"]["state"] == "new")
        .expect("the new pair");
    assert!(arrived["baseline"].get("derived_from").is_none());
}

#[test]
fn a_comparison_lists_what_went_and_a_suppression_does_not() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);
    std::fs::remove_file(root.join("src/b.rs")).unwrap();

    let compared = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--baseline",
            "baseline.json",
            "--baseline-mode",
            "compare",
            "-v",
        ])
        .output()
        .expect("run scan");
    assert!(compared.status.success(), "{compared:?}");
    let text = String::from_utf8(compared.stdout).expect("utf-8");
    assert!(text.contains("since it was recorded:"), "{text}");
    assert!(text.contains("1 gone"), "{text}");
    assert!(text.contains("repeated tokens"), "{text}");
    assert!(text.contains("last seen at src/a.rs"), "{text}");

    // Suppress mode was asked to hide known duplication; a list of duplication
    // that is no longer there is not what it was asked for.
    let suppressed = cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "baseline.json", "-v"])
        .output()
        .expect("run scan");
    assert!(suppressed.status.success(), "{suppressed:?}");
    let text = String::from_utf8(suppressed.stdout).expect("utf-8");
    assert!(text.contains("since it was recorded:"), "{text}");
    assert!(!text.contains("last seen at"), "{text}");
}

#[test]
fn incompatible_baselines_are_rejected_by_scan_and_update() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Every id is computed under a build variant. `scan` must not proceed as
    // though this baseline hid its findings when it cannot describe them.
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--baseline",
            "baseline.json",
        ])
        .output()
        .expect("run scan");
    assert!(!output.status.success(), "{output:?}");
    let scan_error = String::from_utf8(output.stderr).expect("utf-8");
    assert!(scan_error.contains("does not describe this scan"));
    assert!(scan_error.contains("build variant"));

    // Record the incompatible run without applying the baseline, then ensure
    // `baseline update` makes the same refusal rather than treating it as a
    // different kind of mismatch.
    scan_json_with(root, &["--mode", "structural"]);
    let output = cmd()
        .current_dir(root)
        .args(["baseline", "update", ".", "--file", "baseline.json"])
        .output()
        .expect("update baseline");
    assert!(!output.status.success(), "{output:?}");
    let update_error = String::from_utf8(output.stderr).expect("utf-8");
    assert!(update_error.contains("does not describe run"));
    assert!(update_error.contains("build variant"));
}

#[test]
fn ranking_only_changes_keep_a_baseline_usable_for_scan_and_update() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    std::fs::write(
        root.join("codehelion.toml"),
        "[priority]\nmaintenance-risk = 0\nrefactoring-ease = 9\n",
    )
    .unwrap();
    let baselined = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(
        visible_ids(&baselined).is_empty(),
        "ranking does not move ids"
    );

    cmd()
        .current_dir(root)
        .args(["baseline", "update", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 resolved and dropped"));
}

#[test]
fn a_baseline_that_cannot_be_read_stops_the_scan() {
    let dir = fixture();
    let root = dir.path();
    std::fs::write(root.join("broken.json"), "{ not json").unwrap();

    // Scanning on without the baseline would report the very findings the
    // user asked to have hidden, so a named file that cannot be applied is a
    // reason to stop.
    cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "broken.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("broken.json"));

    cmd()
        .current_dir(root)
        .args(["scan", ".", "--baseline", "absent.json"])
        .assert()
        .failure();
}

#[test]
fn recording_a_baseline_needs_a_scan_and_refuses_to_overwrite_silently() {
    let dir = fixture();
    let root = dir.path();

    cmd()
        .current_dir(root)
        .args(["baseline", "create", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("scan"));

    scan_json(root);
    record_baseline(root);
    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    cmd()
        .current_dir(root)
        .args([
            "baseline",
            "create",
            ".",
            "--file",
            "baseline.json",
            "--force",
        ])
        .assert()
        .success();
}
