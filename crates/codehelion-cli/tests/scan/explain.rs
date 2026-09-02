//! Looking a recorded finding up with `explain`.

use super::*;

#[test]
fn explain_looks_up_a_recorded_finding() {
    let dir = fixture();
    let scan = cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .output()
        .expect("run scan");
    assert!(scan.status.success(), "{scan:?}");

    let (finding_hex, file_path, group_hex) = {
        let store = open_store(dir.path());
        let run = store.latest_run().unwrap().expect("a recorded run");
        let groups = store.run_groups(run.id).unwrap();
        let member = &groups[0].members[0];
        (
            member.finding_hex.clone(),
            member.file_path.clone(),
            groups[0].fingerprint_hex.clone(),
        )
    };
    let scan_text = String::from_utf8(scan.stdout).expect("scan output is UTF-8");
    // The listing abbreviates, and what it prints is exactly what the lookup
    // accepts: an id read off the report can be typed straight back in.
    let abbreviated = &group_hex[..8];
    assert!(
        scan_text.contains(abbreviated),
        "the default text report prints an id that explain accepts: {scan_text}"
    );
    cmd()
        .current_dir(dir.path())
        .args(["explain", abbreviated])
        .assert()
        .success()
        .stdout(predicate::str::contains(group_hex.as_str()));

    cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex])
        .assert()
        .success()
        .stdout(predicate::str::contains(&finding_hex))
        .stdout(predicate::str::contains(&file_path));

    // The JSON detail view shares the same shape as a report member.
    let output = cmd()
        .current_dir(dir.path())
        .args(["explain", &finding_hex, "--format", "json"])
        .output()
        .expect("run explain");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(value["finding_id"], finding_hex.as_str());
    assert_eq!(value["file"], file_path.as_str());
    assert_eq!(value["group"]["fingerprint"].as_str().unwrap().len(), 32);
    assert!(value["scan_run"].as_i64().unwrap() >= 1);

    // Well-formed but unknown id: a clear error naming everything it looked
    // for, not silence and not a claim about one kind of id.
    cmd()
        .current_dir(dir.path())
        .args(["explain", "00000000000000000000000000000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no finding or clone/comparison group",
        ));
}

#[test]
fn explain_takes_the_group_id_the_report_printed_and_an_abbreviation_of_it() {
    let dir = fixture();
    let root = dir.path();
    let report = scan_json(root);
    let group = visible_ids(&report)
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // The heading of a group in the report is a group fingerprint. Being
    // unable to paste it back in is the trail these ids exist to keep,
    // broken.
    cmd()
        .current_dir(root)
        .args(["explain", &group])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("clone group {group}")))
        .stdout(predicate::str::contains("maintenance risk"));

    // An abbreviation resolves wherever it names one thing, as it already
    // does for [suppression] clone-ids.
    let output = cmd()
        .current_dir(root)
        .args(["explain", &group[..12], "--format", "json"])
        .output()
        .expect("run explain");
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(value["schema_version"], "finding-detail-v1");
    assert_eq!(value["response_kind"], "clone_group");
    assert_eq!(value["group"]["fingerprint"], group.as_str());
    let reported = report["groups"]
        .as_array()
        .expect("scan report groups")
        .iter()
        .find(|candidate| candidate["fingerprint"].as_str() == Some(group.as_str()))
        .expect("explained group is in the scan report");
    assert_eq!(
        value["group"]["priority"], reported["priority"],
        "explain reuses the priority and inputs persisted for the scan"
    );
    assert!(value["group"]["priority"]["inputs"]["instances"].as_u64() >= Some(2));
    assert!(value["group"]["members"].as_array().expect("members").len() >= 2);
}

/// The `run:` line of an `explain` text view.
fn run_line(text: &str) -> &str {
    text.lines()
        .find(|line| line.trim_start().starts_with("run: "))
        .expect("explain names the run it read")
}

#[test]
fn explain_says_a_group_the_newest_comparable_run_no_longer_holds_is_gone() {
    let dir = one_pair();
    let root = dir.path();
    let group = visible_ids(&scan_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // The duplication is refactored away, and the next scan records a run
    // without it. Confirming exactly that is why the lookup is run at all.
    std::fs::write(root.join("src/b.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);
    let latest = second["run"]["run_id"].as_i64().expect("a second run");
    assert!(!group_ids(&second).contains(&group));

    let (text, json) = explain_group(root, &group);
    assert!(
        run_line(&text).ends_with(&format!("— not present in the latest run {latest}")),
        "{text}"
    );
    assert_eq!(json["latest_scan_run"], latest);
    assert_eq!(json["present_in_latest_run"], false);
    assert_ne!(json["scan_run"], latest);
}

#[test]
fn explain_says_a_group_the_newest_comparable_run_still_holds_is_current() {
    let dir = one_pair();
    let root = dir.path();
    let group = visible_ids(&scan_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // A file that duplicates nothing: the tree differs, so the scan analyses
    // again rather than replaying, and the pair it finds is the same pair.
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);
    let latest = second["run"]["run_id"].as_i64().expect("a second run");
    assert!(
        group_ids(&second).contains(&group),
        "the untouched pair keeps its identity across runs"
    );

    let (text, json) = explain_group(root, &group);
    assert!(run_line(&text).ends_with("— latest"), "{text}");
    assert_eq!(json["latest_scan_run"], latest);
    assert_eq!(json["present_in_latest_run"], true);
    assert_eq!(json["scan_run"], latest);
}

#[test]
fn explain_claims_nothing_about_a_later_run_when_there_is_only_one() {
    let dir = one_pair();
    let root = dir.path();
    let group = visible_ids(&scan_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // One run says nothing about what a later scan found, so the lookup says
    // nothing either, rather than calling the only run it has the latest.
    let (text, json) = explain_group(root, &group);
    assert!(run_line(&text).ends_with(')'), "{text}");
    assert!(json["latest_scan_run"].is_null());
    assert!(json["present_in_latest_run"].is_null());
}

#[test]
fn explain_ignores_a_newer_run_recorded_under_another_build_variant() {
    let dir = one_pair();
    let root = dir.path();
    let group = visible_ids(&scan_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // A later run under another build variant holds none of these groups, and
    // is no evidence that this one is gone: results computed under different
    // variants are never compared.
    let root_text = codehelion_store::path_key(
        &codehelion_core::paths::canonical(root).expect("canonical fixture root"),
    );
    let other = BuildVariant::fast(LanguageSelection::default(), Language::Cpp);
    let mut store = open_store(root);
    let run = store
        .record_snapshot_part(&Snapshot {
            started_at: "2099-01-01T00:00:00Z",
            finished_at: "2099-01-01T00:00:01Z",
            ..empty_snapshot(&root_text, &other)
        })
        .expect("record a run under another build variant");
    store
        .complete_snapshot_parts(&[run])
        .expect("complete the recorded run");
    assert_eq!(
        store.latest_run().unwrap().expect("a recorded run").id,
        run,
        "the seeded run is the newest one, so only the variant keeps it out"
    );
    drop(store);

    let (text, json) = explain_group(root, &group);
    assert!(run_line(&text).ends_with(')'), "{text}");
    assert!(json["latest_scan_run"].is_null());
    assert!(json["present_in_latest_run"].is_null());
}

#[test]
fn text_that_is_not_a_usable_id_is_refused_with_the_reason() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);

    cmd()
        .current_dir(root)
        .args(["explain", "0a1b"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("too short"));

    cmd()
        .current_dir(root)
        .args(["explain", "not-hex-at-all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("hexadecimal"));

    // Every recorded id starts with the empty string, so an empty prefix is
    // the one that always collides; it is refused for length first.
    cmd()
        .current_dir(root)
        .args(["explain", ""])
        .assert()
        .failure();
}

#[test]
fn explain_without_a_database_says_to_scan_first() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["explain", "00000000000000000000000000000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("run `codehelion scan` first"));
}
