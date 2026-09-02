//! What a scan says about the run before it: reuse headers, group identity
//! across runs, top-group churn and the timing breakdown.

use super::*;

#[test]
fn a_scan_says_what_moved_since_the_previous_scan_of_the_tree() {
    let dir = fixture();
    let root = dir.path();

    // Nothing to compare a first scan with, and saying "5 added" would read
    // as a tree written from scratch rather than one never scanned before.
    let first = scan_json(root);
    assert!(
        first["summary"].get("changes").is_none(),
        "a first scan has no run to measure itself against"
    );
    let first_run = first["run"]["run_id"].as_i64().expect("a recorded run");

    // One file edited, one added, one deleted.
    std::fs::write(root.join("src/a.rs"), format!("{CHECKSUM_RS}\n// tail\n")).unwrap();
    std::fs::write(root.join("src/d.rs"), RENAMED_RS).unwrap();
    std::fs::remove_file(root.join("src/two.c")).unwrap();

    let second = scan_json(root);
    let changes = &second["summary"]["changes"];
    assert_eq!(changes["since_run_id"], first_run);
    assert_eq!(changes["modified"], 1);
    assert_eq!(changes["added"], 1);
    assert_eq!(changes["removed"], 1);
    assert_eq!(changes["unchanged"], 3, "the files nobody touched");

    // Scanning again without touching anything is the same tree, and says so.
    let third = scan_json(root);
    let changes = &third["summary"]["changes"];
    assert_eq!(changes["modified"], 0);
    assert_eq!(changes["added"], 0);
    assert_eq!(changes["removed"], 0);
    assert_eq!(changes["unchanged"], 5);
}

#[test]
fn text_headers_name_reuse_changes_and_no_reuse() {
    let dir = fixture();
    let root = dir.path();

    let first = cmd()
        .current_dir(root)
        .args(["scan", "."])
        .output()
        .expect("run the first scan");
    assert!(first.status.success(), "{first:?}");

    let reused = cmd()
        .current_dir(root)
        .args(["scan", "."])
        .output()
        .expect("run the reused scan");
    assert!(reused.status.success(), "{reused:?}");
    let reused_text = String::from_utf8(reused.stdout).expect("text output");
    assert!(
        reused_text.contains("reused: tree unchanged"),
        "{reused_text}"
    );

    std::fs::write(
        root.join("src/a.rs"),
        format!("{CHECKSUM_RS}\n// changed\n"),
    )
    .unwrap();
    std::fs::write(root.join("src/d.rs"), RENAMED_RS).unwrap();
    std::fs::remove_file(root.join("src/two.c")).unwrap();
    let changed = cmd()
        .current_dir(root)
        .args(["scan", "."])
        .output()
        .expect("run the changed scan");
    assert!(changed.status.success(), "{changed:?}");
    let changed_text = String::from_utf8(changed.stdout).expect("text output");
    assert!(changed_text.contains("3 file(s) changed"), "{changed_text}");
    assert!(
        !changed_text.contains("reused: tree unchanged"),
        "{changed_text}"
    );

    let no_reuse = cmd()
        .current_dir(root)
        .args(["scan", ".", "--no-reuse"])
        .output()
        .expect("run with reuse disabled");
    assert!(no_reuse.status.success(), "{no_reuse:?}");
    let no_reuse_text = String::from_utf8(no_reuse.stdout).expect("text output");
    assert!(
        no_reuse_text.contains("0 file(s) changed"),
        "{no_reuse_text}"
    );
    assert!(
        !no_reuse_text.contains("reused: tree unchanged"),
        "{no_reuse_text}"
    );

    let replay = cmd()
        .current_dir(root)
        .args(["report", "--format", "text"])
        .output()
        .expect("replay the recorded run");
    assert!(replay.status.success(), "{replay:?}");
    let replay_text = String::from_utf8(replay.stdout).expect("text output");
    assert!(
        replay_text.contains("replay: codehelion report --run"),
        "{replay_text}"
    );
    assert!(
        !replay_text.contains("reused: tree unchanged"),
        "{replay_text}"
    );
}

#[test]
fn structural_text_header_names_tree_changes() {
    let dir = fixture();
    let root = dir.path();
    let first = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural"])
        .output()
        .expect("run the first structural scan");
    assert!(first.status.success(), "{first:?}");

    std::fs::write(
        root.join("src/a.rs"),
        format!("{CHECKSUM_RS}\n// changed\n"),
    )
    .unwrap();
    let changed = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural"])
        .output()
        .expect("run the changed structural scan");
    assert!(changed.status.success(), "{changed:?}");
    let changed_text = String::from_utf8(changed.stdout).expect("text output");
    assert!(changed_text.contains("1 file(s) changed"), "{changed_text}");
    assert!(
        !changed_text.contains("reused: tree unchanged"),
        "{changed_text}"
    );
}

#[test]
fn a_scan_under_different_settings_has_nothing_to_compare_with() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);

    // A file whose bytes did not move still has to be re-read when the rules
    // for reading it did, so a run under another variant is not a run this
    // one can measure itself against.
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert!(
        value["summary"].get("changes").is_none(),
        "the Fast run is not a baseline for the Structural one"
    );
}

#[test]
fn an_identical_second_scan_reuses_the_recorded_history() {
    let dir = fixture();
    let root = dir.path();

    let first = scan_json(root);
    let second = scan_json(root);
    assert_eq!(
        first["run"]["run_id"], second["run"]["run_id"],
        "an identical scan is answered by its existing local run"
    );
    let store = open_store(root);
    assert_eq!(store.table_count("scan_run").unwrap(), 1);
    assert_eq!(
        store.latest_run().unwrap().expect("the current run").id,
        second["run"]["run_id"].as_i64().expect("a run id")
    );

    // The persisted run stays addressable for replay and the reused scan
    // creates no additional history row.
    cmd()
        .current_dir(root)
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("snapshot:")
                .and(predicate::str::contains("reused: tree unchanged")),
        );
}

/// The detailed text of a scan, where per-group history is written.
fn scan_detailed_text(root: &Path) -> String {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "-vv"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("scan text is UTF-8")
}

/// The recorded history of one group in a report document.
fn identity_of<'a>(report: &'a serde_json::Value, group: &str) -> &'a serde_json::Value {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|entry| entry["fingerprint"] == group)
        .expect("the report lists the group asked about")
        .get("identity")
        .unwrap_or(&serde_json::Value::Null)
}

#[test]
fn a_first_scan_claims_no_history_for_any_group() {
    let dir = one_pair();
    let root = dir.path();
    let first = scan_json(root);
    for group in first["groups"].as_array().expect("groups") {
        assert!(
            group.get("identity").is_none(),
            "a first scan has nothing to compare with: {group}"
        );
    }
    assert!(!scan_detailed_text(root).contains("identity retained"));
}

#[test]
fn a_group_the_earlier_run_knew_by_the_same_id_says_it_kept_its_identity() {
    let dir = one_pair();
    let root = dir.path();
    let first = scan_json(root);
    let first_run = first["run"]["run_id"].as_i64().expect("a first run");
    let group = visible_ids(&first)
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // A file that duplicates nothing, so the tree differs and the scan
    // analyses again while the pair it finds stays the same pair.
    std::fs::write(root.join("src/unrelated.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);

    let identity = identity_of(&second, &group);
    assert_eq!(identity["origin"], "retained", "{identity}");
    assert_eq!(identity["compared_with_run"], first_run);
    assert!(identity.get("adopted_from").is_none(), "{identity}");
    assert!(
        scan_detailed_text(root).contains(&format!("identity retained from run {first_run}")),
        "the detailed text states what the document states"
    );
}

#[test]
fn a_group_with_nothing_behind_it_states_no_history() {
    let dir = one_pair();
    let root = dir.path();
    let first = scan_json(root);
    let known = visible_ids(&first);

    // A second, unrelated duplication appears. It descends from nothing the
    // earlier run held, and a report that said so about every group of an
    // unfamiliar tree would be its longest and least useful column.
    std::fs::write(root.join("src/fmt_a.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/fmt_b.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);
    let fresh = visible_ids(&second)
        .into_iter()
        .find(|group| !known.contains(group))
        .expect("the new pair is a new group");

    assert!(identity_of(&second, &fresh).is_null());
}

/// A group whose membership gained a distinct body, changing the identity a
/// group is known by while most of what it holds stays the same.
///
/// A group is named after the distinct contents it holds, so losing one of
/// several identical copies leaves the name alone. Admitting a body that is
/// only similar is what renames it, and that is the case a reader has to be
/// able to tell from a group that simply appeared.
fn structural_json(root: &Path) -> serde_json::Value {
    scan_json_with(root, &["--mode", "structural"])
}

fn structural_detailed_text(root: &Path) -> String {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "-vv"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("scan text is UTF-8")
}

#[test]
fn a_group_renamed_by_a_new_member_names_the_group_whose_history_it_took_over() {
    let dir = one_pair();
    let root = dir.path();
    let previous = visible_ids(&structural_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // A third copy under a consistent rename. The group now holds two
    // distinct bodies rather than one, so it answers to a different name
    // while still holding what the earlier group held.
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    let second = structural_json(root);
    let successor = visible_ids(&second)
        .into_iter()
        .find(|group| *group != previous)
        .expect("the widened group is known by another id");

    let identity = identity_of(&second, &successor);
    assert_eq!(identity["origin"], "adopted", "{identity}");
    assert_eq!(identity["adopted_from"], serde_json::json!(previous));
    assert!(
        identity["shared_members"].as_u64().unwrap_or(0) >= 1,
        "{identity}"
    );

    let text = structural_detailed_text(root);
    assert!(
        text.contains(&format!("new identity (lineage: {previous},")),
        "{text}"
    );
}

#[test]
fn a_lookup_explains_a_group_s_history_the_way_the_report_did() {
    let dir = one_pair();
    let root = dir.path();
    let previous = visible_ids(&structural_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    let second = structural_json(root);
    let successor = visible_ids(&second)
        .into_iter()
        .find(|group| *group != previous)
        .expect("the widened group is known by another id");

    let (text, json) = explain_group(root, &successor);
    assert_eq!(
        json["group"]["identity"],
        *identity_of(&second, &successor),
        "a lookup and the report it came from give one account"
    );
    assert!(text.contains("new identity (lineage: "), "{text}");
}

/// The line stating what became of the earlier run's highest-ranked groups.
fn churn_line(text: &str) -> Option<&str> {
    text.lines().find(|line| line.starts_with("since run "))
}

/// Every line about the earlier run's highest-ranked groups.
fn churn_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.starts_with("since run "))
        .collect()
}

/// How many ids one part of the churn breakdown names.
fn churn_len(churn: &serde_json::Value, part: &str) -> usize {
    churn[part]
        .as_array()
        .expect("every part of the breakdown is a list of ids")
        .len()
}

#[test]
fn a_first_scan_states_nothing_about_an_earlier_run_s_best_groups() {
    let dir = one_pair();
    let root = dir.path();
    let first = scan_json(root);
    assert!(first["summary"].get("top_churn").is_none(), "{first}");
    assert!(
        churn_line(&scan_detailed_text(root)).is_none(),
        "there is no earlier run to have had a top"
    );
}

#[test]
fn a_closed_group_is_counted_out_of_the_earlier_run_s_top() {
    let dir = one_pair();
    let root = dir.path();
    let first = scan_json(root);
    let first_run = first["run"]["run_id"].as_i64().expect("a first run");
    let closed = visible_ids(&first)
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // The duplication is removed and an unrelated one takes its place, so one
    // group leaves the top and another arrives there.
    std::fs::write(root.join("src/b.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);

    let churn = &second["summary"]["top_churn"];
    assert_eq!(churn["since_run_id"], first_run);
    assert_eq!(churn["top"], 100);
    assert_eq!(churn["closed"], serde_json::json!([closed]));
    assert_eq!(churn_len(churn, "entered"), 1, "{churn}");

    let text = scan_detailed_text(root);
    // `gone` says what it means beside itself. Nothing else happened to the
    // earlier top here, so nothing else is written: a zero would be a number
    // the eye has to read and then dismiss.
    assert_eq!(
        churn_lines(&text),
        vec![
            format!(
                "since run {first_run}: 1 of its top 100 groups are gone (no group holds their content now)"
            ),
            format!("since run {first_run}: 1 new groups entered the top 100"),
        ],
        "{text}"
    );
}

/// The four ways an earlier top-ranked group can have ended up partition it.
///
/// This is the property that lets a reader reconcile what the report says with
/// what they counted themselves. Without it, a count of what left is a number
/// with nothing to check it against, and the arithmetic reads as broken when
/// every part of it is right.
#[test]
fn the_earlier_run_s_top_is_accounted_for_exactly_once_per_group() {
    let dir = one_pair();
    let root = dir.path();
    std::fs::write(root.join("codehelion.toml"), "[report]\nchurn-top = 2\n").unwrap();
    let first = structural_json(root);
    let previously_ranked = visible_ids(&first).len().min(2);
    assert!(previously_ranked > 0, "{first}");

    // One pair is renamed — its history moves to a successor — and another
    // duplication is added, which pushes groups around the top.
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    std::fs::write(root.join("src/d.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/e.rs"), FORMAT_RS).unwrap();
    let second = structural_json(root);
    let churn = &second["summary"]["top_churn"];

    let parts = ["still_ranked", "outranked", "superseded", "closed"];
    let total: usize = parts.iter().map(|part| churn_len(churn, part)).sum();
    assert_eq!(
        total, previously_ranked,
        "the four parts must cover the earlier top exactly once each: {churn}"
    );
    // Exactly once: no id may appear in two of them.
    let mut seen = std::collections::BTreeSet::new();
    for part in parts {
        for id in churn[part].as_array().expect("a list of ids") {
            let id = id.as_str().expect("an id is a string");
            assert!(
                seen.insert(id.to_owned()),
                "{id} appears in more than one part: {churn}"
            );
        }
    }
    // And the arriving side splits the same way.
    let arrived = churn_len(churn, "entered") + churn_len(churn, "promoted");
    let currently_ranked = visible_ids(&second).len().min(2);
    assert!(
        arrived + churn_len(churn, "still_ranked") == currently_ranked,
        "what is in this run's top either was in the earlier one or arrived: {churn}"
    );
}

#[test]
fn a_group_whose_history_moved_to_a_successor_is_not_counted_as_closed() {
    let dir = one_pair();
    let root = dir.path();
    let previous = visible_ids(&structural_json(root))
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");

    // The group answers to another name because it now holds another body.
    // The work behind it did not close, and counting it as closed would report
    // one edit as both a fix and a regression.
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    // One scan, read twice: rescanning an unchanged tree is reused, and a
    // reused run compares with nothing, so the text and the document have to
    // come from the same run.
    let text = structural_detailed_text(root);
    let second = replayed_json(root);
    let churn = &second["summary"]["top_churn"];
    assert!(
        !churn["closed"]
            .as_array()
            .expect("closed")
            .contains(&serde_json::json!(previous)),
        "{churn}"
    );
    // Not closed, and said to be where it actually went. The reader who
    // counted one group leaving the top can now find it.
    assert_eq!(
        churn["superseded"],
        serde_json::json!([previous]),
        "{churn}"
    );
    assert_eq!(
        churn["entered"],
        serde_json::json!([]),
        "a successor that inherited a ranked group's history did not enter"
    );
    assert_eq!(
        churn_len(churn, "promoted"),
        1,
        "the successor is named rather than left out of both sides: {churn}"
    );

    let lines = churn_lines(&text);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("1 of its top 100 groups live on in a successor group")),
        "{text}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("1 entered by taking over a group that was already there")),
        "{text}"
    );
    // Nothing closed and nothing new arrived, so neither is mentioned at all:
    // a part that did not happen is left out rather than written as a zero.
    assert!(
        !lines.iter().any(|line| line.contains("are gone")),
        "{text}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("new groups entered")),
        "{text}"
    );
}

/// The two halves of a run are timed apart, in the detailed view only.
///
/// Which half dominates is what decides whether reuse is worth arranging, and
/// one elapsed time answers neither question. It is left out of the default
/// view because it is not part of what the scan found, and out of the JSON
/// because a duration is not reproducible: a replay reconstructs a document
/// from what was recorded, and no clock reading is.
#[test]
fn a_detailed_scan_times_analysis_and_recording_apart() {
    let dir = one_pair();
    let root = dir.path();
    let timing = regex_free_timing_line;

    let detailed = scan_detailed_text(root);
    let line = timing(&detailed).expect("a detailed scan times its two halves");
    assert!(line.contains("recorded in "), "{line}");

    // Rescanning an unchanged tree writes nothing, and the line says that
    // rather than reporting a recording that did not happen.
    let reused = scan_detailed_text(root);
    let line = timing(&reused).expect("a reused run still times its analysis");
    assert!(line.contains("recorded: reused, nothing written"), "{line}");

    // The default view stays as short as it was.
    let output = cmd()
        .current_dir(root)
        .args(["scan", "."])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    let plain = String::from_utf8(output.stdout).expect("scan text is UTF-8");
    assert!(timing(&plain).is_none(), "{plain}");

    // A replay measured nothing and says nothing.
    let output = cmd()
        .current_dir(root)
        .args(["report", "-v"])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    let replayed = String::from_utf8(output.stdout).expect("report text is UTF-8");
    assert!(timing(&replayed).is_none(), "{replayed}");

    // And no timing reaches the document a consumer parses.
    let document = replayed_json(root).to_string();
    assert!(!document.contains("timings"), "{document}");
    assert!(!document.contains("analysis\":"), "{document}");
}

/// The line stating how long each half of the run took.
fn regex_free_timing_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with("analysis ") && line.contains('s'))
}

/// The latest recorded run of `root`, as a report document.
fn replayed_json(root: &Path) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["report", "--format", "json"])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

#[test]
fn the_compared_top_is_as_wide_as_the_configuration_asks() {
    let dir = one_pair();
    let root = dir.path();
    // Written before the first scan: the configuration is part of what makes
    // two runs comparable, so changing it between them leaves nothing to
    // compare rather than a differently sized comparison.
    std::fs::write(root.join("codehelion.toml"), "[report]\nchurn-top = 3\n").unwrap();
    scan_json(root);
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    let second = scan_json(root);
    assert_eq!(second["summary"]["top_churn"]["top"], 3);
}

#[test]
fn a_replayed_report_states_the_same_top_churn_the_scan_did() {
    let dir = one_pair();
    let root = dir.path();
    scan_json(root);
    std::fs::write(root.join("src/b.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), FORMAT_RS).unwrap();
    let scanned = scan_json(root);
    let run = scanned["run"]["run_id"].as_i64().expect("a second run");

    let output = cmd()
        .current_dir(root)
        .args(["report", "--run", &run.to_string(), "--format", "json"])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    let replayed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(
        replayed["summary"]["top_churn"],
        scanned["summary"]["top_churn"]
    );
}
