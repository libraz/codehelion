use super::*;

/// A rendering routine carrying a measurement loop.
const RENDER_RS: &str = "pub fn render_rows(rows: &[String], width: usize) -> String {
    let mut out = String::new();
    let mut index = 0usize;
    while index < rows.len() {
        out.push_str(&rows[index]);
        out.push('\\n');
        index += 1;
    }
    if out.is_empty() {
        return String::from(\"(empty)\");
    }
    out.push_str(\"---\");
    out.push('\\n');
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    out.push_str(&format!(\"{total} {widest} {width}\"));
    out.push('\\n');
    out.push_str(\"===\");
    out
}
";

/// An auditing routine that computes something else entirely, and carries a
/// verbatim copy of the measurement loop's body. The two functions are not
/// clones of each other; only that stretch is duplicated.
const AUDIT_RS: &str = "pub fn audit_entries(entries: &[String], limit: u64) -> u64 {
    let mut flagged = 0u64;
    match entries.first() {
        Some(first) if first.is_empty() => return 0,
        Some(_) => flagged += 1,
        None => return 0,
    }
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in entries {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    loop {
        if total <= widest {
            break;
        }
        total -= widest.max(1);
        flagged += 1;
    }
    if flagged > limit {
        flagged = limit;
    }
    flagged
}
";

/// A tree whose only duplication is a run shared by two unrelated functions.
fn run_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/render.rs"), RENDER_RS).unwrap();
    std::fs::write(root.join("src/audit.rs"), AUDIT_RS).unwrap();
    dir
}

/// Two unrelated functions whose shared run is structurally identical only
/// after every raw identifier in the run is renamed.
const RENAMED_LEFT_RS: &str = "pub fn collect_records(records: &[u64]) -> u64 {
    let mut accumulator = 0u64;
    let mut sentinel = 7u64;
    for sample in records {
        let adjusted = sample + 1;
        let doubled = adjusted * 2;
        let reduced = doubled - 3;
        accumulator += reduced;
        sentinel ^= reduced;
    }
    accumulator + sentinel
}
";

const RENAMED_RIGHT_RS: &str = "pub fn inspect_values(values: &[u64]) -> u64 {
    let mut tally = 11u64;
    let mut marker = 5u64;
    for entry in values {
        let shifted = entry + 1;
        let amplified = shifted * 2;
        let reserve = amplified - 3;
        tally += reserve;
        marker ^= reserve;
    }
    if tally > marker { tally } else { marker }
}
";

fn renamed_run_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/left.rs"), RENAMED_LEFT_RS).unwrap();
    std::fs::write(root.join("src/right.rs"), RENAMED_RIGHT_RS).unwrap();
    dir
}

#[test]
fn a_run_shared_by_unrelated_units_is_reported_as_a_run() {
    let dir = run_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        // The extent is stated: without it the entry reads as a duplicated
        // function, which neither occurrence is.
        .stdout(predicate::str::contains("type-1 run ×"))
        .stdout(predicate::str::contains("run of 4 statements"))
        // Each occurrence and the unit it sits in. Asserted apart because the
        // two are separate columns, and the space between them is whatever
        // the widest path in the listing needed.
        .stdout(predicate::str::contains("src/audit.rs:11-14"))
        .stdout(predicate::str::contains("audit_entries"))
        .stdout(predicate::str::contains("src/render.rs:17-20"))
        .stdout(predicate::str::contains("render_rows"))
        .stdout(predicate::str::contains(
            "1 of them are runs duplicated inside units that are not clones of each other",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["total"], 1);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 1);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 0);
    // Nothing longer covers this run, so nothing is left out on that account.
    assert_eq!(value["summary"]["groups"]["subsumed_runs"], 0);
    let group = &value["groups"][0];
    assert_eq!(group["scope"], "fragment");
    assert_eq!(group["statements"], 4);
    assert_eq!(group["clone_type"], "type-1");
    // Confirmed by content equality rather than scored across dimensions.
    assert_eq!(group["similarity"], serde_json::Value::Null);
    assert_eq!(group["confidence"], 1.0);
    assert_eq!(group["identifier_jaccard"], 1.0);
    let units: Vec<&str> = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["unit"].as_str().unwrap())
        .collect();
    assert_eq!(units, vec!["audit_entries", "render_rows"]);
}

#[test]
fn identifier_jaccard_distinguishes_verbatim_and_renamed_runs() {
    let verbatim = scan_json(run_fixture().path());
    let verbatim_run = verbatim["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["scope"] == "fragment")
        .expect("the verbatim fixture reports its run");
    assert_eq!(verbatim_run["identifier_jaccard"], 1.0);

    let renamed = scan_json(renamed_run_fixture().path());
    let renamed_run = renamed["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["scope"] == "fragment")
        .expect("the renamed fixture reports its run");
    assert_eq!(renamed_run["clone_type"], "type-2");
    assert!(
        renamed_run["identifier_jaccard"].as_f64().unwrap() < 0.05,
        "the run replaces every raw identifier: {renamed_run:#?}"
    );
}

#[test]
fn a_reported_run_is_recorded_against_the_units_that_host_it() {
    let dir = run_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success();

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let groups = store.run_groups(run.id).unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.member_scope, "fragment");
    assert_eq!(group.clone_type, "type-1");
    // Entropy is measured over the run's own tokens, not its host unit's.
    assert!(group.entropy_bits > 1.0);
    assert_eq!(group.identifier_jaccard, Some(1.0));
    for member in &group.members {
        let host = member.unit_name.as_deref().expect("a host unit");
        assert!(host == "audit_entries" || host == "render_rows");
        // The anchor is the run, so it is a fraction of the unit it sits in.
        assert!(member.token_count < 60);
    }

    let finding = &group.members[0].finding_hex;
    cmd()
        .current_dir(dir.path())
        .args(["explain", finding])
        .assert()
        .success()
        // What the occurrence is, not just where: the unit is the host, and
        // the group is about the run inside it.
        .stdout(predicate::str::contains("duplicated run, type-1"))
        .stdout(predicate::str::contains("2 instances"));
}

#[test]
fn a_run_a_group_already_covers_is_folded_into_it_and_counted() {
    // The gapped fixture's two functions are clones of each other, so every
    // run they share is implied by the group that already reports them.
    // Listing both would describe one duplication twice.
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "were folded into the groups that already cover them",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 0);
    assert!(
        value["summary"]["groups"]["folded_runs"].as_u64().unwrap() > 0,
        "the fold has to have happened, or this proves nothing"
    );
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["scope"] == "unit")
    );
}

#[test]
fn a_path_rule_hides_a_run_as_it_hides_a_group() {
    let dir = run_fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/**\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("run of 4 statements").not());

    // Hidden, not deleted: the run is still recorded with the rule that hid it.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|finding| finding.suppression_scope.as_deref() == Some("path_glob"))
    );
}

#[test]
fn a_suppression_rule_that_matched_nothing_is_named() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        // The path glob names a directory this tree does not have, and the
        // clone id names a group this run did not produce.
        "[suppression]\npaths = [\"third_party/**\"]\nclone-ids = [\"0123456789abcdef\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("note: 2 suppression rule(s) matched nothing")
                .and(predicate::str::contains("path glob \"third_party/**\""))
                .and(predicate::str::contains("clone id 0123456789abcdef")),
        );

    let value = scan_json(dir.path());
    let unused = value["summary"]["unused_suppressions"].as_array().unwrap();
    assert_eq!(unused.len(), 2);
    assert_eq!(unused[0]["scope"], "path_glob");
    assert_eq!(unused[1]["scope"], "stable_clone_id");
}

#[test]
fn a_set_of_related_units_too_large_to_compare_whole_is_cut_and_said_so() {
    let dir = fixture();
    // A third copy, so the three functions form one set of related units.
    std::fs::write(
        dir.path().join("src/c.rs"),
        GAPPED_RS
            .replace("beta", "gamma")
            .replace("state", "total")
            .replace("seen", "hits"),
    )
    .unwrap();
    // A ceiling of two forces the cut on a set this small.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-component = 2\n",
    )
    .unwrap();

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        // A warning rather than a note: a cut set is duplication the run may
        // have reported as several groups, or not at all, which is about
        // whether to believe the report rather than about how to read it.
        .stderr(predicate::str::contains(
            "warning: 1 set(s) of related units were too large to compare as one",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["split_components"], 1);
    // The cut costs recall, not soundness: the pieces are still cohesive
    // groups, each with its own canonical instance.
    let groups = value["groups"].as_array().unwrap();
    assert!(groups.len() >= 2, "the set is reported as several groups");
    for group in groups {
        assert!(group["confidence"].as_f64().unwrap() >= 0.6);
        assert_eq!(group["members"][0]["canonical"], true);
    }
}

#[test]
fn the_run_says_how_far_each_stage_of_the_pipeline_narrowed_it() {
    let dir = fixture();
    let value = scan_json(dir.path());
    let funnel = value["summary"]["funnel"].as_array().unwrap();
    let stage = |name: &str| {
        funnel
            .iter()
            .find(|entry| entry["stage"] == name)
            .unwrap_or_else(|| panic!("stage {name} is reported"))
    };
    let passed = |name: &str| stage(name)["passed"].as_u64().unwrap();

    // Both branches of the run are accounted for: units narrow to verified
    // pairs, and the window seeds narrow to confirmed runs.
    assert!(passed("units") >= 3, "one unit per fixture function");
    assert!(passed("indexed fragments") > passed("unit pairs"));
    assert!(passed("verified pairs") <= passed("unit pairs"));
    assert!(passed("confirmed runs") <= passed("duplicated runs"));

    // Each stage's drops are named rather than folded into the passed count.
    for entry in funnel {
        for drop in entry["dropped"].as_array().unwrap() {
            assert!(
                drop["count"].as_u64().unwrap() > 0,
                "{drop} dropped nothing"
            );
            assert!(drop["cause"].as_str().unwrap().is_ascii());
        }
    }

    // The counts are detail, so they stay out of the default text view.
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:").not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-vv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("candidate pipeline:"))
        .stdout(predicate::str::contains("verified pairs"));
}

#[test]
fn a_suppression_rule_that_hid_something_is_not_called_unused() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/**\", \"third_party/**\"]\n",
    )
    .unwrap();
    let value = scan_json(dir.path());
    let unused = value["summary"]["unused_suppressions"].as_array().unwrap();
    assert_eq!(unused.len(), 1, "only the glob that matched nothing");
    assert_eq!(unused[0]["pattern"], "third_party/**");
}

#[test]
fn a_path_selector_matching_part_of_a_group_is_not_called_unused() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/a.rs\", \"third_party/**\"]\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    let unused = value["summary"]["unused_suppressions"]
        .as_array()
        .expect("unused rules array");

    // The Type-3 group spans src/a.rs and src/b.rs, so it remains visible;
    // nevertheless the selector did match source and is not stale.
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0]["pattern"], "third_party/**");
}
