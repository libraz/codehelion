use super::*;

/// A measuring routine whose loop is a small part of it.
const LOCAL_LEFT_RS: &str = "pub fn summarize_left(rows: &[String], width: usize) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    if width > 0 {
        total /= width;
    }
    total + widest
}
";

/// A routine that shares that loop verbatim and diverges everywhere else, so
/// the two units are alike only overall while the loop matches exactly.
const LOCAL_RIGHT_RS: &str = "pub fn summarize_right(rows: &[String], limit: usize) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    match limit {
        0 => widest = 1,
        other => total = total.min(other),
    }
    while total > widest {
        total -= widest.max(1);
    }
    total + widest
}
";

#[test]
fn a_run_naming_a_place_inside_its_hosts_survives_the_fold() {
    // The group says these two functions are alike overall, and says nothing
    // about where they agree exactly. The run does: this stretch is identical
    // and can be lifted out as it stands. Folding it would lose that, and it
    // is small enough in both hosts that the group is not already pointing
    // the reader at it.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/left.rs"), LOCAL_LEFT_RS).unwrap();
    std::fs::write(root.join("src/right.rs"), LOCAL_RIGHT_RS).unwrap();

    let value = scan_json(root);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 0);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 1);

    let groups = value["groups"].as_array().unwrap();
    let unit = groups.iter().find(|g| g["scope"] == "unit").unwrap();
    assert_eq!(unit["clone_type"], "type-3");
    let run = groups.iter().find(|g| g["scope"] == "fragment").unwrap();
    assert_eq!(run["clone_type"], "type-1");
    assert_eq!(run["statements"], 4);
    // Both hosts are members of the group that nonetheless failed to absorb it.
    let hosts: Vec<&str> = run["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["file"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, vec!["src/left.rs", "src/right.rs"]);
    // Each occurrence is well under half of the unit that hosts it; that is
    // what keeps it out of the fold.
    for member in run["members"].as_array().unwrap() {
        let host = unit["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["file"] == member["file"])
            .unwrap();
        assert!(member["tokens"].as_u64().unwrap() * 2 <= host["tokens"].as_u64().unwrap());
    }
    // Two findings about the same lines, kept apart because they say different
    // things. Read in order they would be two entries with nothing on either
    // connecting them, so the smaller names the one reporting the wider cut.
    assert_eq!(run["narrower_cut_of"], unit["fingerprint"]);
    assert!(
        unit.get("narrower_cut_of").is_none(),
        "nothing reports a wider cut of the widest finding"
    );
}

#[test]
fn a_replay_names_the_same_wider_cut_the_scan_did() {
    // Which findings sit inside which is a property of the run, not of the
    // pipeline that assembled it. A scan and a replay of the same run reaching
    // different answers would be two accounts of one set of findings.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/left.rs"), LOCAL_LEFT_RS).unwrap();
    std::fs::write(root.join("src/right.rs"), LOCAL_RIGHT_RS).unwrap();

    let scanned = scan_json(root);
    let output = cmd()
        .current_dir(root)
        .args(["report", "--format", "json", "--limit", "0"])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    let replayed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");

    let named = |value: &serde_json::Value| -> Vec<(String, Option<String>)> {
        let mut pairs: Vec<(String, Option<String>)> = value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| {
                (
                    group["fingerprint"].as_str().unwrap().to_string(),
                    group["narrower_cut_of"].as_str().map(ToOwned::to_owned),
                )
            })
            .collect();
        pairs.sort();
        pairs
    };
    let scanned = named(&scanned);
    assert!(
        scanned.iter().any(|(_, cover)| cover.is_some()),
        "the fixture is the one where a run survives inside the group holding it"
    );
    assert_eq!(scanned, named(&replayed));
}

/// A function that measures its input twice over, so a run is duplicated
/// inside it.
const SELF_A_RS: &str = "pub fn collect_alpha(rows: &[String]) -> usize {
    let mut total = 0usize;
    let mut widest = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    let mut second = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        total = total.saturating_add(size);
        widest = widest.max(size);
    }
    total + widest + second
}
";

/// A consistently renamed copy of it, so the two functions are a clone group.
const SELF_B_RS: &str = "pub fn collect_beta(items: &[String]) -> usize {
    let mut sum = 0usize;
    let mut peak = 0usize;
    for row in items {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        sum = sum.saturating_add(size);
        peak = peak.max(size);
    }
    let mut spare = 0usize;
    for row in items {
        let trimmed = row.trim_end();
        let size = trimmed.chars().count();
        sum = sum.saturating_add(size);
        peak = peak.max(size);
    }
    sum + peak + spare
}
";

#[test]
fn a_run_duplicated_inside_one_unit_survives_the_fold() {
    // Both cases at once. The run the two functions share is folded away:
    // the group that reports them as clones already implies it. The run each
    // function duplicates inside *itself* is not implied by anything, so it
    // stays — folding it would lose a finding no group states.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), SELF_A_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), SELF_B_RS).unwrap();

    let value = scan_json(root);
    assert_eq!(value["summary"]["groups"]["folded_runs"], 1);
    assert_eq!(value["summary"]["groups"]["fragment_scope"], 2);

    for group in value["groups"].as_array().unwrap() {
        if group["scope"] != "fragment" {
            continue;
        }
        let members = group["members"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(
            members[0]["unit"], members[1]["unit"],
            "the surviving runs are the ones a unit duplicates inside itself"
        );
        assert_ne!(members[0]["start_line"], members[1]["start_line"]);
    }
}

/// A routine whose copy elsewhere is exact.
const TRIO_A_RS: &str = "pub fn measure_alpha(rows: &[String]) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    total
}
";

/// The verbatim copy of it.
const TRIO_B_RS: &str = "pub fn measure_beta(rows: &[String]) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    total
}
";

/// A variant close to the first two but carrying an extra loop, so it is a
/// clone of one of them and further from the rest.
const TRIO_C_RS: &str = "pub fn measure_gamma(rows: &[String], width: usize) -> usize {
    let mut total = 0usize;
    for row in rows {
        let trimmed = row.trim_end();
        total = total.saturating_add(trimmed.len());
    }
    let mut pad = 0usize;
    while pad < width {
        pad += 2;
        total = total.saturating_add(pad);
    }
    total
}
";

#[test]
fn a_pair_no_group_holds_is_reported_and_says_so() {
    // Being a clone is not transitive, so a scan can verify a pair that no
    // group can hold. Dropping it would throw away a verdict the tool reached;
    // reporting it without saying what it is would read as a second, competing
    // account of code already covered elsewhere.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), TRIO_A_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), TRIO_B_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), TRIO_C_RS).unwrap();

    let value = scan_json(root);
    let groups = value["groups"].as_array().unwrap();
    for group in groups {
        assert!(
            group["split_pair"].is_boolean(),
            "every group states whether it is a pair no group holds"
        );
    }
    assert!(
        groups.iter().any(|group| group["split_pair"] == false),
        "the verbatim copies group"
    );
    // Whatever the corpus produces, a pair reported on its own has exactly two
    // members and is a clone class the judge accepted.
    for pair in groups.iter().filter(|group| group["split_pair"] == true) {
        assert_eq!(pair["members"].as_array().unwrap().len(), 2);
        assert_eq!(pair["priority"]["inputs"]["instances"], 2);
        assert!(
            pair["clone_type"].as_str().unwrap().starts_with("type-"),
            "a pair carries the class the judge gave it"
        );
    }
}

#[test]
fn every_entry_carries_the_measures_its_place_was_argued_from() {
    let dir = fixture();
    let value = scan_json(dir.path());

    // The run says how it weighed the measures, because two reports composed
    // under different weights are different orderings of the same findings.
    assert_eq!(value["run"]["ranking"]["maintenance_risk"], 2);
    assert_eq!(value["run"]["ranking"]["refactoring_ease"], 1);

    let groups = value["groups"].as_array().unwrap();
    assert!(!groups.is_empty());
    for group in groups {
        let priority = &group["priority"];
        for measure in [
            "value",
            "clone_confidence",
            "maintenance_risk",
            "refactoring_difficulty",
        ] {
            let value = priority[measure].as_f64().unwrap_or_else(|| {
                panic!("{measure} is a number");
            });
            assert!(
                (0.0..=1.0).contains(&value),
                "{measure} left its range at {value}"
            );
        }
        // Reserved until a backend measures them. Absent, never zero: zero is
        // a measurement, and none of these has been taken.
        for reserved in [
            "semantic_confidence",
            "source_artifact_confidence",
            "savings_confidence",
        ] {
            assert!(priority[reserved].is_null(), "{reserved} is not measured");
        }
        // The facts, so a reader who disagrees with the placement can see
        // which input produced it, and reproduce the ranking from the report.
        let inputs = &priority["inputs"];
        assert_eq!(inputs["min_clone_tokens"], 20);
        assert!(inputs["smallest_member_tokens"].as_u64().unwrap() > 0);
        assert!(
            inputs["smallest_member_tokens"].as_u64().unwrap()
                <= inputs["largest_member_tokens"].as_u64().unwrap()
        );
        assert!(inputs["instances"].as_u64().unwrap() >= 2);
        assert_eq!(inputs["languages"], 1);
        assert!(inputs["churn"].is_null());
        assert!(inputs["ownership_spread"].is_null());
    }
}

#[test]
fn the_weights_change_the_order_and_nothing_else() {
    let dir = fixture();
    let root = dir.path();
    std::fs::write(root.join("src/c.rs"), OTHER_RS.replace("label", "caption")).unwrap();

    let before = scan_json(root);
    // Ranking on confidence alone: the maintenance argument stops being heard.
    std::fs::write(
        root.join("codehelion.toml"),
        "[priority]\nmaintenance-risk = 0\nrefactoring-ease = 0\n",
    )
    .unwrap();
    let after = scan_json(root);

    assert_eq!(after["run"]["ranking"]["maintenance_risk"], 0);
    assert_ne!(
        before["run"]["ranking"]["recipe"], after["run"]["ranking"]["recipe"],
        "the recorded recipe names the weights it was composed under"
    );
    // The same findings, said the same way: weights decide the order a report
    // is read in and nothing about what is in it.
    let names = |value: &serde_json::Value| {
        let mut ids: Vec<String> = value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["fingerprint"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(names(&before), names(&after));
    for (a, b) in before["groups"]
        .as_array()
        .unwrap()
        .iter()
        .zip(after["groups"].as_array().unwrap())
    {
        assert_eq!(
            a["priority"]["clone_confidence"],
            b["priority"]["clone_confidence"]
        );
        assert_eq!(
            a["priority"]["maintenance_risk"],
            b["priority"]["maintenance_risk"]
        );
    }
}

#[test]
fn two_runs_of_one_tree_rank_it_identically() {
    let dir = fixture();
    let first = without_identity(scan_json(dir.path()));
    let second = without_identity(scan_json(dir.path()));
    assert_eq!(first, second);
}

/// A report's groups with their relation to any earlier run dropped. That
/// relation is a statement about a pair of runs; a rerun that names one is not
/// a rerun that ranked anything differently.
fn without_identity(mut report: serde_json::Value) -> serde_json::Value {
    let groups = report["groups"].as_array_mut().expect("groups");
    for group in groups.iter_mut() {
        group
            .as_object_mut()
            .expect("a group object")
            .remove("identity");
    }
    report["groups"].take()
}

#[test]
fn a_ranking_does_not_move_because_something_else_was_found() {
    // What makes a priority comparable between two runs, and what a
    // rank-based composition would give up: a finding's place is computed from
    // its own facts, so it cannot move because the scan found one more group.
    let dir = fixture();
    let root = dir.path();
    let alone = scan_json(root);
    let before: Vec<(String, f64)> = alone["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["fingerprint"].as_str().unwrap().to_string(),
                group["priority"]["value"].as_f64().unwrap(),
            )
        })
        .collect();

    std::fs::write(root.join("src/c.rs"), TRIO_A_RS).unwrap();
    std::fs::write(root.join("src/d.rs"), TRIO_B_RS).unwrap();
    let crowded = scan_json(root);
    let after: std::collections::BTreeMap<String, f64> = crowded["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["fingerprint"].as_str().unwrap().to_string(),
                group["priority"]["value"].as_f64().unwrap(),
            )
        })
        .collect();
    assert!(after.len() > before.len(), "the second scan found more");
    for (fingerprint, value) in before {
        assert_eq!(
            after.get(&fingerprint),
            Some(&value),
            "group {fingerprint} was re-ranked by the arrival of another group"
        );
    }
}

#[test]
fn explain_says_which_fact_put_the_finding_where_it_is() {
    let dir = fixture();
    let root = dir.path();
    let value = scan_json(root);
    let finding = value["groups"][0]["members"][0]["finding_id"]
        .as_str()
        .unwrap()
        .to_string();

    let text = cmd()
        .current_dir(root)
        .args(["explain", &finding])
        .output()
        .expect("run explain");
    assert!(text.status.success(), "{text:?}");
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("priority:"), "{text}");
    // Each measure names the facts behind it rather than only its value.
    assert!(
        text.contains("tokens in the smallest occurrence against a 20-token floor"),
        "{text}"
    );
    assert!(text.contains("maintenance risk"), "{text}");
    assert!(text.contains("refactoring difficulty"), "{text}");
    // And says which inputs nobody has measured, so a zero is never inferred
    // from their absence.
    assert!(
        text.contains("not measured by this run, and so not weighed"),
        "{text}"
    );
}

/// A routine whose body is a closure holding another closure: one duplication
/// the detector finds at three nested cuts.
const NESTED_LEFT_RS: &str =
    "pub fn mappings_left(canonical: &[u32], members: &[Vec<u32>]) -> Vec<(u32, u32, u32)> {
    members
        .iter()
        .enumerate()
        .skip(1)
        .flat_map(|(member, corresponding)| {
            (0..canonical.len().min(corresponding.len()))
                .filter_map(move |node| {
                    let node = u32::try_from(node).ok()?;
                    let member = u32::try_from(member).ok()?;
                    Some((member, node, node))
                })
        })
        .collect()
}
";

#[test]
fn nested_cuts_of_one_duplication_are_folded_into_the_longest_and_counted() {
    // Copying the routine duplicates its closures with it, so the function,
    // the closure and the closure inside that one are each a clone of their
    // counterpart. Three findings over one pair of units say one thing, and
    // the reader going down the report meets it three times.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/left.rs"), NESTED_LEFT_RS).unwrap();
    std::fs::write(
        root.join("src/right.rs"),
        NESTED_LEFT_RS.replace("mappings_left", "mappings_right"),
    )
    .unwrap();

    let value = scan_json(root);

    let groups = value["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    // The one left is the longest cut: the whole routine, not a closure of it.
    let members: Vec<(&str, u64)> = groups[0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            (
                member["file"].as_str().unwrap(),
                member["end_line"].as_u64().unwrap() - member["start_line"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(members, vec![("src/left.rs", 14), ("src/right.rs", 14)]);
    // The two that went are accounted for where everything covered by a
    // longer finding is accounted for.
    assert_eq!(value["summary"]["groups"]["subsumed_runs"], 2);
}
