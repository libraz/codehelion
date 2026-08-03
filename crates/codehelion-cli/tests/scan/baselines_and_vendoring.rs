use super::*;

#[test]
fn baseline_create_and_update_keep_every_completed_partition_of_one_invocation() {
    let dir = fixture();
    let root = dir.path();
    let root_text = root
        .canonicalize()
        .expect("canonical fixture root")
        .to_string_lossy()
        .into_owned();
    let fast = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let structural = BuildVariant::structural(LanguageSelection::default(), Language::C);
    std::fs::create_dir_all(root.join(".codehelion")).expect("create audit directory");
    let mut store = open_store(root);
    let fast_run = store
        .record_snapshot_part(&empty_snapshot(&root_text, &fast))
        .expect("record fast partition");
    let structural_run = store
        .record_snapshot_part(&empty_snapshot(&root_text, &structural))
        .expect("record structural partition");
    store
        .complete_snapshot_parts(&[fast_run, structural_run])
        .expect("complete both partitions atomically");

    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 build variants"));

    let baseline: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("baseline.json")).expect("read written baseline"),
    )
    .expect("parse baseline JSON");
    assert_eq!(
        baseline["schema_version"],
        u64::from(codehelion_cli::baseline::SCHEMA_VERSION)
    );
    let partitions = baseline["partitions"].as_array().expect("partitions");
    assert_eq!(partitions.len(), 2);
    let fingerprints: std::collections::BTreeSet<_> = partitions
        .iter()
        .filter_map(|partition| {
            partition["build_variant"]["fingerprint"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect();
    assert_eq!(
        fingerprints,
        std::collections::BTreeSet::from([fast.fingerprint(), structural.fingerprint()])
    );

    cmd()
        .current_dir(root)
        .args(["baseline", "update", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 build variants"));
}

#[test]
fn a_baseline_hides_what_came_before_it_and_nothing_else() {
    let dir = fixture();
    let root = dir.path();

    let before = scan_json(root);
    let frozen = visible_ids(&before);
    assert!(!frozen.is_empty(), "the fixture duplicates on purpose");
    record_baseline(root);

    // Everything the baseline froze is hidden, and hidden by the baseline.
    let baselined = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(visible_ids(&baselined).is_empty(), "all of it was frozen");
    let status = &baselined["summary"]["baseline"];
    assert_eq!(status["entries"], frozen.len());
    assert_eq!(status["mode"], "suppress", "hiding is the default");
    assert_eq!(status["matched"], frozen.len());
    assert_eq!(status["stale"], 0);
    assert!(status.get("mismatch").is_none(), "the same run's own ids");
    let hidden = baselined["groups"].as_array().expect("groups");
    assert!(
        hidden
            .iter()
            .all(|group| group["suppressed"]["scope"] == "baseline"),
        "suppressed, not deleted, and by the baseline: {hidden:?}"
    );

    // A duplication written after the baseline is the one thing left to see.
    // It has to be unlike anything already there: a near-copy of a frozen
    // group would join that group, and a group's id moves when its membership
    // gains content — which is a different behaviour from this one.
    std::fs::write(root.join("src/new_one.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("src/new_two.rs"), FORMAT_RS).unwrap();
    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    let visible = visible_ids(&after);
    assert_eq!(visible.len(), 1, "only what came after: {visible:?}");
    assert!(!frozen.contains(&visible[0]));
}

#[test]
fn baseline_create_refreshes_findings_hidden_by_an_earlier_baseline() {
    let dir = fixture();
    let root = dir.path();
    let initial = scan_json(root);
    let frozen = visible_ids(&initial);
    assert!(!frozen.is_empty(), "the fixture duplicates on purpose");
    record_baseline(root);

    let baselined = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(
        baselined["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .all(|group| group["suppressed"]["scope"] == "baseline")
    );

    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "refreshed.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "{} findings frozen",
            frozen.len()
        )));
    let refreshed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("refreshed.json")).expect("read refreshed baseline"),
    )
    .expect("parse refreshed baseline");
    let refreshed_ids: std::collections::BTreeSet<String> = refreshed["partitions"][0]["entries"]
        .as_array()
        .expect("baseline entries")
        .iter()
        .map(|entry| entry["group"].as_str().expect("group id").to_string())
        .collect();

    assert_eq!(refreshed_ids, frozen.into_iter().collect());
}

#[test]
fn a_baseline_survives_an_edit_that_changes_no_code() {
    let dir = fixture();
    let root = dir.path();
    scan_json(root);
    record_baseline(root);

    // Comments and blank lines do not survive tokenization, so an edit made
    // of nothing else cannot move a content fingerprint — however far it
    // shifts the line numbers the report prints.
    std::fs::write(
        root.join("src/a.rs"),
        format!("// A leading comment.\n//\n// And another.\n\n{CHECKSUM_RS}"),
    )
    .unwrap();

    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert!(
        visible_ids(&after).is_empty(),
        "reformatting is not new duplication"
    );
    assert_eq!(after["summary"]["baseline"]["stale"], 0);
}

#[test]
fn a_copy_added_to_a_baselined_group_remains_visible() {
    let dir = one_pair();
    let root = dir.path();
    let before = scan_json(root);
    let frozen = before["groups"]
        .as_array()
        .expect("one clone group")
        .iter()
        .find(|group| {
            let files: Vec<&str> = group["members"]
                .as_array()
                .expect("members")
                .iter()
                .filter_map(|member| member["file"].as_str())
                .collect();
            files.contains(&"src/a.rs") && files.contains(&"src/b.rs")
        })
        .expect("the pair being frozen")["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    record_baseline(root);

    // Its normalized content is identical to the first two members. The
    // stable group fingerprint deliberately remains the same; coverage must
    // instead stop at the two occurrences the baseline froze.
    std::fs::write(root.join("src/c.rs"), CHECKSUM_RS).unwrap();
    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    let group = after["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| group["fingerprint"] == frozen)
        .expect("the same-content group");
    assert!(
        group["suppressed"].is_null(),
        "the added copy is actionable"
    );
    assert_eq!(group["members"].as_array().expect("members").len(), 3);
    assert_eq!(group["baseline"]["state"], "expanded");
    assert_eq!(group["baseline"]["added_instances"], 1);

    let status = &after["summary"]["baseline"];
    assert_eq!(status["matched"], 1);
    assert_eq!(status["expanded"], 1);
    assert_eq!(status["expanded_instances"], 1);
}

#[test]
fn resolving_a_duplication_makes_its_entry_stale_and_update_drops_it() {
    let dir = fixture();
    let root = dir.path();
    let before = scan_json(root);
    let frozen = group_ids(&before).len();
    record_baseline(root);

    // The C pair is resolved the way it would be in practice: one copy goes.
    std::fs::remove_file(root.join("src/two.c")).unwrap();
    let after = scan_json_with(root, &["--baseline", "baseline.json"]);
    let stale = after["summary"]["baseline"]["stale"]
        .as_u64()
        .expect("a count");
    assert!(stale > 0, "the duplication the deleted file was half of");

    cmd()
        .current_dir(root)
        .args(["baseline", "update", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("resolved and dropped"));

    // Pruning drops exactly the stale entries and adopts nothing.
    let pruned = scan_json_with(root, &["--baseline", "baseline.json"]);
    assert_eq!(pruned["summary"]["baseline"]["stale"], 0);
    assert_eq!(
        pruned["summary"]["baseline"]["entries"]
            .as_u64()
            .expect("a count"),
        u64::try_from(frozen).unwrap() - stale
    );
}

/// A tree whose duplication sits in a vendored subtree, in a directory whose
/// name merely starts like one, and in the project's own code.
fn vendored_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("third_party/r8brain")).unwrap();
    std::fs::create_dir_all(root.join("external_api")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    // Upstream code duplicating itself: nobody here can unify it.
    std::fs::write(root.join("third_party/r8brain/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("third_party/r8brain/b.rs"), CHECKSUM_RS).unwrap();
    // A directory whose name only starts like a vendored one.
    std::fs::write(root.join("external_api/a.rs"), FORMAT_RS).unwrap();
    std::fs::write(root.join("external_api/b.rs"), FORMAT_RS).unwrap();
    dir
}

/// A Rust function unlike anything else in the fixtures, for a pair that has
/// to land in its own group.
const TRIM_RS: &str = "pub fn trim_suffix(text: &str, suffix: &str) -> String {
    if text.ends_with(suffix) {
        let cut = text.len() - suffix.len();
        return text[..cut].to_string();
    }
    text.to_string()
}
";

#[test]
fn vendored_trees_are_hidden_by_default_and_the_report_says_it_did_that() {
    let dir = vendored_fixture();
    let root = dir.path();

    let report = scan_json(root);
    let visible: Vec<&serde_json::Value> = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|group| group["suppressed"].is_null())
        .collect();
    // A name that merely starts like a vendored one is the project's own code:
    // globs match whole path components, so `external/` does not claim it.
    assert_eq!(visible.len(), 1, "{visible:?}");
    assert_eq!(visible[0]["members"][0]["file"], "external_api/a.rs");

    let hidden = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| group["suppressed"]["scope"] == "vendored_path")
        .expect("the vendored pair, suppressed rather than dropped");
    assert!(
        hidden["suppressed"]["pattern"]
            .as_str()
            .expect("the glob that matched")
            .contains("third_party")
    );
    assert_eq!(report["summary"]["suppressed"]["vendored"], 1);

    // Applied without anybody asking, so the run says so and names the way out.
    cmd()
        .current_dir(root)
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("duplication inside vendored trees")
                .and(predicate::str::contains("--include-vendored")),
        );
}

#[test]
fn vendored_suppression_can_be_undone_for_one_run_or_switched_off() {
    let dir = vendored_fixture();
    let root = dir.path();

    let included = scan_json_with(root, &["--include-vendored"]);
    assert_eq!(included["summary"]["suppressed"]["vendored"], 0);
    assert_eq!(visible_ids(&included).len(), 2);

    std::fs::write(
        root.join("codehelion.toml"),
        "[suppression]\nvendored-paths = []\n",
    )
    .unwrap();
    let configured = scan_json(root);
    assert_eq!(configured["summary"]["suppressed"]["vendored"], 0);
    assert_eq!(visible_ids(&configured).len(), 2);
}

#[test]
fn duplication_between_a_vendored_tree_and_the_project_stays_visible() {
    let dir = vendored_fixture();
    let root = dir.path();
    // The project copied upstream code into its own tree. Nothing about that
    // is upstream's problem, and hiding half of it would hide all of it.
    std::fs::write(root.join("third_party/r8brain/c.rs"), TRIM_RS).unwrap();
    std::fs::write(root.join("src/ours.rs"), TRIM_RS).unwrap();

    let report = scan_json(root);
    let crossing = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| {
            group["members"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| member["file"] == "src/ours.rs")
        })
        .expect("the group crossing the boundary");
    assert!(
        crossing["suppressed"].is_null(),
        "a group is hidden only when every occurrence in it is: {crossing:?}"
    );
}
