use super::*;

/// A configuration naming where the database goes.
///
/// Written as a TOML literal string rather than a basic one, because a
/// Windows path is mostly backslashes and a basic string reads each of them
/// as the start of an escape.
fn database_setting(path: &Path) -> String {
    format!("database = '{}'\n", path.display())
}

/// A scan report with the fields that legitimately differ between runs
/// removed, so two of them can be compared whole.
fn comparable_report(root: &Path, extra: &[&str]) -> serde_json::Value {
    let mut value = scan_json_with(root, extra);
    let run = value["run"].as_object_mut().expect("run object");
    for key in ["started_at", "finished_at", "run_id", "reused"] {
        run.insert(key.to_string(), serde_json::Value::Null);
    }
    // A later run has an earlier one to compare itself with; what it found in
    // the sources is what has to agree, not what it knows about its own
    // history.
    let summary = value["summary"].as_object_mut().expect("summary object");
    for key in ["changes", "audit"] {
        summary.insert(key.to_string(), serde_json::Value::Null);
    }
    value
}

#[test]
fn json_reports_are_deterministic_across_reruns() {
    let dir = fixture();
    let first = comparable_report(dir.path(), &[]);
    let second = comparable_report(dir.path(), &[]);
    assert_eq!(first, second);
}

#[test]
fn report_without_a_run_replays_the_latest_completed_scan() {
    let dir = fixture();
    let first = scan_json(dir.path());
    let second = scan_json(dir.path());
    assert_eq!(first["run"]["run_id"], second["run"]["run_id"]);

    let output = cmd()
        .current_dir(dir.path())
        .args(["report", "--format", "json"])
        .output()
        .expect("replay the latest scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replayed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("report is JSON");
    assert_eq!(replayed["run"]["run_id"], second["run"]["run_id"]);
}

#[test]
fn fast_partial_unit_matches_are_reported_and_replayed_as_fragments() {
    const LEFT: &str = r"pub fn left(values: &[u64]) -> u64 {
    let prefix = values.len() as u64;
    let mut acc = 17_u64;
    for value in values {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^= 0x5a5a;
    acc + prefix
}
";
    const RIGHT: &str = r"pub fn right(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut acc = 17_u64;
    for value in values {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^= 0x5a5a;
    acc.rotate_left(3)
}
";
    let dir = tempfile::tempdir().expect("temporary Fast fixture");
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/left.rs"), LEFT).unwrap();
    std::fs::write(dir.path().join("src/right.rs"), RIGHT).unwrap();
    std::fs::write(dir.path().join("src/exact_a.rs"), FORMAT_RS).unwrap();
    std::fs::write(dir.path().join("src/exact_b.rs"), FORMAT_RS).unwrap();

    let report = scan_json_with(dir.path(), &["--mode", "fast"]);
    let group = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| {
            group["members"]
                .as_array()
                .is_some_and(|members| members.iter().any(|member| member["file"] == "src/left.rs"))
        })
        .expect("the shared body is detected");
    assert_eq!(group["scope"], "fragment");
    assert!(
        group["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|member| member["unit"].is_string())
    );
    let exact_group = report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|group| {
            group["members"].as_array().is_some_and(|members| {
                members
                    .iter()
                    .any(|member| member["file"] == "src/exact_a.rs")
                    && members
                        .iter()
                        .any(|member| member["file"] == "src/exact_b.rs")
            })
        })
        .expect("the whole-unit copies are detected");
    assert_eq!(exact_group["scope"], "unit");

    let store = Store::open_existing(&dir.path().join(".codehelion/audit.db")).unwrap();
    let run = store.latest_run().unwrap().expect("recorded run");
    let stored = store
        .run_groups(run.id)
        .unwrap()
        .into_iter()
        .find(|stored| stored.fingerprint_hex == group["fingerprint"])
        .expect("the reported group is stored");
    assert_eq!(stored.member_scope, "fragment");
}

/// A tree wide enough that the work actually spreads: one file per worker and
/// then some, in three contents so there is grouping to do rather than one
/// group of everything.
fn wide_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    for index in 0..24 {
        let (name, body) = match index % 3 {
            0 => (format!("src/copy{index}.rs"), CHECKSUM_RS),
            1 => (format!("src/renamed{index}.rs"), RENAMED_RS),
            _ => (format!("src/mix{index}.c"), MIX_C),
        };
        std::fs::write(root.join(name), body).unwrap();
    }
    dir
}

#[test]
fn the_worker_count_does_not_change_what_the_scan_reports() {
    // Ordering that comes from whichever worker finished first is the failure
    // this catches, and it is invisible at one thread: a report built by one
    // worker is in the order the tree was walked whether or not anything
    // downstream depends on that order. Comparing the documents whole is what
    // makes the check worth running — a group count would agree while the
    // members inside the groups shuffled.
    let dir = wide_fixture();
    let mut documents = Vec::new();
    for jobs in ["1", "4", "8"] {
        for mode in ["fast", "structural"] {
            let report = comparable_report(dir.path(), &["--jobs", jobs, "--mode", mode]);
            documents.push((
                mode,
                jobs,
                serde_json::to_vec(&report).expect("canonical comparison JSON"),
                report,
            ));
        }
    }
    for mode in ["fast", "structural"] {
        let mut same_mode = documents.iter().filter(|(m, _, _, _)| *m == mode);
        let (_, first_jobs, first_bytes, first) =
            same_mode.next().expect("at least one worker count");
        // An agreement between two empty reports is not the agreement this is
        // about.
        let members: usize = first["groups"]
            .as_array()
            .expect("groups array")
            .iter()
            .map(|group| group["members"].as_array().expect("members array").len())
            .sum();
        assert!(
            members >= 20,
            "{mode} mode placed {members} members over 24 files, too few for an \
             ordering to go wrong in",
        );
        for (_, jobs, other_bytes, _) in same_mode {
            assert_eq!(
                first_bytes, other_bytes,
                "{mode} mode reported differently at {jobs} workers than at {first_jobs}",
            );
        }
    }
}

#[test]
fn json_suppression_status_names_the_matching_rule() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/*.c\"]\n",
    )
    .unwrap();
    let value = scan_json(dir.path());
    let suppressed: Vec<_> = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| !group["suppressed"].is_null())
        .collect();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(suppressed[0]["suppressed"]["kind"], "rule");
    assert_eq!(suppressed[0]["suppressed"]["scope"], "path_glob");
    assert_eq!(suppressed[0]["suppressed"]["pattern"], "src/*.c");

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json", "--show-suppressed"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--show-suppressed applies only to text reports",
        ));
}

/// Engine-derived suppression is as much part of a stored finding as a
/// configured rule, so `explain` must not turn it into an unsuppressed one.
#[test]
fn explain_preserves_an_engine_noise_suppression() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "entropy-ratio-floor = 1.0\n",
    )
    .unwrap();
    let report = scan_json(dir.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| group["suppressed"]["kind"] == "noise")
        .expect("an engine-noise group");
    let finding_id = group["members"][0]["finding_id"]
        .as_str()
        .expect("finding id");

    let output = cmd()
        .current_dir(dir.path())
        .args(["explain", finding_id, "--format", "json"])
        .output()
        .expect("explain noise-suppressed finding");
    assert!(output.status.success(), "{output:?}");
    let detail: serde_json::Value = serde_json::from_slice(&output.stdout).expect("explain JSON");
    assert_eq!(
        detail["group"]["suppressed"], group["suppressed"],
        "the persisted engine reason is preserved by explain"
    );
}

#[test]
fn default_reports_truncate_members_and_verbose_lists_them_all() {
    let dir = fixture();
    // Grow the Rust body-fragment group to 10 members (a.rs, b.rs, the
    // renamed c.rs copy, and 7 verbatim copies).
    for index in 0..7 {
        std::fs::write(dir.path().join(format!("src/copy{index}.rs")), CHECKSUM_RS).unwrap();
    }
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        // Every occurrence is listed under the group, so five of the ten
        // appear and the count carries the rest.
        .stdout(predicate::str::contains("... and 5 more occurrences"));
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--limit", "0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("more occurrences").not())
        .stdout(predicate::str::contains("src/copy6.rs"));
}

/// The quiet view is what a script reads: the findings, and nothing that
/// describes the run around them.
#[test]
fn the_quiet_view_leaves_the_heading_and_the_summary_out() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--quiet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("src/a.rs"))
        .stdout(predicate::str::contains("codehelion scan").not())
        .stdout(predicate::str::contains("sorted by").not());
}

/// Colour follows the destination by default and the flag when it is given,
/// with `NO_COLOR` honoured as every other command-line tool honours it.
#[test]
fn colour_follows_the_destination_the_flag_and_no_color() {
    let dir = fixture();
    let ansi = predicate::str::contains('\x1b');

    // Captured output is not a terminal, so the default emits none.
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(ansi.clone().not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--color", "always"])
        .assert()
        .success()
        .stdout(ansi.clone());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--color", "always"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        // An explicit request outranks the environment: the flag was typed
        // for this run, the variable was set for every run.
        .stdout(ansi.clone());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--color", "never"])
        .assert()
        .success()
        .stdout(ansi.not());
}

/// Glyphs are chosen apart from colour, and a report written to a file keeps
/// the ones a terminal would have shown.
#[test]
fn decoration_is_chosen_by_its_own_flag_and_survives_redirection() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--decoration", "ascii"])
        .assert()
        .success()
        .stdout(predicate::str::contains("|- "))
        .stdout(predicate::str::contains("├─").not())
        .stdout(predicate::str::contains('·').not());
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--decoration", "none"])
        .assert()
        .success()
        .stdout(predicate::str::contains("|- ").not())
        .stdout(predicate::str::contains("├─").not())
        .stdout(predicate::str::contains("src/a.rs"));
    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--decoration",
            "unicode",
            "--output",
            "report.txt",
        ])
        .assert()
        .success();
    let report = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
    // Colour in a file is damage; a box-drawing character in a file is a box-
    // drawing character, so redirection does not change this choice.
    assert!(report.contains("├─"), "{report}");
    assert!(!report.contains('\x1b'), "{report}");
}

#[test]
fn output_flag_writes_the_report_to_a_file() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt"])
        .assert()
        .success()
        // Progress about a redirected report, so it does not take the
        // report's place on standard output.
        .stdout(predicate::str::contains("wrote report.txt").not())
        .stderr(predicate::str::contains("wrote report.txt"));
    let report = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
    assert!(report.contains("codehelion scan · fast mode ·"));
    assert!(report.contains("groups"));
}

#[test]
fn output_flag_preserves_an_existing_file_unless_forced() {
    let dir = fixture();
    let destination = dir.path().join("report.txt");
    std::fs::write(&destination, "do not replace\n").expect("write existing report");

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read_to_string(&destination).expect("read preserved report"),
        "do not replace\n"
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt", "--force"])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote report.txt"));
    let report = std::fs::read_to_string(destination).expect("read forced report");
    assert!(report.contains("codehelion scan · fast mode ·"));
}

#[test]
fn db_flag_overrides_the_database_location() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--db", "custom/audit.db"])
        .assert()
        .success();
    assert!(dir.path().join("custom/audit.db").is_file());
    assert!(!dir.path().join(".codehelion/audit.db").exists());
}

/// A discovered repository configuration has no authority to direct storage
/// outside the tree. Both scan's `SQLite` creation and cache clear use the same
/// resolver, while a person who names `--db` still deliberately has that
/// authority.
#[test]
fn discovered_database_paths_cannot_escape_the_scan_tree() {
    let tree = tempfile::tempdir().expect("temp tree");
    let root = tree.path().join("repository");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();

    let absolute = outside.join("absolute.db");
    for database in [
        database_setting(&absolute),
        "database = \"../outside/traversal.db\"\n".to_string(),
    ] {
        std::fs::write(root.join("codehelion.toml"), database).unwrap();
        cmd()
            .current_dir(&root)
            .args(["scan", "."])
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing database path"))
            .stderr(predicate::str::contains("--db <path>"));
        assert!(!absolute.exists());
        assert!(!outside.join("traversal.db").exists());
    }

    let retained = outside.join("retain.db");
    std::fs::write(&retained, "must survive cache clear").unwrap();
    for database in [
        database_setting(&retained),
        "database = \"../outside/retain.db\"\n".to_string(),
    ] {
        std::fs::write(root.join("codehelion.toml"), database).unwrap();
        cmd()
            .current_dir(&root)
            .args(["cache", "clear", "--force"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing database path"));
        assert_eq!(
            std::fs::read_to_string(&retained).unwrap(),
            "must survive cache clear"
        );
    }

    let trusted_configured = outside.join("trusted-configured.db");
    std::fs::write(
        root.join("codehelion.toml"),
        database_setting(&trusted_configured),
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", ".", "--config", "codehelion.toml"])
        .assert()
        .success();
    assert!(trusted_configured.is_file());

    let untrusted_configured = outside.join("untrusted-configured.db");
    std::fs::write(
        root.join("codehelion.toml"),
        database_setting(&untrusted_configured),
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", ".", "--config", "codehelion.toml", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert!(!untrusted_configured.exists());

    let explicit = outside.join("explicit.db");
    cmd()
        .current_dir(&root)
        .args([
            "scan",
            ".",
            "--untrusted",
            "--db",
            explicit.to_str().expect("temporary path is UTF-8"),
        ])
        .assert()
        .success();
    assert!(explicit.is_file());
    cmd()
        .current_dir(&root)
        .args([
            "cache",
            "clear",
            "--force",
            "--db",
            explicit.to_str().expect("temporary path is UTF-8"),
        ])
        .assert()
        .success();
    assert!(!explicit.exists());
}

/// A lexical relative path is not enough: a repository can place a symlink
/// below its root that would redirect `SQLite` creation or cache deletion.
#[cfg(unix)]
#[test]
fn discovered_database_paths_cannot_escape_through_existing_symlinks() {
    let tree = tempfile::tempdir().expect("temp tree");
    let root = tree.path().join("repository");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("storage")).unwrap();

    std::fs::write(
        root.join("codehelion.toml"),
        "database = \"storage/scan.db\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert!(!outside.join("scan.db").exists());

    let retained = outside.join("retained.db");
    std::fs::write(&retained, "must survive symlinked cache clear").unwrap();
    std::fs::write(
        root.join("codehelion.toml"),
        "database = \"storage/retained.db\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["cache", "clear", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert_eq!(
        std::fs::read_to_string(retained).unwrap(),
        "must survive symlinked cache clear"
    );
}

#[test]
fn default_database_is_placed_at_the_repository_root_for_a_subtree_scan() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "src"])
        .assert()
        .success();

    assert!(dir.path().join(".codehelion/audit.db").is_file());
    assert!(!dir.path().join("src/.codehelion/audit.db").exists());
}

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

#[test]
fn doctor_hints_until_the_database_is_gitignored() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("local database:"))
        .stdout(predicate::str::contains("hint:"));

    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("hint:").not());
}

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
            predicate::str::contains("snapshot:").and(predicate::str::contains(
                "(replay: codehelion report --run ",
            )),
        );
}
