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

/// The commands a report prints are commands that run.
///
/// The check is to execute what was printed, not to compare it against an
/// expected string: an instruction that reads correctly and opens the wrong
/// database is exactly the failure this exists to catch, and a string
/// comparison agrees with it.
#[test]
fn the_commands_a_report_prints_run_as_printed() {
    let dir = fixture();
    let root = dir.path();
    let database = root.join("elsewhere.db");
    let scan = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--db",
            database.to_str().expect("temporary path is UTF-8"),
        ])
        .output()
        .expect("run scan against a named database");
    assert!(scan.status.success(), "{scan:?}");
    let text = String::from_utf8(scan.stdout).expect("scan output is UTF-8");

    let printed = printed_commands(&text);
    assert!(!printed.is_empty(), "{text}");
    for printed in printed {
        let arguments: Vec<&str> = printed.split_whitespace().skip(1).collect();
        assert!(
            arguments.contains(&"--db"),
            "a named database has to be repeated or the next command reads elsewhere: {printed}"
        );
        let output = cmd()
            .current_dir(root)
            .args(&arguments)
            .output()
            .expect("run the command the report printed");
        assert!(
            output.status.success(),
            "the report printed a command that does not run: {printed}\n{output:?}"
        );
    }
}

/// A database nobody named needs no flag: every command resolves the same one.
#[test]
fn a_report_over_the_default_database_prints_the_short_commands() {
    let dir = fixture();
    let root = dir.path();
    let scan = cmd()
        .current_dir(root)
        .args(["scan", "."])
        .output()
        .expect("run scan against the default database");
    assert!(scan.status.success(), "{scan:?}");
    let text = String::from_utf8(scan.stdout).expect("scan output is UTF-8");

    let printed = printed_commands(&text);
    assert!(!printed.is_empty(), "{text}");
    for command in printed {
        assert!(
            !command.contains("--db"),
            "an unnamed database must not be spelled back at the reader: {command}"
        );
        let arguments: Vec<&str> = command.split_whitespace().skip(1).collect();
        let output = cmd()
            .current_dir(root)
            .args(&arguments)
            .output()
            .expect("run the command the report printed");
        assert!(output.status.success(), "{command}\n{output:?}");
    }
}

/// Every `codehelion ...` the report offers as a next step, as printed.
fn printed_commands(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    // Each marker's command runs to the glyph that closes it: the replay is
    // parenthesised, and the next-step line separates its two suggestions with
    // a middle dot.
    for (marker, terminator) in [("replay: ", ')'), ("open one: ", '\u{b7}')] {
        for (at, _) in text.match_indices(marker) {
            let rest = &text[at + marker.len()..];
            let end = rest.find([terminator, '\n']).unwrap_or(rest.len());
            let command = rest[..end].trim();
            assert!(
                command.starts_with("codehelion "),
                "`{marker}` did not introduce a command: {command}"
            );
            found.push(command.to_owned());
        }
    }
    found
}

/// A detail view answers to the same colour flag a report does.
///
/// A display option that exists on one command and not the next is one the
/// reader has to look up again every time, so `explain` takes `--color` with
/// the spelling, the default and the `NO_COLOR` behaviour the report uses —
/// and colours what it is asked to, rather than accepting the flag and
/// ignoring it.
#[test]
fn explain_takes_the_same_colour_flag_a_report_does() {
    let dir = fixture();
    let root = dir.path();
    let report = scan_json(root);
    let group = visible_ids(&report)
        .into_iter()
        .next()
        .expect("the fixture duplicates on purpose");
    let ansi = predicate::str::contains('\x1b');

    cmd()
        .current_dir(root)
        .args(["explain", &group])
        .assert()
        .success()
        .stdout(ansi.clone().not());
    cmd()
        .current_dir(root)
        .args(["explain", &group, "--color", "always"])
        .assert()
        .success()
        .stdout(ansi.clone());
    cmd()
        .current_dir(root)
        .args(["explain", &group, "--color", "always"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(ansi.clone());
    cmd()
        .current_dir(root)
        .args(["explain", &group, "--color", "never"])
        .assert()
        .success()
        .stdout(ansi.not());

    // A machine-readable document is not a place for terminal escapes,
    // whatever was asked for.
    let output = cmd()
        .current_dir(root)
        .args(["explain", &group, "--format", "json", "--color", "always"])
        .output()
        .expect("run explain");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(!text.contains('\x1b'), "{text}");
    serde_json::from_str::<serde_json::Value>(&text).expect("stdout is one JSON document");
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
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--decoration",
            "unicode",
            "--output",
            "report.txt",
        ])
        .output()
        .expect("run redirected scan");
    assert!(output.status.success(), "{output:?}");
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&output.stderr, Some(&expected_hint), 1);
    // Progress about a redirected report and the first-run hint both belong
    // on stderr, never in the report's place on standard output.
    assert!(
        output.stdout.is_empty(),
        "redirected report unexpectedly wrote stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("wrote report.txt"),
        "redirect progress leaked into stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("wrote report.txt"),
        "redirect progress missing from stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let report = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
    assert!(report.contains("codehelion scan · fast mode ·"));
    assert!(report.contains("groups"));
    assert!(
        !report.contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into report file: {report}",
    );
}

#[test]
fn output_flag_preserves_an_existing_file_unless_forced() {
    let dir = fixture();
    let destination = dir.path().join("report.txt");
    std::fs::write(&destination, "do not replace\n").expect("write existing report");

    let failed = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt"])
        .output()
        .expect("run scan with an existing output");
    assert!(!failed.status.success(), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("refusing to overwrite"),
        "{}",
        String::from_utf8_lossy(&failed.stderr),
    );
    assert_database_hint_lines(&failed.stderr, None, 0);
    assert!(
        dir.path().join(".codehelion").is_dir(),
        "database directory is created before report output is attempted",
    );
    assert_eq!(
        std::fs::read_to_string(&destination).expect("read preserved report"),
        "do not replace\n"
    );

    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--decoration",
            "unicode",
            "--output",
            "report.txt",
            "--force",
        ])
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

/// The text and JSON `explain` views of one clone group, from one database.
fn explain_group(root: &Path, group: &str) -> (String, serde_json::Value) {
    let text = cmd()
        .current_dir(root)
        .args(["explain", group])
        .output()
        .expect("run explain");
    assert!(text.status.success(), "{text:?}");
    let json = cmd()
        .current_dir(root)
        .args(["explain", group, "--format", "json"])
        .output()
        .expect("run explain as JSON");
    assert!(json.status.success(), "{json:?}");
    (
        String::from_utf8(text.stdout).expect("explain text is UTF-8"),
        serde_json::from_slice(&json.stdout).expect("stdout is one JSON document"),
    )
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

const DATABASE_DIRECTORY_HINT: &str = "created local database directory";

fn database_directory_hint_line(root: &Path) -> String {
    let directory = codehelion_core::paths::canonical(root)
        .expect("canonicalize scan root")
        .join(".codehelion");
    format!(
        "note: created local database directory {}; consider adding `.codehelion/` to .gitignore",
        directory.display(),
    )
}

fn assert_database_hint_lines(stderr: &[u8], expected: Option<&str>, count: usize) {
    let stderr = String::from_utf8_lossy(stderr);
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains(DATABASE_DIRECTORY_HINT))
        .collect();
    assert_eq!(
        lines.len(),
        count,
        "database-directory hint lines: {lines:?}; full stderr: {stderr}",
    );
    if let Some(expected) = expected {
        assert_eq!(
            lines,
            vec![expected],
            "database-directory hint must be one exact line; full stderr: {stderr}",
        );
    }
}

fn parse_json_scan(output: &std::process::Output) -> serde_json::Value {
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into stdout: {stdout}",
    );
    serde_json::from_slice(&output.stdout).expect("scan output is one JSON document")
}

#[test]
fn the_first_scan_hints_about_a_new_unignored_database_directory_only_once() {
    let dir = fixture();
    let first = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run first scan");
    let first_report = parse_json_scan(&first);
    assert!(first_report["run"]["run_id"].is_number());
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&first.stderr, Some(&expected_hint), 1);

    let second = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run second scan");
    let second_report = parse_json_scan(&second);
    assert_eq!(
        second_report["run"]["run_id"],
        first_report["run"]["run_id"]
    );
    assert_database_hint_lines(&second.stderr, None, 0);
}

#[test]
fn a_gitignored_database_directory_does_not_get_a_first_scan_hint() {
    let dir = fixture();
    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run ignored-directory scan");
    parse_json_scan(&output);
    assert_database_hint_lines(&output.stderr, None, 0);
}

#[test]
fn an_explicit_database_path_does_not_get_a_default_directory_hint() {
    let dir = fixture();
    let external = tempfile::tempdir().expect("external database directory");
    let database = external.path().join("audit.db");
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--db",
            database.to_str().expect("temporary path is UTF-8"),
        ])
        .output()
        .expect("run explicit-database scan");
    parse_json_scan(&output);
    assert!(database.is_file());
    assert_database_hint_lines(&output.stderr, None, 0);
}

#[test]
fn structural_scans_use_the_same_first_directory_hint() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run first structural scan");
    parse_json_scan(&output);
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&output.stderr, Some(&expected_hint), 1);
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
