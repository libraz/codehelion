//! How a scan or a replayed run is rendered: determinism, member listing,
//! verbosity, colour and decoration.

use super::*;

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
    // the decoration's separator — a middle dot where the terminal takes
    // Unicode and a vertical bar where it does not, so both close the command
    // and a fixture that knows only one of them reads the rest of the line as
    // arguments.
    for (marker, closers) in [
        ("replay: ", &[')'][..]),
        ("open one: ", &['\u{b7}', '|'][..]),
    ] {
        for (at, _) in text.match_indices(marker) {
            let rest = &text[at + marker.len()..];
            let end = rest
                .find(|character: char| closers.contains(&character) || character == '\n')
                .unwrap_or(rest.len());
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

/// A reader that stops early — `codehelion scan | head` — is the consumer
/// deciding how much of the report it wants. The analysis and the recording
/// are finished before the first line is printed, so the closed pipe ends the
/// output and nothing else: a run that exits non-zero here tells a CI gate the
/// scan failed when it did everything it was asked to.
#[cfg(unix)]
#[test]
// Spawning the binary directly is the point: the reader has to close the pipe
// while the scan still holds the writing end, which needs a handle to a live
// child rather than a finished run's captured output.
#[allow(clippy::disallowed_types)]
fn a_reader_that_stops_early_leaves_the_scan_successful_and_recorded() {
    let dir = wide_fixture();
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("codehelion"))
        .current_dir(dir.path())
        .args(["scan", ".", "--verbose"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("binary should build");
    // The only end that could read the report is closed before the scan has
    // one to write.
    drop(child.stdout.take());
    let status = child.wait().expect("the scan runs to completion");
    assert_eq!(status.code(), Some(0), "{status}");

    let store = Store::open_existing(&dir.path().join(".codehelion/audit.db")).unwrap();
    let run = store.latest_run().unwrap().expect("recorded run");
    assert!(!store.run_groups(run.id).unwrap().is_empty());
}
