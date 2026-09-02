//! Running a scan and recording it: what reaches the snapshot, what a
//! replay makes of it, and how the stored database is kept.

use super::*;
use rusqlite::Connection;

#[test]
fn scan_detects_clones_and_records_a_snapshot() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "files: 5 analysed (rust 3, c 2, cpp 0)",
        ))
        .stdout(predicate::str::contains("2 groups"))
        .stdout(predicate::str::contains("type-1"))
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(run.analysis_mode, "fast");
    let groups = store.run_groups(run.id).unwrap();
    assert!(!groups.is_empty());

    // The Rust copies share a body fragment; the renamed copy joins the same
    // Type-2 finding without turning that partial match into a whole-unit one.
    let rust_group = groups
        .iter()
        .find(|group| {
            group.clone_type == "type-2" && group.members.iter().any(|m| m.file_path == "src/a.rs")
        })
        .expect("a Type-2 body-fragment group for the Rust copies");
    assert_eq!(rust_group.member_scope, "fragment");
    assert!(rust_group.members.iter().any(|m| m.file_path == "src/b.rs"));
    assert!(
        rust_group
            .members
            .iter()
            .any(|m| m.unit_name.as_deref() == Some("checksum_block"))
    );

    // The C pair lands in its own Type-1 group.
    let c_group = groups
        .iter()
        .find(|group| {
            group.clone_type == "type-1"
                && group.members.iter().any(|m| m.file_path == "src/one.c")
                && group.members.iter().any(|m| m.file_path == "src/two.c")
        })
        .expect("the complete C copies form a group");
    assert_eq!(c_group.member_scope, "unit");

    assert!(rust_group.members.iter().any(|m| m.file_path == "src/c.rs"));

    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn persistence_failure_still_emits_a_fast_or_structural_json_report() {
    for mode in ["fast", "structural"] {
        let dir = fixture();
        let initial = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode, "--format", "json"])
            .output()
            .expect("initial scan creates the real database");
        assert!(initial.status.success(), "{mode}: {initial:?}");
        let database = dir.path().join(".codehelion/audit.db");
        let connection = Connection::open(&database).expect("open initialized SQLite database");
        connection
            .execute_batch(
                "CREATE TRIGGER force_scan_insert BEFORE INSERT ON scan_run
                 BEGIN SELECT RAISE(FAIL, 'forced persistence failure'); END;",
            )
            .expect("install deterministic persistence trigger");
        let before: i64 = connection
            .query_row("SELECT COUNT(*) FROM scan_run", [], |row| row.get(0))
            .expect("count initial scan runs");
        drop(connection);

        let failed = cmd()
            .current_dir(dir.path())
            .args([
                "scan",
                ".",
                "--mode",
                mode,
                "--format",
                "json",
                "--no-reuse",
            ])
            .output()
            .expect("run scan with forced persistence failure");
        assert!(!failed.status.success(), "{mode}: {failed:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&failed.stdout).expect("provisional stdout is valid JSON");
        assert!(report["run"].get("run_id").is_none(), "{report}");
        assert!(report["run"].get("reused").is_none(), "{report}");
        assert!(report["summary"].get("changes").is_none(), "{report}");
        assert!(
            report["groups"].as_array().is_some_and(|groups| {
                groups.iter().all(|group| {
                    group["artifact_savings"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                })
            }),
            "{report}"
        );
        let stderr = String::from_utf8_lossy(&failed.stderr);
        let warning = "warning: this run was not recorded (";
        assert_eq!(stderr.matches(warning).count(), 1, "{stderr}");
        assert!(stderr.contains("forced persistence failure"), "{stderr}");
        assert!(
            !stderr.contains("hint: "),
            "persistence failure is not analysis: {stderr}"
        );

        let report_path = dir.path().join(format!("{mode}-unrecorded.json"));
        let failed_file = cmd()
            .current_dir(dir.path())
            .args([
                "scan",
                ".",
                "--mode",
                mode,
                "--format",
                "json",
                "--no-reuse",
                "--output",
                report_path.to_str().expect("UTF-8 report path"),
            ])
            .output()
            .expect("run redirected scan with forced persistence failure");
        assert!(!failed_file.status.success(), "{mode}: {failed_file:?}");
        assert!(
            failed_file.stdout.is_empty(),
            "redirected report leaked to stdout"
        );
        let redirected: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&report_path).expect("read redirected provisional report"),
        )
        .expect("redirected provisional report is valid JSON");
        assert!(redirected["run"].get("run_id").is_none(), "{redirected}");
        assert!(redirected["run"].get("reused").is_none(), "{redirected}");
        assert!(
            redirected["summary"].get("changes").is_none(),
            "{redirected}"
        );
        assert!(
            redirected["groups"].as_array().is_some_and(|groups| {
                groups.iter().all(|group| {
                    group["artifact_savings"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                })
            }),
            "{redirected}"
        );
        let redirected_stderr = String::from_utf8_lossy(&failed_file.stderr);
        assert_eq!(
            redirected_stderr
                .matches("warning: this run was not recorded (")
                .count(),
            1,
            "{redirected_stderr}"
        );
        assert!(!redirected_stderr.contains("hint: "), "{redirected_stderr}");

        let connection = Connection::open(&database).expect("reopen SQLite database");
        let after: i64 = connection
            .query_row("SELECT COUNT(*) FROM scan_run", [], |row| row.get(0))
            .expect("count scan runs after rollback");
        assert_eq!(after, before, "{mode}: failed recording changed scan_run");
    }
}

#[test]
fn fast_validation_failure_does_not_emit_an_analysis_hint() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "fast", "--jobs", "0"])
        .output()
        .expect("run Fast scan with invalid jobs");
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("jobs must be at least 1"), "{stderr}");
    assert!(
        !stderr.contains("hint: "),
        "validation is not analysis: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scan_records_distinct_non_utf8_source_paths_without_rolling_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).expect("create git marker");
    std::fs::create_dir_all(root.join("src")).expect("create sources");
    let first = OsString::from_vec(b"src/\x80.rs".to_vec());
    let second = OsString::from_vec(b"src/\x81.rs".to_vec());
    std::fs::write(root.join(first), "pub fn first() {}\n").expect("write first source");
    std::fs::write(root.join(second), "pub fn second() {}\n").expect("write second source");

    cmd()
        .current_dir(root)
        .args(["scan", "."])
        .assert()
        .success();

    let store = open_store(root);
    let run = store
        .latest_run()
        .expect("latest run")
        .expect("recorded run");
    let paths = store.run_tree(run.id).expect("recorded source tree");
    assert_eq!(paths.len(), 2);
    assert_eq!(paths.keys().count(), 2);
    assert!(paths.keys().all(|path| path.starts_with('\u{001f}')));
}

#[test]
fn report_reformats_a_recorded_run_without_scanning_again() {
    let dir = fixture();
    let scanned = scan_json(dir.path());
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");

    let json = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("reformat recorded JSON report");
    assert!(json.status.success(), "{json:?}");
    let rendered: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("report stdout is JSON");
    assert_eq!(rendered["run"]["run_id"].as_i64(), Some(run_id));
    assert_eq!(
        rendered["run"]["detector_versions"], scanned["run"]["detector_versions"],
        "replaying a run preserves the detector contract in its original order"
    );
    assert_eq!(
        rendered["run"]["database"], scanned["run"]["database"],
        "replaying a run preserves the database path representation"
    );
    assert_eq!(rendered["groups"], scanned["groups"]);
    assert_eq!(
        rendered["summary"], scanned["summary"],
        "a stored run retains every scan-summary field"
    );
    assert_eq!(
        rendered["run"]["ranking"], scanned["run"]["ranking"],
        "the original ranking recipe and weights are preserved"
    );

    cmd()
        .current_dir(dir.path())
        .args([
            "report",
            "--run",
            &run_id.to_string(),
            "--format",
            "text",
            "-v",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("snapshot:"));

    let sarif = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "sarif"])
        .output()
        .expect("reformat recorded SARIF report");
    assert!(sarif.status.success(), "{sarif:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&sarif.stdout).expect("report stdout is SARIF JSON");
    assert_eq!(document["version"], "2.1.0");
}

/// One occurrence as a view lists it: its file, its finding id, and whether it
/// is the group's canonical copy.
type ReportedMember = (String, String, bool);

/// One group as a view lists it: its fingerprint and its occurrences in order.
type ReportedGroup = (String, Vec<ReportedMember>);

/// Every group's occurrences, as the fingerprint they belong to and the
/// `(file, finding id, canonical)` of each, in the order the view lists them.
fn member_order(report: &serde_json::Value) -> Vec<ReportedGroup> {
    report["groups"]
        .as_array()
        .expect("a report lists its groups")
        .iter()
        .map(|group| {
            let members = group["members"]
                .as_array()
                .expect("a group lists its members")
                .iter()
                .map(|member| {
                    (
                        member["file"].as_str().expect("member file").to_string(),
                        member["finding_id"]
                            .as_str()
                            .expect("member finding id")
                            .to_string(),
                        member["canonical"].as_bool().expect("canonical mark"),
                    )
                })
                .collect();
            (
                group["fingerprint"]
                    .as_str()
                    .expect("group fingerprint")
                    .to_string(),
                members,
            )
        })
        .collect()
}

/// The canonical occurrence of each group, keyed by the group's fingerprint.
fn canonical_members(report: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
    member_order(report)
        .into_iter()
        .map(|(fingerprint, members)| {
            let canonical = members
                .into_iter()
                .find(|(_, _, canonical)| *canonical)
                .map(|(file, finding, _)| format!("{file} {finding}"))
                .expect("every group nominates one occurrence");
            (fingerprint, canonical)
        })
        .collect()
}

#[test]
fn a_replay_nominates_the_occurrence_the_scan_nominated() {
    let dir = fixture();
    let scanned = scan_json(dir.path());
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");

    let replayed = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("replay the recorded run");
    assert!(replayed.status.success(), "{replayed:?}");
    let replayed: serde_json::Value =
        serde_json::from_slice(&replayed.stdout).expect("report stdout is JSON");

    // The scan and the replay are two views of one verdict: the same
    // occurrences, in the same order, with the same one kept rather than
    // counted as duplicated.
    let scanned_members = member_order(&scanned);
    assert!(
        scanned_members.iter().any(|(_, members)| members.len() > 2),
        "the fixture has a group large enough for the order to be visible"
    );
    assert_eq!(scanned_members, member_order(&replayed));
    for (fingerprint, members) in &scanned_members {
        let marked: Vec<usize> = members
            .iter()
            .enumerate()
            .filter(|(_, (_, _, canonical))| *canonical)
            .map(|(position, _)| position)
            .collect();
        assert_eq!(
            marked,
            vec![0],
            "group {fingerprint} marks exactly its first occurrence"
        );
    }

    // The nomination is made from the occurrences' own identities, so moving a
    // file cannot move it. Under the walk order it would: renaming the first
    // file scanned hands that place to another occurrence.
    let before = canonical_members(&scanned);
    std::fs::rename(dir.path().join("src/a.rs"), dir.path().join("src/z.rs"))
        .expect("rename a source file");
    let renamed = scan_json(dir.path());
    assert_eq!(before, canonical_members(&renamed));
}

/// Every command that reads the scan database resolves the selected repository
/// and configuration the same way as `scan`, even when invoked below it.
#[test]
fn database_readers_share_repository_path_and_config_resolution() {
    let dir = fixture();
    let root = dir.path();
    let config = root.join("audit.toml");
    let database = root.join("state/audit.db");
    std::fs::write(&config, "database = \"state/audit.db\"\n").unwrap();

    let scanned = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("scan fixture");
    assert!(scanned.status.success(), "{scanned:?}");
    assert!(database.is_file(), "scan used the named configuration");
    // What the readers print is where the database resolved to, not the
    // spelling the configuration reached it by.
    let resolved_database =
        codehelion_core::paths::canonical(&database).expect("resolving the database");
    let report: serde_json::Value = serde_json::from_slice(&scanned.stdout).unwrap();
    let run = report["run"]["run_id"].as_i64().expect("recorded run id");
    let group = group_ids(&report).into_iter().next().expect("clone group");

    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let config_arg = config.to_str().unwrap();
    let run_arg = run.to_string();

    cmd()
        .current_dir(&nested)
        .args([
            "report", "--path", "..", "--config", config_arg, "--run", &run_arg, "--format", "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"run_id\": "));

    cmd()
        .current_dir(&nested)
        .args(["explain", "--path", "..", "--config", config_arg, &group])
        .assert()
        .success()
        .stdout(predicate::str::contains("clone group"));

    cmd()
        .current_dir(&nested)
        .args([
            "baseline",
            "create",
            "..",
            "--config",
            config_arg,
            "--file",
            "../baseline.json",
        ])
        .assert()
        .success();
    assert!(root.join("baseline.json").is_file());

    cmd()
        .current_dir(&nested)
        .args(["cache", "status", "--path", "..", "--config", config_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            resolved_database.to_string_lossy().as_ref(),
        ));

    cmd()
        .current_dir(&nested)
        .args([
            "cache", "clear", "--force", "--path", "..", "--config", config_arg,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));
    assert!(!database.exists(), "cache clear removes the scan database");
}

#[test]
fn replayed_summary_retains_guardrails_and_each_skip_cause() {
    let dir = fixture();
    let root = dir.path();
    std::fs::write(root.join("oversized.rs"), "x".repeat(1_024)).unwrap();
    std::fs::write(root.join("binary.rs"), [0_u8, 1, 2, 3]).unwrap();
    std::fs::write(
        root.join("codehelion.toml"),
        "[limits]\nmax-file-bytes = 512\n",
    )
    .unwrap();

    let scanned = cmd()
        .current_dir(root)
        .args(["scan", ".", "--untrusted", "--format", "json"])
        .output()
        .expect("scan fixture");
    assert!(scanned.status.success(), "{scanned:?}");
    let scanned: serde_json::Value = serde_json::from_slice(&scanned.stdout).unwrap();
    let run = scanned["run"]["run_id"].as_i64().expect("recorded run id");
    assert_eq!(scanned["summary"]["excluded"]["too_large"], 1);
    assert_eq!(scanned["summary"]["excluded"]["binary"], 1);
    assert_eq!(scanned["summary"]["excluded"]["skipped"], 2);
    assert_eq!(scanned["summary"]["guardrails"]["profile"], "untrusted");

    let replayed = cmd()
        .current_dir(root)
        .args(["report", "--run", &run.to_string(), "--format", "json"])
        .output()
        .expect("replay report");
    assert!(replayed.status.success(), "{replayed:?}");
    let replayed: serde_json::Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(
        replayed["summary"], scanned["summary"],
        "report --run preserves the run's guardrails and exclusion accounting"
    );
}

/// Fast and Structural use their local frontends directly. This stays in the
/// package-scoped CI job that deliberately does not build compiler helpers.
#[test]
fn fast_and_structural_modes_run_without_compiler_helpers() {
    let dir = fixture();

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--decoration", "unicode"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion scan · fast mode ·"));

    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--decoration",
            "unicode",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "codehelion scan · structural mode ·",
        ));
}

#[test]
fn fast_mode_does_not_report_copies_from_alternative_c_preprocessor_arms() {
    let dir = tempfile::tempdir().expect("temporary C tree");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/platform.c"),
        format!("#ifdef _WIN32\n{MIX_C}\n#else\n{MIX_C}\n#endif\n"),
    )
    .unwrap();

    let report = scan_json(root);
    assert!(
        report["groups"].as_array().expect("groups").is_empty(),
        "alternative platform implementations are not a clone finding: {report}"
    );
    let dropped = report["summary"]["funnel"]
        .as_array()
        .expect("funnel")
        .iter()
        .flat_map(|stage| stage["dropped"].as_array().expect("dropped"))
        .find(|drop| drop["cause"] == "conditional_arms")
        .and_then(|drop| drop["count"].as_u64())
        .unwrap_or(0);
    assert!(dropped > 0, "the Fast funnel records the excluded pair");
}

#[test]
fn an_identical_rescan_reuses_the_current_snapshot() {
    let dir = fixture();
    for _ in 0..2 {
        cmd()
            .current_dir(dir.path())
            .args(["scan", "."])
            .assert()
            .success();
    }
    let store = open_store(dir.path());
    let latest = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(latest.id, 1, "a reused scan records no second run");
    assert_eq!(store.table_count("scan_run").unwrap(), 1);
}

#[test]
fn fail_on_findings_gates_the_exit_code() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--fail-on-findings"])
        .assert()
        .code(3);
    // Without the flag, findings do not fail the scan.
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();
}

#[test]
fn no_ignore_scans_files_gitignore_hides() {
    let dir = fixture();
    std::fs::write(dir.path().join(".gitignore"), "src/b.rs\n").unwrap();
    std::fs::create_dir_all(dir.path().join(".hidden")).unwrap();
    std::fs::write(dir.path().join(".hidden/extra.rs"), CHECKSUM_RS).unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("files: 4 analysed"));
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-ignore", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("files: 6 analysed"));
}

#[test]
fn cache_clear_refuses_a_database_held_by_a_scan() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();

    let database = dir.path().join(".codehelion/audit.db");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join(".codehelion/audit.db.lock"))
        .expect("scan created its database lock");
    FileExt::try_lock_exclusive(&lock).expect("test owns the scan lock");

    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another codehelion scan or cache clear",
        ));
    assert!(database.is_file(), "the held database remains intact");
}

#[test]
fn reports_show_the_priority_and_its_inputs() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sorted by priority"))
        .stdout(predicate::str::contains("priority"))
        .stdout(predicate::str::contains("similarity"));
}

/// A database left behind by a run interrupted while schema initialization
/// was still under the default rollback journal (before `WAL` mode took
/// over) has a `-journal` sidecar rather than `-wal`/`-shm`. `cache clear`
/// has to remove it along with the others, or the next `scan` fails opening
/// what looks like an orphaned sidecar.
#[test]
fn cache_clear_removes_a_leftover_rollback_journal_so_the_next_scan_succeeds() {
    let dir = fixture();
    let database = dir.path().join(".codehelion/audit.db");
    std::fs::create_dir_all(database.parent().expect("database has a parent")).unwrap();
    std::fs::write(&database, b"").unwrap();
    let journal = format!("{}-journal", database.display());
    std::fs::write(&journal, b"leftover").unwrap();

    let status = cmd()
        .current_dir(dir.path())
        .args([
            "cache",
            "status",
            "--db",
            database.to_str().expect("utf-8 database path"),
        ])
        .output()
        .expect("run cache status");
    assert!(status.status.success(), "{status:?}");
    let status = String::from_utf8(status.stdout).expect("cache status is UTF-8");
    let counted_bytes =
        std::fs::metadata(&database).unwrap().len() + std::fs::metadata(&journal).unwrap().len();
    assert!(
        status.contains(&format!("({counted_bytes} bytes)")),
        "the reported size covers the -journal sidecar: {status}"
    );

    cmd()
        .current_dir(dir.path())
        .args([
            "cache",
            "clear",
            "--force",
            "--db",
            database.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();
    assert!(
        !Path::new(&journal).exists(),
        "cache clear must remove the -journal sidecar along with the database"
    );

    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--db",
            database.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();
}

/// `cache status` sits beside `discard_expired_abandoned_runs`, which grants a
/// grace period before it treats a `running` partition as abandoned. The
/// diagnostic has to make the same distinction: while the database lease is
/// held, an unfinished partition belongs to the scan currently writing it,
/// not to one that was left behind.
#[test]
fn cache_status_calls_a_lease_held_partition_incomplete_not_abandoned() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success();

    let database = dir.path().join(".codehelion/audit.db");
    {
        let connection = Connection::open(&database).expect("open the scan database");
        connection
            .execute(
                "INSERT INTO scan_run
                     (build_variant_id, root_path, tool_version, config_hash, config_source,
                      analysis_mode, started_at, finished_at, status, min_clone_tokens)
                 VALUES (1, '.', 'test', 'hash', 'defaults', 'fast',
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'running', 20)",
                [],
            )
            .expect("record an in-flight partition");
    }

    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join(".codehelion/audit.db.lock"))
        .expect("scan created its database lock");
    FileExt::try_lock_exclusive(&lock).expect("test owns the scan lock");

    cmd()
        .current_dir(dir.path())
        .args(["cache", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "incomplete partitions: 1 (a scan is running)",
        ))
        .stdout(predicate::str::contains("abandoned runs").not());
}
