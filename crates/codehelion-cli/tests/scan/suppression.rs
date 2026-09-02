//! Suppression policies: what they hide, what they still record, and how a
//! stale or overreaching selector is reported.

use super::*;
use rusqlite::Connection;

#[test]
fn path_suppression_hides_but_records_findings() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/*.c\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/one.c").not());

    // Hidden, not deleted: the finding is recorded with its rule.
    {
        let store = open_store(dir.path());
        let run = store.latest_run().unwrap().expect("a recorded run");
        let findings = store.run_findings(run.id).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.suppression_scope.as_deref() == Some("path_glob"))
        );
    }

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains("suppressed groups:"))
        .stdout(predicate::str::contains("src/one.c"));
}

#[test]
fn reuse_restores_the_recorded_suppression_policy_for_replay() {
    for mode in ["fast", "structural"] {
        let dir = fixture();
        let root = dir.path();
        let config = root.join("codehelion.toml");
        let scan = |root: &Path, mode: &str| {
            let output = cmd()
                .current_dir(root)
                .args(["scan", ".", "--mode", mode, "--format", "json"])
                .output()
                .expect("scan suppression-policy fixture");
            assert!(output.status.success(), "{mode}: {output:?}");
            serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("scan emits JSON")
        };

        std::fs::write(&config, "[suppression]\npaths = [\"src/*.c\"]\n").unwrap();
        let first = scan(root, mode);
        let first_run = first["run"]["run_id"].as_i64().expect("first run id");

        std::fs::write(&config, "[suppression]\npaths = [\"src/*.rs\"]\n").unwrap();
        let intervening = scan(root, mode);
        assert_ne!(intervening["run"]["run_id"], first_run);

        std::fs::write(&config, "[suppression]\npaths = [\"src/*.c\"]\n").unwrap();
        let reused = scan(root, mode);
        assert_eq!(reused["run"]["run_id"], first_run, "{reused}");
        assert_eq!(reused["run"]["reused"], true, "{reused}");
        assert_eq!(reused["groups"], first["groups"]);

        let replay = cmd()
            .current_dir(root)
            .args([
                "report",
                "--run",
                &first_run.to_string(),
                "--format",
                "json",
            ])
            .output()
            .expect("replay reused policy");
        assert!(replay.status.success(), "{mode}: {replay:?}");
        let replay: serde_json::Value =
            serde_json::from_slice(&replay.stdout).expect("replay emits JSON");
        assert_eq!(replay["groups"], first["groups"]);

        let connection = Connection::open(root.join(".codehelion/audit.db")).unwrap();
        let active: Vec<(String, bool)> = connection
            .prepare(
                "SELECT pattern, active FROM suppression \
                 WHERE pattern IN ('src/*.c', 'src/*.rs') ORDER BY pattern",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            active,
            vec![
                ("src/*.c".to_string(), true),
                ("src/*.rs".to_string(), false)
            ]
        );
    }
}

#[test]
fn a_path_selector_matching_part_of_a_group_is_not_stale() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\npaths = [\"src/a.rs\", \"third_party/**\"]\n",
    )
    .unwrap();

    let report = scan_json(dir.path());
    let unused = report["summary"]["unused_suppressions"]
        .as_array()
        .expect("unused rules array");

    // The selector does not hide the Rust Type-1 group because its other
    // member is in src/b.rs, but it still matched src/a.rs and must not be
    // described as an ineffective rule.
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0]["pattern"], "third_party/**");
}

#[test]
fn a_clone_id_still_naming_one_group_is_reported_as_neither_stale_nor_overreaching() {
    let dir = fixture();
    let first = scan_json(dir.path());
    let id = first["groups"][0]["fingerprint"]
        .as_str()
        .expect("a group carries its stable id");
    let prefix = &id[..8];
    std::fs::write(
        dir.path().join("codehelion.toml"),
        format!("[suppression]\npaths = [\"third_party/**\"]\nclone-ids = [\"{prefix}\"]\n"),
    )
    .unwrap();

    let report = scan_json(dir.path());
    assert_eq!(report["summary"]["suppressed"]["by_rule"], 1, "{report}");

    // The clone id hid the one group it names, so the only rule to report is
    // the glob that matched nothing, and it says so with a count of its own.
    let unused = report["summary"]["unused_suppressions"]
        .as_array()
        .expect("unused rules array");
    assert_eq!(unused.len(), 1, "{report}");
    assert_eq!(unused[0]["pattern"], "third_party/**");
    assert_eq!(unused[0]["matched"], 0);

    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("hide more than the one group they name").not());
}

#[test]
fn an_inline_marker_suppresses_the_next_unit() {
    let dir = fixture();
    let marked = format!("// codehelion:ignore\n{MIX_C}");
    std::fs::write(dir.path().join("src/one.c"), &marked).unwrap();
    std::fs::write(dir.path().join("src/two.c"), &marked).unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        // The complete C units are both marked and therefore suppressed; the
        // unrelated Rust fragment group stays visible.
        .stdout(predicate::str::contains("1 by rule"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("inline_comment"))
    );
}

#[test]
fn a_symbol_glob_suppresses_by_unit_name_wherever_the_unit_lives() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"mix_*\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        // Both C instances are named mix_bytes, so their group is hidden;
        // the Rust groups are untouched.
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/one.c").not())
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("symbol_pattern"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbol glob \"mix_*\""));
}

#[test]
fn a_symbol_glob_matching_only_part_of_a_group_leaves_it_visible() {
    let dir = fixture();
    // checksum_block appears twice and digest_chunk once; naming only the
    // renamed copy leaves the duplication actionable, so nothing is hidden.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"digest_chunk\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"))
        .stdout(predicate::str::contains("src/c.rs"));
}

/// Fast mode works from tokens alone, so structural classifications cannot
/// silently decide whether a configured suppression policy took effect.
#[test]
fn fast_mode_reports_suppression_policies_it_cannot_apply() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\ntest-code = \"hide\"\nwidth-family = \"report\"\n\
         [suppression.boilerplate]\ntrivial-body = \"hide\"\n",
    )
    .unwrap();

    let json = scan_json(dir.path());
    assert_eq!(
        json["summary"]["unapplied_suppression_policies"],
        serde_json::json!([
            "suppression.boilerplate",
            "suppression.test-code",
            "suppression.width-family",
        ])
    );

    let text = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "text"])
        .output()
        .expect("run text scan");
    assert!(text.status.success(), "{text:?}");
    // A note about the run, not a finding: it goes to the error stream so a
    // report being piped somewhere still carries it.
    assert!(
        String::from_utf8(text.stderr)
            .expect("text report notes")
            .contains("Fast mode did not apply suppression policies")
    );

    let sarif = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "sarif"])
        .output()
        .expect("run SARIF scan");
    assert!(sarif.status.success(), "{sarif:?}");
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("SARIF JSON");
    assert!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .is_some_and(|notices| notices.iter().any(|notice| {
                notice["descriptor"]["id"] == "coverage/unapplied-suppression-policy"
                    && notice["properties"]["policies"]
                        == serde_json::json!([
                            "suppression.boilerplate",
                            "suppression.test-code",
                            "suppression.width-family",
                        ])
            }))
    );

    let structural = scan_json_with(dir.path(), &["--mode", "structural"]);
    assert!(
        structural["summary"]
            .get("unapplied_suppression_policies")
            .is_none(),
        "structural mode applies the policies: {structural}"
    );
}
