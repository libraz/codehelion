use super::*;

#[test]
fn scan_detects_clones_and_records_a_snapshot() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "files: 5 analysed (rust 3, c 2, cpp 0)",
        ))
        .stdout(predicate::str::contains("clone groups:"))
        .stdout(predicate::str::contains("type-1"))
        .stdout(predicate::str::contains("src/a.rs"));

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert_eq!(run.analysis_mode, "fast");
    let groups = store.run_groups(run.id).unwrap();
    assert!(!groups.is_empty());

    // The verbatim Rust pair lands in a Type-1 group anchored to both files.
    let rust_type1 = groups
        .iter()
        .find(|group| {
            group.clone_type == "type-1" && group.members.iter().any(|m| m.file_path == "src/a.rs")
        })
        .expect("a Type-1 group for the Rust pair");
    assert!(rust_type1.members.iter().any(|m| m.file_path == "src/b.rs"));
    assert!(
        rust_type1
            .members
            .iter()
            .any(|m| m.unit_name.as_deref() == Some("checksum_block"))
    );

    // The C pair lands in its own Type-1 group.
    assert!(groups.iter().any(|group| {
        group.clone_type == "type-1"
            && group.members.iter().any(|m| m.file_path == "src/one.c")
            && group.members.iter().any(|m| m.file_path == "src/two.c")
    }));

    // The renamed copy is recovered as a Type-2 member.
    assert!(groups.iter().any(|group| {
        group.clone_type == "type-2" && group.members.iter().any(|m| m.file_path == "src/c.rs")
    }));

    let findings = store.run_findings(run.id).unwrap();
    assert!(!findings.is_empty());
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
    assert_eq!(paths.keys().collect::<Vec<_>>().len(), 2);
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
        .args(["report", "--run", &run_id.to_string(), "--format", "text"])
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

#[test]
fn recorded_artifact_savings_reach_json_text_and_sarif_reports() {
    let dir = fixture();
    let scanned = scan_json(dir.path());
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");
    let group = scanned["groups"]
        .as_array()
        .and_then(|groups| groups.first())
        .expect("scan finds a clone group");
    let group_fingerprint = fingerprint(group["fingerprint"].as_str().expect("group fingerprint"));
    let source_variant = fingerprint(
        scanned["run"]["build_variant"]["fingerprint"]
            .as_str()
            .expect("source build variant fingerprint"),
    );
    record_artifact_savings(dir.path(), run_id, group_fingerprint, source_variant);

    let run = run_id.to_string();
    let json = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run, "--format", "json"])
        .output()
        .expect("render JSON report");
    assert!(json.status.success(), "{json:?}");
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).expect("JSON report");
    let expected = json["groups"]
        .as_array()
        .and_then(|groups| {
            groups
                .iter()
                .find(|candidate| candidate["fingerprint"] == group["fingerprint"])
        })
        .expect("reported group")["artifact_savings"]
        .clone();
    assert_eq!(expected[0]["estimated_refactor_savings_bytes"], 9);

    let text = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run, "--format", "text"])
        .output()
        .expect("render text report");
    assert!(text.status.success(), "{text:?}");
    let text = String::from_utf8(text.stdout).expect("text report");
    assert!(text.contains("artifact refactoring estimates (not guaranteed):"));
    assert!(text.contains("9 estimated bytes from 24 attributed duplicate bytes"));

    let sarif = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run, "--format", "sarif"])
        .output()
        .expect("render SARIF report");
    assert!(sarif.status.success(), "{sarif:?}");
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("SARIF report");
    let sarif_savings = sarif["runs"][0]["results"]
        .as_array()
        .and_then(|results| {
            results.iter().find(|result| {
                result["partialFingerprints"]["cloneGroupFingerprint/v1"] == group["fingerprint"]
            })
        })
        .expect("matching SARIF result")["properties"]["artifact_savings"]
        .clone();
    assert_eq!(sarif_savings, expected);
}

fn fingerprint(value: &str) -> [u8; 16] {
    let mut bytes = [0; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16).expect("hex fingerprint");
    }
    bytes
}

fn record_artifact_savings(
    root: &Path,
    source_run: i64,
    clone_group_fingerprint: [u8; 16],
    source_variant: [u8; 16],
) {
    let db = root.join(".codehelion/audit.db");
    let mut store = Store::open(&db).expect("open scan database");
    store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: "artifact-ir-v1",
            path: "fixture.wasm",
            format: "wasm",
            content_fingerprint: [7; 16],
            observed_bytes: 24,
            ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
            build_variant_manifest_path: None,
            build_variant_fingerprint: Some([8; 16]),
            started_at: "2026-08-01T00:00:00Z",
            finished_at: "2026-08-01T00:00:01Z",
            symbols: &[],
            mappings: &[],
            unmapped_symbols: &[],
            unmapped_sources: &[],
            correlation: Some(ArtifactAnalysisCorrelation {
                schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
                source_scan_run_id: source_run,
                mapping_count: 0,
                artifact_symbol_count: 0,
                mapped_symbol_count: 0,
                artifact_symbol_bytes: 0,
                mapped_symbol_bytes: 0,
            }),
            clone_group_savings: &[ArtifactAnalysisCloneGroupSavings {
                schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_string(),
                source_scan_run_id: source_run,
                clone_group_fingerprint,
                source_build_variant_fingerprint: source_variant,
                artifact_build_variant_fingerprint: [8; 16],
                duplicated_bytes: 24,
                estimated_refactor_savings_bytes: 9,
                mapping_confidence: ArtifactAnalysisSavingsConfidence::High,
                clone_confidence: 1.0,
                model_confidence: ArtifactAnalysisSavingsConfidence::Low,
                savings_confidence: ArtifactAnalysisSavingsConfidence::Low,
                model_schema_version: "refactor-savings-model-v1".to_string(),
                assumptions_json: r#"[{"kind":"inlining_outcome_unknown"}]"#.to_string(),
            }],
        })
        .expect("record artifact correlation and savings");
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
            database.to_string_lossy().as_ref(),
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
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion scan (fast mode)"));

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "codehelion scan (structural mode)",
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
fn a_rescan_replaces_the_current_snapshot() {
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
    assert!(latest.id > 1, "a replacement receives a fresh run id");
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
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("files: 4 analysed"));
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-ignore"])
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
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("top groups by priority:"))
        .stdout(predicate::str::contains("priority"))
        .stdout(predicate::str::contains("similarity"));
}

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
        .args(["scan", "."])
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
fn an_inline_marker_suppresses_the_next_unit() {
    let dir = fixture();
    let marked = format!("// codehelion:ignore\n{CHECKSUM_RS}");
    std::fs::write(dir.path().join("src/a.rs"), &marked).unwrap();
    std::fs::write(dir.path().join("src/b.rs"), &marked).unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .success()
        // The verbatim Rust pair (both instances marked) is suppressed; the
        // Type-2 group still holds the unmarked src/c.rs and stays visible.
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
        .args(["scan", "."])
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
        .args(["scan", "."])
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
    assert!(
        String::from_utf8(text.stdout)
            .expect("text report")
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
