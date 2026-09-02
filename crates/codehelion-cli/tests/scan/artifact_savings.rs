//! Artifact savings recorded beside a run: how they reach every report
//! format, and what a reuse or a replay makes of them.

use super::*;
use rusqlite::Connection;

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

    let explained = cmd()
        .current_dir(dir.path())
        .args([
            "explain",
            group["fingerprint"].as_str().expect("group fingerprint"),
            "--format",
            "json",
        ])
        .output()
        .expect("explain clone group as JSON");
    assert!(explained.status.success(), "{explained:?}");
    let explained: serde_json::Value =
        serde_json::from_slice(&explained.stdout).expect("explain JSON");
    assert_eq!(explained["group"]["artifact_savings"], expected);

    let text = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run, "--format", "text", "-v"])
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

#[test]
fn a_reused_scan_hydrates_artifact_savings_before_text_guidance() {
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

    let before = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "text", "-v"])
        .output()
        .expect("render reused scan without artifact evidence");
    assert!(before.status.success(), "{before:?}");
    let before_stdout = String::from_utf8(before.stdout).expect("text report");
    let before_notes = String::from_utf8(before.stderr).expect("notes output");
    assert!(
        before_notes.contains("no artifact savings are recorded"),
        "{before_notes}"
    );
    assert!(
        before_notes.contains(
            "note: no artifact savings are recorded; run artifact analyze <PATH> --source-run <id> --build-variant <manifest> on a build of this tree, supplying the evidence its format carries:\n"
        ),
        "{before_notes}"
    );
    // The guidance is now one line per format rather than a single sentence;
    // pin the WASM line specifically, since it is the one format whose name
    // section attributes whole symbols without a line range.
    assert!(
        before_notes.contains(
            "  wasm: the name section attributes whole symbols only; source line ranges need DWARF, and emitting it changes the size being measured\n"
        ),
        "{before_notes}"
    );
    assert_eq!(
        before_notes
            .matches("no artifact savings are recorded")
            .count(),
        1,
        "the artifact guidance is run-scoped, not repeated per group"
    );
    assert!(
        !before_stdout.contains("no artifact savings are recorded"),
        "{before_stdout}"
    );

    record_artifact_savings(dir.path(), run_id, group_fingerprint, source_variant);

    let after = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "text", "-v"])
        .output()
        .expect("render reused scan with artifact evidence");
    assert!(after.status.success(), "{after:?}");
    let after_stdout = String::from_utf8(after.stdout).expect("text report");
    let after_notes = String::from_utf8(after.stderr).expect("notes output");
    assert!(
        after_stdout.contains("artifact refactoring estimates (not guaranteed):"),
        "{after_stdout}"
    );
    assert!(
        !after_notes.contains("no artifact savings are recorded"),
        "{after_notes}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn artifact_hydration_corruption_keeps_recorded_identity_for_reuse_and_replay() {
    for mode in ["fast", "structural"] {
        let dir = fixture();
        let initial = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode, "--format", "json"])
            .output()
            .expect("initial scan creates the recorded snapshot");
        assert!(initial.status.success(), "{mode}: {initial:?}");
        let initial: serde_json::Value =
            serde_json::from_slice(&initial.stdout).expect("initial JSON report");
        let run_id = initial["run"]["run_id"]
            .as_i64()
            .expect("initial report has a run id");
        let group = initial["groups"]
            .as_array()
            .and_then(|groups| groups.first())
            .expect("initial report has a clone group");
        let second_group = initial["groups"]
            .as_array()
            .and_then(|groups| groups.get(1))
            .expect("initial report has a second clone group");
        let group_fingerprint = fingerprint(
            group["fingerprint"]
                .as_str()
                .expect("initial group fingerprint"),
        );
        let source_variant = fingerprint(
            initial["run"]["build_variant"]["fingerprint"]
                .as_str()
                .expect("initial source variant fingerprint"),
        );
        record_artifact_savings(dir.path(), run_id, group_fingerprint, source_variant);
        let second_group_fingerprint = fingerprint(
            second_group["fingerprint"]
                .as_str()
                .expect("second group fingerprint"),
        );
        record_artifact_savings(dir.path(), run_id, second_group_fingerprint, source_variant);

        let database = dir.path().join(".codehelion/audit.db");
        Connection::open(&database)
            .expect("open scan database")
            .execute(
                "UPDATE artifact_analysis_clone_group_savings
                 SET assumptions_json = 'not-json'
                 WHERE clone_group_fingerprint = ?1",
                [second_group_fingerprint.as_slice()],
            )
            .expect("corrupt the second supplemental assumptions payload");

        let failed_reuse = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode, "--format", "json"])
            .output()
            .expect("reuse scan with corrupt artifact evidence");
        assert!(!failed_reuse.status.success(), "{mode}: {failed_reuse:?}");
        let reused: serde_json::Value =
            serde_json::from_slice(&failed_reuse.stdout).expect("failed reuse still emits JSON");
        assert_eq!(reused["run"]["run_id"], run_id, "{reused}");
        assert_eq!(reused["run"]["reused"], serde_json::json!(true), "{reused}");
        assert_artifacts_cleared(&reused);
        let reuse_stderr = String::from_utf8_lossy(&failed_reuse.stderr);
        assert_eq!(
            reuse_stderr
                .matches("warning: artifact savings were not loaded")
                .count(),
            1,
            "{reuse_stderr}"
        );
        assert!(
            !reuse_stderr.contains("no artifact savings are recorded"),
            "{reuse_stderr}"
        );
        assert!(!reuse_stderr.contains("hint: "), "{reuse_stderr}");

        let failed_text = cmd()
            .current_dir(dir.path())
            .args(["scan", ".", "--mode", mode, "--format", "text", "-v"])
            .output()
            .expect("text reuse scan with corrupt artifact evidence");
        assert!(!failed_text.status.success(), "{mode}: {failed_text:?}");
        let text_stdout = String::from_utf8_lossy(&failed_text.stdout);
        assert!(text_stdout.contains("snapshot:"), "{text_stdout}");
        let text_stderr = String::from_utf8_lossy(&failed_text.stderr);
        assert_eq!(
            text_stderr
                .matches("warning: artifact savings were not loaded")
                .count(),
            1,
            "{text_stderr}"
        );
        assert!(
            !text_stderr.contains("no artifact savings are recorded"),
            "{text_stderr}"
        );
        assert!(
            !text_stderr.contains("artifact refactoring estimates"),
            "{text_stderr}"
        );
        assert!(!text_stderr.contains("hint: "), "{text_stderr}");

        let output_path = dir.path().join(format!("{mode}-hydration-failure.json"));
        let failed_output = cmd()
            .current_dir(dir.path())
            .args([
                "scan",
                ".",
                "--mode",
                mode,
                "--format",
                "json",
                "--output",
                output_path.to_str().expect("UTF-8 output path"),
            ])
            .output()
            .expect("redirected reuse scan with corrupt artifact evidence");
        assert!(!failed_output.status.success(), "{mode}: {failed_output:?}");
        assert!(failed_output.stdout.is_empty(), "{failed_output:?}");
        let redirected: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&output_path).expect("read redirected hydration report"),
        )
        .expect("redirected hydration report is valid JSON");
        assert_eq!(redirected["run"]["run_id"], run_id, "{redirected}");
        assert_eq!(
            redirected["run"]["reused"],
            serde_json::json!(true),
            "{redirected}"
        );
        assert_artifacts_cleared(&redirected);
        let output_stderr = String::from_utf8_lossy(&failed_output.stderr);
        assert_eq!(
            output_stderr
                .matches("warning: artifact savings were not loaded")
                .count(),
            1,
            "{output_stderr}"
        );
        assert!(
            !output_stderr.contains("no artifact savings are recorded"),
            "{output_stderr}"
        );

        let run_arg = run_id.to_string();
        let replay = cmd()
            .current_dir(dir.path())
            .args(["report", "--run", &run_arg, "--format", "json"])
            .output()
            .expect("replay recorded run with corrupt artifact evidence");
        assert!(!replay.status.success(), "{mode}: {replay:?}");
        let replayed: serde_json::Value =
            serde_json::from_slice(&replay.stdout).expect("failed replay still emits JSON");
        assert_eq!(replayed["run"]["run_id"], run_id, "{replayed}");
        assert!(replayed["run"].get("reused").is_none(), "{replayed}");
        assert_artifacts_cleared(&replayed);
        let replay_stderr = String::from_utf8_lossy(&replay.stderr);
        assert_eq!(
            replay_stderr
                .matches("warning: artifact savings were not loaded")
                .count(),
            1,
            "{replay_stderr}"
        );
        assert!(
            !replay_stderr.contains("no artifact savings are recorded"),
            "{replay_stderr}"
        );
        assert!(!replay_stderr.contains("hint: "), "{replay_stderr}");

        let store = open_store(dir.path());
        assert_eq!(
            store.table_count("scan_run").expect("count scan runs"),
            1,
            "hydration failures must not create or remove the recorded run"
        );
    }
}

fn assert_artifacts_cleared(report: &serde_json::Value) {
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
            build_variant_fingerprint: Some(BuildVariantFingerprint::from_bytes([8; 16])),
            started_at: "2026-08-01T00:00:00Z",
            finished_at: "2026-08-01T00:00:01Z",
            symbols: &[],
            source_maps: &[],
            containment: None,
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
                source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes(
                    source_variant,
                ),
                artifact_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([8; 16]),
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
