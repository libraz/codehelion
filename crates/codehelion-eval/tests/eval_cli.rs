//! End-to-end coverage for the evaluator's sibling-metric output.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;

use assert_cmd::Command;
use serde_json::json;

fn evaluator() -> Command {
    Command::cargo_bin("codehelion-eval").expect("evaluator binary should build")
}

#[test]
fn prints_sibling_metrics_after_primary_metrics() {
    let temporary = tempfile::tempdir().expect("temp dir");
    let report_path = temporary.path().join("report.json");
    let labels_path = temporary.path().join("labels.json");
    let report = json!({
        "schema_version": 2,
        "summary": {
            "files": {"rust": 0, "c": 0, "cpp": 3},
            "lines": 12,
            "search_truncated": false
        },
        "groups": [{
            "fingerprint": "owner",
            "clone_type": "type-1",
            "priority": {"value": 1.0, "inputs": {"largest_member_tokens": 10}},
            "similarity": {
                "weight_version": "structural-verify-v1",
                "lexical": 1.0,
                "structural": 1.0,
                "control_flow": 1.0,
                "type_similarity": null,
                "api": null,
                "composite": 1.0,
                "confidence_band": "high"
            },
            "boilerplate": null,
            "test_code": false,
            "test_code_evidence": null,
            "width_family": false,
            "split_pair": false,
            "ranked_down": false,
            "suppressed": null,
            "members": [
                {"file": "seed.cpp", "language": "cpp", "start_line": 1, "end_line": 3, "tokens": 10},
                {"file": "copy.cpp", "language": "cpp", "start_line": 1, "end_line": 3, "tokens": 10}
            ]
        }],
        "siblings": [{
            "group_fingerprint": "owner",
            "siblings": [{
                "clone_type": "type-3",
                "confidence_band": "low",
                "basis": "signature",
                "signature": "int(const int*,int)",
                "similarity": {
                    "weight_version": "structural-verify-v1",
                    "lexical": 0.2,
                    "structural": 0.5,
                    "control_flow": null,
                    "type_similarity": null,
                    "api": null,
                    "composite": 0.5
                },
                "member": {"file": "mirror.cpp", "language": "cpp", "start_line": 1, "end_line": 3, "tokens": 10},
                "suppressed": null
            }]
        }]
    });
    let labels = json!({
        "schema_version": 1,
        "language": "cpp",
        "files": ["seed.cpp", "copy.cpp", "mirror.cpp"],
        "clone_pairs": [],
        "non_clones": [],
        "known_siblings": [{
            "id": "ks-001",
            "basis": "signature",
            "primary_fragments": [
                {"file": "seed.cpp", "start_line": 1, "end_line": 3},
                {"file": "copy.cpp", "start_line": 1, "end_line": 3}
            ],
            "sibling": {"file": "mirror.cpp", "start_line": 1, "end_line": 3}
        }]
    });
    fs::write(
        &report_path,
        serde_json::to_vec(&report).expect("serialize report"),
    )
    .expect("write report");
    fs::write(
        &labels_path,
        serde_json::to_vec(&labels).expect("serialize labels"),
    )
    .expect("write labels");

    evaluator()
        .args([
            "--results",
            report_path.to_str().expect("report path is utf-8"),
            "--labels",
            labels_path.to_str().expect("labels path is utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "known mirrors recovered     1 / 1",
        ))
        .stdout(predicates::str::contains("signature-derived siblings  1"));
}
