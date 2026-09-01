//! `artifact report` reproduces what `artifact analyze` printed.
//!
//! A saved analysis is a record of what one run established, so re-rendering it
//! must restate that run rather than describe the artifact as it is today. The
//! two facts most easily lost are the outcome of each declared source-map
//! reference and the ceilings an untrusted run installed: both are established
//! while the analysis runs and neither can be derived from the stored IR.
//!
//! Each case compares the two renderings whole. Nothing is excluded, because
//! the point is that nothing else drifts either: the report names the same
//! analysis id and the same artifact path, and no timestamp reaches any
//! rendering, so the two outputs are equal byte for byte.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use codehelion_artifact::ArtifactBackend;
use codehelion_artifact::wasm::WasmBackend;
use codehelion_store::Store;
use codehelion_store::artifact::{
    ArtifactAnalysisContainment, ArtifactAnalysisSnapshot, ArtifactAnalysisSourceMap,
    ArtifactAnalysisSourceMapOutcome,
};

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Every format a report is rendered in, so no one of them can drift alone.
const FORMATS: [&str; 3] = ["text", "json", "csv"];

/// A minimal WASM module declaring a `sourceMappingURL` custom section.
///
/// Hand-built rather than taken from a toolchain: only the magic header, the
/// version, and the one custom section matter here, and the single-byte LEB128
/// lengths hold because the URI is short.
fn wasm_with_source_mapping_url(uri: &str) -> Vec<u8> {
    let mut content = vec![16u8]; // length of b"sourceMappingURL"
    content.extend_from_slice(b"sourceMappingURL");
    content.extend_from_slice(uri.as_bytes());
    assert!(
        content.len() < 128,
        "fixture section is too long for a single-byte LEB128 length"
    );
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    module.push(0); // custom section id
    module.push(u8::try_from(content.len()).expect("fixture section is short"));
    module.extend_from_slice(&content);
    module
}

/// A directory holding one WASM artifact and the local map it declares.
fn fixture_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("fixture directory");
    std::fs::write(
        directory.path().join("module.wasm"),
        wasm_with_source_mapping_url("module.wasm.map"),
    )
    .expect("write wasm fixture");
    std::fs::write(
        directory.path().join("module.wasm.map"),
        br#"{"version":3,"sources":["src/lib.rs"],"names":[],"mappings":"YAIA"}"#,
    )
    .expect("write source map fixture");
    directory
}

fn stdout_of(assertion: assert_cmd::assert::Assert) -> String {
    String::from_utf8(assertion.success().get_output().stdout.clone())
        .expect("reports are UTF-8 text")
}

/// Analyse the fixture into its own database, then re-render that analysis.
///
/// Each format gets a database of its own so the re-render can take the latest
/// saved analysis, which is the one the same call just recorded.
fn analyzed_and_replayed(
    directory: &std::path::Path,
    format: &str,
    extra: &[&str],
) -> (String, String) {
    let database = directory.join(format!("{format}.sqlite"));
    let mut analyze = cmd();
    analyze
        .current_dir(directory)
        .args(["artifact", "analyze", "module.wasm", "--format", format])
        .args(extra)
        .arg("--db")
        .arg(&database);
    let live = stdout_of(analyze.assert());
    let replayed = stdout_of(
        cmd()
            .current_dir(directory)
            .args(["artifact", "report", "--format", format])
            .arg("--db")
            .arg(&database)
            .assert(),
    );
    (live, replayed)
}

/// What the JSON rendering says about the fixture's one declared reference.
fn source_map(report: &str) -> serde_json::Value {
    let json: serde_json::Value = serde_json::from_str(report).expect("valid JSON");
    json["source_maps"][0].clone()
}

fn containment(report: &str) -> serde_json::Value {
    let json: serde_json::Value = serde_json::from_str(report).expect("valid JSON");
    json["containment"].clone()
}

#[test]
fn a_report_restates_the_source_maps_its_analysis_resolved() {
    let directory = fixture_directory();
    for format in FORMATS {
        let (live, replayed) = analyzed_and_replayed(directory.path(), format, &[]);
        assert_eq!(
            live, replayed,
            "the {format} rendering of a saved analysis differs from the analysis itself"
        );
    }

    // The comparison is only worth making because the fixture's reference did
    // resolve: a report that lost the section entirely would otherwise match a
    // report that never had one.
    let (live, replayed) = analyzed_and_replayed(directory.path(), "json", &[]);
    let resolved = source_map(&live);
    assert_eq!(resolved["status"], "resolved");
    assert_eq!(resolved["sources"][0], "src/lib.rs");
    assert!(
        resolved["local_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("module.wasm.map")),
        "{resolved}"
    );
    assert_eq!(source_map(&replayed), resolved);
}

/// A reference nothing local can resolve keeps its reason across a re-render,
/// which is the outcome a re-derivation would be most tempted to re-decide.
#[test]
fn a_report_restates_why_a_source_map_was_unavailable() {
    let directory = tempfile::tempdir().expect("fixture directory");
    std::fs::write(
        directory.path().join("module.wasm"),
        wasm_with_source_mapping_url("https://example.invalid/module.wasm.map"),
    )
    .expect("write wasm fixture");

    for format in FORMATS {
        let (live, replayed) = analyzed_and_replayed(directory.path(), format, &[]);
        assert_eq!(
            live, replayed,
            "the {format} rendering of a saved analysis differs from the analysis itself"
        );
    }

    let (live, replayed) = analyzed_and_replayed(directory.path(), "json", &[]);
    let unavailable = source_map(&live);
    assert_eq!(unavailable["status"], "unavailable");
    assert_eq!(unavailable["reason"], "non_local_reference");
    assert_eq!(source_map(&replayed), unavailable);
}

/// Where this build can install the untrusted preset's ceilings, the report of
/// such a run states the ceilings that run installed. The flag belongs to the
/// analysis, so the re-render can only get them from the saved analysis.
#[cfg(target_os = "linux")]
#[test]
fn a_report_restates_the_containment_its_analysis_ran_under() {
    let directory = fixture_directory();
    for format in FORMATS {
        let (live, replayed) = analyzed_and_replayed(directory.path(), format, &["--untrusted"]);
        assert_eq!(
            live, replayed,
            "the {format} rendering of an untrusted analysis differs from the analysis itself"
        );
    }

    let (live, replayed) = analyzed_and_replayed(directory.path(), "json", &["--untrusted"]);
    let installed = containment(&live);
    assert_eq!(
        installed["max_input_bytes"],
        codehelion::cli::UNTRUSTED_ARTIFACT_MAX_BYTES
    );
    assert_eq!(
        installed["worker_timeout_seconds"],
        codehelion::cli::UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS
    );
    assert_eq!(
        installed["worker_memory_limit_bytes"],
        codehelion::cli::UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES
    );
    assert_eq!(containment(&replayed), installed);
}

/// An analysis that installed no ceilings is reported as having installed
/// none, rather than acquiring the reading build's defaults.
#[test]
fn a_report_of_an_uncontained_analysis_states_no_containment() {
    let directory = fixture_directory();
    let (live, replayed) = analyzed_and_replayed(directory.path(), "json", &[]);
    assert_eq!(containment(&live), serde_json::Value::Null);
    assert_eq!(containment(&replayed), serde_json::Value::Null);
}

/// Every rendering states the ceilings a saved analysis ran under.
///
/// Only a host that can install the untrusted preset can produce such an
/// analysis by running one, so this records it the way the analysis does — into
/// the real database, through the same store API — and then asks each rendering
/// what that analysis says. It is the containment half of the equality the
/// preceding cases assert, on the hosts where the preset is unavailable.
#[test]
fn every_rendering_states_the_ceilings_a_saved_analysis_ran_under() {
    let directory = fixture_directory();
    let database = directory.path().join("seeded.sqlite");
    let artifact = WasmBackend
        .parse(&std::fs::read(directory.path().join("module.wasm")).expect("read wasm fixture"))
        .expect("parse the WASM fixture");
    let installed = ArtifactAnalysisContainment {
        max_input_bytes: 4096,
        worker_timeout_seconds: 30,
        worker_memory_limit_bytes: 8192,
    };
    let source_maps = [ArtifactAnalysisSourceMap {
        uri: "module.wasm.map".to_owned(),
        outcome: ArtifactAnalysisSourceMapOutcome::Resolved {
            local_path: directory
                .path()
                .join("module.wasm.map")
                .display()
                .to_string(),
            sources: vec!["src/lib.rs".to_owned()],
        },
    }];
    let analysis_id = Store::open(&database)
        .expect("open the audit database")
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: &artifact.schema_version,
            path: "module.wasm",
            format: artifact.format.name(),
            content_fingerprint: artifact.fingerprint.as_bytes(),
            observed_bytes: artifact.observed_bytes,
            ir_json: &serde_json::to_string(&artifact).expect("serialize the artifact IR"),
            build_variant_manifest_path: None,
            build_variant_fingerprint: None,
            started_at: "2026-08-01T00:00:00Z",
            finished_at: "2026-08-01T00:00:01Z",
            symbols: &[],
            source_maps: &source_maps,
            containment: Some(installed),
            mappings: &[],
            unmapped_symbols: &[],
            unmapped_sources: &[],
            correlation: None,
            clone_group_savings: &[],
        })
        .expect("record the analysis");

    let rendered = |format: &str| {
        stdout_of(
            cmd()
                .args(["artifact", "report", "--format", format, "--analysis"])
                .arg(analysis_id.to_string())
                .arg("--db")
                .arg(&database)
                .assert(),
        )
    };

    assert!(
        rendered("text").contains(
            "untrusted containment: input 4096 bytes, worker timeout 30s, worker memory 8192 bytes"
        ),
        "{}",
        rendered("text")
    );
    assert_eq!(
        containment(&rendered("json")),
        serde_json::json!({
            "max_input_bytes": 4096,
            "worker_timeout_seconds": 30,
            "worker_memory_limit_bytes": 8192,
        })
    );
    let csv = rendered("csv");
    let record = csv
        .lines()
        .find(|line| line.starts_with("containment,"))
        .unwrap_or_else(|| panic!("no containment record in {csv}"))
        .to_owned();
    for ceiling in ["4096", "30", "8192"] {
        assert!(
            record.split(',').any(|field| field == ceiling),
            "{record} omits {ceiling}"
        );
    }
    // The source-map outcome travels with it, in each of the same renderings.
    assert!(rendered("text").contains("module.wasm.map: resolved to "));
    assert_eq!(source_map(&rendered("json"))["sources"][0], "src/lib.rs");
    assert!(
        rendered("csv")
            .lines()
            .any(|line| line.starts_with("source-map,")),
        "{}",
        rendered("csv")
    );
}
