//! SARIF output of the compiled binary, checked against the published SARIF
//! 2.1.0 JSON Schema.
//!
//! The schema is the one published at
//! `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`,
//! vendored under `tests/data/` so the check runs offline and cannot change
//! under the tests' feet.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use boon::{Compiler, Schemas};
use serde_json::Value;

/// The vendored schema and the URI it is published under.
const SARIF_SCHEMA: &str = include_str!("data/sarif-2.1.0.schema.json");
const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A verbatim duplicate, a gapped (Type-3) copy of it, and one file whose
/// path a suppression rule hides.
const ALPHA_RS: &str = "pub fn alpha(data: &[u32]) -> u32 {
    let mut acc = 0u32;
    let mut count = 0u32;
    for value in data {
        if *value > 10 {
            acc = acc.wrapping_add(*value);
        } else {
            acc = acc.wrapping_sub(1);
        }
        count += 1;
    }
    acc = acc.wrapping_mul(3);
    return acc + count;
}
";

const GAPPED_RS: &str = "pub fn beta(feed: &[u32]) -> u32 {
    let mut state = 3u32;
    let mut seen = 7u32;
    for item in feed {
        if *item > 99 {
            state = state.wrapping_add(*item);
        } else {
            state = state.wrapping_sub(2);
        }
        seen += 4;
    }
    state = state.wrapping_mul(8);
    let extra = state ^ seen;
    return state + seen + extra;
}
";

/// Duplicated only under `vendor/`, so every member of its group is hidden by
/// the path rule.
const VENDOR_RS: &str = "pub fn label(name: &str) -> usize {
    let trimmed = name.trim();
    let width = trimmed.chars().count();
    for _ in 0..width {
        if width > 3 {
            return width;
        }
    }
    return width.saturating_mul(2);
}
";

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("vendor")).unwrap();
    std::fs::write(root.join("src/a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), GAPPED_RS).unwrap();
    std::fs::write(root.join("vendor/label_a.rs"), VENDOR_RS).unwrap();
    std::fs::write(root.join("vendor/label_b.rs"), VENDOR_RS).unwrap();
    std::fs::write(
        root.join("codehelion.toml"),
        "[suppression]\npaths = [\"vendor/**\"]\n",
    )
    .unwrap();
    dir
}

/// Run `scan --format sarif` in `root` and parse the produced log.
fn scan_sarif(root: &Path, mode: &str) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", mode, "--format", "sarif"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// Validate a log against the published schema, returning the schema's own
/// diagnostics on failure.
fn validate_sarif(log: &Value) -> Result<(), String> {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let schema: Value = serde_json::from_str(SARIF_SCHEMA).expect("the vendored schema parses");
    compiler
        .add_resource(SARIF_SCHEMA_URI, schema)
        .expect("register the schema");
    let index = compiler
        .compile(SARIF_SCHEMA_URI, &mut schemas)
        .expect("compile the schema");
    schemas
        .validate(log, index)
        .map_err(|error| format!("{error:#}"))
}

fn assert_valid_sarif(log: &Value) {
    if let Err(error) = validate_sarif(log) {
        panic!("SARIF output does not satisfy the published schema:\n{error}");
    }
}

#[test]
fn structural_output_satisfies_the_published_schema() {
    let dir = fixture();
    let log = scan_sarif(dir.path(), "structural");
    assert_valid_sarif(&log);

    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "codehelion");
    assert_eq!(run["automationDetails"]["id"], "codehelion/structural");
    assert_eq!(run["properties"]["mode"], "structural");

    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());
    let gapped = results
        .iter()
        .find(|result| result["ruleId"] == "clone/type-3")
        .expect("the gapped group is reported");

    // The primary location is the canonical instance and every member is
    // reachable from the result.
    let uri = gapped["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap();
    assert!(matches!(uri, "src/a.rs" | "src/b.rs"), "{uri}");
    assert_eq!(
        gapped["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"],
        "SRCROOT"
    );
    assert!(gapped["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64() >= Some(1));
    let related = gapped["relatedLocations"].as_array().unwrap();
    assert_eq!(
        u64::try_from(related.len()).unwrap(),
        gapped["occurrenceCount"].as_u64().unwrap()
    );

    // The evidence the group was judged on travels with the result.
    let similarity = &gapped["properties"]["similarity"];
    assert_eq!(similarity["weight_version"], "structural-verify-v1");
    assert!(similarity["composite"].as_f64().unwrap() > 0.6);
    assert_eq!(similarity["type_similarity"], Value::Null);
}

#[test]
fn reruns_produce_the_same_log() {
    let dir = fixture();
    let mut logs = Vec::new();
    for _ in 0..2 {
        let mut log = scan_sarif(dir.path(), "structural");
        // Everything except when the scan ran and which snapshot it wrote.
        let run = &mut log["runs"][0];
        run["invocations"][0]["startTimeUtc"] = Value::Null;
        run["invocations"][0]["endTimeUtc"] = Value::Null;
        run["properties"]["run_id"] = Value::Null;
        logs.push(log);
    }
    assert_eq!(logs[0], logs[1], "reruns agree token for token");
}

#[test]
fn the_stable_clone_id_is_published_as_a_partial_fingerprint() {
    let dir = fixture();
    let first = scan_sarif(dir.path(), "structural");
    let second = scan_sarif(dir.path(), "structural");

    let fingerprints = |log: &Value| -> Vec<String> {
        log["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|result| {
                result["partialFingerprints"]["cloneGroupFingerprint/v1"]
                    .as_str()
                    .expect("every result carries the stable clone id")
                    .to_string()
            })
            .collect()
    };
    let before = fingerprints(&first);
    assert!(!before.is_empty());
    // A rescan of unchanged sources yields the same identities, which is what
    // lets a consumer track a group across runs.
    assert_eq!(before, fingerprints(&second));

    // The same id the other views report.
    let json = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run scan");
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    let reported: Vec<String> = report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["fingerprint"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(before, reported);
}

#[test]
fn a_hidden_group_is_reported_with_its_suppression() {
    let dir = fixture();
    let log = scan_sarif(dir.path(), "fast");
    assert_valid_sarif(&log);

    let results = log["runs"][0]["results"].as_array().unwrap();
    let hidden: Vec<&Value> = results
        .iter()
        .filter(|result| result.get("suppressions").is_some())
        .collect();
    assert!(
        !hidden.is_empty(),
        "the vendor copies are hidden, not dropped"
    );
    let suppression = &hidden[0]["suppressions"][0];
    assert_eq!(suppression["kind"], "external");
    assert!(
        suppression["justification"]
            .as_str()
            .unwrap()
            .contains("vendor/**")
    );
    assert_eq!(
        hidden[0]["properties"]["suppressed"]["scope"], "path_glob",
        "the reason survives in the property bag too"
    );
}

#[test]
fn fast_output_satisfies_the_published_schema_and_scores_no_dimensions() {
    let dir = fixture();
    let log = scan_sarif(dir.path(), "fast");
    assert_valid_sarif(&log);

    assert_eq!(log["runs"][0]["properties"]["mode"], "fast");
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for result in results {
        assert!(
            result["properties"].get("similarity").is_none(),
            "a mode that measures no dimensions reports none"
        );
        assert_eq!(result["level"], "note");
        assert!(result["ruleIndex"].as_u64().unwrap() < 3);
    }
}

#[test]
fn the_schema_check_would_catch_a_malformed_log() {
    let dir = fixture();
    let mut log = scan_sarif(dir.path(), "structural");
    assert_valid_sarif(&log);

    // SARIF forbids undeclared members on a result, so a stray field must be
    // rejected: without this the validation above would prove nothing.
    log["runs"][0]["results"][0]["notASarifProperty"] = Value::Bool(true);
    assert!(validate_sarif(&log).is_err());
}

#[test]
fn the_log_is_written_to_the_requested_file() {
    let dir = fixture();
    let path = dir.path().join("report.sarif");
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--format", "sarif"])
        .arg("--output")
        .arg(&path)
        .assert()
        .success();
    let log: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the log was written"))
            .unwrap();
    assert_valid_sarif(&log);
}
