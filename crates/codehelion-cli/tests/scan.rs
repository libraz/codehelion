//! End-to-end scan tests: the compiled binary against real fixture trees,
//! with the recorded snapshot verified through the store's query layer.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs::OpenOptions;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;

use assert_cmd::Command;
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_eval::detected;
use codehelion_eval::metrics::stability;
use codehelion_store::artifact::{
    ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION,
    ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION, ArtifactAnalysisCloneGroupSavings,
    ArtifactAnalysisCorrelation, ArtifactAnalysisSavingsConfidence, ArtifactAnalysisSnapshot,
};
use codehelion_store::snapshot::{Snapshot, SummaryRow};
use codehelion_store::{BuildVariantFingerprint, Store};
use fs2::FileExt;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A ~40-token Rust function; long enough for the 20-token clone floor.
const CHECKSUM_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
    }
    acc ^ 0x5a5a
}
";

/// The same function under a consistent rename with changed literals.
const RENAMED_RS: &str = "pub fn digest_chunk(start: u64, items: &[u64]) -> u64 {
    let mut total = start;
    for item in items {
        total = total.wrapping_mul(37).wrapping_add(*item);
    }
    total ^ 0x1234
}
";

/// A Rust function sharing nothing structural with the checksum family, so a
/// pair of these is its own group rather than a member of an existing one.
const FORMAT_RS: &str = "pub fn describe_entry(name: &str, size: usize) -> String {
    let mut text = String::new();
    text.push_str(name);
    text.push(':');
    text.push(' ');
    text.push_str(&size.to_string());
    text
}
";

/// A verbatim C clone pair member.
const MIX_C: &str =
    "unsigned long mix_bytes(unsigned long seed, const unsigned long *data, int len) {
    unsigned long acc = seed;
    for (int i = 0; i < len; i++) {
        acc = acc * 31u + data[i];
    }
    return acc ^ 0x5a5aU;
}
";

/// A mixed Rust/C tree holding one verbatim Rust pair, one renamed Rust
/// copy and one verbatim C pair. The `.git` directory makes ignore rules
/// effective for the tests that add a `.gitignore`.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/c.rs"), RENAMED_RS).unwrap();
    std::fs::write(root.join("src/one.c"), MIX_C).unwrap();
    std::fs::write(root.join("src/two.c"), MIX_C).unwrap();
    dir
}

/// Copy one generated Rust corpus into an isolated directory for a scan that
/// writes configuration and its own audit databases beside the source files.
fn synthetic_rust_corpus(name: &str) -> tempfile::TempDir {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/synthetic")
        .join(name);
    let destination = tempfile::tempdir().expect("temporary corpus directory");
    for entry in std::fs::read_dir(&source).expect("read source corpus") {
        let entry = entry.expect("read corpus entry");
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            std::fs::copy(&path, destination.path().join(entry.file_name()))
                .expect("copy source corpus file");
        }
    }
    destination
}

/// Run a fresh Structural scan with an explicit number of lexer/parser jobs.
fn structural_json_with_jobs(root: &Path, jobs: usize, database: &Path) -> serde_json::Value {
    let jobs = jobs.to_string();
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "structural",
            "--format",
            "json",
            "--jobs",
            &jobs,
            "--db",
            database.to_str().expect("temporary path is UTF-8"),
        ])
        .output()
        .expect("run structural scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

fn open_store(root: &Path) -> Store {
    Store::open(&root.join(".codehelion/audit.db")).expect("open audit db")
}

fn empty_snapshot<'a>(root: &'a str, variant: &'a BuildVariant) -> Snapshot<'a> {
    Snapshot {
        root_path: root,
        tool_version: env!("CARGO_PKG_VERSION"),
        config_hash: "baseline-partition-fixture",
        config_source: "defaults",
        config_path: None,
        started_at: "2026-08-01T00:00:00Z",
        finished_at: "2026-08-01T00:00:01Z",
        variant,
        min_clone_tokens: 20,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: Vec::new(),
        groups: Vec::new(),
        sibling_groups: Vec::new(),
        near_misses: Vec::new(),
        files: Vec::new(),
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: SummaryRow::default(),
    }
}

/// Run `scan --format json` in `root` and parse the produced document.
fn scan_json(root: &Path) -> serde_json::Value {
    scan_json_with(root, &[])
}

/// The same, with extra arguments appended to the scan.
///
/// Always analyses: these tests are about what the analysis produces, and a
/// scan that reports a recorded run again would be testing the database
/// instead. The reuse path has its own tests.
fn scan_json_with(root: &Path, extra: &[&str]) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--format", "json"])
        .args(extra)
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// A tree of `names`, each holding a small translation unit, plus a bare
/// header. The header's content is C++ that the C grammar cannot follow, so a
/// misread shows up as a language count rather than as a silent difference.
fn header_fixture(names: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    for name in names {
        std::fs::write(root.join(name), MIX_C).unwrap();
    }
    std::fs::write(
        root.join("shared.h"),
        "namespace demo {\nclass Widget {\n public:\n  int size() const { return n_; }\n\
         \n private:\n  int n_ = 0;\n};\n}\n",
    )
    .unwrap();
    dir
}

/// The `(c, cpp)` analysed-file counts and the reported header grammar.
fn header_reading(root: &Path, config: Option<&str>) -> (u64, u64, String) {
    if let Some(config) = config {
        std::fs::write(root.join("codehelion.toml"), config).unwrap();
    }
    let value = scan_json(root);
    let variant = &value["run"]["build_variant"];
    (
        value["summary"]["files"]["c"].as_u64().unwrap(),
        value["summary"]["files"]["cpp"].as_u64().unwrap(),
        variant["headers"].as_str().unwrap().to_string(),
    )
}

/// The fingerprints of every group a report lists, visible or not.
fn group_ids(report: &serde_json::Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|group| group["fingerprint"].as_str().expect("a hex id").to_string())
        .collect()
}

/// The fingerprints a report lists without a suppression.
fn visible_ids(report: &serde_json::Value) -> Vec<String> {
    report["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|group| group["suppressed"].is_null())
        .map(|group| group["fingerprint"].as_str().expect("a hex id").to_string())
        .collect()
}

/// Record a baseline of `root`'s last scan into `root/baseline.json`.
fn record_baseline(root: &Path) {
    cmd()
        .current_dir(root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .success();
}
/// The checksum function rewritten, for writing over both copies of it at
/// once: the same duplication in the same two places, made of other content,
/// so it is known by another id.
const CHECKSUM_REWORKED_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for value in data {
        acc = acc.wrapping_mul(31).wrapping_add(*value);
        acc = acc.rotate_left(7);
    }
    acc ^ 0x5a5a
}
";

/// A tree holding one duplicated Rust function and nothing else, so that a
/// count of groups is a count of one thing.
fn one_pair() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    dir
}

#[path = "scan/baselines_and_vendoring.rs"]
mod baselines_and_vendoring;
#[path = "scan/headers_and_limits.rs"]
mod headers_and_limits;
#[path = "scan/lifecycle_and_suppression.rs"]
mod lifecycle_and_suppression;
#[path = "scan/reporting_and_paths.rs"]
mod reporting_and_paths;
#[path = "scan/semantic.rs"]
mod semantic;
#[path = "scan/sorting_and_comparison.rs"]
mod sorting_and_comparison;
