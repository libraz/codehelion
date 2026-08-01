//! End-to-end Structural-mode scan tests: the compiled binary against real
//! fixture trees, with the recorded snapshot verified through the store's
//! query layer.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_store::Store;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// The original function.
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

/// A consistently renamed copy carrying one extra statement: a gapped
/// (Type-3) clone that Fast mode cannot recover.
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

/// An unrelated function, which must stay out of the group.
const OTHER_RS: &str = "pub fn label(name: &str) -> usize {
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
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), GAPPED_RS).unwrap();
    std::fs::write(root.join("src/other.rs"), OTHER_RS).unwrap();
    dir
}

fn open_store(root: &Path) -> Store {
    Store::open(&root.join(".codehelion/audit.db")).expect("open audit db")
}

/// Run `scan --mode structural --format json` in `root` and parse the
/// produced document.
///
/// Always analyses: these tests are about what the analysis produces, and a
/// scan that reports a recorded run again would be testing the database
/// instead. The reuse path has its own tests.
fn scan_json(root: &Path) -> serde_json::Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

#[path = "scan_structural/boilerplate_and_suppression.rs"]
mod boilerplate_and_suppression;
#[path = "scan_structural/deduplication_and_limits.rs"]
mod deduplication_and_limits;
#[path = "scan_structural/pipeline_and_evidence.rs"]
mod pipeline_and_evidence;
#[path = "scan_structural/ranking_and_folding.rs"]
mod ranking_and_folding;
#[path = "scan_structural/runs_and_suppressions.rs"]
mod runs_and_suppressions;
#[path = "scan_structural/test_code.rs"]
mod test_code;
