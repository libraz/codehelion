//! Price a ceiling in verdicts rather than in candidates.
//!
//! Every ceiling in the scan says when it was reached and how much it left
//! undone, and none of that converts to anything a reader can act on. A count
//! of unexamined candidate pairs is not a count of lost findings — most pairs
//! die in verification — and a count of components that were cut says nothing
//! about whether cutting them mattered. "The ceiling was reached" is equally
//! compatible with losing nothing anybody wanted and with losing the clearest
//! duplication in the tree.
//!
//! The labelled corpora carry the missing half: a verdict on every group a scan
//! reports. They are far too small to reach the shipped ceilings, but the
//! ceilings are configurable, so they can be brought down to the corpora
//! instead. Lowering one until it bites and re-scoring what survives says what
//! it costs in the only currency that matters — findings someone ruled on — and
//! says it on code where that ruling exists.
//!
//! ```sh
//! cargo run -p codehelion-eval --example truncation-cost -- \
//!     corpus/labeled/spdlog --bin target/release/codehelion
//! cargo run -p codehelion-eval --example truncation-cost -- corpus/labeled/lz4 \
//!     --limit max-component --values 1024,64,16,4,2
//! ```
//!
//! One tab-separated row per case and setting: the ceiling, whether the pair
//! budget bit, the groups that came out, and the confirmed / refuted / unjudged
//! split of them. The first row of each case is the scan with nothing lowered,
//! which is what the others are read against. A case whose sources have not
//! been materialized is skipped aloud rather than scored as costing nothing.
//!
//! `--limit` names any key of the configuration's `[limits]` table, so a
//! ceiling nobody has questioned yet can be questioned without writing a second
//! harness.

// Like the benchmark harness, this drives the compiled `codehelion` binary
// rather than running inside it; it is not part of the scan path the
// workspace-wide lint locks.
#![allow(clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::process::Command;

use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, adjudicate};

/// The ceiling lowered when none is named.
const DEFAULT_LIMIT: &str = "pair-budget";

/// Settings tried when none are given.
///
/// The labelled cases hold between seventy and thirty-five hundred seed pairs,
/// so this range runs from "barely bites" to "the search never started" on all
/// of them. Another ceiling wants another range, which is what `--values` is
/// for.
const DEFAULT_VALUES: &[usize] = &[2000, 1000, 500, 300, 200, 100, 50, 20];

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mut cases: Vec<PathBuf> = Vec::new();
    let mut binary = PathBuf::from("target/release/codehelion");
    let mut limit = DEFAULT_LIMIT.to_string();
    let mut values: Vec<usize> = Vec::new();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bin" => match arguments.next() {
                Some(path) => binary = PathBuf::from(path),
                None => usage(),
            },
            "--limit" => match arguments.next() {
                Some(key) => limit = key,
                None => usage(),
            },
            "--values" | "--budgets" => match arguments.next() {
                Some(list) => values = parse_values(&list),
                None => usage(),
            },
            _ => cases.push(PathBuf::from(argument)),
        }
    }
    if cases.is_empty() {
        usage();
    }
    if values.is_empty() {
        values = DEFAULT_VALUES.to_vec();
    }

    let scratch = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("no scratch directory: {error}");
            std::process::exit(1);
        }
    };

    println!("case\t{limit}\texhausted\tgroups\tconfirmed\trefuted\tunjudged\tconflicting");
    for case in &cases {
        run_case(case, &binary, &limit, &values, scratch.path());
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: truncation-cost <labelled-case-dir>... [--bin <codehelion>] \
         [--limit pair-budget] [--values 500,200,50]"
    );
    std::process::exit(2);
}

fn parse_values(list: &str) -> Vec<usize> {
    list.split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

fn run_case(case: &Path, binary: &Path, limit: &str, values: &[usize], scratch: &Path) {
    let name = case.file_name().map_or_else(
        || case.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let labels_text = match std::fs::read_to_string(case.join("labels.json")) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{name}: no labels: {error}");
            return;
        }
    };
    let Ok(labels) = LabelSet::from_json(&labels_text) else {
        eprintln!("{name}: labels do not parse");
        return;
    };
    let snapshot = case.join("snapshot");
    if !snapshot.is_dir() {
        eprintln!("{name}: no snapshot; run corpus/scripts/materialize-labeled.sh");
        return;
    }

    for setting in std::iter::once(None).chain(values.iter().copied().map(Some)) {
        let Some(report) = scan(binary, &snapshot, limit, setting, scratch, &name) else {
            continue;
        };
        let Ok((result, _lines)) = detected::from_report_json(&report) else {
            eprintln!("{name}: report does not parse");
            continue;
        };
        let ruled = adjudicate(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        let exhausted = serde_json::from_str::<serde_json::Value>(&report)
            .ok()
            .and_then(|value| value["summary"]["pair_budget_exhausted"].as_bool())
            .unwrap_or(false);
        let ceiling = setting.map_or_else(|| "none".to_string(), |value| value.to_string());
        println!(
            "{name}\t{ceiling}\t{exhausted}\t{}\t{}\t{}\t{}\t{}",
            result.findings.len(),
            ruled.confirmed,
            ruled.refuted,
            ruled.unjudged,
            ruled.conflicting
        );
    }
}

/// Scan `snapshot` in Structural mode, optionally with one ceiling lowered.
fn scan(
    binary: &Path,
    snapshot: &Path,
    limit: &str,
    setting: Option<usize>,
    scratch: &Path,
    name: &str,
) -> Option<String> {
    let mut command = Command::new(binary);
    command
        .arg("scan")
        .arg(snapshot)
        .args(["--mode", "structural", "--format", "json"])
        .arg("--db")
        .arg(scratch.join(format!("{name}.db")));
    if let Some(value) = setting {
        let config = scratch.join(format!("{name}-{limit}-{value}.toml"));
        if let Err(error) = std::fs::write(&config, format!("[limits]\n{limit} = {value}\n")) {
            eprintln!("{name}: writing the ceiling: {error}");
            return None;
        }
        command.arg("--config").arg(config);
    }
    // A fresh database per run: a scan that reuses a previous one answers with
    // what it stored rather than with what this ceiling let it find.
    let _ = std::fs::remove_file(scratch.join(format!("{name}.db")));
    match command.output() {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout).ok(),
        Ok(output) => {
            eprintln!(
                "{name}: scan failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            None
        }
        Err(error) => {
            eprintln!("{name}: cannot run {}: {error}", binary.display());
            None
        }
    }
}
