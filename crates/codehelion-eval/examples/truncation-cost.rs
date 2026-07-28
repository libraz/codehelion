//! Price a candidate-pair ceiling in verdicts rather than in candidates.
//!
//! Candidate generation walks posting lists rarest-first so that a ceiling
//! sacrifices the frequent, low-signal ones, and the run says so when the
//! ceiling is reached. What it has never said is what was lost: "the budget
//! ran out" is compatible with dropping nothing anybody wanted and with
//! dropping the clearest finding in the tree. The funnel counts candidates,
//! and a candidate is not a finding — most pairs die in verification, so a
//! count of unexamined pairs converts to nothing a reader can act on.
//!
//! The labelled corpora already carry the missing half: a verdict on every
//! group a scan reports. They never reach the shipped ceiling, but the ceiling
//! is configurable, so it can be brought down to them instead. Lowering it
//! until it bites and re-scoring what survives says what truncation costs in
//! the only currency that matters — findings someone ruled real — and it says
//! it on code where that ruling exists.
//!
//! ```sh
//! cargo run -p codehelion-eval --example truncation-cost -- \
//!     corpus/labeled/spdlog --bin target/release/codehelion
//! ```
//!
//! One tab-separated row per case and budget: the ceiling, whether it bit, the
//! groups that came out, and the confirmed / refuted / unjudged split of them.
//! The first row of each case is the unbounded scan, which is what the others
//! are read against. A case whose sources have not been materialized is skipped
//! aloud rather than scored as costing nothing.

// Like the benchmark harness, this drives the compiled `codehelion` binary
// rather than running inside it; it is not part of the scan path the
// workspace-wide lint locks.
#![allow(clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::process::Command;

use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, adjudicate};

/// Ceilings tried when none are given.
///
/// The labelled cases hold between seventy and thirty-five hundred seed pairs,
/// so this range runs from "barely bites" to "the search never started" on all
/// of them.
const DEFAULT_BUDGETS: &[usize] = &[2000, 1000, 500, 300, 200, 100, 50, 20];

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mut cases: Vec<PathBuf> = Vec::new();
    let mut binary = PathBuf::from("target/release/codehelion");
    let mut budgets: Vec<usize> = Vec::new();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bin" => match arguments.next() {
                Some(path) => binary = PathBuf::from(path),
                None => usage(),
            },
            "--budgets" => match arguments.next() {
                Some(list) => budgets = parse_budgets(&list),
                None => usage(),
            },
            _ => cases.push(PathBuf::from(argument)),
        }
    }
    if cases.is_empty() {
        usage();
    }
    if budgets.is_empty() {
        budgets = DEFAULT_BUDGETS.to_vec();
    }

    let scratch = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("no scratch directory: {error}");
            std::process::exit(1);
        }
    };

    println!("case\tbudget\texhausted\tgroups\tconfirmed\trefuted\tunjudged\tconflicting");
    for case in &cases {
        run_case(case, &binary, &budgets, scratch.path());
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: truncation-cost <labelled-case-dir>... [--bin <codehelion>] \
         [--budgets 500,200,50]"
    );
    std::process::exit(2);
}

fn parse_budgets(list: &str) -> Vec<usize> {
    list.split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

fn run_case(case: &Path, binary: &Path, budgets: &[usize], scratch: &Path) {
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

    for budget in std::iter::once(None).chain(budgets.iter().copied().map(Some)) {
        let Some(report) = scan(binary, &snapshot, budget, scratch, &name) else {
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
        let ceiling = budget.map_or_else(|| "none".to_string(), |value| value.to_string());
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

/// Scan `snapshot` in Structural mode, optionally under a lowered ceiling.
fn scan(
    binary: &Path,
    snapshot: &Path,
    budget: Option<usize>,
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
    if let Some(budget) = budget {
        let config = scratch.join(format!("{name}-{budget}.toml"));
        if let Err(error) = std::fs::write(&config, format!("[limits]\npair-budget = {budget}\n")) {
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
