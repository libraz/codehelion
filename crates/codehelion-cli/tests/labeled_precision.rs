//! Precision of Structural mode over hand-labelled real code.
//!
//! The synthetic corpora answer "how much of what is there does it find". They
//! cannot answer "how much of what it reports is real", because a generated
//! corpus labels the clones it was built around and nothing else, so every
//! unlabelled true copy counts against precision. That is why
//! `corpus_accuracy.rs` prints precision and asserts nothing about it.
//!
//! These corpora answer the second question instead. They are snapshots of real
//! projects, and what is labelled is what the detector reported: every group is
//! ruled on by hand, as a clone worth reporting or as a lookalike that must not
//! be. Precision over those verdicts is a number a partial label set supports,
//! and it is asserted here.
//!
//! Adding a labelled corpus therefore means running the scan, reading every
//! group, and recording a verdict for each. A group nobody ruled on is counted
//! and reported, never silently treated as either.
//!
//! What is committed is the verdicts, not the code they are about: the sources
//! belong to the projects they were cut from. Each case records the commit it
//! is anchored to, and `corpus/scripts/materialize-labeled.sh` rebuilds it. A
//! case without its snapshot is reported as unscored instead of scored as
//! perfect.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, adjudicate};

/// One labelled corpus and the verdict split it currently produces.
struct Expected {
    /// Directory under `corpus/labeled`.
    name: &'static str,
    /// Groups ruled a clone worth reporting.
    confirmed: usize,
    /// Groups ruled a lookalike that must not be reported.
    refuted: usize,
}

/// The labelled corpora, with the split each currently reaches.
///
/// Both numbers are pinned, not bounded. A fall in `confirmed` is a clone the
/// detector used to find and no longer does. A rise in `refuted` is a lookalike
/// class coming back. A change in their sum means the detector reported
/// something new about labelled code, which is a verdict waiting to be made,
/// not a number to update.
const CORPORA: &[Expected] = &[
    Expected {
        name: "fast-yaml-cpp",
        confirmed: 20,
        refuted: 5,
    },
    Expected {
        name: "fast-yaml",
        confirmed: 1,
        refuted: 0,
    },
    Expected {
        name: "codehelion-store",
        confirmed: 2,
        refuted: 2,
    },
];

/// Repository root, from this test's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// Scan a corpus in Structural mode and return its report JSON.
fn scan(corpus: &Path, database: &Path) -> String {
    let output = Command::cargo_bin("codehelion")
        .expect("binary should build")
        .arg("scan")
        .arg(corpus)
        .args(["--mode", "structural", "--format", "json"])
        .arg("--db")
        .arg(database)
        .output()
        .expect("scan runs");
    assert!(
        output.status.success(),
        "scanning {} failed: {}",
        corpus.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("report is utf-8")
}

#[test]
fn every_labelled_group_still_gets_the_verdict_it_was_given() {
    let root = repo_root();
    let scratch = tempfile::tempdir().expect("temp dir");
    let mut table =
        String::from("\ncorpus            precision  confirmed  refuted  unjudged  conflicts\n");
    let mut complaints = String::new();
    let mut unmaterialized = 0usize;

    for expected in CORPORA {
        let corpus = root.join("corpus/labeled").join(expected.name);
        let labels_path = corpus.join("labels.json");
        let labels_text = std::fs::read_to_string(&labels_path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
        let labels = LabelSet::from_json(&labels_text).expect("labels parse");

        // The sources belong to the projects they came from and are not
        // committed here; the case records the commit they are cut from, and
        // the script rebuilds them. Say so rather than passing quietly.
        let snapshot = corpus.join("snapshot");
        if !snapshot.is_dir() {
            writeln!(
                table,
                "{:<16} {:>9} {:>10} {:>8} {:>9} {:>10}",
                expected.name, "-", "-", "-", "-", "-"
            )
            .expect("writing to a string cannot fail");
            unmaterialized += 1;
            continue;
        }

        let database = scratch.path().join(format!("{}.db", expected.name));
        let report = scan(&snapshot, &database);
        let (result, _lines) = detected::from_report_json(&report)
            .unwrap_or_else(|error| panic!("reading the report for {}: {error}", expected.name));

        let ruled = adjudicate(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        writeln!(
            table,
            "{:<16} {:>9.4} {:>10} {:>8} {:>9} {:>10}",
            expected.name,
            ruled.precision(),
            ruled.confirmed,
            ruled.refuted,
            ruled.unjudged,
            ruled.conflicting,
        )
        .expect("writing to a string cannot fail");

        if ruled.confirmed != expected.confirmed || ruled.refuted != expected.refuted {
            writeln!(
                complaints,
                "{}: {} confirmed and {} refuted, expected {} and {}",
                expected.name, ruled.confirmed, ruled.refuted, expected.confirmed, expected.refuted,
            )
            .expect("writing to a string cannot fail");
        }
        // Every group in these corpora was ruled on when the labels were
        // written. One without a verdict is a group the detector has started
        // reporting since, and it needs reading rather than counting.
        if ruled.unjudged > 0 {
            writeln!(
                complaints,
                "{}: {} reported group(s) carry no verdict — read them and label them",
                expected.name, ruled.unjudged,
            )
            .expect("writing to a string cannot fail");
        }
        // Two labels claiming one finding is the corpus disagreeing with
        // itself, which no detector change can fix.
        if ruled.conflicting > 0 {
            writeln!(
                complaints,
                "{}: {} finding(s) are labelled both a clone and a non-clone",
                expected.name, ruled.conflicting,
            )
            .expect("writing to a string cannot fail");
        }
    }

    println!("{table}");
    if unmaterialized > 0 {
        println!(
            "{unmaterialized} of {} labelled corpora have no snapshot and were not scored.\n\
             Run corpus/scripts/materialize-labeled.sh to cut them from their pinned commits.",
            CORPORA.len(),
        );
    }
    assert!(complaints.is_empty(), "\n{complaints}");
}
