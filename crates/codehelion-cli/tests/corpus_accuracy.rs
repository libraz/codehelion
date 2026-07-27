//! Accuracy of Structural mode over the committed evaluation corpora.
//!
//! Every other test in this repository pins a fact about one input: this group
//! is recovered, that pair stays apart. None of them answers the question the
//! detector is actually judged by — over a body of labelled code, how much of
//! what is there does it find, and how much of what it reports is real. This
//! test asks that question on every run, so a change that trades recall for
//! quiet, or quiet for noise, is visible the moment it lands rather than the
//! next time someone looks.
//!
//! A pair pinned in isolation can still be lost in company: grouping decides
//! what goes with what across the whole corpus, so two units that pair up when
//! scanned alone may land in different groups when their neighbours are there
//! too. That is why this runs over whole corpora and not over pairs.
//!
//! What is asserted and what is only printed differs by how much the corpora
//! can support. Recall and the labelled non-clones are ground truth: the
//! corpora were built around those pairs and every one of them is labelled.
//! Precision is not — a corpus labels the clones it was built around, not
//! every clone in the file, so an unlabelled true copy counts against
//! precision. Those figures are printed for the record and left unasserted.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, evaluate};
use codehelion_eval::schema::CloneType;

/// One corpus and what the detector currently recovers from it.
struct Expected {
    /// Directory under `corpus/synthetic`.
    name: &'static str,
    /// Fraction of labelled clone pairs recovered.
    recall: f64,
    /// Why it is not 1.0, when it is not.
    shortfall: &'static str,
}

/// The committed corpora, with the recall each currently reaches.
///
/// These are pinned rather than bounded: a number that moves either way is
/// something to look at. A rise is a gap closed and belongs in the table; a
/// fall is a regression, and the corpora are small enough that any fall is one
/// specific labelled pair going missing.
const CORPORA: &[Expected] = &[
    Expected {
        name: "rust",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "c",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "cpp",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "rust-graded",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "rust-literals",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "rust-replaced",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "rust-negative",
        recall: 1.0,
        shortfall: "",
    },
    Expected {
        name: "rust-partial",
        recall: 1.0 / 2.0,
        shortfall: "the renamed three-statement transplant is shorter than the \
                    shortest statement window, so no seed can propose it. \
                    Looking for three-statement runs recovers it, and costs \
                    what was measured over a 324k-line C++ tree: 87 per cent \
                    more seed pairs, 73 per cent more confirmed runs and 29 \
                    per cent more findings, most of them a binding-glue \
                    preamble repeated across twenty-odd wrappers. That is a \
                    decision about how much a report should hold, not a \
                    detector bug, and it is left as one",
    },
    Expected {
        name: "rust-divergent",
        recall: 4.0 / 5.0,
        shortfall: "the remaining labelled pair is the seed against the variant \
                    that disturbs control flow and the call surface at once, \
                    which the judge rejects outright at 0.57. The pair that \
                    grouping splits — the seed and its renamed-callee variant, \
                    the strongest agreement in the corpus — is recovered, \
                    reported on its own because no group can hold both halves",
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
fn every_corpus_recovers_what_it_did_and_reports_no_labelled_non_clone() {
    let root = repo_root();
    let scratch = tempfile::tempdir().expect("temp dir");
    let mut table = String::from(
        "\ncorpus            recall  precision  findings/kLOC  FP/kLOC  non-clone hits\n",
    );
    // Recall split by what the labelled pair was made to be. Overall recall
    // says how much went missing; this says which kind did, and the kinds are
    // not interchangeable — a Type-1 copy that goes missing is a broken
    // detector, while a Type-3 pair that does is the acceptance threshold
    // doing its job. Printed, not asserted: the per-corpus recall above is the
    // assertion, and it is the same numbers with the split undone.
    let mut by_type = String::from("\ncorpus              type-1   type-2   type-3\n");
    let mut complaints = String::new();

    for expected in CORPORA {
        let corpus = root.join("corpus/synthetic").join(expected.name);
        let labels_path = corpus.join("labels.json");
        let labels_text = std::fs::read_to_string(&labels_path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
        let labels = LabelSet::from_json(&labels_text).expect("labels parse");

        let database = scratch.path().join(format!("{}.db", expected.name));
        let report = scan(&corpus, &database);
        let (result, lines) = detected::from_report_json(&report)
            .unwrap_or_else(|error| panic!("reading the report for {}: {error}", expected.name));

        let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        writeln!(
            table,
            "{:<16} {:>6.4} {:>10.4} {:>14.2} {:>8.2} {:>15}",
            expected.name,
            metrics.recall_overall,
            metrics.precision_overall,
            metrics.findings_per_kloc,
            metrics.false_positives_per_kloc,
            metrics.non_clone_hits,
        )
        .expect("writing to a string cannot fail");
        write!(by_type, "{:<16}", expected.name).expect("writing to a string cannot fail");
        for clone_type in [CloneType::Type1, CloneType::Type2, CloneType::Type3] {
            // A dash rather than a zero where the corpus has no pair of that
            // type: nothing was recovered because nothing was asked for, and a
            // zero would read as a failure.
            match metrics.recall_by_type.get(&clone_type) {
                Some(recall) => write!(by_type, " {recall:>8.4}"),
                None => write!(by_type, " {:>8}", "-"),
            }
            .expect("writing to a string cannot fail");
        }
        by_type.push('\n');

        if (metrics.recall_overall - expected.recall).abs() >= 1e-9 {
            writeln!(
                complaints,
                "{}: recall {:.4}, expected {:.4}{}{}",
                expected.name,
                metrics.recall_overall,
                expected.recall,
                if expected.shortfall.is_empty() {
                    ""
                } else {
                    " — the expected shortfall is that "
                },
                expected.shortfall,
            )
            .expect("writing to a string cannot fail");
        }
        // A labelled non-clone is a pair built to look alike and compute
        // something else. Reporting one is a false positive by construction,
        // with no argument about incomplete labelling to excuse it.
        if metrics.non_clone_hits > 0 {
            writeln!(
                complaints,
                "{}: reported {} pair(s) the corpus labels as deliberate non-clones",
                expected.name, metrics.non_clone_hits,
            )
            .expect("writing to a string cannot fail");
        }
    }

    // Printed so a run leaves the figures behind: `make eval` shows this table.
    println!("{table}");
    println!("{by_type}");
    // Every corpus is scored before anything is asserted: a change to the
    // detector moves several of these at once, and stopping at the first one
    // would hide the rest behind a re-run.
    assert!(complaints.is_empty(), "\n{complaints}");
}
