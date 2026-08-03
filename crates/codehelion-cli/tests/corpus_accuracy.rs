//! Accuracy of Fast and Structural modes over the committed evaluation corpora.
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
//! Every figure it prints is also pinned, but not every pin means the same
//! thing. Recall and the labelled non-clones are ground truth: the corpora were
//! built around those pairs and every one of them is labelled, so those numbers
//! are what they ought to be. Precision and the per-kLOC rates are not — a
//! corpus labels the clones it was built around, not every clone in the file,
//! so an unlabelled true copy counts against precision and no value is the
//! right one. They are recorded rather than judged: the pin says the figure has
//! not moved since somebody last looked, and a move is a change to explain
//! rather than a failure to fix.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, Metrics, evaluate};
use codehelion_eval::schema::CloneType;

/// What one analysis mode currently recovers from one corpus.
struct Measurements {
    /// Analysis mode passed to `scan`.
    mode: &'static str,
    /// Fraction of labelled clone pairs recovered.
    recall: f64,
    /// The same, split by the clone type the labelled pair was made to be:
    /// Type-1, Type-2, Type-3. `None` where the corpus holds no pair of that
    /// type, which is not the same as recovering none.
    by_type: [Option<f64>; 3],
    /// Share of what was reported that a label calls a clone.
    precision: f64,
    /// Findings per thousand source lines.
    findings_per_kloc: f64,
    /// Findings per thousand source lines that no label calls a clone.
    false_positives_per_kloc: f64,
    /// Deliberate non-clones the mode reported.
    non_clone_hits: usize,
    /// Why recall is not 1.0, when it is not.
    shortfall: &'static str,
}

/// One corpus and what each mode currently recovers from it.
struct Expected {
    /// Directory under `corpus/synthetic`.
    name: &'static str,
    /// Measurements for every user-selectable local source analysis mode.
    measurements: [Measurements; 2],
}

/// The committed corpora, with what the detector currently reaches on each.
///
/// These are pinned rather than bounded: a number that moves either way is
/// something to look at. A rise is a gap closed and belongs in the table; a
/// fall is a regression, and the corpora are small enough that any fall is one
/// specific labelled pair going missing.
///
/// Recall is pinned as a claim — the corpora were built around those pairs, so
/// the number ought to be what it is. The rest are pinned as measurements: a
/// generated corpus labels the clones it was built around and nothing else, so
/// a true copy nobody labelled counts against precision, and no value here is
/// the right one. What they are for is that a change cannot move them quietly.
const CORPORA: &[Expected] = &[
    Expected {
        name: "rust",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), Some(1.0), Some(0.0)],
                precision: 1.0,
                findings_per_kloc: 14.3885,
                false_positives_per_kloc: 0.0,
                recall: 5.0 / 6.0,
                non_clone_hits: 0,
                shortfall: "Fast reports contiguous matching fragments, so it does not recover the gapped Type-3 pair",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(1.0), Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 21.5827,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "c",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), Some(1.0), Some(0.0)],
                precision: 1.0 / 3.0,
                findings_per_kloc: 44.4444,
                false_positives_per_kloc: 29.6296,
                recall: 5.0 / 6.0,
                non_clone_hits: 0,
                shortfall: "Fast reports contiguous matching fragments, so it does not recover the gapped Type-3 pair",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(1.0), Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 22.2222,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "cpp",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), Some(1.0), Some(0.0)],
                precision: 1.0 / 3.0,
                findings_per_kloc: 43.1655,
                false_positives_per_kloc: 28.7770,
                recall: 5.0 / 6.0,
                non_clone_hits: 0,
                shortfall: "Fast reports contiguous matching fragments, so it does not recover the gapped Type-3 pair",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(1.0), Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 21.5827,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "rust-graded",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [None, None, Some(1.0)],
                precision: 2.0 / 9.0,
                findings_per_kloc: 51.7241,
                false_positives_per_kloc: 40.2299,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [None, None, Some(1.0)],
                precision: 0.25,
                findings_per_kloc: 22.9885,
                false_positives_per_kloc: 17.2414,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "rust-literals",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [None, Some(1.0), None],
                precision: 0.2,
                findings_per_kloc: 58.1395,
                false_positives_per_kloc: 46.5116,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [None, Some(1.0), None],
                precision: 1.0,
                findings_per_kloc: 11.6279,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "rust-replaced",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [None, None, Some(1.0)],
                precision: 0.25,
                findings_per_kloc: 37.3832,
                false_positives_per_kloc: 28.0374,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [None, None, Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 9.3458,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "rust-negative",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), None, None],
                precision: 1.0,
                findings_per_kloc: 36.3636,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), None, None],
                precision: 1.0,
                findings_per_kloc: 36.3636,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "rust-partial",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), Some(1.0), None],
                precision: 0.2,
                findings_per_kloc: 55.2486,
                false_positives_per_kloc: 44.1989,
                recall: 1.0,
                // The two `parse-error-boilerplate` negatives deliberately
                // exercise recovery after malformed syntax. Fast mode only
                // sees their shared normalized token runs, so this is a
                // recorded false-positive baseline rather than an accepted
                // precision target.
                non_clone_hits: 2,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(0.0), None],
                precision: 1.0 / 3.0,
                findings_per_kloc: 16.5746,
                false_positives_per_kloc: 11.0497,
                recall: 1.0 / 2.0,
                non_clone_hits: 0,
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
        ],
    },
    Expected {
        name: "rust-divergent",
        measurements: [
            Measurements {
                mode: "fast",
                by_type: [None, Some(1.0), Some(0.25)],
                precision: 2.0 / 17.0,
                findings_per_kloc: 96.0452,
                false_positives_per_kloc: 84.7458,
                recall: 2.0 / 5.0,
                non_clone_hits: 0,
                shortfall: "Fast does not form structural near-match candidates for the divergent Type-3 variants",
            },
            Measurements {
                mode: "structural",
                by_type: [None, Some(1.0), Some(0.75)],
                precision: 2.0 / 3.0,
                findings_per_kloc: 16.9492,
                false_positives_per_kloc: 5.6497,
                recall: 4.0 / 5.0,
                non_clone_hits: 0,
                shortfall: "the remaining labelled pair is the seed against the variant \
                            that disturbs control flow and the call surface at once, \
                            which the judge rejects outright at 0.57. The pair that \
                            grouping splits — the seed and its renamed-callee variant, \
                            the strongest agreement in the corpus — is recovered, \
                            reported on its own because no group can hold both halves",
            },
        ],
    },
];

/// Whether a per-type recall is what was recorded, absence included.
fn same_measure(measured: Option<f64>, recorded: Option<f64>) -> bool {
    match (measured, recorded) {
        (Some(left), Some(right)) => (left - right).abs() < 1e-9,
        (None, None) => true,
        _ => false,
    }
}

/// Whether two measured rates agree at the precision the table records.
fn same_printed_measure(measured: Option<f64>, recorded: Option<f64>) -> bool {
    match (measured, recorded) {
        (Some(left), Some(right)) => format!("{left:.4}") == format!("{right:.4}"),
        (None, None) => true,
        _ => false,
    }
}

/// A per-type recall as the table shows it.
fn show(recall: Option<f64>) -> String {
    recall.map_or_else(|| "absent".to_owned(), |value| format!("{value:.4}"))
}

/// A corpus-wide metric as the table shows it.
fn show_metric(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |measure| format!("{measure:.4}"))
}

/// Metrics whose values are pinned as recorded measurements for one corpus.
const fn pinned_rates(
    metrics: &Metrics,
    expected: &Measurements,
) -> [(&'static str, Option<f64>, Option<f64>); 3] {
    [
        (
            "precision",
            metrics.precision_overall,
            Some(expected.precision),
        ),
        (
            "findings per kLOC",
            metrics.findings_per_kloc,
            Some(expected.findings_per_kloc),
        ),
        (
            "false positives per kLOC",
            metrics.false_positives_per_kloc,
            Some(expected.false_positives_per_kloc),
        ),
    ]
}

/// Repository root, from this test's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// Scan a corpus in one source-analysis mode and return its report JSON.
fn scan(corpus: &Path, mode: &str, database: &Path) -> String {
    let output = Command::cargo_bin("codehelion")
        .expect("binary should build")
        .arg("scan")
        .arg(corpus)
        .args(["--mode", mode, "--format", "json"])
        // The labels describe every duplication in the tree, so the
        // measurement has to see every one of them. A corpus with a directory
        // the vendored default happens to name — bitflags writes its
        // external-crate integrations in `src/external` — would otherwise have
        // its ground truth moved by a presentation setting.
        .arg("--include-vendored")
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

// Recall split by what the labelled pair was made to be. Overall recall says
// how much went missing; this says which kind did, and the kinds are not
// interchangeable. Pinned separately because two pairs of different types
// changing state in opposite directions leaves the total where it was.
#[allow(clippy::too_many_lines)]
#[test]
fn every_corpus_stays_at_its_recorded_accuracy_in_each_mode() {
    let root = repo_root();
    let scratch = tempfile::tempdir().expect("temp dir");
    let mut table = String::from(
        "\nmode       corpus            recall  precision  findings/kLOC  FP/kLOC  non-clone hits\n",
    );
    let mut by_type = String::from("\nmode       corpus              type-1   type-2   type-3\n");
    let mut complaints = String::new();

    for expected in CORPORA {
        let corpus = root.join("corpus/synthetic").join(expected.name);
        let labels_path = corpus.join("labels.json");
        let labels_text = std::fs::read_to_string(&labels_path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
        let labels = LabelSet::from_json(&labels_text).expect("labels parse");

        for measurement in &expected.measurements {
            let database = scratch
                .path()
                .join(format!("{}-{}.db", expected.name, measurement.mode));
            let report = scan(&corpus, measurement.mode, &database);
            let (result, lines) = detected::from_report_json(&report).unwrap_or_else(|error| {
                panic!(
                    "reading the {} report for {}: {error}",
                    measurement.mode, expected.name
                )
            });

            let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
            writeln!(
                table,
                "{:<10} {:<16} {:>6} {:>10} {:>14} {:>8} {:>15}",
                measurement.mode,
                expected.name,
                show_metric(metrics.recall_overall),
                show_metric(metrics.precision_overall),
                show_metric(metrics.findings_per_kloc),
                show_metric(metrics.false_positives_per_kloc),
                metrics.non_clone_hits,
            )
            .expect("writing to a string cannot fail");
            write!(by_type, "{:<10} {:<16}", measurement.mode, expected.name)
                .expect("writing to a string cannot fail");
            let types = [CloneType::Type1, CloneType::Type2, CloneType::Type3];
            for (clone_type, recorded) in types.into_iter().zip(measurement.by_type) {
                let measured = metrics.recall_by_type.get(&clone_type).copied();
                // A dash rather than a zero where the corpus has no pair of that
                // type: nothing was recovered because nothing was asked for, and a
                // zero would read as a failure.
                match measured {
                    Some(recall) => write!(by_type, " {recall:>8.4}"),
                    None => write!(by_type, " {:>8}", "-"),
                }
                .expect("writing to a string cannot fail");
                if !same_measure(measured, recorded) {
                    writeln!(
                        complaints,
                        "{} {}: {clone_type:?} recall is {}, recorded as {}",
                        measurement.mode,
                        expected.name,
                        show(measured),
                        show(recorded),
                    )
                    .expect("writing to a string cannot fail");
                }
            }
            by_type.push('\n');

            for (what, measured, recorded) in pinned_rates(&metrics, measurement) {
                // Compared at the width the table prints, which is what anybody
                // copying a new value back into it would be reading.
                if !same_printed_measure(measured, recorded) {
                    writeln!(
                        complaints,
                        "{} {}: {what} is {}, recorded as {}",
                        measurement.mode,
                        expected.name,
                        show_metric(measured),
                        show_metric(recorded),
                    )
                    .expect("writing to a string cannot fail");
                }
            }

            if !same_measure(metrics.recall_overall, Some(measurement.recall)) {
                writeln!(
                    complaints,
                    "{} {}: recall {}, expected {:.4}{}{}",
                    measurement.mode,
                    expected.name,
                    show_metric(metrics.recall_overall),
                    measurement.recall,
                    if measurement.shortfall.is_empty() {
                        ""
                    } else {
                        " — the expected shortfall is that "
                    },
                    measurement.shortfall,
                )
                .expect("writing to a string cannot fail");
            }
            if metrics.non_clone_hits != measurement.non_clone_hits {
                writeln!(
                    complaints,
                    "{} {}: reported {} pair(s) the corpus labels as deliberate non-clones, recorded as {}",
                    measurement.mode,
                    expected.name,
                    metrics.non_clone_hits,
                    measurement.non_clone_hits,
                )
                .expect("writing to a string cannot fail");
            }
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
