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

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{
    DEFAULT_MATCH_THRESHOLD, Metrics, evaluate, evaluate_siblings, stability,
};
use codehelion_eval::schema::{CloneType, SiblingBasis};

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
                by_type: [Some(0.75), Some(1.0), Some(0.0)],
                precision: 2.0 / 3.0,
                findings_per_kloc: 16.4835,
                false_positives_per_kloc: 5.4945,
                recall: 5.0 / 7.0,
                non_clone_hits: 0,
                shortfall: "Fast reports contiguous matching fragments, so it misses the duplicated-loop Type-1 pair and does not recover the gapped Type-3 pair",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(1.0), Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 21.9780,
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
                // The fragment pass reports the `sum_even` conditional, which
                // is byte-identical across seed, type1 and type3 at exactly
                // `min_clone_tokens`. It is a true copy the corpus has no
                // label for: it recovers part of the gapped Type-3 pair, and
                // the line overlap against that label falls under the
                // coverage threshold, so it is charged as a false positive.
                precision: 2.0 / 6.0,
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
                // As in the C corpus, the fragment pass reports the
                // `sum_even` conditional shared verbatim by seed, type1 and
                // type3, which no label covers.
                precision: 3.0 / 7.0,
                // The signature mirror adds fifteen source lines without
                // entering the primary finding stream, so the counts stay
                // fixed while the per-kLOC denominators move from 170 to
                // 185 lines.
                findings_per_kloc: 37.8378,
                false_positives_per_kloc: 21.6216,
                recall: 6.0 / 7.0,
                non_clone_hits: 0,
                shortfall: "Fast reports contiguous matching fragments, so it does not recover the gapped Type-3 pair",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), Some(1.0), Some(1.0)],
                precision: 1.0,
                findings_per_kloc: 21.6216,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
        ],
    },
    Expected {
        name: "cpp-common-signature",
        measurements: [
            // One signature covers every function in the corpus, and only one
            // of them is duplicated. Both modes report that one pair and
            // nothing else: the shared signature is not by itself a reason to
            // report anything, in either the primary stream or the side one.
            Measurements {
                mode: "fast",
                by_type: [Some(1.0), None, None],
                precision: 1.0,
                findings_per_kloc: 7.5758,
                false_positives_per_kloc: 0.0,
                recall: 1.0,
                non_clone_hits: 0,
                shortfall: "",
            },
            Measurements {
                mode: "structural",
                by_type: [Some(1.0), None, None],
                precision: 1.0,
                findings_per_kloc: 7.5758,
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
                // Reading `true` and `false` as keywords rather than boolean
                // literals keeps them apart under literal normalization, so
                // the pair that differed only in a boolean constant is no
                // longer reported. This corpus is the only one carrying both
                // spellings in one unit.
                precision: 1.0 / 3.0,
                findings_per_kloc: 17.2414,
                false_positives_per_kloc: 11.4943,
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
    scan_with_signature(corpus, mode, database, false)
}

fn scan_with_signature(
    corpus: &Path,
    mode: &str,
    database: &Path,
    siblings_by_signature: bool,
) -> String {
    let mut command = Command::cargo_bin("codehelion").expect("binary should build");
    command
        .arg("scan")
        .arg(corpus)
        .args(["--mode", mode, "--format", "json"])
        // The labels describe every duplication in the tree, so the
        // measurement has to see every one of them. A corpus with a directory
        // the vendored default happens to name — bitflags writes its
        // external-crate integrations in `src/external` — would otherwise have
        // its ground truth moved by a presentation setting.
        .arg("--include-vendored");
    if siblings_by_signature {
        command.arg("--siblings-by-signature");
    }
    let output = command
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

/// The primary stream's identity is the set of source ranges, not the
/// detector-assigned fingerprint. This is the same identity used by the
/// evaluation harness's stability metric, kept here so the regression test
/// also makes the set comparison explicit.
fn primary_keys(
    result: &codehelion_eval::schema::DetectionResult,
) -> BTreeSet<Vec<(String, u32, u32)>> {
    result
        .findings
        .iter()
        .map(|finding| {
            let mut key: Vec<_> = finding
                .fragments
                .iter()
                .map(|fragment| {
                    (
                        fragment.file.clone(),
                        fragment.start_line,
                        fragment.end_line,
                    )
                })
                .collect();
            key.sort();
            key
        })
        .collect()
}

/// How many units a report's funnel let through one stage.
fn funnel_stage(report: &str, name: &str) -> u64 {
    let json: serde_json::Value = serde_json::from_str(report).expect("report is JSON");
    json["summary"]["funnel"]
        .as_array()
        .expect("the report has a funnel")
        .iter()
        .find(|stage| stage["stage"] == name)
        .and_then(|stage| stage["passed"].as_u64())
        .unwrap_or_else(|| panic!("the funnel has a {name} stage"))
}

/// How many units may share one signature before it stops being evidence.
fn sharing_limit() -> u64 {
    u64::try_from(
        codehelion_core::structural::SignatureSiblingConfig::default().max_units_per_signature,
    )
    .expect("the sharing limit fits in u64")
}

#[test]
fn cpp_signature_mirror_is_measured_outside_primary_accuracy() {
    let root = repo_root();
    let corpus = root.join("corpus/synthetic/cpp");
    let labels_text =
        std::fs::read_to_string(corpus.join("labels.json")).expect("cpp labels are committed");
    let labels = LabelSet::from_json(&labels_text).expect("cpp labels parse");
    assert_eq!(labels.known_siblings.len(), 1);

    let scratch = tempfile::tempdir().expect("temp dir");
    let report_off = scan(
        &corpus,
        "structural",
        &scratch.path().join("cpp-structural-off.db"),
    );
    let (result_off, lines_off, sibling_groups_off) =
        detected::from_report_json_with_siblings(&report_off)
            .expect("default-off structural report has the sibling contract");
    let sibling_metrics_off =
        evaluate_siblings(&sibling_groups_off, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(sibling_metrics_off.known_mirrors_recovered, 0);
    assert_eq!(sibling_metrics_off.known_mirrors_total, 1);
    assert_eq!(sibling_metrics_off.signature_siblings_total, 0);
    let off_json: serde_json::Value = serde_json::from_str(&report_off).expect("off JSON");
    assert!(
        off_json["summary"]["funnel"]
            .as_array()
            .expect("off funnel")
            .iter()
            .all(|stage| stage["stage"] != "signature sibling entries")
    );

    let report = scan_with_signature(
        &corpus,
        "structural",
        &scratch.path().join("cpp-structural-on.db"),
        true,
    );
    let (result, lines, sibling_groups) = detected::from_report_json_with_siblings(&report)
        .expect("structural report has the current sibling contract");
    let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);

    // The pre-existing Structural primary baseline remains four true
    // positives. The mirror is supplemental evidence, not a fifth finding.
    assert_eq!(metrics.total_findings, 4);
    assert_eq!(metrics.true_positives, 4);
    assert_eq!(metrics.false_positives, 0);
    assert_eq!(metrics.recall_overall, Some(1.0));
    assert!(result.findings.iter().all(|finding| {
        finding
            .fragments
            .iter()
            .all(|fragment| fragment.file != "signature_mirror.cpp")
    }));

    let sibling_metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(sibling_metrics.known_mirrors_recovered, 1);
    assert_eq!(sibling_metrics.known_mirrors_total, 1);
    // Structural currently retains one similarity sibling and two exact
    // signature siblings (the edited mirror and the existing Type-3 variant).
    assert_eq!(sibling_metrics.signature_siblings_total, 2);

    let signature_siblings: Vec<_> = sibling_groups
        .iter()
        .flat_map(|group| &group.siblings)
        .filter(|sibling| sibling.basis == SiblingBasis::Signature)
        .collect();
    assert_eq!(signature_siblings.len(), 2);
    assert!(signature_siblings.iter().all(|sibling| {
        sibling.confidence_band == "low"
            && sibling
                .signature
                .as_ref()
                .is_some_and(|signature| !signature.is_empty())
            && sibling.similarity.composite.is_finite()
            && (0.0..=1.0).contains(&sibling.similarity.composite)
    }));
    let mirror_siblings: Vec<_> = sibling_groups
        .iter()
        .flat_map(|group| &group.siblings)
        .filter(|sibling| sibling.member.file == "signature_mirror.cpp")
        .collect();
    assert_eq!(mirror_siblings.len(), 1);
    assert_eq!(mirror_siblings[0].basis, SiblingBasis::Signature);
    assert!(
        sibling_groups
            .iter()
            .flat_map(|group| &group.siblings)
            .filter(|sibling| sibling.member.file == "signature_mirror.cpp")
            .all(|sibling| sibling.basis == SiblingBasis::Signature)
    );
    assert_eq!(primary_keys(&result_off), primary_keys(&result));
    assert_eq!(
        evaluate(&result_off, &labels, lines_off, DEFAULT_MATCH_THRESHOLD, 10).total_findings,
        metrics.total_findings
    );
}

/// A signature earns attention by being rare. When one signature covers a
/// whole file, the sibling channel has nothing to say about any unit holding
/// it — not even about the one pair inside it that really is a copy. That pair
/// is what primary grouping is for, and losing it from the side stream costs
/// nothing as long as the primary result still reports it, which is the two
/// halves this pins together.
#[test]
fn cpp_common_signature_silences_siblings_while_primary_keeps_the_duplicate() {
    let root = repo_root();
    let corpus = root.join("corpus/synthetic/cpp-common-signature");
    let labels_text = std::fs::read_to_string(corpus.join("labels.json"))
        .expect("common-signature labels are committed");
    let labels = LabelSet::from_json(&labels_text).expect("common-signature labels parse");
    // The corpus expects no sibling at all, so it carries no mirror label: the
    // duplication it does hold is an ordinary labelled clone pair.
    assert!(labels.known_siblings.is_empty());
    assert_eq!(labels.clone_pairs.len(), 1);

    let scratch = tempfile::tempdir().expect("temp dir");
    let report = scan_with_signature(
        &corpus,
        "structural",
        &scratch.path().join("common-signature-on.db"),
        true,
    );
    let (result, lines, sibling_groups) = detected::from_report_json_with_siblings(&report)
        .expect("structural report has the current sibling contract");

    // Every function in this corpus takes the same parameters and returns the
    // same type, so the unit count is also the number of units sharing the one
    // signature, and it is above what that signature is allowed to cover.
    let units = funnel_stage(&report, "units");
    assert_eq!(units, 10);
    assert!(units > sharing_limit());
    assert_eq!(funnel_stage(&report, "signature sibling entries"), 0);

    let sibling_metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(sibling_metrics.signature_siblings_total, 0);
    assert!(
        sibling_groups
            .iter()
            .flat_map(|group| &group.siblings)
            .all(|sibling| sibling.basis != SiblingBasis::Signature)
    );

    // The copied function is recovered by the primary path, which is the half
    // of the trade that has to hold for the silenced channel to be acceptable.
    let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    assert_eq!(metrics.total_findings, 1);
    assert_eq!(metrics.true_positives, 1);
    assert_eq!(metrics.false_positives, 0);
    assert_eq!(metrics.recall_overall, Some(1.0));
    let files: BTreeSet<&str> = result
        .findings
        .iter()
        .flat_map(|finding| &finding.fragments)
        .map(|fragment| fragment.file.as_str())
        .collect();
    assert_eq!(
        files,
        ["copy.cpp", "seed.cpp"]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );

    // Asking for signature siblings changed nothing in the primary stream: the
    // sharing limit belongs to the side channel and stays there.
    let report_off = scan(
        &corpus,
        "structural",
        &scratch.path().join("common-signature-off.db"),
    );
    let (result_off, _) =
        detected::from_report_json(&report_off).expect("default-off report reads");
    assert_eq!(primary_keys(&result_off), primary_keys(&result));
}

/// The silence above is the sharing limit's doing and not an absence of
/// candidates: the same corpus with few enough functions left in it offers the
/// remaining same-signature units as siblings of the very same group.
#[test]
fn cpp_common_signature_offers_siblings_once_few_enough_units_share_it() {
    let root = repo_root();
    let corpus = root.join("corpus/synthetic/cpp-common-signature");
    let scratch = tempfile::tempdir().expect("temp dir");
    let thinned = scratch.path().join("cpp-fewer-sharers");
    std::fs::create_dir(&thinned).expect("thinned corpus directory");
    // The seed writes one function per blank-line-separated block after its
    // header comment, so keeping the first blocks keeps whole functions.
    let seed = std::fs::read_to_string(corpus.join("seed.cpp")).expect("seed is committed");
    let kept: Vec<&str> = seed.split("\n\n").take(5).collect();
    std::fs::write(thinned.join("seed.cpp"), kept.join("\n\n")).expect("thinned seed");
    std::fs::copy(corpus.join("copy.cpp"), thinned.join("copy.cpp")).expect("copied duplicate");

    let report = scan_with_signature(
        &thinned,
        "structural",
        &scratch.path().join("fewer-sharers.db"),
        true,
    );
    let units = funnel_stage(&report, "units");
    assert_eq!(units, 5);
    assert!(units <= sharing_limit());

    let (_, _, sibling_groups) = detected::from_report_json_with_siblings(&report)
        .expect("structural report has the current sibling contract");
    let signature_siblings: Vec<_> = sibling_groups
        .iter()
        .flat_map(|group| &group.siblings)
        .filter(|sibling| sibling.basis == SiblingBasis::Signature)
        .collect();
    // Every ungrouped unit left in the tree holds the signature, and each of
    // them is offered as evidence about the group that holds it too.
    assert_eq!(signature_siblings.len(), 3);
    assert_eq!(funnel_stage(&report, "signature sibling entries"), 3);
    assert!(
        signature_siblings
            .iter()
            .all(|sibling| sibling.confidence_band == "low")
    );
}

#[test]
fn cpp_mirror_does_not_change_primary_sets_or_stability() {
    let root = repo_root();
    let committed = root.join("corpus/synthetic/cpp");
    let scratch = tempfile::tempdir().expect("temp dir");
    let fixtureless = scratch.path().join("cpp-without-mirror");
    std::fs::create_dir(&fixtureless).expect("fixtureless corpus directory");
    for file in ["seed.cpp", "type1.cpp", "type2.cpp", "type3.cpp"] {
        std::fs::copy(committed.join(file), fixtureless.join(file))
            .unwrap_or_else(|error| panic!("copying {file}: {error}"));
    }

    for (mode, expected_count) in [("fast", 7), ("structural", 4)] {
        let committed_report = scan(
            &committed,
            mode,
            &scratch.path().join(format!("committed-{mode}.db")),
        );
        let fixtureless_report = scan(
            &fixtureless,
            mode,
            &scratch.path().join(format!("fixtureless-{mode}.db")),
        );
        let (committed_result, _) =
            detected::from_report_json(&committed_report).expect("committed report reads");
        let (fixtureless_result, _) =
            detected::from_report_json(&fixtureless_report).expect("fixtureless report reads");

        assert_eq!(
            committed_result.findings.len(),
            expected_count,
            "{mode} count"
        );
        assert_eq!(
            fixtureless_result.findings.len(),
            expected_count,
            "{mode} fixtureless count"
        );
        assert_eq!(
            primary_keys(&committed_result),
            primary_keys(&fixtureless_result),
            "{mode} primary finding set"
        );
        let run_stability = stability(&committed_result, &fixtureless_result);
        assert!(run_stability.identical, "{mode} primary stability");
        assert!(
            (run_stability.jaccard - 1.0).abs() < f64::EPSILON,
            "{mode} primary jaccard"
        );
    }
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
        "\nmode       corpus                recall  precision  findings/kLOC  FP/kLOC  non-clone hits\n",
    );
    let mut by_type =
        String::from("\nmode       corpus                  type-1   type-2   type-3\n");
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
                "{:<10} {:<20} {:>6} {:>10} {:>14} {:>8} {:>15}",
                measurement.mode,
                expected.name,
                show_metric(metrics.recall_overall),
                show_metric(metrics.precision_overall),
                show_metric(metrics.findings_per_kloc),
                show_metric(metrics.false_positives_per_kloc),
                metrics.non_clone_hits,
            )
            .expect("writing to a string cannot fail");
            write!(by_type, "{:<10} {:<20}", measurement.mode, expected.name)
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
