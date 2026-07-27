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
use codehelion_eval::metrics::{
    BandSplit, DEFAULT_MATCH_THRESHOLD, RankedVerdicts, SizeSplit, adjudicate,
};
use codehelion_eval::schema::Finding;

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
        refuted: 2,
    },
    Expected {
        name: "fast-yaml",
        confirmed: 1,
        refuted: 0,
    },
    Expected {
        name: "codehelion-store",
        confirmed: 2,
        refuted: 0,
    },
    Expected {
        name: "cjson",
        confirmed: 14,
        refuted: 6,
    },
    Expected {
        name: "lz4",
        confirmed: 17,
        refuted: 21,
    },
    Expected {
        name: "serde-json",
        confirmed: 44,
        refuted: 30,
    },
];

/// Cut-offs the ranking is pinned at, with the share of the top `k` that has
/// to be a confirmed clone.
///
/// Pinned rather than bounded loosely, and pinned below what the ranking
/// currently reaches, because these numbers move for two different reasons: a
/// ranking change, which is what they are here to catch, and a detector change
/// that alters which findings exist to be ranked, which is not. The margin is
/// what separates the two.
const PRECISION_AT: &[(usize, f64)] = &[(10, 1.0), (50, 0.86)];

/// Floor the composed ranking has to keep over the whole ordering.
///
/// This floor is a statement about a population, so adding a case to the
/// corpus moves it: the accumulated ordering now runs over a project whose
/// reported groups are a little over half real, which pulls the mean down
/// without anything about the ranking having changed. What the ranking has to
/// keep earning is the gap to a plain size sort, which is asserted separately
/// and is what would actually catch a ranking regression.
const MIN_MEAN_AVERAGE_PRECISION: f64 = 0.87;

/// Compare the ranking the tool prints against sorting by size, and complain
/// when it stops earning its place.
///
/// Size is the right baseline: it is what a reader would sort by if the tool
/// offered nothing, and it is already a strong signal — nothing the labels
/// refuted in these corpora is long. A ranking that cannot beat it is a
/// ranking that is only adding opinions.
///
/// What this does *not* measure: the labels say whether a finding is real
/// duplication, and nothing else. Maintenance risk and refactoring difficulty
/// are statements about a finding that is already real, so no verdict here
/// speaks about them, and a composition that weighs them cannot be validated
/// by this test — only kept from doing damage.
fn report_ranking(ranked: &RankedVerdicts, by_size: &RankedVerdicts, complaints: &mut String) {
    println!("\nranking over {} judged findings", ranked.len());
    println!(
        "{:<22} {:>8} {:>8} {:>8}",
        "ordered by", "p@10", "p@50", "MAP"
    );
    for (name, verdicts) in [("priority", ranked), ("size", by_size)] {
        println!(
            "{name:<22} {:>8.3} {:>8.3} {:>8.3}",
            verdicts.precision_at(10),
            verdicts.precision_at(50),
            verdicts.mean_average_precision(),
        );
    }

    for &(k, floor) in PRECISION_AT {
        let reached = ranked.precision_at(k);
        if reached < floor {
            writeln!(
                complaints,
                "precision@{k} fell to {reached:.4}, below the pinned {floor:.4}",
            )
            .expect("writing to a string cannot fail");
        }
    }
    let map = ranked.mean_average_precision();
    if map < MIN_MEAN_AVERAGE_PRECISION {
        writeln!(
            complaints,
            "mean average precision fell to {map:.4}, below the pinned \
             {MIN_MEAN_AVERAGE_PRECISION:.4}",
        )
        .expect("writing to a string cannot fail");
    }
    // The claim the separated measures exist to make good on. If sorting by
    // size does as well, the composition is decoration.
    let baseline = by_size.mean_average_precision();
    if map <= baseline {
        writeln!(
            complaints,
            "the composed ranking scores {map:.4} against {baseline:.4} for a plain \
             size sort, so it is no longer earning its place",
        )
        .expect("writing to a string cannot fail");
    }
}

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
    let mut sizes = SizeSplit::default();
    let mut bands = BandSplit::default();
    // Two orderings of the same verdicts: the one the tool prints, and the one
    // anybody would reach for without it.
    let mut ranked = RankedVerdicts::default();
    let mut by_size = RankedVerdicts::default();

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
        sizes.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        bands.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        ranked.record(&result, &labels, DEFAULT_MATCH_THRESHOLD, |finding| {
            finding.score
        });
        #[allow(clippy::cast_precision_loss)]
        by_size.record(
            &result,
            &labels,
            DEFAULT_MATCH_THRESHOLD,
            |finding: &Finding| finding.size_tokens as f64,
        );
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

    if !ranked.is_empty() {
        report_ranking(&ranked, &by_size, &mut complaints);
    }
    println!("{table}");
    // Printed, not asserted. Length is the first knob anyone reaches for when
    // precision is short, and these two ranges are what says whether it can
    // help: they answer the question in one command instead of by intuition.
    println!("{sizes}\n");
    // Printed for the same reason, and pinned to nothing. What a band is worth
    // against the verdicts is a property of the labelled projects, so an
    // assertion here would be a claim about them; what it is here to do is
    // keep the band's name from standing in for a number nobody measured.
    print!("{bands}");
    if unmaterialized > 0 {
        println!(
            "{unmaterialized} of {} labelled corpora have no snapshot and were not scored.\n\
             Run corpus/scripts/materialize-labeled.sh to cut them from their pinned commits.",
            CORPORA.len(),
        );
    }
    assert!(complaints.is_empty(), "\n{complaints}");
}
