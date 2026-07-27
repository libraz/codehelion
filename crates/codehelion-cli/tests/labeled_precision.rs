//! Precision of Structural mode over hand-labelled real code.
//!
//! The synthetic corpora answer "how much of what is there does it find". They
//! cannot answer "how much of what it reports is real", because a generated
//! corpus labels the clones it was built around and nothing else, so every
//! unlabelled true copy counts against precision. `corpus_accuracy.rs` records
//! its precision so a move is seen, and claims nothing about the value.
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
//!
//! # What the "put forward" column has said so far
//!
//! Ranking a finding down is not, in general, a precision device. On seven of
//! these projects the column moves by a point or two against the overall
//! figure or not at all — down on two, up on one, unchanged on four — which is
//! what it should do if the findings the report files below the rest are about
//! as likely to be real as the ones above. That agrees with the reason they
//! are filed there: a pair says less per finding than a group does, and a test
//! suite repeats itself on purpose, neither of which is a claim that the
//! finding is wrong.
//!
//! The eighth is eleven points higher put forward than overall, and it is the
//! only case whose test suite is in scope at all. What the column measures
//! there is the four groups in the library against the twenty-one in the
//! suite, so the gap is the difference between the two bodies of code rather
//! than anything the ranking knows. Which is the point of having the column:
//! where it moves, it says what moved it.
//!
//! Added up, ranking down files nineteen confirmed findings below the rest
//! against nine refuted ones, and the put-forward figure comes out a point
//! under the overall one. Read as a precision device that is a loss. It is not
//! read that way here, because these verdicts cannot settle it either way: a
//! verdict says the duplication is real and worth reporting, and ranking down
//! does not dispute either — it says to read something else first. Two of every
//! three findings it sets aside are real, which is what filing rather than
//! hiding is for. Measuring whether the order is the right one needs a verdict
//! nobody has written: not whether a finding is worth reporting, but whether it
//! is the one to do something about. Until that exists, this column says where
//! the fold falls and not whether it falls in the right place.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_core::frontend::{Frontend, Token};
use codehelion_core::substitution::{self, Witness};
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{
    Adjudication, AxisSplit, BandSplit, DEFAULT_MATCH_THRESHOLD, RankedVerdicts, SizeSplit,
    WidthFamily, adjudicate,
};
use codehelion_eval::schema::{DetectionResult, Finding, Fragment};

/// One labelled corpus and the verdict split it currently produces.
struct Expected {
    /// Directory under `corpus/labeled`.
    name: &'static str,
    /// Groups ruled a clone worth reporting.
    confirmed: usize,
    /// Groups ruled a lookalike that must not be reported.
    refuted: usize,
    /// Of the confirmed groups, the ones the report puts forward.
    forward_confirmed: usize,
    /// Of the refuted groups, the ones the report puts forward.
    forward_refuted: usize,
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
        forward_confirmed: 19,
        forward_refuted: 2,
    },
    Expected {
        name: "fast-yaml",
        confirmed: 1,
        refuted: 0,
        forward_confirmed: 1,
        forward_refuted: 0,
    },
    Expected {
        name: "codehelion-store",
        confirmed: 2,
        refuted: 0,
        forward_confirmed: 2,
        forward_refuted: 0,
    },
    Expected {
        name: "cjson",
        confirmed: 14,
        refuted: 6,
        forward_confirmed: 14,
        forward_refuted: 6,
    },
    Expected {
        name: "lz4",
        confirmed: 17,
        refuted: 17,
        forward_confirmed: 17,
        forward_refuted: 16,
    },
    Expected {
        name: "serde-json",
        confirmed: 44,
        refuted: 22,
        forward_confirmed: 39,
        forward_refuted: 22,
    },
    Expected {
        name: "spdlog",
        confirmed: 21,
        refuted: 18,
        forward_confirmed: 21,
        forward_refuted: 18,
    },
    Expected {
        name: "bitflags",
        confirmed: 16,
        refuted: 9,
        forward_confirmed: 3,
        forward_refuted: 1,
    },
];

/// What one ordering of the verdicts currently measures.
struct Ordering {
    /// How the findings were sorted.
    name: &'static str,
    /// Share of the top ten that a label confirmed.
    at_10: f64,
    /// Share of the top fifty that a label confirmed.
    at_50: f64,
    /// Mean average precision over the whole ordering.
    map: f64,
}

/// The two orderings, as last measured over the whole labelled corpus.
///
/// Recorded, not bounded. A floor with margin under it answers "is this still
/// acceptable", which nobody can settle in advance; these answer "is this
/// still what it was", which is a fact. Any move fails, and the failure states
/// the measurement to write here instead — so the number changes when somebody
/// decides it should, and the decision is in the diff beside the change that
/// caused it.
///
/// Both orderings are pinned, including the size sort that exists as a
/// baseline: it moves only when the population does, so a move in the baseline
/// alone says the corpus changed rather than the ranking.
const ORDERINGS: &[Ordering] = &[
    Ordering {
        name: "priority",
        at_10: 1.0,
        at_50: 0.96,
        map: 0.9333,
    },
    Ordering {
        name: "size",
        at_10: 0.9,
        at_50: 0.94,
        map: 0.8556,
    },
];

/// The verdicts under each confidence band, as last measured.
///
/// Pinned for what a move would mean rather than for the values being right:
/// which band a finding lands in is a boundary the detector draws, and moving
/// one silently redistributes every finding here. What the numbers say about
/// the bands themselves is argued from the table, not from this assertion.
const BANDS: &[(&str, usize, usize)] = &[
    ("high", 64, 60),
    ("medium", 15, 3),
    ("low", 14, 5),
    ("(unscored)", 42, 6),
];

/// The length spans of the two verdict populations, as last measured: the
/// shortest and longest confirmed finding, the same for refuted, and how many
/// confirmed findings a length floor clearing every refuted one would take.
///
/// The last number is the one with an argument attached — it is the price of a
/// length floor, and it is why there is not one — so it is pinned rather than
/// printed and re-argued from memory.
const SIZES: (u32, u32, u32, u32, usize) = (4, 96, 3, 23, 97);

/// What a floor on each similarity axis could remove without hiding a real
/// clone, as last measured.
///
/// A similarity floor is the second thing anyone reaches for when precision is
/// short, and the answer has had to be worked out by hand from a report three
/// times: for length, for the confidence band, and for these. Zero means the
/// lowest confirmed finding on that axis sits at or below every refuted one, so
/// no floor can cut a lookalike without cutting a real clone first.
///
/// Four of the five are zero. The composite is not, and it is the reason to
/// record these rather than assert a rule about them: nine refuted findings sit
/// below the lowest confirmed one, in a band three hundredths wide. That is a
/// gap in this sample, not a separation — held out of the training set,
/// serde-json contributes both the finding that sets the floor and two more the
/// floor learned without it would hide, which is the same shape the length
/// floor turned out to have. Leave-one-case-out is what says so, and it is not
/// something a pin can run.
///
/// A move here is a change to explain. A rise means the populations are pulling
/// apart on that axis and somebody should re-run leave-one-case-out; a fall
/// means a real clone has appeared below where they were.
const FLOORS: &[(&str, usize)] = &[
    ("lexical", 0),
    ("structural", 0),
    ("control flow", 0),
    ("api", 0),
    ("composite", 9),
];

/// Whether two measurements differ once rounded the way they are printed,
/// which is the width anybody copying a new value back into this file reads.
fn moved(actual: f64, pinned: f64) -> bool {
    format!("{actual:.4}") != format!("{pinned:.4}")
}

/// Compare the ranking the tool prints against sorting by size, and complain
/// when either has moved or when the composition stops earning its place.
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
fn report_ranking(
    ranked: &RankedVerdicts,
    by_size: &RankedVerdicts,
    pinned: bool,
    complaints: &mut String,
) {
    println!("\nranking over {} judged findings", ranked.len());
    println!(
        "{:<22} {:>8} {:>8} {:>8}",
        "ordered by", "p@10", "p@50", "MAP"
    );
    let measured = [("priority", ranked), ("size", by_size)];
    for (name, verdicts) in measured {
        println!(
            "{name:<22} {:>8.4} {:>8.4} {:>8.4}",
            verdicts.precision_at(10),
            verdicts.precision_at(50),
            verdicts.mean_average_precision(),
        );
    }
    if pinned {
        for (expected, (_, verdicts)) in ORDERINGS.iter().zip(measured) {
            for (what, actual, was) in [
                ("precision@10", verdicts.precision_at(10), expected.at_10),
                ("precision@50", verdicts.precision_at(50), expected.at_50),
                (
                    "mean average precision",
                    verdicts.mean_average_precision(),
                    expected.map,
                ),
            ] {
                if moved(actual, was) {
                    writeln!(
                        complaints,
                        "{what} ordered by {} is {actual:.4}, recorded as {was:.4}",
                        expected.name,
                    )
                    .expect("writing to a string cannot fail");
                }
            }
        }
    }
    let map = ranked.mean_average_precision();
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
    // "put forward" is precision over the findings the report asks to be read
    // first, which is the number a reader's first impression is made of. It
    // sits beside the overall figure rather than replacing it: the difference
    // between the two is what ranking a finding down is worth.
    let mut table = String::from(
        "\ncorpus            precision  put forward  confirmed  refuted  unjudged  conflicts\n",
    );
    let mut complaints = String::new();
    let mut unmaterialized = 0usize;
    // The same verdicts added up across every case that was scored. Nothing
    // here is pinned — each corpus's split already is, and this is their sum —
    // but no per-corpus row asks the question it answers, which is what ranking
    // a finding down does to the population it is applied to.
    let mut every = Adjudication {
        confirmed: 0,
        refuted: 0,
        conflicting: 0,
        unjudged: 0,
        actionable_confirmed: 0,
        actionable_refuted: 0,
    };
    let mut sizes = SizeSplit::default();
    let mut axes = AxisSplit::default();
    // Which corpora the "written once per width" rule reaches, and in total.
    let mut widths = String::from("\nwritten once per width\n");
    let mut every_width = WidthFamily::default();
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
            unscored_row(expected.name, &mut table);
            unmaterialized += 1;
            continue;
        }

        let database = scratch.path().join(format!("{}.db", expected.name));
        let report = scan(&snapshot, &database);
        let (result, _lines) = detected::from_report_json(&report)
            .unwrap_or_else(|error| panic!("reading the report for {}: {error}", expected.name));

        let ruled = adjudicate(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        sizes.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        axes.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        width_family(
            expected.name,
            &snapshot,
            &result,
            &labels,
            &mut every_width,
            &mut widths,
            &mut complaints,
        );
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
        row(expected.name, &ruled, &mut table);
        absorb(&mut every, &ruled);
        compare_verdicts(expected, &ruled, &mut complaints);
    }
    if every.judged() > 0 {
        row("every case", &every, &mut table);
    }

    // Every measure below this line accumulates across the whole corpus, so a
    // partial set produces a number that is not the recorded one and is not a
    // regression either. Print it, compare nothing.
    let whole = unmaterialized == 0;
    if !ranked.is_empty() {
        report_ranking(&ranked, &by_size, whole, &mut complaints);
    }
    println!("{table}");
    if every.judged() > 0 {
        println!(
            "ranking down filed {} confirmed and {} refuted below the rest\n",
            every.confirmed - every.actionable_confirmed,
            every.refuted - every.actionable_refuted,
        );
    }
    // Length is the first knob anyone reaches for when precision is short, and
    // these two ranges are what says whether it can help.
    println!("{sizes}\n");
    // Similarity is the second, and it is the more tempting of the two because
    // the numbers are already there.
    println!("{axes}\n");
    print!("{widths}");
    println!("{every_width}\n");
    print!("{bands}");
    if whole {
        compare_bands(&bands, &mut complaints);
        compare_sizes(&sizes, &mut complaints);
        compare_floors(&axes, &mut complaints);
    } else {
        println!(
            "\n{unmaterialized} of {} labelled corpora have no snapshot and were not scored, \
             so the measures over the whole corpus were printed and not compared.\n\
             Run corpus/scripts/materialize-labeled.sh to cut them from their pinned commits.",
            CORPORA.len(),
        );
    }
    assert!(complaints.is_empty(), "\n{complaints}");
}

/// What the "written once per width" rule reaches in each corpus, as last
/// measured: the refuted findings, and the largest gap in unpaired tokens any
/// of them spans. A corpus it reaches nothing in is absent.
///
/// The rule is a candidate, not something the detector acts on, and this is
/// what stands between it and being one. Two facts have to hold before a rule
/// that sets duplication aside is worth having, and neither is a precision
/// figure: it must reach no finding somebody confirmed, and it must reach
/// findings in a project whose examples it was not read from. The first is
/// asserted for every corpus on every run, over every judged finding. The
/// second is why this is a list rather than a total — the rule was read from
/// these two, in two languages by two authors, and each reaches findings the
/// other did not supply.
///
/// The second number is there in place of a bound. A routine written for the
/// wider type does work the narrower one does not, so the rule does not ask the
/// two occurrences to be the same size; what it would take to ask that is a
/// threshold, and no threshold over this corpus has ever separated the two
/// populations. This says how far apart the rule has actually been seen to
/// reach, so reaching further is a change somebody reads.
const WIDTH_FAMILY: &[(&str, usize, usize)] = &[("lz4", 5, 57), ("serde-json", 7, 5)];

/// The row for a corpus whose sources are not on this machine. Dashes, not
/// zeroes: nothing was measured, which is not the same as measuring nothing.
fn unscored_row(name: &str, table: &mut String) {
    writeln!(
        table,
        "{name:<16} {:>9} {:>12} {:>10} {:>8} {:>9} {:>10}",
        "-", "-", "-", "-", "-", "-"
    )
    .expect("writing to a string cannot fail");
}

/// Score one corpus against the width-family rule: add it to the total, put it
/// in the printed list if it reached anything, and complain if it should not
/// have.
///
/// Kept per corpus and not only in total. A rule read off the substitutions is
/// a rule read off the projects it was written from, and the only thing that
/// says otherwise is it reaching findings in a project that supplied none of
/// the examples.
fn width_family(
    name: &'static str,
    snapshot: &Path,
    result: &DetectionResult,
    labels: &LabelSet,
    every: &mut WidthFamily,
    listing: &mut String,
    complaints: &mut String,
) {
    let mut reached = WidthFamily::default();
    reached.record(result, labels, DEFAULT_MATCH_THRESHOLD, |finding| {
        witness_for(snapshot, finding)
    });
    if reached.refuted > 0 || reached.confirmed > 0 {
        writeln!(
            listing,
            "{name:<16} {:>3} refuted, {:>3} confirmed, widest gap {:>3}",
            reached.refuted, reached.confirmed, reached.most_edits,
        )
        .expect("writing to a string cannot fail");
    }
    compare_width_family(name, &reached, complaints);
    every.refuted += reached.refuted;
    every.confirmed += reached.confirmed;
    every.untouched += reached.untouched;
    every.unalignable += reached.unalignable;
    every.most_edits = every.most_edits.max(reached.most_edits);
}

/// Complain when the rule reaches a real clone, or reaches a different number
/// of lookalikes than it did, or reaches further apart than it has.
fn compare_width_family(name: &str, reached: &WidthFamily, complaints: &mut String) {
    // A confirmed finding inside the rule is not a number to write down. It is
    // the rule being wrong about a clone somebody read and kept.
    if reached.confirmed > 0 {
        writeln!(
            complaints,
            "{name}: the width-family rule reaches {} finding(s) a label confirmed",
            reached.confirmed,
        )
        .expect("writing to a string cannot fail");
    }
    let (recorded, gap) = WIDTH_FAMILY
        .iter()
        .find(|&&(corpus, _, _)| corpus == name)
        .map_or((0, 0), |&(_, count, gap)| (count, gap));
    if reached.refuted != recorded {
        writeln!(
            complaints,
            "{name}: the width-family rule reaches {} refuted finding(s), recorded as {recorded}",
            reached.refuted,
        )
        .expect("writing to a string cannot fail");
    }
    if reached.most_edits != gap {
        writeln!(
            complaints,
            "{name}: the widest gap the width-family rule spans is {} token(s), recorded as {gap}",
            reached.most_edits,
        )
        .expect("writing to a string cannot fail");
    }
}

/// The substitutions between a finding's first two occurrences, read from the
/// sources it was found in.
///
/// The report does not carry them — normalization erases the names before
/// anything writes a report — so measuring what a rule over them would reach
/// means going back to the code. A pair too large to align has no witness,
/// which is what the `None` says.
fn witness_for(snapshot: &Path, finding: &Finding) -> Option<Witness> {
    let [left, right, ..] = finding.fragments.as_slice() else {
        return None;
    };
    substitution::witness(&tokens_of(snapshot, left)?, &tokens_of(snapshot, right)?)
}

/// The tokens of one fragment, lexed the way the scan lexed them.
///
/// A bare `.h` is read as C++, which lexes C too. A scan settles the question
/// from the rest of the tree; here the answer only has to produce the same
/// lexemes, and for these files either grammar does.
fn tokens_of(snapshot: &Path, fragment: &Fragment) -> Option<Vec<Token>> {
    let path = snapshot.join(&fragment.file);
    let source = std::fs::read_to_string(&path).ok()?;
    let lexed = match path.extension().and_then(std::ffi::OsStr::to_str)? {
        "rs" => codehelion_frontend_rust::RustFrontend.lex(&source),
        "c" => codehelion_frontend_c::CFrontend.lex(&source),
        _ => codehelion_frontend_cpp::CppFrontend.lex(&source),
    };
    Some(
        lexed
            .tokens
            .into_iter()
            .filter(|token| {
                (fragment.start_line..=fragment.end_line).contains(&token.span.start_line)
            })
            .collect(),
    )
}

/// One line of the corpus table: the two precisions and the counts they are
/// made of. Shared by the per-corpus rows and the row that adds them up, so the
/// total is computed the way every other row is.
fn row(name: &str, ruled: &Adjudication, table: &mut String) {
    writeln!(
        table,
        "{name:<16} {:>9.4} {:>12.4} {:>10} {:>8} {:>9} {:>10}",
        ruled.precision(),
        ruled.actionable_precision(),
        ruled.confirmed,
        ruled.refuted,
        ruled.unjudged,
        ruled.conflicting,
    )
    .expect("writing to a string cannot fail");
}

/// Add one corpus's verdicts to the running total.
const fn absorb(every: &mut Adjudication, ruled: &Adjudication) {
    every.confirmed += ruled.confirmed;
    every.refuted += ruled.refuted;
    every.conflicting += ruled.conflicting;
    every.unjudged += ruled.unjudged;
    every.actionable_confirmed += ruled.actionable_confirmed;
    every.actionable_refuted += ruled.actionable_refuted;
}

/// Complain about anything one corpus's verdicts say that the recorded split
/// does not.
fn compare_verdicts(expected: &Expected, ruled: &Adjudication, complaints: &mut String) {
    if ruled.confirmed != expected.confirmed || ruled.refuted != expected.refuted {
        writeln!(
            complaints,
            "{}: {} confirmed and {} refuted, expected {} and {}",
            expected.name, ruled.confirmed, ruled.refuted, expected.confirmed, expected.refuted,
        )
        .expect("writing to a string cannot fail");
    }
    // The same split over the findings the report puts forward, which is what
    // makes the "put forward" column a measurement rather than a printed
    // number: the ranking cannot move a finding across the fold without one of
    // these two changing.
    if ruled.actionable_confirmed != expected.forward_confirmed
        || ruled.actionable_refuted != expected.forward_refuted
    {
        writeln!(
            complaints,
            "{}: {} confirmed and {} refuted put forward, expected {} and {}",
            expected.name,
            ruled.actionable_confirmed,
            ruled.actionable_refuted,
            expected.forward_confirmed,
            expected.forward_refuted,
        )
        .expect("writing to a string cannot fail");
    }
    // Every group in these corpora was ruled on when the labels were written.
    // One without a verdict is a group the detector has started reporting
    // since, and it needs reading rather than counting.
    if ruled.unjudged > 0 {
        writeln!(
            complaints,
            "{}: {} reported group(s) carry no verdict — read them and label them",
            expected.name, ruled.unjudged,
        )
        .expect("writing to a string cannot fail");
    }
    // Two labels claiming one finding is the corpus disagreeing with itself,
    // which no detector change can fix.
    if ruled.conflicting > 0 {
        writeln!(
            complaints,
            "{}: {} finding(s) are labelled both a clone and a non-clone",
            expected.name, ruled.conflicting,
        )
        .expect("writing to a string cannot fail");
    }
}

/// Complain about any band whose verdicts are not what was recorded.
fn compare_bands(bands: &BandSplit, complaints: &mut String) {
    for &(name, confirmed, refuted) in BANDS {
        let measured = bands.bands.get(name).copied().unwrap_or((0, 0));
        if measured != (confirmed, refuted) {
            writeln!(
                complaints,
                "band {name} holds {} confirmed and {} refuted, recorded as {confirmed} and \
                 {refuted}",
                measured.0, measured.1,
            )
            .expect("writing to a string cannot fail");
        }
    }
    // A band nobody recorded is a band the detector started using, which is a
    // boundary change rather than a number to add.
    for name in bands.bands.keys() {
        if !BANDS.iter().any(|&(recorded, _, _)| recorded == name) {
            writeln!(complaints, "band {name} is not one of the recorded bands")
                .expect("writing to a string cannot fail");
        }
    }
}

/// Complain when a similarity axis has started to sort the verdicts, or has
/// stopped being measured.
fn compare_floors(axes: &AxisSplit, complaints: &mut String) {
    for &(axis, recorded) in FLOORS {
        match axes.floor_that_costs_nothing(axis) {
            Some((_, removed)) if removed == recorded => {}
            Some((floor, removed)) => writeln!(
                complaints,
                "a floor of {floor:.2} on {axis} would now remove {removed} refuted \
                 finding(s) for free, recorded as {recorded}",
            )
            .expect("writing to a string cannot fail"),
            // An axis nothing carries any more is not an axis that separates
            // nothing; it is one nobody can ask about.
            None => writeln!(complaints, "no finding was scored on {axis}")
                .expect("writing to a string cannot fail"),
        }
    }
}

/// Complain when either verdict population has changed length.
fn compare_sizes(sizes: &SizeSplit, complaints: &mut String) {
    let span = |lines: &[u32]| (lines.first().copied(), lines.last().copied());
    let measured = (
        span(&sizes.confirmed),
        span(&sizes.refuted),
        sizes.confirmed_within_refuted_range(),
    );
    let (low_confirmed, high_confirmed, low_refuted, high_refuted, within) = SIZES;
    let recorded = (
        (Some(low_confirmed), Some(high_confirmed)),
        (Some(low_refuted), Some(high_refuted)),
        within,
    );
    if measured != recorded {
        writeln!(
            complaints,
            "the length spans are {measured:?}, recorded as {recorded:?}"
        )
        .expect("writing to a string cannot fail");
    }
}
