//! Precision of Fast and Structural modes over hand-labelled real code.
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
//! Ranking a finding down is not, in general, a precision device: a verdict
//! says whether duplication is real and worth reporting, while ranking says
//! what to read first. The column records where the fold falls, not whether it
//! is right. Measuring the latter would need a distinct verdict about action
//! priority.
//!
//! Aggregate pins use only cases whose `snapshot.toml` records a reproducible
//! origin. A local-only case remains visible and pinned on the machine that
//! can materialize it, but cannot make a portable precision number depend on
//! one developer's directory layout.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_core::frontend::{Frontend, Token};
use codehelion_core::substitution::{self, Witness};
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{
    Adjudication, AxisSplit, BandSplit, DEFAULT_MATCH_THRESHOLD, RankedVerdicts, ReasonSplit,
    SizeSplit, Verdict, WidthFamily, adjudicate, verdict,
};
use codehelion_eval::schema::{DetectionResult, Finding, Fragment};

/// The verdict split one analysis mode currently produces.
#[derive(Clone, Copy)]
struct Verdicts {
    /// Groups ruled a clone worth reporting.
    confirmed: usize,
    /// Groups ruled a lookalike that must not be reported.
    refuted: usize,
    /// Of the confirmed groups, the ones the report puts forward.
    forward_confirmed: usize,
    /// Of the refuted groups, the ones the report puts forward.
    forward_refuted: usize,
    /// Findings which need a human verdict before precision can be claimed.
    unjudged: usize,
    /// Findings matched by inconsistent labels.
    conflicting: usize,
}

/// One labelled corpus and the verdict split it currently produces.
struct Expected {
    /// Directory under `corpus/labeled`.
    name: &'static str,
    /// Whether `snapshot.toml` supplies a reproducible source origin. Local
    /// cases remain useful as individual observations but do not define the
    /// aggregate precision pins.
    has_origin: bool,
    /// Groups ruled a clone worth reporting.
    confirmed: usize,
    /// Groups ruled a lookalike that must not be reported.
    refuted: usize,
    /// Of the confirmed groups, the ones the report puts forward.
    forward_confirmed: usize,
    /// Of the refuted groups, the ones the report puts forward.
    forward_refuted: usize,
    /// Fast-mode measurements. The structural fields above predate Fast-mode
    /// coverage and remain the Structural pins used by the detailed analysis.
    fast: Verdicts,
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
        has_origin: false,
        confirmed: 16,
        refuted: 2,
        forward_confirmed: 15,
        forward_refuted: 2,
        fast: Verdicts {
            confirmed: 11,
            refuted: 1,
            forward_confirmed: 11,
            forward_refuted: 1,
            unjudged: 138,
            conflicting: 0,
        },
    },
    Expected {
        name: "fast-yaml",
        has_origin: true,
        confirmed: 1,
        refuted: 0,
        forward_confirmed: 1,
        forward_refuted: 0,
        fast: Verdicts {
            confirmed: 1,
            refuted: 0,
            forward_confirmed: 1,
            forward_refuted: 0,
            unjudged: 19,
            conflicting: 0,
        },
    },
    Expected {
        name: "codehelion-store",
        has_origin: true,
        confirmed: 2,
        refuted: 0,
        forward_confirmed: 2,
        forward_refuted: 0,
        fast: Verdicts {
            confirmed: 0,
            refuted: 0,
            forward_confirmed: 0,
            forward_refuted: 0,
            unjudged: 17,
            conflicting: 0,
        },
    },
    Expected {
        name: "cjson",
        has_origin: true,
        confirmed: 13,
        refuted: 6,
        forward_confirmed: 13,
        forward_refuted: 6,
        fast: Verdicts {
            confirmed: 12,
            refuted: 6,
            forward_confirmed: 12,
            forward_refuted: 6,
            unjudged: 82,
            conflicting: 0,
        },
    },
    Expected {
        name: "lz4",
        has_origin: true,
        confirmed: 15,
        refuted: 14,
        forward_confirmed: 15,
        forward_refuted: 14,
        fast: Verdicts {
            confirmed: 12,
            refuted: 9,
            forward_confirmed: 12,
            forward_refuted: 9,
            unjudged: 219,
            conflicting: 0,
        },
    },
    Expected {
        name: "serde-json",
        has_origin: true,
        confirmed: 46,
        refuted: 39,
        forward_confirmed: 41,
        forward_refuted: 20,
        fast: Verdicts {
            confirmed: 30,
            refuted: 27,
            forward_confirmed: 30,
            forward_refuted: 27,
            unjudged: 552,
            conflicting: 1,
        },
    },
    Expected {
        name: "spdlog",
        has_origin: true,
        confirmed: 21,
        // One refuted finding fewer than the two this corpus used to produce
        // over `registry-inl.h`: the two sinks it was matched against differ
        // only in identifiers, so the report stated one relation twice. The
        // surviving finding still covers both labelled fragments and is still
        // refuted, so what left the count is the repetition, not the verdict.
        refuted: 17,
        forward_confirmed: 21,
        forward_refuted: 16,
        fast: Verdicts {
            confirmed: 23,
            refuted: 1,
            forward_confirmed: 23,
            forward_refuted: 1,
            unjudged: 160,
            conflicting: 0,
        },
    },
    Expected {
        name: "bitflags",
        has_origin: true,
        confirmed: 11,
        refuted: 3,
        forward_confirmed: 3,
        forward_refuted: 1,
        fast: Verdicts {
            confirmed: 3,
            refuted: 2,
            forward_confirmed: 3,
            forward_refuted: 2,
            unjudged: 227,
            conflicting: 0,
        },
    },
    Expected {
        name: "tinyxml2",
        has_origin: true,
        confirmed: 10,
        refuted: 11,
        forward_confirmed: 9,
        forward_refuted: 11,
        fast: Verdicts {
            confirmed: 3,
            refuted: 8,
            forward_confirmed: 3,
            forward_refuted: 8,
            unjudged: 48,
            conflicting: 0,
        },
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
        map: 0.9231,
    },
    Ordering {
        name: "size",
        at_10: 1.0,
        at_50: 0.94,
        map: 0.8725,
    },
];

/// The verdicts under each confidence band, as last measured.
///
/// Pinned for what a move would mean rather than for the values being right:
/// which band a finding lands in is a boundary the detector draws, and moving
/// one silently redistributes every finding here. What the numbers say about
/// the bands themselves is argued from the table, not from this assertion.
const BANDS: &[(&str, usize, usize)] = &[
    ("high", 43, 22),
    ("medium", 44, 41),
    ("low", 14, 22),
    ("(unscored)", 18, 5),
];

/// The lookalike classes reached by the report, as last measured.
///
/// Each tuple records labels put forward, labels reached anywhere in the
/// report, and labels in the reproducible corpus.  Pinning the table makes a
/// change in the kinds of false positives a regression, rather than merely
/// diagnostic output for a reviewer to notice.
const REASONS: &[(&str, usize, usize, usize)] = &[
    ("assertion-run", 0, 10, 32),
    ("const-overload-pair", 0, 0, 1),
    ("declaration-run", 5, 5, 5),
    ("dispatch-table-entry", 1, 1, 1),
    ("exhaustive-match-table", 1, 1, 3),
    ("field-mapping-boilerplate", 0, 0, 1),
    ("forwarding-wrapper", 10, 13, 24),
    ("getter-boilerplate", 4, 4, 5),
    ("guarded-forwarding", 3, 3, 5),
    ("lifecycle-teardown", 2, 2, 6),
    ("list-walk-idiom", 1, 1, 1),
    ("member-call-run", 1, 1, 2),
    ("mirrored-operation", 4, 4, 4),
    ("nested-inside-copy", 0, 0, 6),
    ("parameterised-dispatch", 2, 2, 2),
    ("single-expression-return", 0, 0, 1),
    ("trivial-accessor-pair", 1, 1, 1),
    ("trivial-factory", 10, 10, 10),
    ("type-dispatch-accessor", 6, 25, 27),
    ("type-specialised-variant", 16, 18, 35),
    ("unrolled-repetition", 0, 0, 4),
    ("validated-setter", 1, 1, 1),
];

/// The length spans of the two verdict populations, as last measured: the
/// shortest and longest confirmed finding, the same for refuted, and how many
/// confirmed findings a length floor clearing every refuted one would take.
///
/// The last number is the one with an argument attached — it is the price of a
/// length floor, and it is why there is not one — so it is pinned rather than
/// printed and re-argued from memory.
const SIZES: (u32, u32, u32, u32, usize) = (4, 47, 3, 26, 99);

/// What a floor on each similarity axis could remove without hiding a real
/// clone, as last measured.
///
/// A similarity floor is the second thing anyone reaches for when precision is
/// short, and the answer has had to be worked out by hand from a report three
/// times: for length, for the confidence band, and for these. Zero means the
/// lowest confirmed finding on that axis sits at or below every refuted one, so
/// no floor can cut a lookalike without cutting a real clone first.
///
/// All five are zero: no similarity dimension separates the two populations
/// without removing a confirmed finding. The pin records that result instead
/// of turning a sample-specific gap into a detector rule.
///
/// A move here is a change to explain. A rise means the populations are pulling
/// apart on that axis and somebody should re-run leave-one-case-out; a fall
/// means a real clone has appeared below where they were.
const FLOORS: &[(&str, usize)] = &[
    ("lexical", 0),
    ("structural", 0),
    ("control flow", 0),
    ("api", 0),
    ("composite", 0),
];

/// Whether two measurements differ once rounded the way they are printed,
/// which is the width anybody copying a new value back into this file reads.
fn moved(actual: f64, pinned: f64) -> bool {
    format!("{actual:.4}") != format!("{pinned:.4}")
}

/// Render a rate without turning an absent denominator into a failed result.
fn show_measure(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |measure| format!("{measure:.4}"))
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
            "{name:<22} {:>8} {:>8} {:>8.4}",
            show_measure(verdicts.precision_at(10)),
            show_measure(verdicts.precision_at(50)),
            verdicts.mean_average_precision(),
        );
    }
    if pinned {
        for (name, verdicts) in measured {
            let Some(expected) = ORDERINGS.iter().find(|expected| expected.name == name) else {
                writeln!(
                    complaints,
                    "ordering {name} is not one of the recorded orderings"
                )
                .expect("writing to a string cannot fail");
                continue;
            };
            for (what, actual, was) in [
                ("precision@10", verdicts.precision_at(10), expected.at_10),
                ("precision@50", verdicts.precision_at(50), expected.at_50),
                (
                    "mean average precision",
                    Some(verdicts.mean_average_precision()),
                    expected.map,
                ),
            ] {
                if actual.is_some_and(|actual| moved(actual, was)) {
                    writeln!(
                        complaints,
                        "{what} ordered by {} is {}, recorded as {was:.4}",
                        expected.name,
                        show_measure(actual),
                    )
                    .expect("writing to a string cannot fail");
                } else if actual.is_none() {
                    writeln!(
                        complaints,
                        "{what} ordered by {} was unmeasured",
                        expected.name,
                    )
                    .expect("writing to a string cannot fail");
                }
            }
        }
        for expected in ORDERINGS {
            if !measured.iter().any(|(name, _)| *name == expected.name) {
                writeln!(
                    complaints,
                    "recorded ordering {} was unmeasured",
                    expected.name
                )
                .expect("writing to a string cannot fail");
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

/// Whether at least one labelled snapshot was available for measurement.
const fn has_materialized_snapshot(unmaterialized: usize, total: usize) -> bool {
    unmaterialized < total
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

/// The recorded verdicts for one corpus and mode.
fn recorded_verdicts(expected: &Expected, mode: &str) -> Verdicts {
    if mode == "fast" {
        expected.fast
    } else {
        Verdicts {
            confirmed: expected.confirmed,
            refuted: expected.refuted,
            forward_confirmed: expected.forward_confirmed,
            forward_refuted: expected.forward_refuted,
            unjudged: 0,
            conflicting: 0,
        }
    }
}

/// Print every measure that accumulates over the whole corpus.
///
/// Ordered as the questions arrive: what could be filtered out, then what the
/// filters that exist reached, then what is left and what it is.
fn print_measures(
    sizes: &SizeSplit,
    axes: &AxisSplit,
    widths: &str,
    every_width: &WidthFamily,
    bands: &BandSplit,
    reasons: &ReasonSplit,
) {
    // Length is the first knob anyone reaches for when precision is short, and
    // these two ranges are what says whether it can help.
    println!("{sizes}\n");
    // Similarity is the second, and it is the more tempting of the two because
    // the numbers are already there.
    println!("{axes}\n");
    print!("{widths}");
    println!("{every_width}\n");
    print!("{bands}");
    // Precision says how much was wrong; this says what it was wrong about,
    // which is the question the next rule has to answer.
    println!("\n{reasons}");
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
const WIDTH_FAMILY: &[(&str, usize, usize)] = &[("lz4", 4, 57), ("serde-json", 7, 5)];

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

/// The tokens of one fragment, lexed the way the scan lexed them, or `None`
/// when the lines do not yield the tokens the scan counted.
///
/// A bare `.h` is read as C++, which lexes C too. A scan settles the question
/// from the rest of the tree; here the answer only has to produce the same
/// lexemes, and for these files either grammar does.
///
/// The line range is not where the detector drew the edges — it works in token
/// spans and reports the lines those happen to cover — so taking whole lines
/// can pick up a token either side. The count the report states is what says
/// so, and a fragment whose count disagrees is one this cannot speak about.
/// Without the check the disagreement is invisible and every number read off
/// these tokens is quietly about a different span.
fn tokens_of(snapshot: &Path, fragment: &Fragment) -> Option<Vec<Token>> {
    let path = snapshot.join(&fragment.file);
    let source = std::fs::read_to_string(&path).ok()?;
    let lexed = match path.extension().and_then(std::ffi::OsStr::to_str)? {
        "rs" => codehelion_frontend_rust::RustFrontend.lex(&source),
        "c" => codehelion_frontend_c::CFrontend.lex(&source),
        _ => codehelion_frontend_cpp::CppFrontend.lex(&source),
    };
    let tokens: Vec<Token> = lexed
        .tokens
        .into_iter()
        .filter(|token| (fragment.start_line..=fragment.end_line).contains(&token.span.start_line))
        .collect();
    (tokens.len() as u64 == fragment.tokens).then_some(tokens)
}

/// One line of the corpus table: the two precisions and the counts they are
/// made of. Shared by the per-corpus rows and the row that adds them up, so the
/// total is computed the way every other row is.
fn row(name: &str, ruled: &Adjudication, table: &mut String) {
    writeln!(
        table,
        "{name:<16} {:>9} {:>12} {:>10} {:>8} {:>9} {:>10}",
        show_measure(ruled.precision()),
        show_measure(ruled.actionable_precision()),
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

/// Complain when a recorded lookalike class changes or a new class appears.
fn compare_reasons(reasons: &ReasonSplit, complaints: &mut String) {
    for &(name, forward, shown, labelled) in REASONS {
        let measured = reasons.reasons.get(name).copied().unwrap_or((0, 0, 0));
        if measured != (forward, shown, labelled) {
            writeln!(
                complaints,
                "lookalike class {name} has {measured:?}, recorded as ({forward}, {shown}, {labelled})",
            )
            .expect("writing to a string cannot fail");
        }
    }
    for name in reasons.reasons.keys() {
        if !REASONS.iter().any(|&(recorded, ..)| recorded == name) {
            writeln!(
                complaints,
                "lookalike class {name} is not one of the recorded classes"
            )
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

#[path = "labeled_precision/corpus_policy.rs"]
mod corpus_policy;
#[path = "labeled_precision/verdict_regression.rs"]
mod verdict_regression;
