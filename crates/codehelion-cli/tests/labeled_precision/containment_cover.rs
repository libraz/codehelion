//! What it takes for a longer finding to answer for a label it contains.
//!
//! The report keeps one finding per duplication: a duplicated function is also
//! a duplicated body and a duplicated run, and the longest cut is the one it
//! shows. The corpus labels the shorter cuts too, so a label can name a
//! duplication that no finding's bounds match and that the report nonetheless
//! puts in front of the reader.
//!
//! Scoring reads those labels off the longer finding. That is the more generous
//! direction, so what is asserted here is mostly what it must refuse: both
//! labelled regions inside one finding, each in a member of its own, and the
//! finding classifying at least as strictly as the label asks. Everything is
//! measured from a real scan of a labelled snapshot and the corpus's own
//! labels; the negative cases are labels written over regions the scan
//! reported, which is the only way to ask about a relation the corpus author
//! had no reason to record.

use super::*;

use codehelion_eval::labels::LabelPair;
use codehelion_eval::metrics::{confirms, matches_pair};
use codehelion_eval::schema::CloneType;

/// The corpus these cases are read from: the one whose labels record a nested
/// cut of a duplication as a pair of its own.
const CASE: &str = "serde-json";

/// One scan of [`CASE`], with the labels written against it.
///
/// `None` when the snapshot is not on this machine. The sources belong to the
/// project they were cut from and are not committed, so a machine without them
/// measures nothing here rather than passing on an empty result.
fn scanned(scratch: &Path) -> Option<(DetectionResult, LabelSet)> {
    let corpus = repo_root().join("corpus/labeled").join(CASE);
    let snapshot = corpus.join("snapshot");
    if !snapshot.is_dir() {
        println!("{CASE} has no materialized snapshot, so nothing was measured");
        return None;
    }
    let labels_path = corpus.join("labels.json");
    let labels_text = std::fs::read_to_string(&labels_path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
    let labels = LabelSet::from_json(&labels_text).expect("labels parse");
    let report = scan(&snapshot, "structural", &scratch.join("containment.db"));
    let (result, _lines) = detected::from_report_json(&report)
        .unwrap_or_else(|error| panic!("reading the report for {CASE}: {error}"));
    Some((result, labels))
}

/// The labelled pairs no finding's bounds match.
///
/// These are the labels the containment reading exists for, and asking the
/// corpus for them rather than naming them keeps the cases pointed at the
/// relation instead of at two line ranges.
fn unmatched_labels<'a>(result: &DetectionResult, labels: &'a LabelSet) -> Vec<&'a LabelPair> {
    labels
        .clone_pairs
        .iter()
        .filter(|pair| {
            !result
                .findings
                .iter()
                .any(|finding| matches_pair(finding, pair, DEFAULT_MATCH_THRESHOLD))
        })
        .collect()
}

/// Whether one of `finding`'s members holds the whole of `fragment`.
fn holds(finding: &Finding, fragment: &Fragment) -> bool {
    finding.fragments.iter().any(|member| {
        member.file == fragment.file
            && member.start_line <= fragment.start_line
            && fragment.end_line <= member.end_line
    })
}

/// The findings whose members hold the whole of `fragment`.
fn holders<'a>(result: &'a DetectionResult, fragment: &Fragment) -> Vec<&'a Finding> {
    result
        .findings
        .iter()
        .filter(|finding| holds(finding, fragment))
        .collect()
}

/// A label over `fragments` demanding `clone_type`.
fn label_over(id: &str, clone_type: CloneType, fragments: Vec<Fragment>) -> LabelPair {
    LabelPair {
        id: id.to_owned(),
        clone_type,
        rule_id: None,
        fragments,
    }
}

/// A copy of `fragment` with no token count, as a hand-written label carries it.
fn region(fragment: &Fragment) -> Fragment {
    Fragment {
        file: fragment.file.clone(),
        start_line: fragment.start_line,
        end_line: fragment.end_line,
        tokens: 0,
    }
}

#[test]
fn a_label_shown_inside_one_longer_finding_counts_as_confirmed() {
    let scratch = tempfile::tempdir().expect("temp dir");
    let Some((result, labels)) = scanned(scratch.path()) else {
        return;
    };
    let nested: Vec<&LabelPair> = unmatched_labels(&result, &labels)
        .into_iter()
        .filter(|pair| confirms(&result, pair, DEFAULT_MATCH_THRESHOLD))
        .collect();
    assert!(
        !nested.is_empty(),
        "no label in {CASE} is answered for from inside a longer finding, so this \
         corpus can no longer say what such a label is worth"
    );
    for pair in nested {
        // The point of the case: nothing carries these bounds, and the
        // duplication is shown all the same.
        assert!(
            !result.findings.iter().any(|finding| matches_pair(
                finding,
                pair,
                DEFAULT_MATCH_THRESHOLD
            )),
            "{} is matched by a finding's bounds, so it says nothing about containment",
            pair.id,
        );
        for fragment in &pair.fragments {
            assert!(
                !holders(&result, fragment).is_empty(),
                "{} has a region no finding holds",
                pair.id,
            );
        }
    }
}

#[test]
fn a_label_whose_regions_sit_in_two_findings_is_not_confirmed() {
    let scratch = tempfile::tempdir().expect("temp dir");
    let Some((result, labels)) = scanned(scratch.path()) else {
        return;
    };
    let nested: Vec<&LabelPair> = unmatched_labels(&result, &labels)
        .into_iter()
        .filter(|pair| confirms(&result, pair, DEFAULT_MATCH_THRESHOLD))
        .collect();
    let [pair, ..] = nested.as_slice() else {
        panic!("{CASE} no longer has a label answered for from inside a longer finding");
    };
    let held = &pair.fragments[0];
    // A region of some other finding: one the report holds, and one no single
    // finding holds together with the first. Every region is then one a finding
    // does hold and the only thing missing is a finding that holds both.
    let elsewhere = result
        .findings
        .iter()
        .flat_map(|finding| &finding.fragments)
        .find(|candidate| {
            !result
                .findings
                .iter()
                .any(|finding| holds(finding, held) && holds(finding, candidate))
        })
        .expect("the report holds regions no one finding shows together");
    let split = label_over(
        "split-across-two-findings",
        CloneType::Type3,
        vec![region(held), region(elsewhere)],
    );
    for fragment in &split.fragments {
        assert!(
            !holders(&result, fragment).is_empty(),
            "{}:{}-{} is held by no finding, so the case is not about the split",
            fragment.file,
            fragment.start_line,
            fragment.end_line,
        );
    }
    assert!(
        !confirms(&result, &split, DEFAULT_MATCH_THRESHOLD),
        "two findings, one region each, were read as one finding showing both",
    );
}

#[test]
fn a_label_only_a_weaker_clone_class_holds_is_not_confirmed() {
    let scratch = tempfile::tempdir().expect("temp dir");
    let Some((result, labels)) = scanned(scratch.path()) else {
        return;
    };
    let nested: Vec<&LabelPair> = unmatched_labels(&result, &labels)
        .into_iter()
        .filter(|pair| confirms(&result, pair, DEFAULT_MATCH_THRESHOLD))
        .collect();
    let [pair, ..] = nested.as_slice() else {
        panic!("{CASE} no longer has a label answered for from inside a longer finding");
    };
    // Every finding holding either region classifies more loosely than
    // verbatim, so a verbatim label is a demand none of them meets.
    for fragment in &pair.fragments {
        for finding in holders(&result, fragment) {
            assert_ne!(
                finding.clone_type,
                CloneType::Type1,
                "a verbatim finding holds {}, so demanding verbatim asks nothing extra",
                pair.id,
            );
        }
    }
    let verbatim = label_over(
        "same-regions-demanding-verbatim",
        CloneType::Type1,
        pair.fragments.iter().map(region).collect(),
    );
    assert!(
        !confirms(&result, &verbatim, DEFAULT_MATCH_THRESHOLD),
        "a finding matching only up to renaming was read as showing a verbatim label",
    );
}

#[test]
fn a_finding_that_merely_spans_a_labels_lines_does_not_confirm_it() {
    let scratch = tempfile::tempdir().expect("temp dir");
    let Some((result, _labels)) = scanned(scratch.path()) else {
        return;
    };
    // The longest member the report has: whatever it is, it spans plenty of
    // lines nobody claimed were duplicated within it.
    let longest = result
        .findings
        .iter()
        .flat_map(|finding| &finding.fragments)
        .max_by_key(|member| member.line_count())
        .expect("the corpus reports at least one member");
    assert!(
        longest.line_count() >= 8,
        "the longest member spans {} line(s), too few to cut two regions from",
        longest.line_count(),
    );
    // Two regions inside that one member. The member's lines enclose both, and
    // the finding says nothing whatever about the two being copies of each
    // other.
    let inside = |offset: u32, length: u32| Fragment {
        file: longest.file.clone(),
        start_line: longest.start_line + offset,
        end_line: longest.start_line + offset + length - 1,
        tokens: 0,
    };
    let spanned = label_over(
        "two-regions-inside-one-member",
        CloneType::Type3,
        vec![inside(1, 2), inside(4, 2)],
    );
    for fragment in &spanned.fragments {
        assert!(
            !holders(&result, fragment).is_empty(),
            "the longest member no longer holds the regions cut from it",
        );
    }
    assert!(
        !confirms(&result, &spanned, DEFAULT_MATCH_THRESHOLD),
        "a finding whose lines merely span both regions was read as showing them",
    );
}
