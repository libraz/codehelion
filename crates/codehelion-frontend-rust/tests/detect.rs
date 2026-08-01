//! End-to-end detection over the committed labelled corpus: lex real Rust
//! sources with the frontend, run the engine, and check the labelled clone
//! pairs are recovered at the right places.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::engine::{self, EngineConfig, InputFile};
use codehelion_core::frontend::{Frontend, LexedFile};
use codehelion_eval::labels::{LabelPair, LabelSet};
use codehelion_eval::schema::{CloneType, Fragment};
use codehelion_frontend_rust::RustFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-partial";

/// Labels and lexed sources of the committed Fast-mode corpus.
struct Corpus {
    labels: LabelSet,
    files: Vec<String>,
    lexed: Vec<LexedFile>,
}

fn corpus() -> Corpus {
    let root = PathBuf::from(CORPUS);
    let labels_path = root.join("labels.json");
    let labels = LabelSet::from_json(
        &std::fs::read_to_string(&labels_path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display())),
    )
    .expect("committed corpus labels parse");
    let files = labels.files.clone();
    let lexed = files
        .iter()
        .map(|name| {
            let path = root.join(name);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            RustFrontend.lex(&source)
        })
        .collect();
    Corpus {
        labels,
        files,
        lexed,
    }
}

fn detect_corpus(lexed: &[LexedFile]) -> engine::EngineReport {
    let files: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|l| InputFile {
            tokens: &l.tokens,
            units: &l.units,
        })
        .collect();
    engine::detect(&files, &EngineConfig::default())
}

/// Whether some group of `clone_type` has one member in `file_a` overlapping
/// `lines_a` and another in `file_b` overlapping `lines_b`.
fn found(
    report: &engine::EngineReport,
    clone_type: CloneClass,
    file_a: usize,
    lines_a: (u32, u32),
    file_b: usize,
    lines_b: (u32, u32),
) -> bool {
    let overlaps = |m: &engine::Instance, file: usize, lines: (u32, u32)| {
        m.file == file && m.start_line <= lines.1 && lines.0 <= m.end_line
    };
    report.groups.iter().any(|g| {
        g.clone_type == clone_type
            && g.members.iter().any(|m| overlaps(m, file_a, lines_a))
            && g.members.iter().any(|m| overlaps(m, file_b, lines_b))
    })
}

fn file_index(files: &[String], fragment: &Fragment) -> usize {
    files
        .iter()
        .position(|file| file == &fragment.file)
        .unwrap_or_else(|| panic!("label refers to unlisted file {}", fragment.file))
}

fn clone_class(clone_type: CloneType) -> CloneClass {
    match clone_type {
        CloneType::Type1 => CloneClass::Type1,
        CloneType::Type2 => CloneClass::Type2,
        CloneType::Type3 => CloneClass::Type3,
        CloneType::RestrictedSemantic => {
            panic!("Fast-mode corpus label cannot use restricted-semantic")
        }
    }
}

fn pair_is_recovered(report: &engine::EngineReport, files: &[String], pair: &LabelPair) -> bool {
    let [left, right] = pair.fragments.as_slice() else {
        panic!("label {} must contain exactly two fragments", pair.id);
    };
    found(
        report,
        clone_class(pair.clone_type),
        file_index(files, left),
        (left.start_line, left.end_line),
        file_index(files, right),
        (right.start_line, right.end_line),
    )
}

#[test]
fn every_labelled_fast_pair_is_recovered() {
    let corpus = corpus();
    let report = detect_corpus(&corpus.lexed);
    for pair in &corpus.labels.clone_pairs {
        assert!(
            pair_is_recovered(&report, &corpus.files, pair),
            "{} ({}) not found; groups: {:#?}",
            pair.id,
            pair.clone_type.as_str(),
            report.groups
        );
    }
}

#[test]
fn partial_matches_are_anchored_to_their_host_units() {
    let corpus = corpus();
    let report = detect_corpus(&corpus.lexed);
    for group in &report.groups {
        for member in &group.members {
            let units = &corpus.lexed[member.file].units;
            let Some(unit_idx) = member.unit else {
                continue;
            };
            let unit = &units[unit_idx];
            assert!(
                unit.token_start <= member.token_start && member.token_end <= unit.token_end,
                "anchor does not enclose its member"
            );
        }
    }
}

#[test]
fn corpus_detection_is_deterministic() {
    let corpus = corpus();
    let first = detect_corpus(&corpus.lexed);
    let second = detect_corpus(&corpus.lexed);
    assert_eq!(first.stats, second.stats);
    assert_eq!(first.groups.len(), second.groups.len());
    for (a, b) in first.groups.iter().zip(second.groups.iter()) {
        assert_eq!(a.content_key, b.content_key);
        assert_eq!(a.members, b.members);
    }
}
