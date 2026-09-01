//! End-to-end detection over the committed labelled corpus: lex real Rust
//! sources with the frontend, run the engine, and check the labelled clone
//! pairs are recovered at the right places.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;
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

/// The units of `lexed`, with every record definition removed.
fn callable_units(lexed: &LexedFile) -> Vec<codehelion_core::frontend::Unit> {
    lexed
        .units
        .iter()
        .filter(|unit| unit.kind != codehelion_core::frontend::UnitKind::Record)
        .cloned()
        .collect()
}

/// The shape of a report that does not depend on which units were supplied:
/// one entry per group member, in order.
fn member_ranges(report: &engine::EngineReport) -> Vec<(CloneClass, usize, usize, usize)> {
    report
        .groups
        .iter()
        .flat_map(|group| {
            group
                .members
                .iter()
                .map(move |m| (group.clone_type, m.file, m.token_start, m.token_end))
        })
        .collect()
}

#[test]
fn a_record_definition_anchors_a_clone_without_regrouping_it() {
    // Duplicated record definitions are found by the same token-run search
    // whether or not records are units: a record body contributes no candidate
    // fragment and no segment. What a record unit adds is the anchor, so the
    // duplicate is reported under the name of the record holding it instead of
    // under nothing.
    let mut fields = String::new();
    for index in 0..24 {
        let _ = writeln!(fields, "    f{index}: i32,");
    }
    let sources = [
        format!("struct Point {{\n{fields}}}\nfn a() -> i32 {{ 1 }}\n"),
        format!("struct Other {{\n{fields}}}\nfn b() -> i32 {{ 2 }}\n"),
    ];
    let lexed: Vec<LexedFile> = sources.iter().map(|s| RustFrontend.lex(s)).collect();
    let without: Vec<Vec<codehelion_core::frontend::Unit>> =
        lexed.iter().map(callable_units).collect();

    let with_records = engine::detect(
        &lexed
            .iter()
            .map(|l| InputFile {
                tokens: &l.tokens,
                units: &l.units,
            })
            .collect::<Vec<_>>(),
        &EngineConfig::default(),
    );
    let without_records = engine::detect(
        &lexed
            .iter()
            .zip(&without)
            .map(|(l, units)| InputFile {
                tokens: &l.tokens,
                units,
            })
            .collect::<Vec<_>>(),
        &EngineConfig::default(),
    );

    assert_eq!(
        with_records.groups.len(),
        without_records.groups.len(),
        "records changed how many groups are reported"
    );
    assert_eq!(
        member_ranges(&with_records),
        member_ranges(&without_records),
        "records changed which ranges are grouped"
    );

    let anchored: Vec<Option<&str>> = with_records
        .groups
        .iter()
        .flat_map(|group| group.members.iter())
        .map(|m| {
            m.unit
                .and_then(|index| lexed[m.file].units[index].name.as_deref())
        })
        .collect();
    let unanchored: Vec<Option<&str>> = without_records
        .groups
        .iter()
        .flat_map(|group| group.members.iter())
        .map(|m| {
            m.unit
                .and_then(|index| without[m.file][index].name.as_deref())
        })
        .collect();
    assert_eq!(anchored, vec![Some("Point"), Some("Other")]);
    assert_eq!(unanchored, vec![None, None]);
}
