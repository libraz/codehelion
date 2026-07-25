//! End-to-end detection over the committed labelled corpus: lex real Rust
//! sources with the frontend, run the engine, and check the labelled clone
//! pairs are recovered at the right places.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::engine::{self, EngineConfig, InputFile};
use codehelion_core::frontend::{Frontend, LexedFile};
use codehelion_frontend_rust::RustFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-partial";
const FILES: [&str; 3] = ["seed.rs", "partial1.rs", "partial2.rs"];

fn lex_corpus() -> Vec<LexedFile> {
    FILES
        .iter()
        .map(|name| {
            let path = PathBuf::from(CORPUS).join(name);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            RustFrontend.lex(&source)
        })
        .collect()
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

#[test]
fn labelled_type1_transplant_is_recovered() {
    let lexed = lex_corpus();
    let report = detect_corpus(&lexed);
    // A measurement loop transplanted verbatim from seed.rs into an unrelated
    // host function in partial1.rs.
    assert!(
        found(&report, CloneClass::Type1, 0, (9, 22), 1, (10, 23)),
        "type-1 transplant seed.rs:9-22 <-> partial1.rs:10-23 not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn labelled_type2_transplant_is_recovered() {
    let lexed = lex_corpus();
    let report = detect_corpus(&lexed);
    // A checksum statement run transplanted with renames and a changed
    // literal from seed.rs into an unrelated host function in partial2.rs.
    assert!(
        found(&report, CloneClass::Type2, 0, (34, 41), 2, (10, 17)),
        "type-2 transplant seed.rs:34-41 <-> partial2.rs:10-17 not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn partial_matches_are_anchored_to_their_host_units() {
    let lexed = lex_corpus();
    let report = detect_corpus(&lexed);
    for group in &report.groups {
        for member in &group.members {
            let units = &lexed[member.file].units;
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
    let lexed = lex_corpus();
    let first = detect_corpus(&lexed);
    let second = detect_corpus(&lexed);
    assert_eq!(first.stats, second.stats);
    assert_eq!(first.groups.len(), second.groups.len());
    for (a, b) in first.groups.iter().zip(second.groups.iter()) {
        assert_eq!(a.content_key, b.content_key);
        assert_eq!(a.members, b.members);
    }
}
