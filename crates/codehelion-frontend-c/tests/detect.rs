//! End-to-end detection over inline C sources: lex with the C frontend, run
//! the engine, and check that a verbatim transplant (Type-1) and a
//! renamed-with-changed-literals copy (Type-2) are both recovered.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::clone_class::CloneClass;
use codehelion_core::engine::{self, EngineConfig, InputFile};
use codehelion_core::frontend::{Frontend, LexedFile};
use codehelion_frontend_c::CFrontend;

/// The donor: a checksum loop that the other files copy.
const SEED: &str = "\
#include <stddef.h>

unsigned checksum_block(const unsigned char *data, size_t len) {
    unsigned acc = 5381u;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 5) + acc;
        acc = acc ^ (unsigned)data[i];
        acc = acc + (acc >> 7);
    }
    return acc;
}

int unrelated_sum(const int *xs, size_t n) {
    int total = 0;
    for (size_t i = 0; i < n; i++) {
        total += xs[i] * 3;
    }
    return total;
}
";

/// A verbatim copy of the checksum function (Type-1) among unrelated code.
const VERBATIM: &str = "\
#include <stddef.h>

static int clamp_positive(int v) {
    if (v < 0) {
        return 0;
    }
    return v;
}

unsigned checksum_block(const unsigned char *data, size_t len) {
    unsigned acc = 5381u;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 5) + acc;
        acc = acc ^ (unsigned)data[i];
        acc = acc + (acc >> 7);
    }
    return acc;
}
";

/// The same function with consistently renamed identifiers and changed
/// literals (Type-2).
const RENAMED: &str = "\
#include <stddef.h>

unsigned digest_chunk(const unsigned char *bytes, size_t count) {
    unsigned state = 7919u;
    for (size_t k = 0; k < count; k++) {
        state = (state << 5) + state;
        state = state ^ (unsigned)bytes[k];
        state = state + (state >> 7);
    }
    return state;
}
";

fn lex_all() -> Vec<LexedFile> {
    [SEED, VERBATIM, RENAMED]
        .iter()
        .map(|src| CFrontend.lex(src))
        .collect()
}

fn detect_all(lexed: &[LexedFile]) -> engine::EngineReport {
    let files: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|l| InputFile {
            tokens: &l.tokens,
            units: &l.units,
        })
        .collect();
    engine::detect(&files, &EngineConfig::default())
}

/// Whether some group of `clone_type` has members in both files.
fn linked(
    report: &engine::EngineReport,
    clone_type: CloneClass,
    file_a: usize,
    file_b: usize,
) -> bool {
    report.groups.iter().any(|g| {
        g.clone_type == clone_type
            && g.members.iter().any(|m| m.file == file_a)
            && g.members.iter().any(|m| m.file == file_b)
    })
}

#[test]
fn c_sources_lex_clean() {
    for lexed in lex_all() {
        assert!(lexed.diagnostics.is_empty(), "{:#?}", lexed.diagnostics);
        assert!(
            lexed.units.iter().any(|u| u.name.is_some()),
            "function units expected"
        );
    }
}

#[test]
fn verbatim_c_copy_is_recovered_as_type1() {
    // Keep the exact pair separate from the renamed variant. A mixed group is
    // deliberately classified as Type-2 because that is its weakest member
    // relationship; this focused fixture establishes the Type-1 guarantee.
    let lexed: Vec<_> = [SEED, VERBATIM]
        .iter()
        .map(|source| CFrontend.lex(source))
        .collect();
    let report = detect_all(&lexed);
    assert!(
        linked(&report, CloneClass::Type1, 0, 1),
        "type-1 copy seed <-> verbatim not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn renamed_c_copy_is_recovered_as_type2() {
    let lexed = lex_all();
    let report = detect_all(&lexed);
    assert!(
        linked(&report, CloneClass::Type2, 0, 2),
        "type-2 rename seed <-> renamed not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn matches_are_anchored_to_their_host_units() {
    let lexed = lex_all();
    let report = detect_all(&lexed);
    for group in &report.groups {
        for member in &group.members {
            let Some(unit_idx) = member.unit else {
                continue;
            };
            let unit = &lexed[member.file].units[unit_idx];
            assert!(
                unit.token_start <= member.token_start && member.token_end <= unit.token_end,
                "anchor does not enclose its member"
            );
        }
    }
}

#[test]
fn c_detection_is_deterministic() {
    let lexed = lex_all();
    let first = detect_all(&lexed);
    let second = detect_all(&lexed);
    assert_eq!(first.stats, second.stats);
    assert_eq!(first.groups.len(), second.groups.len());
    for (a, b) in first.groups.iter().zip(second.groups.iter()) {
        assert_eq!(a.content_key, b.content_key);
        assert_eq!(a.members, b.members);
    }
}
