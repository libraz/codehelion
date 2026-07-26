//! Stable-ID regression: the edit scenarios that must never change an
//! identifier. Real Rust sources are lexed, detected and identified; then the
//! same clone is re-identified after unrelated edits, Type-1 edits (comments
//! and formatting) and a file move, and every stable identifier must come out
//! bit-identical. Only the anchors (lines, offsets) may differ.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::engine::{self, EngineConfig, InputFile};
use codehelion_core::frontend::{Frontend, LexedFile};
use codehelion_core::stable_id::{self, FileContext};
use codehelion_frontend_rust::RustFrontend;

/// The clone both files share: 40+ tokens, no internal repetition.
const CHECKSUM: &str = "\
fn checksum(data: &[u32]) -> u32 {
    let mut acc = 5381u32;
    for value in data {
        acc = (acc << 5).wrapping_add(acc);
        acc ^= *value;
    }
    acc
}
";

/// An unrelated function living next to the clone in file A.
const SCALE: &str = "\
fn scale(values: &mut [u32], factor: u32) {
    for entry in values.iter_mut() {
        *entry = entry.wrapping_mul(factor).rotate_left(3);
    }
}
";

/// File B after unrelated edits: a new import, reindentation of the clone
/// (tokens unchanged) and a new trailing function.
const B_UNRELATED_EDITS: &str = "\
use std::num::Wrapping;

fn checksum(data: &[u32]) -> u32 {
        let mut acc = 5381u32;
        for value in data {
            acc = (acc << 5).wrapping_add(acc);
            acc ^= *value;
        }
        acc
}

fn report(count: usize) -> String {
    format!(\"{count} blocks\")
}
";

/// File B after Type-1 edits: comments inside the cloned function.
const B_TYPE1_EDITS: &str = "\
// Rolling checksum over a block of words.
fn checksum(data: &[u32]) -> u32 {
    let mut acc = 5381u32; // djb2 seed
    for value in data {
        /* shift-add, then fold the word in */
        acc = (acc << 5).wrapping_add(acc);
        acc ^= *value;
    }
    acc
}
";

/// File B after a Type-2 edit: consistent renames and a changed literal.
const B_RENAMED: &str = "\
fn digest(feed: &[u32]) -> u32 {
    let mut state = 7919u32;
    for item in feed {
        state = (state << 5).wrapping_add(state);
        state ^= *item;
    }
    state
}
";

fn file_a() -> String {
    format!("{CHECKSUM}\n{SCALE}")
}

/// Lex `sources`, run detection, and flatten every stable identifier into a
/// comparable, order-independent form: sorted `(group hex, sorted finding
/// hexes)` pairs.
fn ids_of(sources: &[&str]) -> Vec<(String, Vec<String>)> {
    let lexed: Vec<LexedFile> = sources.iter().map(|s| RustFrontend.lex(s)).collect();
    let files: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|l| InputFile {
            tokens: &l.tokens,
            units: &l.units,
        })
        .collect();
    let contexts: Vec<FileContext<'_>> = lexed
        .iter()
        .map(|l| FileContext {
            frontend_version: l.frontend_version,
            language: l.language,
        })
        .collect();
    let config = EngineConfig::default();
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let report = engine::detect(&files, &config);
    let ids = stable_id::report_ids(&files, &contexts, &variant, &report, config.literals);

    let mut out: Vec<(String, Vec<String>)> = ids
        .iter()
        .map(|g| {
            let mut findings: Vec<String> = g.members.iter().map(|m| m.finding.to_hex()).collect();
            findings.sort();
            (g.fingerprint.to_hex(), findings)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn the_base_pair_produces_a_group_with_ids() {
    let ids = ids_of(&[&file_a(), CHECKSUM]);
    assert!(!ids.is_empty(), "the verbatim pair must form a group");
    for (_, findings) in &ids {
        assert!(findings.len() >= 2);
    }
}

#[test]
fn unrelated_edits_leave_every_stable_id_unchanged() {
    let base = ids_of(&[&file_a(), CHECKSUM]);
    let edited = ids_of(&[&file_a(), B_UNRELATED_EDITS]);
    assert_eq!(base, edited);
}

#[test]
fn type1_edits_leave_every_stable_id_unchanged() {
    let base = ids_of(&[&file_a(), CHECKSUM]);
    let edited = ids_of(&[&file_a(), B_TYPE1_EDITS]);
    assert_eq!(base, edited);
}

#[test]
fn moving_a_file_leaves_every_stable_id_unchanged() {
    // The engine identifies files by input position and never hashes a path,
    // so a moved or renamed file is exactly a reordered input.
    let base = ids_of(&[&file_a(), CHECKSUM]);
    let moved = ids_of(&[CHECKSUM, &file_a()]);
    assert_eq!(base, moved);
}

#[test]
fn a_type2_edit_produces_a_new_group_identity() {
    // Renaming one copy replaces the Type-1 group with a Type-2 group; the
    // group fingerprint changes, and bridging that transition is lineage's
    // job, not the fingerprint's.
    let base = ids_of(&[&file_a(), CHECKSUM]);
    let renamed = ids_of(&[&file_a(), B_RENAMED]);
    assert!(!renamed.is_empty(), "the renamed pair must still group");
    for (fingerprint, _) in &renamed {
        assert!(
            base.iter().all(|(b, _)| b != fingerprint),
            "a type-2 group must not reuse the type-1 identity"
        );
    }
}

#[test]
fn type2_members_share_their_normalized_content_fingerprint() {
    let sources = [file_a(), B_RENAMED.to_string()];
    let lexed: Vec<LexedFile> = sources.iter().map(|s| RustFrontend.lex(s)).collect();
    let files: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|l| InputFile {
            tokens: &l.tokens,
            units: &l.units,
        })
        .collect();
    let contexts: Vec<FileContext<'_>> = lexed
        .iter()
        .map(|l| FileContext {
            frontend_version: l.frontend_version,
            language: l.language,
        })
        .collect();
    let config = EngineConfig::default();
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let report = engine::detect(&files, &config);
    let ids = stable_id::report_ids(&files, &contexts, &variant, &report, config.literals);

    let type2 = report
        .groups
        .iter()
        .zip(ids.iter())
        .find(|(g, _)| g.clone_type == CloneClass::Type2)
        .map(|(_, i)| i)
        .expect("a type-2 group");
    let first = &type2.members[0];
    assert!(
        type2.members.iter().all(|m| m.content == first.content),
        "type-2 members must share one normalized content fingerprint"
    );
    // Findings still tell the occurrences apart.
    let mut findings: Vec<_> = type2.members.iter().map(|m| m.finding).collect();
    findings.sort_unstable();
    findings.dedup();
    assert_eq!(findings.len(), type2.members.len());
}
