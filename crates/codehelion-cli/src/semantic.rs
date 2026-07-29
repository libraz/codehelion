//! Asking compiler helpers about a tree, and turning what they answered into
//! what normalization reads.
//!
//! The two sides were built to meet here and nowhere else. A helper reports
//! resolved names as symbols anchored at byte offsets in a file;
//! [`Resolution`] answers, for one byte offset, whether the name starting
//! there was defined outside the code being scanned. This is the only place
//! that knows both shapes — the engine crate does not depend on the protocol
//! crate, so that comparing programs stays independent of how a compiler was
//! asked about them.
//!
//! # Why the file has to be named
//!
//! One analysis covers a crate, and a crate is many files. Offsets are per
//! file, so folding two files' symbols into one resolution would have byte 400
//! of each answering for the other — silently, and in the direction that keeps
//! names a normalizer should have replaced.
//!
//! # Why a file that was never asked about is its own outcome
//!
//! A run holds three kinds of file: the ones a compiler answered about, the
//! ones it was asked about and could not answer for, and the ones nobody asked
//! about at all — a C file while only a Rust helper is installed, a file in no
//! crate the layout could name. Folding the last two together would report a
//! helper as having failed on files it was never shown, and would hide the
//! reason the run is thin. They are separate outcomes and stay separate.

use std::path::Path;
use std::time::Duration;

use codehelion_core::discovery::{Language, SourceUnit};
use codehelion_core::engine::normalize::Resolution;
use codehelion_core::ir::ByteRange;
use codehelion_core::types::TypeTag;
use codehelion_helper::ir::{CompilerIr, Unavailability, UnitRef};
use codehelion_helper::protocol::Capability;
use codehelion_helper::{Analysis, Supervisor};

/// Everything a run can use from a compiler.
///
/// Asked for as one set: a helper narrows the request to what it said it
/// offers, so asking for more than one helper supplies costs nothing and
/// stops the request from being the place a capability is forgotten.
pub(crate) const WANTED: [Capability; 5] = [
    Capability::Types,
    Capability::NameResolution,
    Capability::CallTargets,
    Capability::MacroExpansion,
    Capability::TemplateInstantiation,
];

/// What came back about one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// A compiler answered.
    Analyzed(Box<CompilerIr>),
    /// One was asked and could not answer, for this reason.
    Unavailable(Unavailability),
    /// Nobody was asked: no helper here analyses this file's language, or the
    /// layout does not say which crate it belongs to.
    NotAsked,
}

impl Answer {
    /// The analysis, when there is one.
    pub(crate) fn analysis(&self) -> Option<&CompilerIr> {
        match self {
            Self::Analyzed(ir) => Some(ir),
            Self::Unavailable(_) | Self::NotAsked => None,
        }
    }
}

/// The types `ir` resolved inside `file`, at the bytes they were written at.
///
/// Anchored rather than summed: which unit a type belongs to is decided by the
/// crate that read the tree into units, and handing it a per-file total would
/// be attributing a type to a unit this side guessed at.
///
/// A category this build does not recognise, or one the helper could not
/// resolve, contributes nothing: an unresolved type is the compiler saying it
/// does not know, and two units full of those would otherwise agree perfectly
/// about nothing.
#[must_use]
pub(crate) fn resolved_types_for(ir: &CompilerIr, file: &str) -> Vec<(ByteRange, TypeTag)> {
    ir.symbols
        .iter()
        .filter(|symbol| symbol.anchor.expansion.file == file)
        .filter_map(|symbol| {
            let index = usize::try_from(symbol.type_index?).ok()?;
            let tag = TypeTag::from_category(ir.types.get(index)?.category.name())?;
            let range = &symbol.anchor.expansion;
            Some((
                ByteRange {
                    start: usize::try_from(range.start_byte).ok()?,
                    end: usize::try_from(range.end_byte).ok()?,
                },
                tag,
            ))
        })
        .collect()
}

/// A helper program and the language it answers about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Backend<'a> {
    /// The program to run.
    pub(crate) program: &'a Path,
    /// The language whose files it is asked about.
    pub(crate) analyzes: Language,
}

/// What a helper said about a tree.
#[derive(Debug, Clone)]
pub(crate) struct Answers {
    /// One entry per source, in the order the sources were given.
    pub(crate) per_source: Vec<Answer>,
    /// How many times the helper had to be restarted along the way.
    pub(crate) restarts: u32,
}

/// Ask `backend` about every source it analyses, one at a time.
///
/// Runs the helper under a [`Supervisor`], so a source that kills it costs
/// that source rather than the run: what the helper could not survive comes
/// back as an unavailability like any other.
pub(crate) fn ask(
    backend: Backend<'_>,
    sources: &[SourceUnit],
    variant: &str,
    timeout: Duration,
) -> Answers {
    let mut supervisor = Supervisor::new(backend.program.to_path_buf(), Vec::new(), timeout);
    let per_source = gather(backend.analyzes, sources, variant, &mut |unit| {
        supervisor.analyze(unit, &WANTED)
    });
    let restarts = supervisor.restarts();
    supervisor.shutdown();
    Answers {
        per_source,
        restarts,
    }
}

/// The asking itself, with the process kept behind `ask_one`.
///
/// Split out so that what a run does with a tree — which files are asked
/// about, under which crate, and what an answer is filed as — is decided here
/// and checked without a subprocess. How a helper behaves when it is slow,
/// broken or from another release is fixed against real processes in the
/// helper crate's own conformance suite; repeating that here would test the
/// same two things again and this one not at all.
fn gather(
    analyzes: Language,
    sources: &[SourceUnit],
    variant: &str,
    ask_one: &mut dyn FnMut(&UnitRef) -> Analysis,
) -> Vec<Answer> {
    sources
        .iter()
        .map(|source| {
            let Some(unit) = unit_ref(source, analyzes, variant) else {
                return Answer::NotAsked;
            };
            match ask_one(&unit) {
                Analysis::Done(ir) => Answer::Analyzed(ir),
                Analysis::Missing(reason) => Answer::Unavailable(reason),
            }
        })
        .collect()
}

/// How to name `source` when asking about it, or `None` when it is not this
/// helper's to answer.
///
/// A file whose crate the layout cannot name is not asked about rather than
/// asked about under a guess: a guessed crate name either names nothing, which
/// wastes the round trip, or names another crate, whose answer would be
/// recorded against this file.
///
/// A C or C++ file is named by the translation unit that compiles it, which a
/// compilation database says and a Cargo layout does not; a helper that
/// analyses those reads it from there.
fn unit_ref(source: &SourceUnit, analyzes: Language, variant: &str) -> Option<UnitRef> {
    if source.language != analyzes {
        return None;
    }
    Some(UnitRef {
        unit: source.crate_name.clone()?,
        file: source.absolute_path.display().to_string(),
        variant: variant.to_string(),
    })
}

/// What `ir` resolved about the names written in `file`.
///
/// `file` is matched against the path the helper reported, which is how the
/// project spells it rather than how this machine does.
#[must_use]
pub fn resolution_for(ir: &CompilerIr, file: &str) -> Resolution {
    let mut resolution = Resolution::new();
    for symbol in &ir.symbols {
        let anchor = &symbol.anchor.expansion;
        if anchor.file != file {
            continue;
        }
        // A symbol whose anchor spans more than the name it reports is a
        // declaration, not a name occurrence: its range covers the whole item,
        // attributes and doc comment included. Feeding its start offset in
        // would answer for whatever token happens to begin there.
        if anchor.end_byte.saturating_sub(anchor.start_byte) != symbol.name.len() as u64 {
            continue;
        }
        let Ok(start) = usize::try_from(anchor.start_byte) else {
            continue;
        };
        resolution.insert(start, symbol.external);
    }
    resolution
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use codehelion_helper::ir::{Anchor, ResolvedSymbol, SourceRange, SymbolKind, UnitRef};

    fn symbol(name: &str, file: &str, start: u64, width: u64, external: bool) -> ResolvedSymbol {
        ResolvedSymbol {
            id: format!("{file}::{name}@{start}"),
            name: name.to_string(),
            kind: SymbolKind::Binding,
            anchor: Anchor::written_here(SourceRange {
                file: file.to_string(),
                start_byte: start,
                end_byte: start + width,
                start_line: 1,
            }),
            type_index: None,
            external,
        }
    }

    fn ir(symbols: Vec<ResolvedSymbol>) -> CompilerIr {
        let mut ir = CompilerIr::empty(UnitRef {
            unit: "ledger".into(),
            file: "src/lib.rs".into(),
            variant: "host".into(),
        });
        ir.symbols = symbols;
        ir
    }

    #[test]
    fn a_name_keeps_the_verdict_it_was_given() {
        let analysis = ir(vec![
            symbol("String", "src/lib.rs", 10, 6, true),
            symbol("total", "src/lib.rs", 40, 5, false),
        ]);
        let resolution = resolution_for(&analysis, "src/lib.rs");
        assert!(!resolution.is_empty());
        // Round-tripped through the type's own accessor rather than its
        // internals, because what a caller can see is what has to be right.
        assert_eq!(resolution, {
            let mut expected = Resolution::new();
            expected.insert(10, true);
            expected.insert(40, false);
            expected
        });
    }

    /// Offsets are per file. A crate's other files answering for this one would
    /// be wrong in whichever direction their bytes happened to line up.
    #[test]
    fn another_file_in_the_same_crate_does_not_answer_for_this_one() {
        let analysis = ir(vec![
            symbol("total", "src/lib.rs", 40, 5, false),
            symbol("Vec", "src/report.rs", 40, 3, true),
        ]);
        let resolution = resolution_for(&analysis, "src/lib.rs");
        let mut expected = Resolution::new();
        expected.insert(40, false);
        assert_eq!(resolution, expected);
    }

    /// A declaration's anchor spans the item it declares, so its start byte is
    /// whatever the item opens with — an attribute, a doc comment, `pub`. Read
    /// as a name occurrence it would give a verdict about a token nobody asked
    /// about.
    #[test]
    fn a_declaration_is_not_read_as_a_name_occurrence() {
        let mut declaration = symbol("debits", "src/lib.rs", 100, 6, false);
        declaration.anchor.expansion.end_byte = 260;
        declaration.kind = SymbolKind::Function;
        let resolution = resolution_for(&ir(vec![declaration]), "src/lib.rs");
        assert!(resolution.is_empty());
    }

    #[test]
    fn an_analysis_that_resolved_nothing_leaves_normalization_as_it_was() {
        let resolution = resolution_for(&ir(Vec::new()), "src/lib.rs");
        assert!(resolution.is_empty());
    }

    fn source(path: &str, language: Language, crate_name: Option<&str>) -> SourceUnit {
        SourceUnit {
            relative_path: std::path::PathBuf::from(path),
            absolute_path: std::path::PathBuf::from("/repo").join(path),
            language,
            is_header: false,
            content_hash: codehelion_core::discovery::ContentHash::of(b""),
            byte_len: 0,
            package: crate_name.map(ToString::to_string),
            crate_name: crate_name.map(ToString::to_string),
            target_kind: codehelion_core::discovery::TargetKind::Library,
        }
    }

    /// Every source gets an entry, in the order it was given: a run reports
    /// per file what it got, and a list that skipped the files nobody asked
    /// about would have to be re-aligned by whoever reads it.
    #[test]
    fn every_source_is_accounted_for_in_the_order_it_was_given() {
        let sources = [
            source("src/lib.rs", Language::Rust, Some("ledger")),
            source("src/native.c", Language::C, None),
            source("build.rs", Language::Rust, None),
        ];
        let mut asked = Vec::new();
        let answers = gather(Language::Rust, &sources, "host", &mut |unit| {
            asked.push(unit.clone());
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        });
        assert!(matches!(answers[0], Answer::Analyzed(_)));
        // A C file, with no helper here that reads C.
        assert_eq!(answers[1], Answer::NotAsked);
        // A build script belongs to no crate the layout can name.
        assert_eq!(answers[2], Answer::NotAsked);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].unit, "ledger");
        assert_eq!(asked[0].file, "/repo/src/lib.rs");
        assert_eq!(asked[0].variant, "host");
    }

    /// A helper that was asked and could not answer is not a helper that was
    /// never asked: one says the run is thin because the file is hard, the
    /// other because nothing here reads it.
    #[test]
    fn being_unable_to_answer_is_not_the_same_as_never_being_asked() {
        let sources = [
            source("src/lib.rs", Language::Rust, Some("ledger")),
            source("src/native.c", Language::C, None),
        ];
        let answers = gather(Language::Rust, &sources, "host", &mut |_| {
            Analysis::Missing(Unavailability::RequiresExecution)
        });
        assert_eq!(
            answers[0],
            Answer::Unavailable(Unavailability::RequiresExecution)
        );
        assert_eq!(answers[1], Answer::NotAsked);
        assert!(answers.iter().all(|answer| answer.analysis().is_none()));
    }
}
