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
use codehelion_helper::protocol::{Capability, Execution, HelperIdentity};
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
    Analyzed {
        /// Which of [`Answers::helpers`] answered.
        helper: usize,
        /// What it said.
        ir: Box<CompilerIr>,
    },
    /// One was asked and could not answer, for this reason.
    Unavailable {
        /// Which of [`Answers::helpers`] was asked, when it got far enough to
        /// say who it was. A helper that fell over before its handshake is not
        /// in that list, and a run that named it anyway would be naming a
        /// program it never heard from.
        helper: Option<usize>,
        /// What was asked about.
        unit: UnitRef,
        /// Why there is no analysis of it.
        reason: Unavailability,
    },
    /// Nobody was asked, and why not: no helper here analyses this file's
    /// language, or nothing says which unit it is compiled as.
    NotAsked {
        /// What would have been asked about. Its unit name is empty exactly
        /// when nothing could supply one, which is one of the two reasons
        /// nothing was asked.
        unit: UnitRef,
        /// Why nobody was asked.
        reason: Unavailability,
    },
}

impl Answer {
    /// The analysis, when there is one.
    pub(crate) fn analysis(&self) -> Option<&CompilerIr> {
        match self {
            Self::Analyzed { ir, .. } => Some(ir),
            Self::Unavailable { .. } | Self::NotAsked { .. } => None,
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

/// A helper program, the languages it answers about, and what it may run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Backend<'a> {
    /// The program to run.
    pub(crate) program: &'a Path,
    /// The languages whose files it is asked about. One helper answers about
    /// C and C++ both, because one compiler does.
    pub(crate) analyzes: &'a [Language],
    /// What it is allowed to run out of the project while answering.
    ///
    /// Already narrowed to classes the helper said it acts on, so nothing here
    /// is a permission that will be silently dropped at the other end.
    pub(crate) permitted: &'a [Execution],
}

/// One helper that took part, as it described itself.
#[derive(Debug, Clone)]
pub(crate) struct Answered {
    /// What it said about itself at the handshake.
    pub(crate) identity: HelperIdentity,
    /// The protocol revision the two sides settled on.
    pub(crate) agreed: u32,
    /// How many times it had to be restarted along the way.
    pub(crate) restarts: u32,
}

/// What the helpers said about a tree.
#[derive(Debug, Clone)]
pub(crate) struct Answers {
    /// Every helper that got as far as saying who it was.
    ///
    /// Empty when none was ever started, which is a run where every source
    /// turned out to be one nobody could be asked about. Shorter than the list
    /// of backends when one of them was installed and never reached — a helper
    /// that answered nothing about itself is not one the run can report having
    /// used.
    pub(crate) helpers: Vec<Answered>,
    /// One entry per source, in the order the sources were given.
    pub(crate) per_source: Vec<Answer>,
}

/// Ask each backend about the sources it analyses, one at a time.
///
/// Every helper runs under its own [`Supervisor`], so a source that kills one
/// costs that source rather than the run — and rather than the other language:
/// what one helper could not survive comes back as an unavailability like any
/// other while the other helper is still answering.
pub(crate) fn ask(
    backends: &[Backend<'_>],
    sources: &[SourceUnit],
    variant: &str,
    timeout: Duration,
) -> Answers {
    let mut supervisors: Vec<Supervisor> = backends
        .iter()
        .map(|backend| {
            Supervisor::new(backend.program.to_path_buf(), Vec::new(), timeout)
                .permitting(backend.permitted.to_vec())
        })
        .collect();
    let analyzes: Vec<&[Language]> = backends.iter().map(|backend| backend.analyzes).collect();
    let gathered = gather(&analyzes, sources, variant, &mut |backend, unit| {
        supervisors
            .get_mut(backend)
            .map_or(Analysis::Missing(Unavailability::NotSupported), |helper| {
                helper.analyze(unit, &WANTED)
            })
    });
    // A backend that never said who it was leaves no row to point at, so the
    // rows are compacted and what the answers point at is moved with them.
    let mut helpers = Vec::new();
    let mut row = Vec::with_capacity(supervisors.len());
    for supervisor in &mut supervisors {
        let restarts = supervisor.restarts();
        let answered = supervisor.spoke_with().map(|(identity, agreed)| Answered {
            identity: identity.clone(),
            agreed,
            restarts,
        });
        row.push(answered.map(|answered| {
            helpers.push(answered);
            helpers.len() - 1
        }));
        supervisor.shutdown();
    }
    Answers {
        helpers,
        per_source: gathered
            .into_iter()
            .map(|answer| answer.pointing_at(&row))
            .collect(),
    }
}

/// One answer, still naming the backend that produced it rather than the row it
/// will be reported under.
enum Gathered {
    Analyzed {
        backend: usize,
        ir: Box<CompilerIr>,
    },
    Unavailable {
        backend: usize,
        unit: UnitRef,
        reason: Unavailability,
    },
    NotAsked {
        unit: UnitRef,
        reason: Unavailability,
    },
}

impl Gathered {
    /// The same answer, naming the row `row` puts this backend at.
    fn pointing_at(self, row: &[Option<usize>]) -> Answer {
        let at = |backend: usize| row.get(backend).copied().flatten();
        match self {
            Self::Analyzed { backend, ir } => Answer::Analyzed {
                // An analysis came out of a conversation, so the helper that
                // produced it said who it was; the fallback cannot be reached
                // and is the harmless one either way.
                helper: at(backend).unwrap_or(0),
                ir,
            },
            Self::Unavailable {
                backend,
                unit,
                reason,
            } => Answer::Unavailable {
                helper: at(backend),
                unit,
                reason,
            },
            Self::NotAsked { unit, reason } => Answer::NotAsked { unit, reason },
        }
    }
}

/// The asking itself, with the processes kept behind `ask_one`.
///
/// Split out so that what a run does with a tree — which files are asked
/// about, of which helper, under which unit, and what an answer is filed as —
/// is decided here and checked without a subprocess. How a helper behaves when
/// it is slow, broken or from another release is fixed against real processes
/// in the helper crate's own conformance suite; repeating that here would test
/// the same two things again and this one not at all.
fn gather(
    analyzes: &[&[Language]],
    sources: &[SourceUnit],
    variant: &str,
    ask_one: &mut dyn FnMut(usize, &UnitRef) -> Analysis,
) -> Vec<Gathered> {
    sources
        .iter()
        .map(|source| {
            let unit = unit_ref(source, variant);
            let Some(backend) = analyzes
                .iter()
                .position(|reads| reads.contains(&source.language))
            else {
                return Gathered::NotAsked {
                    unit,
                    reason: Unavailability::NotSupported,
                };
            };
            if unit.unit.is_empty() {
                return Gathered::NotAsked {
                    unit,
                    reason: Unavailability::NoBuildInformation,
                };
            }
            match ask_one(backend, &unit) {
                Analysis::Done(ir) => Gathered::Analyzed { backend, ir },
                Analysis::Missing(reason) => Gathered::Unavailable {
                    backend,
                    unit,
                    reason,
                },
            }
        })
        .collect()
}

/// How `source` is named, whether or not anything is asked about it.
///
/// The unit name is left empty when nothing can supply one, which is one of the
/// reasons nobody is asked: a guessed name either names nothing, which wastes
/// the round trip, or names another unit, whose answer would then be recorded
/// against this file.
fn unit_ref(source: &SourceUnit, variant: &str) -> UnitRef {
    UnitRef {
        unit: unit_name(source).unwrap_or_default(),
        file: source.absolute_path.display().to_string(),
        variant: variant.to_string(),
    }
}

/// The unit `source` is compiled as part of, when something says.
///
/// The two languages answer this differently, and the difference is not a
/// detail of spelling. A Rust file is compiled as part of a crate, which only
/// the layout knows and which a file in no crate — a build script, a stray file
/// beside a workspace — therefore has no name for at all. A C or C++ file is
/// its own translation unit, named by where it is; which command compiles it is
/// the compilation database's answer, and the helper reads that itself rather
/// than being told.
fn unit_name(source: &SourceUnit) -> Option<String> {
    match source.language {
        Language::Rust => source.crate_name.clone(),
        Language::C | Language::Cpp => Some(source.absolute_path.display().to_string()),
    }
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    /// The only helper installed reads Rust.
    const RUST_ONLY: [&[Language]; 1] = [&[Language::Rust]];

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
        let answers = gather(&RUST_ONLY, &sources, "host", &mut |_, unit| {
            asked.push(unit.clone());
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        });
        assert!(matches!(answers[0], Gathered::Analyzed { .. }));
        // A C file, with no helper here that reads C.
        assert!(matches!(
            answers[1],
            Gathered::NotAsked {
                reason: Unavailability::NotSupported,
                ..
            }
        ));
        // A build script belongs to no crate the layout can name.
        assert!(matches!(
            answers[2],
            Gathered::NotAsked {
                reason: Unavailability::NoBuildInformation,
                ..
            }
        ));
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
        let answers = gather(&RUST_ONLY, &sources, "host", &mut |_, _| {
            Analysis::Missing(Unavailability::RequiresExecution)
        });
        let Gathered::Unavailable { unit, reason, .. } = &answers[0] else {
            panic!("the helper was asked and could not answer");
        };
        assert_eq!(*reason, Unavailability::RequiresExecution);
        // The unit is kept: a run records what it asked about, and a reason
        // with nothing attached names no file.
        assert_eq!(unit.unit, "ledger");
        assert_eq!(unit.file, "/repo/src/lib.rs");
        assert!(matches!(answers[1], Gathered::NotAsked { .. }));
    }

    /// A file nobody could be asked about is still named, so the run can say
    /// which files those were. Its unit name is empty because there is none —
    /// the alternative is inventing one, which is what makes an answer land on
    /// the wrong file.
    #[test]
    fn a_file_nobody_was_asked_about_is_named_without_a_unit_being_invented() {
        let sources = [source("build.rs", Language::Rust, None)];
        let answers = gather(&RUST_ONLY, &sources, "host", &mut |_, _| {
            panic!("nothing should be asked")
        });
        let Gathered::NotAsked { unit, reason } = &answers[0] else {
            panic!("nobody was asked about it");
        };
        assert_eq!(*reason, Unavailability::NoBuildInformation);
        assert_eq!(unit.file, "/repo/build.rs");
        assert!(unit.unit.is_empty());
    }

    /// Two helpers, and each file goes to the one that reads its language. A
    /// run that sent every file to the first would report the C++ half as
    /// unanswerable by a compiler that was never going to be asked about it.
    #[test]
    fn each_file_is_put_to_the_helper_that_reads_its_language() {
        let analyzes: [&[Language]; 2] = [&[Language::Rust], &[Language::C, Language::Cpp]];
        let sources = [
            source("src/lib.rs", Language::Rust, Some("ledger")),
            source("src/accumulate.cpp", Language::Cpp, None),
            source("src/native.c", Language::C, None),
        ];
        let mut asked: Vec<(usize, String)> = Vec::new();
        let answers = gather(&analyzes, &sources, "host", &mut |backend, unit| {
            asked.push((backend, unit.unit.clone()));
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        });
        assert!(
            answers
                .iter()
                .all(|answer| matches!(answer, Gathered::Analyzed { .. }))
        );
        assert_eq!(
            asked,
            vec![
                (0, "ledger".to_string()),
                // A C or C++ file is its own translation unit, named by where
                // it is: no layout says which command compiles it, and the
                // helper reads that from the compilation database itself.
                (1, "/repo/src/accumulate.cpp".to_string()),
                (1, "/repo/src/native.c".to_string()),
            ]
        );
    }

    /// A C++ file belongs to no crate, and a run that asked a Cargo layout for
    /// one would rule out every C++ file in the tree before anything was asked
    /// — reported as a project that says nothing about itself rather than as
    /// the question having been the wrong one.
    #[test]
    fn a_cpp_file_is_not_ruled_out_for_belonging_to_no_crate() {
        let analyzes: [&[Language]; 1] = [&[Language::C, Language::Cpp]];
        let sources = [source("src/accumulate.cpp", Language::Cpp, None)];
        let answers = gather(&analyzes, &sources, "host", &mut |_, unit| {
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        });
        assert!(matches!(answers[0], Gathered::Analyzed { .. }));
    }

    /// A helper that never got as far as saying who it was leaves no row, and
    /// the answers it did produce must not point at another helper's.
    #[test]
    fn an_answer_names_the_helper_that_produced_it_rather_than_a_position() {
        let row = [None, Some(0)];
        let unit = UnitRef {
            unit: "ledger".into(),
            file: "/repo/src/lib.rs".into(),
            variant: "host".into(),
        };
        let silent = Gathered::Unavailable {
            backend: 0,
            unit: unit.clone(),
            reason: Unavailability::HelperDied,
        }
        .pointing_at(&row);
        assert!(matches!(silent, Answer::Unavailable { helper: None, .. }));
        let answered = Gathered::Analyzed {
            backend: 1,
            ir: Box::new(CompilerIr::empty(unit)),
        }
        .pointing_at(&row);
        assert!(matches!(answered, Answer::Analyzed { helper: 0, .. }));
    }
}
