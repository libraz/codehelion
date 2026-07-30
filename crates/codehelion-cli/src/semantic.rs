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
//! # Why a header is answered by the units that read it
//!
//! A C or C++ header is compiled by no command of its own, so nothing can be
//! asked about it as a unit — and a scan that stopped there would have nothing
//! to say about the files a header-only library is entirely made of. What reads
//! it is a translation unit, and that unit's analysis carries the header's
//! names filed under the header.
//!
//! When several units read one header, what it is answered with is what they
//! all agree on. The disagreements are real — the same declaration can resolve
//! to a 32-bit accumulator in one unit and a 64-bit one in another — and there
//! is exactly one thing to do with them that is neither picking a reading nor
//! discarding the file: say nothing about the names the readings differ over,
//! which leaves those to be compared as text, and say what the compiler
//! resolved about the rest. Telling the readings apart instead would mean
//! recording them under build variants of their own, which is a unit of
//! recording this run does not have.
//!
//! # Why a file that was never asked about is its own outcome
//!
//! A run holds three kinds of file: the ones a compiler answered about, the
//! ones it was asked about and could not answer for, and the ones nobody asked
//! about at all — a C file while only a Rust helper is installed, a file in no
//! crate the layout could name. Folding the last two together would report a
//! helper as having failed on files it was never shown, and would hide the
//! reason the run is thin. They are separate outcomes and stay separate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use codehelion_core::discovery::{Language, SourceUnit};
use codehelion_core::engine::normalize::Resolution;
use codehelion_core::ir::ByteRange;
use codehelion_core::types::TypeTag;
use codehelion_helper::ir::{
    CallSite, CompilerIr, Instantiation, ResolvedSymbol, ResolvedType, Unavailability, UnitRef,
};
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
    let mut gathered = gather(&analyzes, sources, variant, &mut |backend, unit| {
        supervisors
            .get_mut(backend)
            .map_or(Analysis::Missing(Unavailability::NotSupported), |helper| {
                helper.analyze(unit, &WANTED)
            })
    });
    read_by_other_units(&mut gathered, sources);
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

/// Answer the files nothing could be asked about as units of their own from the
/// units that read them.
///
/// A header is the case this exists for: no command compiles one, so the
/// request naming it comes back unanswerable, while the translation units that
/// include it carry its names in their own analyses.
///
/// Only files nothing answered for are filled in. A file that is its own unit
/// has an answer about the program it is, and replacing that with what its
/// readers saw would be a worse answer arrived at indirectly.
fn read_by_other_units(gathered: &mut [Gathered], sources: &[SourceUnit]) {
    // Who read what, worked out in one pass over the analyses rather than
    // searched per file: a tree holds about as many headers as units, and
    // looking through every unit's symbols once per header is that product.
    //
    // Keyed by the root as well as by the name, because a name is only a name
    // against something: two helpers can read one tree from different roots,
    // and a file the one spells `src/a.hpp` is not whatever the other spells
    // the same way.
    let mut readers: BTreeMap<(&str, &str), Vec<(usize, &CompilerIr)>> = BTreeMap::new();
    let mut roots: BTreeSet<&str> = BTreeSet::new();
    for answer in gathered.iter() {
        let Gathered::Analyzed { backend, ir } = answer else {
            continue;
        };
        let root = ir.anchored_at.as_deref().unwrap_or_default();
        roots.insert(root);
        let mut seen = BTreeSet::new();
        for symbol in &ir.symbols {
            let file = symbol.anchor.expansion.file.as_str();
            if seen.insert(file) {
                readers
                    .entry((root, file))
                    .or_default()
                    .push((*backend, ir));
            }
        }
        for instantiation in &ir.instantiations {
            let file = instantiation.anchor.expansion.file.as_str();
            if seen.insert(file) {
                readers
                    .entry((root, file))
                    .or_default()
                    .push((*backend, ir));
            }
        }
        for call in &ir.calls {
            let file = call.anchor.expansion.file.as_str();
            if seen.insert(file) {
                readers
                    .entry((root, file))
                    .or_default()
                    .push((*backend, ir));
            }
        }
    }
    let mut filled: Vec<(usize, Gathered)> = Vec::new();
    for (at, (answer, source)) in gathered.iter().zip(sources).enumerate() {
        let (Gathered::Unavailable { unit, .. } | Gathered::NotAsked { unit, .. }) = answer else {
            continue;
        };
        // Named as the analyses that hold it would have filed it, which is how
        // the project spells it against the root a helper read it from — worked
        // out from that root rather than guessed at, so that a scan started in a
        // subdirectory still finds its own files in the answers.
        let mut readings: Vec<(usize, &CompilerIr, String)> = Vec::new();
        for root in &roots {
            let file = codehelion_helper::ir::spell(
                (!root.is_empty()).then(|| Path::new(root)),
                &source.absolute_path,
            );
            for (backend, ir) in readers.get(&(*root, file.as_str())).into_iter().flatten() {
                readings.push((*backend, *ir, file.clone()));
            }
        }
        let Some((backend, _, _)) = readings.first() else {
            continue;
        };
        if let Some(ir) = agreed(unit.clone(), &readings) {
            filled.push((
                at,
                Gathered::Analyzed {
                    backend: *backend,
                    ir: Box::new(ir),
                },
            ));
        }
    }
    for (at, answer) in filled {
        if let Some(slot) = gathered.get_mut(at) {
            *slot = answer;
        }
    }
}

/// What every reading of one file agrees it holds.
///
/// Two readings agree about a name when they put it at the same bytes, call it
/// the same thing, resolve it to the same definition, place that definition on
/// the same side of the project boundary, and give it the same type. Template
/// uses likewise have to agree on their stable specialization key, origin,
/// definition anchor and resolved type arguments. Calls have to agree on the
/// complete macro-aware anchor and target. Anything less than all of that is a
/// disagreement, and a disagreement is dropped: the occurrence is then
/// compared as it is written, which is what a run with no compiler would have
/// done with it and is the direction that cannot mislead.
///
/// `None` when no symbol, instantiation or call survived, which is a file its
/// readers say nothing common about — reported as unanswerable rather than as
/// an analysis that found nothing, because those are different claims.
///
/// What the result is filed under keeps naming the file, and names the unit
/// only when one unit read it. An agreement between several is an answer about
/// no single unit, and the empty name is what this side already spells that
/// with — while naming one of them would file the whole agreement under the
/// program of whichever reading happened to come first.
fn agreed(file: UnitRef, readings: &[(usize, &CompilerIr, String)]) -> Option<CompilerIr> {
    let (_, first, first_file) = readings.first()?;
    let unit = UnitRef {
        unit: match readings {
            [(_, only, _)] => only.unit.unit.clone(),
            _ => String::new(),
        },
        ..file
    };
    let mut kept = written_in(first, first_file);
    for (_, ir, file) in readings.iter().skip(1) {
        let other = written_in(ir, file);
        kept.retain(|at, held| {
            other
                .get(at)
                .is_some_and(|found| same(ir, found, first, held))
        });
    }
    let mut instantiations = instantiations_in(first, first_file);
    for (_, ir, file) in readings.iter().skip(1) {
        let other = instantiations_in(ir, file);
        instantiations.retain(|at, held| {
            other
                .get(at)
                .is_some_and(|found| same_instantiation(ir, found, first, held))
        });
    }
    let mut calls = calls_in(first, first_file);
    for (_, ir, file) in readings.iter().skip(1) {
        let other = calls_in(ir, file);
        calls.retain(|at, held| other.get(at).is_some_and(|found| *found == *held));
    }
    if kept.is_empty() && instantiations.is_empty() && calls.is_empty() {
        return None;
    }
    let mut merged = CompilerIr::empty(unit);
    merged.anchored_at.clone_from(&first.anchored_at);
    let mut types = Interned::default();
    merged.symbols = kept
        .into_values()
        .map(|symbol| ResolvedSymbol {
            type_index: symbol.type_index.and_then(|index| types.copy(first, index)),
            ..symbol.clone()
        })
        .collect();
    merged.instantiations = instantiations
        .into_values()
        .map(|instantiation| Instantiation {
            arguments: instantiation
                .arguments
                .iter()
                .filter_map(|index| types.copy(first, *index))
                .collect(),
            ..instantiation.clone()
        })
        .collect();
    merged.calls = calls.into_values().cloned().collect();
    merged.types = types.types;
    Some(merged)
}

/// Where each name written in `file` sits, keyed so that two readings of the
/// same file line up.
///
/// The bytes and the name are the key because they are what makes two entries
/// the same occurrence; everything else about a symbol is what the two readings
/// are being compared on, and folding any of it into the key would turn a
/// disagreement into two occurrences that each survive.
fn written_in<'a>(
    ir: &'a CompilerIr,
    file: &str,
) -> BTreeMap<(u64, u64, &'a str), &'a ResolvedSymbol> {
    ir.symbols
        .iter()
        .filter(|symbol| symbol.anchor.expansion.file == file)
        .map(|symbol| {
            (
                (
                    symbol.anchor.expansion.start_byte,
                    symbol.anchor.expansion.end_byte,
                    symbol.name.as_str(),
                ),
                symbol,
            )
        })
        .collect()
}

/// Whether two readings resolved one occurrence to the same thing.
fn same(
    ir: &CompilerIr,
    symbol: &ResolvedSymbol,
    against: &CompilerIr,
    held: &ResolvedSymbol,
) -> bool {
    let resolved = |ir: &CompilerIr, symbol: &ResolvedSymbol| {
        symbol
            .type_index
            .and_then(|index| ir.types.get(usize::try_from(index).ok()?))
            .map(|ty| (ty.display.clone(), ty.category))
    };
    symbol.id == held.id
        && symbol.kind == held.kind
        && symbol.external == held.external
        && symbol.anchor.definition == held.anchor.definition
        && resolved(ir, symbol) == resolved(against, held)
}

/// Where each template use written in `file` sits.
///
/// The stable key is included so two readings that specialize the same written
/// use differently do not turn into one representative reading. The first
/// reading's entry survives only when every other reading has the same family
/// at the same bytes and agrees on the origin and argument types.
fn instantiations_in<'a>(
    ir: &'a CompilerIr,
    file: &str,
) -> BTreeMap<(u64, u64, &'a str), &'a Instantiation> {
    ir.instantiations
        .iter()
        .filter(|instantiation| instantiation.anchor.expansion.file == file)
        .map(|instantiation| {
            (
                (
                    instantiation.anchor.expansion.start_byte,
                    instantiation.anchor.expansion.end_byte,
                    instantiation.instantiation_key.as_str(),
                ),
                instantiation,
            )
        })
        .collect()
}

/// Whether two readings give one template use the same semantic answer.
fn same_instantiation(
    ir: &CompilerIr,
    instantiation: &Instantiation,
    against: &CompilerIr,
    held: &Instantiation,
) -> bool {
    let arguments = |ir: &CompilerIr, instantiation: &Instantiation| {
        instantiation
            .arguments
            .iter()
            .map(|index| {
                ir.types
                    .get(usize::try_from(*index).ok()?)
                    .map(|ty| (ty.display.clone(), ty.category))
            })
            .collect::<Option<Vec<_>>>()
    };
    let arguments_agree = match (arguments(ir, instantiation), arguments(against, held)) {
        (Some(found), Some(expected)) => found == expected,
        (None, _) | (_, None) => false,
    };
    instantiation.definition == held.definition
        && instantiation.anchor.definition == held.anchor.definition
        && arguments_agree
}

/// Calls written in `file`, lined up by their physical occurrence.
///
/// The complete anchor and target are deliberately values rather than parts of
/// the key. A macro body or overload selected differently by another
/// translation unit must contradict the first reading, not become a second
/// independent occurrence that survives.
fn calls_in<'a>(ir: &'a CompilerIr, file: &str) -> BTreeMap<(u64, u64), &'a CallSite> {
    ir.calls
        .iter()
        .filter(|call| call.anchor.expansion.file == file)
        .map(|call| {
            (
                (
                    call.anchor.expansion.start_byte,
                    call.anchor.expansion.end_byte,
                ),
                call,
            )
        })
        .collect()
}

/// Types copied out of the analyses they were resolved in.
#[derive(Default)]
struct Interned {
    /// Where each type landed, keyed by the resolved form, which is what says
    /// two spellings are one type.
    at: BTreeMap<String, u32>,
    types: Vec<ResolvedType>,
}

impl Interned {
    /// The place `ir.types[index]` takes here, copying it and everything it is
    /// built from.
    fn copy(&mut self, ir: &CompilerIr, index: u32) -> Option<u32> {
        let source = ir.types.get(usize::try_from(index).ok()?)?;
        if let Some(already) = self.at.get(&source.display) {
            return Some(*already);
        }
        let at = u32::try_from(self.types.len()).ok()?;
        // Its place is taken before what it is built from is copied, for the
        // reason a helper's own table reserves one: a type can be built from
        // itself, and a copy that recursed first would not stop.
        self.at.insert(source.display.clone(), at);
        self.types.push(ResolvedType {
            arguments: Vec::new(),
            ..source.clone()
        });
        let arguments = source
            .arguments
            .iter()
            .filter_map(|argument| self.copy(ir, *argument))
            .collect();
        if let Some(recorded) = self.types.get_mut(at as usize) {
            recorded.arguments = arguments;
        }
        Some(at)
    }
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
    use codehelion_helper::ir::{
        Anchor, CallTarget, ResolvedSymbol, SourceRange, SymbolKind, UnitRef,
    };

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

    /// One reading of a file, as a helper that read the whole unit reports it.
    fn read(unit: &str, symbols: Vec<ResolvedSymbol>, types: Vec<ResolvedType>) -> Gathered {
        read_with_instantiations(unit, symbols, types, Vec::new())
    }

    fn read_with_instantiations(
        unit: &str,
        symbols: Vec<ResolvedSymbol>,
        types: Vec<ResolvedType>,
        instantiations: Vec<Instantiation>,
    ) -> Gathered {
        let mut ir = CompilerIr::empty(UnitRef {
            unit: format!("/repo/src/{unit}"),
            file: format!("/repo/src/{unit}"),
            variant: "host".into(),
        });
        ir.anchored_at = Some("/repo".into());
        ir.symbols = symbols;
        ir.types = types;
        ir.instantiations = instantiations;
        Gathered::Analyzed {
            backend: 0,
            ir: Box::new(ir),
        }
    }

    fn read_with_calls(unit: &str, calls: Vec<CallSite>) -> Gathered {
        let mut gathered = read(unit, Vec::new(), Vec::new());
        let Gathered::Analyzed { ir, .. } = &mut gathered else {
            unreachable!("read always produces an analysis");
        };
        ir.calls = calls;
        gathered
    }

    fn call(start: u64, target: CallTarget, definition: Option<&str>) -> CallSite {
        CallSite {
            anchor: Anchor {
                expansion: SourceRange {
                    file: "include/accumulate.hpp".into(),
                    start_byte: start,
                    end_byte: start + 8,
                    start_line: 20,
                },
                definition: definition.map(|file| SourceRange {
                    file: file.into(),
                    start_byte: 10,
                    end_byte: 30,
                    start_line: 2,
                }),
            },
            target,
        }
    }

    fn typed(mut symbol: ResolvedSymbol, at: u32) -> ResolvedSymbol {
        symbol.type_index = Some(at);
        symbol
    }

    fn defined(mut symbol: ResolvedSymbol, file: &str, start: u64) -> ResolvedSymbol {
        symbol.anchor.definition = Some(SourceRange {
            file: file.into(),
            start_byte: start,
            end_byte: start + 10,
            start_line: 1,
        });
        symbol
    }

    fn integer(display: &str) -> ResolvedType {
        ResolvedType {
            display: display.into(),
            category: codehelion_helper::ir::TypeCategory::Integer,
            arguments: Vec::new(),
            definition: None,
        }
    }

    fn instantiation(key: &str, argument: u32) -> Instantiation {
        Instantiation {
            anchor: Anchor {
                expansion: SourceRange {
                    file: "include/accumulate.hpp".into(),
                    start_byte: 600,
                    end_byte: 606,
                    start_line: 20,
                },
                definition: Some(SourceRange {
                    file: "include/templates.hpp".into(),
                    start_byte: 20,
                    end_byte: 80,
                    start_line: 3,
                }),
            },
            definition: "c:@N@accumulate@FT@sum".into(),
            instantiation_key: key.into(),
            arguments: vec![argument],
        }
    }

    fn header() -> SourceUnit {
        let mut source = source("include/accumulate.hpp", Language::Cpp, None);
        source.is_header = true;
        source
    }

    fn unanswerable(source: &SourceUnit) -> Gathered {
        Gathered::Unavailable {
            backend: 0,
            unit: unit_ref(source, "host"),
            reason: Unavailability::NoBuildInformation,
        }
    }

    /// No command compiles a header, so nothing can be asked about it as a unit
    /// of its own. The unit that includes it read it, and its names are in that
    /// unit's answer — which is the only place they are.
    #[test]
    fn a_file_no_command_compiles_is_answered_by_the_unit_that_read_it() {
        let sources = [source("src/narrow.cpp", Language::Cpp, None), header()];
        let mut gathered = vec![
            read(
                "narrow.cpp",
                vec![symbol("sum", "include/accumulate.hpp", 300, 3, false)],
                Vec::new(),
            ),
            unanswerable(&sources[1]),
        ];
        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[1] else {
            panic!("the header is answered by the unit that read it");
        };
        // Filed under the header, and under the unit that read it — which is
        // the program these names were resolved in, and is not the header.
        assert_eq!(ir.unit.file, "/repo/include/accumulate.hpp");
        assert_eq!(ir.unit.unit, "/repo/src/narrow.cpp");
        assert_eq!(ir.anchored_at.as_deref(), Some("/repo"));
        assert_eq!(ir.symbols.len(), 1);
        assert_eq!(ir.symbols[0].name, "sum");
    }

    /// Two units can compile one header into two different programs. A run with
    /// one build variant has nowhere to keep both readings apart, so what it
    /// says about the header is what both agree on — and the names they differ
    /// over are left to be compared as they are written.
    #[test]
    fn what_two_readings_of_one_header_disagree_about_is_left_unsaid() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let agree = symbol("values", "include/accumulate.hpp", 400, 6, false);
        let differ = symbol("total", "include/accumulate.hpp", 500, 5, false);
        let mut gathered = vec![
            read(
                "narrow.cpp",
                vec![agree.clone(), typed(differ.clone(), 0)],
                vec![integer("unsigned int")],
            ),
            read(
                "wide.cpp",
                vec![agree, typed(differ, 0)],
                vec![integer("unsigned long long")],
            ),
            unanswerable(&sources[2]),
        ];
        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[2] else {
            panic!("the header is answered by the units that read it");
        };
        assert_eq!(
            ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>(),
            vec!["values"],
            "the name the two readings resolved differently is not reported"
        );
        // An agreement between two readings is an answer about no single unit,
        // and naming one of them would file it under that reading's program.
        assert!(ir.unit.unit.is_empty(), "{:?}", ir.unit);
        // And what did survive carries no type it never had: the table holds
        // what the kept names refer to and nothing else.
        assert!(ir.types.is_empty());
    }

    /// A macro selected differently in two translation units can stamp a name
    /// at the same bytes with the same type and definition identity. Its body
    /// anchor is still part of the answer: retaining the first reading would
    /// claim a definition site the other unit explicitly contradicts.
    #[test]
    fn macro_definition_anchors_must_agree_across_translation_units() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let stable = symbol("values", "include/accumulate.hpp", 400, 6, false);
        let expanded = symbol("total", "include/accumulate.hpp", 500, 5, false);
        let mut gathered = vec![
            read(
                "narrow.cpp",
                vec![
                    stable.clone(),
                    defined(expanded.clone(), "include/narrow_macro.hpp", 20),
                ],
                Vec::new(),
            ),
            read(
                "wide.cpp",
                vec![stable, defined(expanded, "include/wide_macro.hpp", 30)],
                Vec::new(),
            ),
            unanswerable(&sources[2]),
        ];

        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[2] else {
            panic!("the stable part of the header is still answered");
        };
        assert_eq!(
            ir.symbols
                .iter()
                .map(|symbol| &symbol.name)
                .collect::<Vec<_>>(),
            vec!["values"],
            "a representative macro definition was retained despite disagreement"
        );
    }

    /// A header can be known only through template uses, so reader discovery
    /// cannot be driven by symbols alone. The type index belongs to the first
    /// translation unit's table and must be remapped into the merged table.
    #[test]
    fn agreed_header_instantiations_are_retained_with_remapped_types() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let key = "clang-usr-v1:c:@N@accumulate@F@sum<#I>";
        let mut gathered = vec![
            read_with_instantiations(
                "narrow.cpp",
                Vec::new(),
                vec![integer("unused"), integer("int")],
                vec![instantiation(key, 1)],
            ),
            read_with_instantiations(
                "wide.cpp",
                Vec::new(),
                vec![integer("int")],
                vec![instantiation(key, 0)],
            ),
            unanswerable(&sources[2]),
        ];

        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[2] else {
            panic!("the agreed template use answers the header");
        };
        assert!(ir.symbols.is_empty());
        assert_eq!(ir.instantiations.len(), 1);
        assert_eq!(ir.instantiations[0].instantiation_key, key);
        assert_eq!(ir.instantiations[0].arguments, [0]);
        assert_eq!(ir.types.len(), 1);
        assert_eq!(ir.types[0].display, "int");
    }

    /// Picking the first translation unit would silently select one concrete
    /// specialization for a header whose build-dependent reading disagrees.
    /// With no common answer, the header stays unavailable.
    #[test]
    fn disagreeing_header_instantiations_do_not_choose_a_representative() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let mut gathered = vec![
            read_with_instantiations(
                "narrow.cpp",
                Vec::new(),
                vec![integer("int")],
                vec![instantiation("clang-usr-v1:int", 0)],
            ),
            read_with_instantiations(
                "wide.cpp",
                Vec::new(),
                vec![integer("long")],
                vec![instantiation("clang-usr-v1:long", 0)],
            ),
            unanswerable(&sources[2]),
        ];

        read_by_other_units(&mut gathered, &sources);
        assert!(
            matches!(gathered[2], Gathered::Unavailable { .. }),
            "one translation unit's specialization was selected"
        );
    }

    /// Header calls are useful only when every translation unit reports the
    /// same macro-aware anchor and exact target. A stable direct call survives;
    /// overload and macro-definition disagreements are omitted instead of
    /// selecting whichever translation unit happened to be first.
    #[test]
    fn header_calls_survive_only_exact_translation_unit_agreement() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let stable = call(
            700,
            CallTarget::Static {
                symbol: "c:@F@stable#I#".into(),
            },
            None,
        );
        let selected = call(
            800,
            CallTarget::Static {
                symbol: "c:@F@choose#I#".into(),
            },
            None,
        );
        let expanded = call(
            900,
            CallTarget::Static {
                symbol: "c:@F@macro_call#I#".into(),
            },
            Some("include/first.hpp"),
        );
        let mut gathered = vec![
            read_with_calls("narrow.cpp", vec![stable.clone(), selected, expanded]),
            read_with_calls(
                "wide.cpp",
                vec![
                    stable.clone(),
                    call(
                        800,
                        CallTarget::Static {
                            symbol: "c:@F@choose#L#".into(),
                        },
                        None,
                    ),
                    call(
                        900,
                        CallTarget::Static {
                            symbol: "c:@F@macro_call#I#".into(),
                        },
                        Some("include/second.hpp"),
                    ),
                ],
            ),
            unanswerable(&sources[2]),
        ];

        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[2] else {
            panic!("the agreed call answers the header");
        };
        assert!(ir.symbols.is_empty());
        assert!(ir.instantiations.is_empty());
        assert_eq!(ir.calls, [stable]);
    }

    /// With no agreed call, choosing the first reading would turn a
    /// build-dependent overload into a false static answer.
    #[test]
    fn a_header_with_only_disagreeing_calls_stays_unavailable() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
            header(),
        ];
        let mut gathered = vec![
            read_with_calls(
                "narrow.cpp",
                vec![call(
                    800,
                    CallTarget::Static {
                        symbol: "c:@F@choose#I#".into(),
                    },
                    None,
                )],
            ),
            read_with_calls(
                "wide.cpp",
                vec![call(
                    800,
                    CallTarget::Static {
                        symbol: "c:@F@choose#L#".into(),
                    },
                    None,
                )],
            ),
            unanswerable(&sources[2]),
        ];

        read_by_other_units(&mut gathered, &sources);
        assert!(
            matches!(gathered[2], Gathered::Unavailable { .. }),
            "one translation unit's call target was selected"
        );
    }

    /// A file that is its own unit was answered about the program it actually
    /// is. Replacing that with what some other unit saw of it would be a worse
    /// answer arrived at indirectly.
    #[test]
    fn a_file_that_is_its_own_unit_keeps_the_answer_about_itself() {
        let sources = [
            source("src/narrow.cpp", Language::Cpp, None),
            source("src/wide.cpp", Language::Cpp, None),
        ];
        let mut gathered = vec![
            read(
                "narrow.cpp",
                vec![symbol("narrow_sum", "src/narrow.cpp", 80, 10, false)],
                Vec::new(),
            ),
            // A unity build: one unit includes the other's source outright.
            read(
                "wide.cpp",
                vec![symbol("narrow_sum", "src/narrow.cpp", 80, 10, true)],
                Vec::new(),
            ),
        ];
        read_by_other_units(&mut gathered, &sources);
        let Gathered::Analyzed { ir, .. } = &gathered[0] else {
            panic!("it was answered about itself");
        };
        assert!(!ir.symbols[0].external, "its own answer, not the other's");
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
