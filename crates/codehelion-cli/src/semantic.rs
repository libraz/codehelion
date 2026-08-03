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
use std::path::{Path, PathBuf};
use std::time::Duration;

use codehelion_core::discovery::{Language, SourceUnit};
use codehelion_core::engine::normalize::Resolution;
use codehelion_core::ir::ByteRange;
use codehelion_core::semantic::{
    ApiNormalization, ConstructObservation, DirectPropagation as CoreDirectPropagation,
    FallibleKind as CoreFallibleKind, OperationKind, OperationObservation, SemanticGraphError,
    SemanticSourceRange, normalize_registered_observations_with_ranges,
};
use codehelion_core::types::TypeTag;
use codehelion_helper::ir::{
    CallSite, CallTarget, CompilerIr, DirectPropagation as HelperDirectPropagation,
    FallibleKind as HelperFallibleKind, Instantiation, ResolvedExpression, ResolvedSymbol,
    ResolvedType, SemanticConstructKind, Unavailability, UnexpandedMacro, UnitRef,
};
use codehelion_helper::protocol::{Capability, CompileCommandSelector, Execution, HelperIdentity};
use codehelion_helper::{Analysis, SandboxRequest, Supervisor};

/// Everything a run can use from a compiler.
///
/// Asked for as one set: a helper narrows the request to what it said it
/// offers, so asking for more than one helper supplies costs nothing and
/// stops the request from being the place a capability is forgotten.
pub(crate) const WANTED: [Capability; 6] = [
    Capability::Types,
    Capability::NameResolution,
    Capability::CallTargets,
    Capability::MirCfg,
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
        /// Bounded diagnostic output from the helper that failed this unit.
        diagnostics: Vec<String>,
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

pub(crate) mod resolution;

pub(crate) use resolution::{registered_sog_in_range, resolved_api_for, resolved_types_for};

#[cfg(test)]
use resolution::registered_sog_for;

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
    /// The containment policy every process for this backend must satisfy.
    pub(crate) sandbox: SandboxRequest,
    /// Boundary for paths the helper may read from a compilation command.
    pub(crate) read_boundary: Option<&'a Path>,
}

/// One helper that took part, as it described itself.
#[derive(Debug, Clone)]
pub(crate) struct Answered {
    /// What it said about itself at the handshake.
    pub(crate) identity: HelperIdentity,
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

/// Ask helpers with the exact compile commands selected for this partition.
///
/// Only C and C++ source paths appear in `commands`; Rust units keep their
/// crate-derived identity and have no compilation-database entry to select.
pub(crate) fn ask_with_commands(
    backends: &[Backend<'_>],
    sources: &[SourceUnit],
    variant: &str,
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    timeout: Duration,
) -> Answers {
    let mut supervisors: Vec<Supervisor> = backends
        .iter()
        .map(|backend| {
            Supervisor::new(backend.program.to_path_buf(), Vec::new(), timeout)
                .permitting(backend.permitted.to_vec())
                .sandboxed(backend.sandbox)
        })
        .collect();
    let analyzes: Vec<&[Language]> = backends.iter().map(|backend| backend.analyzes).collect();
    let mut gathered = gather(
        &analyzes,
        sources,
        variant,
        commands,
        &mut |backend, unit, command| {
            let Some(helper) = supervisors.get_mut(backend) else {
                return (Analysis::Missing(Unavailability::NotSupported), Vec::new());
            };
            let analysis = helper.analyze_with_command_and_boundary(
                unit,
                command,
                backends[backend].read_boundary,
                &WANTED,
            );
            (analysis, helper.take_diagnostics())
        },
    );
    read_by_other_units(&mut gathered, sources);
    // A backend that never said who it was leaves no row to point at, so the
    // rows are compacted and what the answers point at is moved with them.
    let mut helpers = Vec::new();
    let mut row = Vec::with_capacity(supervisors.len());
    for supervisor in &mut supervisors {
        let restarts = supervisor.restarts();
        let answered = supervisor.spoke_with().map(|identity| Answered {
            identity: identity.clone(),
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
        diagnostics: Vec<String>,
    },
    NotAsked {
        unit: UnitRef,
        reason: Unavailability,
    },
}

type AskOne<'a> =
    dyn FnMut(usize, &UnitRef, Option<&CompileCommandSelector>) -> (Analysis, Vec<String>) + 'a;

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
                diagnostics,
            } => Answer::Unavailable {
                helper: at(backend),
                unit,
                reason,
                diagnostics,
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
    commands: &BTreeMap<PathBuf, CompileCommandSelector>,
    ask_one: &mut AskOne<'_>,
) -> Vec<Gathered> {
    sources
        .iter()
        .map(|source| {
            let command = commands.get(&source.absolute_path);
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
            let (analysis, diagnostics) = ask_one(backend, &unit, command);
            match analysis {
                Analysis::Done(ir) => Gathered::Analyzed { backend, ir },
                Analysis::Missing(reason) => Gathered::Unavailable {
                    backend,
                    unit,
                    reason,
                    diagnostics,
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
        for expression in &ir.expressions {
            let file = expression.anchor.expansion.file.as_str();
            if seen.insert(file) {
                readers
                    .entry((root, file))
                    .or_default()
                    .push((*backend, ir));
            }
        }
        for macro_ in &ir.unexpanded_macros {
            let file = macro_.invocation.file.as_str();
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
        if !source.is_header {
            continue;
        }
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
/// `None` when no symbol, instantiation, call, expression, or unexpanded macro survived,
/// which is a file its readers say nothing common about — reported as
/// unanswerable rather than as an analysis that found nothing, because those
/// are different claims.
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
    let mut expressions = expressions_in(first, first_file);
    for (_, ir, file) in readings.iter().skip(1) {
        let other = expressions_in(ir, file);
        expressions.retain(|at, held| {
            other
                .get(at)
                .is_some_and(|found| same_expression(ir, found, first, held))
        });
    }
    let mut unexpanded_macros = unexpanded_macros_in(first, first_file);
    for (_, ir, file) in readings.iter().skip(1) {
        let other = unexpanded_macros_in(ir, file);
        unexpanded_macros.retain(|at, held| other.get(at).is_some_and(|found| *found == *held));
    }
    if kept.is_empty()
        && instantiations.is_empty()
        && calls.is_empty()
        && expressions.is_empty()
        && unexpanded_macros.is_empty()
    {
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
    merged.expressions = expressions
        .into_values()
        .filter_map(|expression| {
            Some(ResolvedExpression {
                anchor: expression.anchor.clone(),
                type_index: types.copy(first, expression.type_index)?,
            })
        })
        .collect();
    merged.unexpanded_macros = unexpanded_macros.into_values().cloned().collect();
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

/// Expression types written in `file`, lined up by the observable invocation
/// range. Their type is deliberately a value rather than a key: a type that
/// changes across translation units is a disagreement, not another expression.
fn expressions_in<'a>(
    ir: &'a CompilerIr,
    file: &str,
) -> BTreeMap<(u64, u64), &'a ResolvedExpression> {
    ir.expressions
        .iter()
        .filter(|expression| expression.anchor.expansion.file == file)
        .map(|expression| {
            (
                (
                    expression.anchor.expansion.start_byte,
                    expression.anchor.expansion.end_byte,
                ),
                expression,
            )
        })
        .collect()
}

/// Whether two readers gave an expanded expression the same type and origin.
fn same_expression(
    ir: &CompilerIr,
    expression: &ResolvedExpression,
    against: &CompilerIr,
    held: &ResolvedExpression,
) -> bool {
    let resolved = |ir: &CompilerIr, expression: &ResolvedExpression| {
        ir.types
            .get(usize::try_from(expression.type_index).ok()?)
            .map(|ty| (ty.display.clone(), ty.category))
    };
    expression.anchor.definition == held.anchor.definition
        && resolved(ir, expression) == resolved(against, held)
}

/// Unexpanded macro invocations written in `file`, lined up by their source
/// range. The reason stays a value so differing coverage reports contradict
/// each other instead of appearing as independent invocations.
fn unexpanded_macros_in<'a>(
    ir: &'a CompilerIr,
    file: &str,
) -> BTreeMap<(u64, u64), &'a UnexpandedMacro> {
    ir.unexpanded_macros
        .iter()
        .filter(|macro_| macro_.invocation.file == file)
        .map(|macro_| {
            (
                (macro_.invocation.start_byte, macro_.invocation.end_byte),
                macro_,
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
mod tests;
