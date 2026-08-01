//! Storage for what a compiler helper answered.
//!
//! One subsystem rather than a split across the write and read modules,
//! because the compiler IR is the one part of the store whose shape is defined
//! elsewhere: [`codehelion_helper_protocol::ir`] is the contract, and the tables here
//! exist to hold it and give it back unchanged. Keeping both directions
//! together is what lets a round-trip be the test.
//!
//! What gets written is not only the answers. A unit a helper could not
//! analyse gets a row saying which reason applied, because a scan of a real
//! project always has some — a crate whose build script would have to run, a
//! file no compile command mentions — and reporting less about those is the
//! correct result rather than a failed run. Recording them as missing rows
//! would make "asked and could not" read the same as "never asked".
//!
//! The same care runs through the payload: an empty control-flow graph and a
//! helper that builds none are stored differently, as are an effect summary
//! that found nothing and one nobody computed, and a dynamic call with no
//! candidates keeps its resolution rather than collapsing into an unresolved
//! one.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_helper_protocol::ir::{
    Anchor, BasicBlock, CallSite, CallTarget, CompilerIr, ControlFlowGraph, DataFlowSummary,
    DirectPropagation, Edge, EdgeKind, EffectSummary, FallibleKind, Instantiation,
    ResolvedExpression, ResolvedSymbol, ResolvedType, SemanticConstruct, SemanticConstructKind,
    SourceRange, SymbolKind, TypeCategory, Unavailability, UnexpandedMacro, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper_protocol::protocol::{Capability, Execution, HelperIdentity};
use rusqlite::{Row, Transaction, params};

use crate::snapshot::Snapshot;
use crate::{Store, StoreError};

/// The detector-version component a run declares its compiler IR schema under.
///
/// Declared by the run rather than by the build that made it: a run holds a
/// schema only if a compiler answered something about the tree, which is not
/// known until the tree has been read.
pub const IR_SCHEMA_COMPONENT: &str = "compiler_ir";

/// A compiler helper that took part in a run, as it described itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerHelperRow {
    /// What the helper said about itself at handshake.
    pub identity: HelperIdentity,
    /// How many times the run had to restart it, when the run counted.
    ///
    /// `None` from a run recorded before this was kept. Zero is the different
    /// claim that the helper survived the whole tree.
    pub restarts: Option<u32>,
}

/// One unit a run put to a helper, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerUnitRow {
    /// Index into [`Snapshot::compiler_helpers`] of the helper that answered.
    ///
    /// `None` for a unit ruled out before any helper was asked — nothing says
    /// how the file is compiled, or analysing it would mean running the
    /// project's own code.
    pub helper: Option<usize>,
    /// What came back.
    pub outcome: CompilerOutcome,
}

/// Either an analysis or the reason there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompilerOutcome {
    /// A compiler answered.
    Analyzed(Box<CompilerIr>),
    /// Nothing could answer, and this is why.
    Unavailable {
        /// The unit that was asked about.
        unit: UnitRef,
        /// Why there is no analysis of it.
        reason: Unavailability,
    },
}

impl CompilerOutcome {
    /// The unit this outcome is about, whichever way it went.
    #[must_use]
    pub const fn unit(&self) -> &UnitRef {
        match self {
            Self::Analyzed(ir) => &ir.unit,
            Self::Unavailable { unit, .. } => unit,
        }
    }
}

/// How much of a run a compiler could speak for, counted off the stored rows.
///
/// The three outcomes stay apart here as they do in the rows: a file a helper
/// answered, one it was given and could not answer, and one nobody was asked
/// about. Summing the last two would report a helper as having failed on files
/// it was never shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompilerCoverage {
    /// Files a compiler answered about.
    pub answered: u64,
    /// Files nobody was asked about.
    pub not_asked: u64,
    /// Files a helper was asked about and could not answer, by reason.
    pub unavailable: BTreeMap<String, u64>,
    /// How often the run had to restart a helper.
    ///
    /// `None` from a run that ran one and did not count. A run that started no
    /// helper — every file ruled out before anything was asked — restarted
    /// nothing, and says zero.
    pub restarts: Option<u32>,
}

/// A stored compiler result, with the helper that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCompilerUnit {
    /// Which helper answered, when one did.
    pub helper: Option<StoredHelperRef>,
    /// What it answered.
    pub outcome: CompilerOutcome,
}

/// How a stored unit names the helper behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHelperRef {
    /// Helper name, as `doctor` reports it.
    pub name: String,
    /// Helper version.
    pub version: String,
}

/// One place a generic or template definition was instantiated.
///
/// The shape the expansion/definition anchoring exists to produce: a family
/// keyed by `instantiation_key` is one definition and every place it was
/// stamped out, which is a different claim from that many copies of one body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExpansion {
    /// The unit the expansion sits in.
    pub unit: UnitRef,
    /// The generic or template it came from.
    pub definition: String,
    /// Where it sits, and where it was written.
    pub anchor: Anchor,
}

impl Store {
    /// Every compiler helper that took part in `run_id`, in name order.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_compiler_helpers(&self, run_id: i64) -> Result<Vec<CompilerHelperRow>, StoreError> {
        read::helpers(&self.conn, run_id)
    }

    /// Every unit `run_id` put to a compiler, answered or not, in the order
    /// they were written.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownVocabulary`] when a row names a classification
    /// this build does not know; otherwise any underlying database error.
    pub fn run_compiler_units(&self, run_id: i64) -> Result<Vec<StoredCompilerUnit>, StoreError> {
        read::units(&self.conn, run_id)
    }

    /// How much of `run_id` a compiler could speak for, or `None` when the run
    /// put nothing to one.
    ///
    /// Counted in the database rather than by reading the units back: the
    /// answer is four numbers and the rows behind them carry every symbol and
    /// type a compiler resolved.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_compiler_coverage(
        &self,
        run_id: i64,
    ) -> Result<Option<CompilerCoverage>, StoreError> {
        read::coverage(&self.conn, run_id)
    }

    /// Every expansion of `key` recorded by `run_id`.
    ///
    /// Answered through the index on `instantiation_key`, which is not scoped
    /// to a unit: the family is exactly the thing that spans them.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn instantiation_family(
        &self,
        run_id: i64,
        key: &str,
    ) -> Result<Vec<StoredExpansion>, StoreError> {
        read::family(&self.conn, run_id, key)
    }
}

mod read;
mod write;

pub(crate) fn write(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
) -> Result<BTreeSet<String>, StoreError> {
    write::write(tx, snapshot, run_id, variant_id)
}

/// The anchor stored in eight consecutive columns starting at `first`.
fn anchor_at(row: &Row<'_>, first: usize) -> rusqlite::Result<Anchor> {
    let expansion = SourceRange {
        file: row.get(first)?,
        start_byte: read::extent(row.get(first + 1)?),
        end_byte: read::extent(row.get(first + 2)?),
        start_line: line(row.get(first + 3)?),
    };
    let file: Option<String> = row.get(first + 4)?;
    let definition = match file {
        None => None,
        Some(file) => Some(SourceRange {
            file,
            start_byte: read::extent(row.get(first + 5)?),
            end_byte: read::extent(row.get(first + 6)?),
            start_line: line(row.get(first + 7)?),
        }),
    };
    Ok(Anchor {
        expansion,
        definition,
    })
}

/// A stored line number back in its own width.
fn line(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
