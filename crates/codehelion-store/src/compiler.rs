//! Storage for what a compiler helper answered.
//!
//! One subsystem rather than a split across the write and read modules,
//! because the compiler IR is the one part of the store whose shape is defined
//! elsewhere: [`codehelion_helper::ir`] is the contract, and the tables here
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

use std::collections::BTreeSet;

use codehelion_helper::ir::{
    Anchor, BasicBlock, CallSite, CallTarget, CompilerIr, ControlFlowGraph, DataFlowSummary, Edge,
    EdgeKind, EffectSummary, Instantiation, ResolvedSymbol, ResolvedType, SourceRange, SymbolKind,
    TypeCategory, Unavailability, UnitRef,
};
use codehelion_helper::protocol::{Capability, HelperIdentity};
use rusqlite::{Row, Transaction, params};

use crate::snapshot::Snapshot;
use crate::{Store, StoreError};

/// A compiler helper that took part in a run, as it described itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerHelperRow {
    /// What the helper said about itself at handshake.
    pub identity: HelperIdentity,
    /// The protocol revision the two sides settled on, which is the highest
    /// both could speak and so is not derivable from either range alone.
    pub protocol_agreed: u32,
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

/// Write a run's compiler results, returning the distinct IR schema versions
/// they were written against.
///
/// The versions come back rather than being recorded here so the caller can
/// declare them as detector versions of the run: a run holding IR from a
/// schema this build no longer reads has to be recognisable as such, and the
/// stored rows say which schema each unit used but nothing at run level does.
pub(crate) fn write(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
) -> Result<BTreeSet<String>, StoreError> {
    let helper_ids = write_helpers(tx, &snapshot.compiler_helpers, run_id)?;
    let mut schemas = BTreeSet::new();
    for row in &snapshot.compiler_units {
        let helper_id =
            match row.helper {
                None => None,
                Some(index) => Some(*helper_ids.get(index).ok_or(
                    StoreError::UnknownHelperIndex {
                        index,
                        helpers: helper_ids.len(),
                    },
                )?),
            };
        let unit_id = write_unit_row(tx, &row.outcome, run_id, variant_id, helper_id)?;
        if let CompilerOutcome::Analyzed(ir) = &row.outcome {
            schemas.insert(ir.schema_version.clone());
            write_payload(tx, ir, unit_id)?;
        }
    }
    Ok(schemas)
}

/// Record the helpers, returning their row ids by snapshot index.
fn write_helpers(
    tx: &Transaction<'_>,
    helpers: &[CompilerHelperRow],
    run_id: i64,
) -> Result<Vec<i64>, StoreError> {
    let mut ids = Vec::with_capacity(helpers.len());
    for helper in helpers {
        tx.execute(
            "INSERT INTO compiler_helper
                 (scan_run_id, name, version, protocol_min, protocol_max, protocol_agreed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id,
                helper.identity.name,
                helper.identity.version,
                i64::from(helper.identity.protocol.min),
                i64::from(helper.identity.protocol.max),
                i64::from(helper.protocol_agreed),
            ],
        )?;
        let id = tx.last_insert_rowid();
        for capability in &helper.identity.capabilities {
            tx.execute(
                "INSERT OR IGNORE INTO compiler_helper_capability
                     (compiler_helper_id, capability) VALUES (?1, ?2)",
                params![id, capability_name(*capability)],
            )?;
        }
        for toolchain in &helper.identity.toolchains {
            tx.execute(
                "INSERT OR IGNORE INTO compiler_helper_toolchain
                     (compiler_helper_id, toolchain) VALUES (?1, ?2)",
                params![id, toolchain],
            )?;
        }
        ids.push(id);
    }
    Ok(ids)
}

/// Write the `compiler_unit` row and return its id.
fn write_unit_row(
    tx: &Transaction<'_>,
    outcome: &CompilerOutcome,
    run_id: i64,
    variant_id: i64,
    helper_id: Option<i64>,
) -> Result<i64, StoreError> {
    let unit = outcome.unit();
    let (schema, reason, cfg, effects, flows) = match outcome {
        CompilerOutcome::Analyzed(ir) => (
            Some(ir.schema_version.as_str()),
            None,
            ir.cfg.is_some(),
            ir.effects.computed,
            ir.data_flow.computed,
        ),
        CompilerOutcome::Unavailable { reason, .. } => (
            None,
            Some(unavailability_name(*reason)),
            false,
            false,
            false,
        ),
    };
    tx.execute(
        "INSERT INTO compiler_unit
             (scan_run_id, build_variant_id, compiler_helper_id, unit_name, file_path,
              variant_key, schema_version, unavailable_reason, has_cfg, effects_computed,
              data_flow_computed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            run_id,
            variant_id,
            helper_id,
            unit.unit,
            unit.file,
            unit.variant,
            schema,
            reason,
            i64::from(cfg),
            i64::from(effects),
            i64::from(flows),
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Write everything hanging off one analysed unit.
fn write_payload(tx: &Transaction<'_>, ir: &CompilerIr, unit_id: i64) -> Result<(), StoreError> {
    // Types first: symbols and instantiations reference them by index.
    write_types(tx, &ir.types, unit_id)?;
    write_symbols(tx, &ir.symbols, unit_id)?;
    write_calls(tx, &ir.calls, unit_id)?;
    if let Some(cfg) = &ir.cfg {
        write_cfg(tx, cfg, unit_id)?;
    }
    write_instantiations(tx, &ir.instantiations, unit_id)?;
    write_effects(tx, &ir.effects, unit_id)?;
    write_data_flow(tx, &ir.data_flow, unit_id)?;
    Ok(())
}

fn write_types(
    tx: &Transaction<'_>,
    types: &[ResolvedType],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (index, resolved) in types.iter().enumerate() {
        let index = index_of(index);
        tx.execute(
            "INSERT INTO compiler_type
                 (compiler_unit_id, type_index, display, category, definition)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                unit_id,
                index,
                resolved.display,
                category_name(resolved.category),
                resolved.definition,
            ],
        )?;
        for (position, argument) in resolved.arguments.iter().enumerate() {
            tx.execute(
                "INSERT INTO compiler_type_argument
                     (compiler_unit_id, type_index, position, argument_index)
                 VALUES (?1, ?2, ?3, ?4)",
                params![unit_id, index, index_of(position), i64::from(*argument)],
            )?;
        }
    }
    Ok(())
}

fn write_symbols(
    tx: &Transaction<'_>,
    symbols: &[ResolvedSymbol],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, symbol) in symbols.iter().enumerate() {
        let cells = AnchorCells::of(&symbol.anchor);
        tx.execute(
            "INSERT INTO compiler_symbol
                 (compiler_unit_id, ordinal, symbol_id, name, symbol_kind, type_index, external,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                unit_id,
                index_of(ordinal),
                symbol.id,
                symbol.name,
                symbol_kind_name(symbol.kind),
                symbol.type_index.map(i64::from),
                i64::from(symbol.external),
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line,
            ],
        )?;
    }
    Ok(())
}

fn write_calls(tx: &Transaction<'_>, sites: &[CallSite], unit_id: i64) -> Result<(), StoreError> {
    for (ordinal, call) in sites.iter().enumerate() {
        let cells = AnchorCells::of(&call.anchor);
        let (resolution, target) = match &call.target {
            CallTarget::Static { symbol } => ("static", Some(symbol.as_str())),
            CallTarget::Dynamic { .. } => ("dynamic", None),
            CallTarget::Unresolved => ("unresolved", None),
        };
        tx.execute(
            "INSERT INTO compiler_call
                 (compiler_unit_id, ordinal, resolution, target_symbol,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                unit_id,
                index_of(ordinal),
                resolution,
                target,
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line,
            ],
        )?;
        if let CallTarget::Dynamic { candidates } = &call.target {
            let call_id = tx.last_insert_rowid();
            for (position, candidate) in candidates.iter().enumerate() {
                tx.execute(
                    "INSERT INTO compiler_call_candidate (compiler_call_id, position, symbol)
                     VALUES (?1, ?2, ?3)",
                    params![call_id, index_of(position), candidate],
                )?;
            }
        }
    }
    Ok(())
}

fn write_cfg(tx: &Transaction<'_>, cfg: &ControlFlowGraph, unit_id: i64) -> Result<(), StoreError> {
    for (index, block) in cfg.blocks.iter().enumerate() {
        let cells = AnchorCells::of(&block.anchor);
        tx.execute(
            "INSERT INTO compiler_block
                 (compiler_unit_id, block_index, length,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                unit_id,
                index_of(index),
                i64::from(block.length),
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line,
            ],
        )?;
    }
    for (ordinal, edge) in cfg.edges.iter().enumerate() {
        tx.execute(
            "INSERT INTO compiler_edge
                 (compiler_unit_id, ordinal, from_block, to_block, edge_kind)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                unit_id,
                index_of(ordinal),
                i64::from(edge.from),
                i64::from(edge.to),
                edge_kind_name(edge.kind),
            ],
        )?;
    }
    Ok(())
}

fn write_instantiations(
    tx: &Transaction<'_>,
    instantiations: &[Instantiation],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, instantiation) in instantiations.iter().enumerate() {
        let cells = AnchorCells::of(&instantiation.anchor);
        tx.execute(
            "INSERT INTO compiler_instantiation
                 (compiler_unit_id, ordinal, definition, instantiation_key,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                unit_id,
                index_of(ordinal),
                instantiation.definition,
                instantiation.instantiation_key,
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line,
            ],
        )?;
        let row_id = tx.last_insert_rowid();
        for (position, argument) in instantiation.arguments.iter().enumerate() {
            tx.execute(
                "INSERT INTO compiler_instantiation_argument
                     (compiler_instantiation_id, position, type_index)
                 VALUES (?1, ?2, ?3)",
                params![row_id, index_of(position), i64::from(*argument)],
            )?;
        }
    }
    Ok(())
}

/// Write the effect summary's contents, whose order across the two kinds is
/// recovered from the ordinal.
fn write_effects(
    tx: &Transaction<'_>,
    effects: &EffectSummary,
    unit_id: i64,
) -> Result<(), StoreError> {
    let writes = effects.writes.iter().map(|subject| ("write", subject));
    let interactions = effects
        .interactions
        .iter()
        .map(|subject| ("interaction", subject));
    for (ordinal, (kind, subject)) in writes.chain(interactions).enumerate() {
        tx.execute(
            "INSERT INTO compiler_effect (compiler_unit_id, ordinal, effect_kind, subject)
             VALUES (?1, ?2, ?3, ?4)",
            params![unit_id, index_of(ordinal), kind, subject],
        )?;
    }
    Ok(())
}

fn write_data_flow(
    tx: &Transaction<'_>,
    data_flow: &DataFlowSummary,
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, (source, sink)) in data_flow.flows.iter().enumerate() {
        tx.execute(
            "INSERT INTO compiler_data_flow
                 (compiler_unit_id, ordinal, source_symbol, sink_symbol)
             VALUES (?1, ?2, ?3, ?4)",
            params![unit_id, index_of(ordinal), source, sink],
        )?;
    }
    Ok(())
}

/// The eight columns an anchored row stores, in the types they store as.
struct AnchorCells<'a> {
    file: &'a str,
    start_byte: i64,
    end_byte: i64,
    start_line: i64,
    definition_file: Option<&'a str>,
    definition_start_byte: Option<i64>,
    definition_end_byte: Option<i64>,
    definition_start_line: Option<i64>,
}

impl<'a> AnchorCells<'a> {
    fn of(anchor: &'a Anchor) -> Self {
        Self {
            file: &anchor.expansion.file,
            start_byte: offset(anchor.expansion.start_byte),
            end_byte: offset(anchor.expansion.end_byte),
            start_line: i64::from(anchor.expansion.start_line),
            definition_file: anchor.definition.as_ref().map(|site| site.file.as_str()),
            definition_start_byte: anchor
                .definition
                .as_ref()
                .map(|site| offset(site.start_byte)),
            definition_end_byte: anchor.definition.as_ref().map(|site| offset(site.end_byte)),
            definition_start_line: anchor
                .definition
                .as_ref()
                .map(|site| i64::from(site.start_line)),
        }
    }
}

/// A byte offset as the column stores it. Saturating rather than failing: no
/// source file reaches the boundary, and a write that refused a whole run over
/// one impossible offset would be the worse outcome.
fn offset(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A position in a list as the column stores it.
fn index_of(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

const fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::Types => "types",
        Capability::CallTargets => "call_targets",
        Capability::MirCfg => "mir_cfg",
        Capability::MacroExpansion => "macro_expansion",
        Capability::TemplateInstantiation => "template_instantiation",
        Capability::OverloadResolution => "overload_resolution",
        Capability::Unknown => "unknown",
    }
}

const fn unavailability_name(reason: Unavailability) -> &'static str {
    match reason {
        Unavailability::RequiresExecution => "requires_execution",
        Unavailability::NoBuildInformation => "no_build_information",
        Unavailability::ToolchainMismatch => "toolchain_mismatch",
        Unavailability::HelperTimedOut => "helper_timed_out",
        Unavailability::HelperDied => "helper_died",
        Unavailability::UnreadableSchema => "unreadable_schema",
        Unavailability::NotSupported => "not_supported",
    }
}

const fn category_name(category: TypeCategory) -> &'static str {
    match category {
        TypeCategory::Integer => "integer",
        TypeCategory::Float => "float",
        TypeCategory::Boolean => "boolean",
        TypeCategory::Character => "character",
        TypeCategory::Text => "text",
        TypeCategory::Handle => "handle",
        TypeCategory::Sequence => "sequence",
        TypeCategory::Mapping => "mapping",
        TypeCategory::Tuple => "tuple",
        TypeCategory::Record => "record",
        TypeCategory::Enumeration => "enumeration",
        TypeCategory::Interface => "interface",
        TypeCategory::Callable => "callable",
        TypeCategory::Parameter => "parameter",
        TypeCategory::Nothing => "nothing",
        TypeCategory::Unresolved => "unresolved",
    }
}

const fn symbol_kind_name(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "function",
        SymbolKind::Type => "type",
        SymbolKind::Field => "field",
        SymbolKind::Variant => "variant",
        SymbolKind::Binding => "binding",
        SymbolKind::Constant => "constant",
        SymbolKind::Namespace => "namespace",
        SymbolKind::Other => "other",
    }
}

const fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Flow => "flow",
        EdgeKind::Taken => "taken",
        EdgeKind::NotTaken => "not_taken",
        EdgeKind::Unwind => "unwind",
        EdgeKind::Return => "return",
    }
}

/// Reading stored compiler results back into the shape they were written from.
mod read {
    use std::collections::BTreeMap;

    use rusqlite::Connection;

    use super::{
        BasicBlock, CallSite, CallTarget, Capability, CompilerHelperRow, CompilerIr,
        CompilerOutcome, ControlFlowGraph, DataFlowSummary, Edge, EdgeKind, EffectSummary,
        HelperIdentity, Instantiation, ResolvedSymbol, ResolvedType, Row, StoreError,
        StoredCompilerUnit, StoredExpansion, StoredHelperRef, SymbolKind, TypeCategory,
        Unavailability, UnitRef, anchor_at, params,
    };
    use codehelion_helper::protocol::VersionRange;

    pub(super) fn helpers(
        conn: &Connection,
        run_id: i64,
    ) -> Result<Vec<CompilerHelperRow>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT id, name, version, protocol_min, protocol_max, protocol_agreed
             FROM compiler_helper WHERE scan_run_id = ?1 ORDER BY name, version",
        )?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut helpers = Vec::with_capacity(rows.len());
        for (id, name, version, min, max, agreed) in rows {
            helpers.push(CompilerHelperRow {
                identity: HelperIdentity {
                    name,
                    version,
                    protocol: VersionRange {
                        min: revision(min),
                        max: revision(max),
                    },
                    toolchains: strings(
                        conn,
                        "SELECT toolchain FROM compiler_helper_toolchain
                         WHERE compiler_helper_id = ?1 ORDER BY toolchain",
                        id,
                    )?,
                    capabilities: capabilities(conn, id)?,
                },
                protocol_agreed: revision(agreed),
            });
        }
        Ok(helpers)
    }

    pub(super) fn units(
        conn: &Connection,
        run_id: i64,
    ) -> Result<Vec<StoredCompilerUnit>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT u.id, u.unit_name, u.file_path, u.variant_key, u.schema_version,
                    u.unavailable_reason, u.has_cfg, u.effects_computed, u.data_flow_computed,
                    h.name, h.version
             FROM compiler_unit u
             LEFT JOIN compiler_helper h ON h.id = u.compiler_helper_id
             WHERE u.scan_run_id = ?1 ORDER BY u.id",
        )?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    UnitRef {
                        unit: row.get(1)?,
                        file: row.get(2)?,
                        variant: row.get(3)?,
                    },
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    (
                        row.get::<_, i64>(6)? != 0,
                        row.get::<_, i64>(7)? != 0,
                        row.get::<_, i64>(8)? != 0,
                    ),
                    helper_ref(row)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut units = Vec::with_capacity(rows.len());
        for (id, unit, schema, reason, flags, helper) in rows {
            let outcome = match (schema, reason) {
                (Some(schema), _) => {
                    CompilerOutcome::Analyzed(Box::new(payload(conn, id, unit, schema, flags)?))
                }
                (None, Some(reason)) => CompilerOutcome::Unavailable {
                    unit,
                    reason: unavailability(&reason)?,
                },
                // The schema forbids it; a database that arrives here anyway
                // is reported rather than guessed at.
                (None, None) => {
                    return Err(StoreError::UnknownVocabulary {
                        field: "unavailable_reason",
                        value: String::new(),
                    });
                }
            };
            units.push(StoredCompilerUnit { helper, outcome });
        }
        Ok(units)
    }

    pub(super) fn family(
        conn: &Connection,
        run_id: i64,
        key: &str,
    ) -> Result<Vec<StoredExpansion>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT u.unit_name, u.file_path, u.variant_key, i.definition,
                    i.expansion_file, i.expansion_start_byte, i.expansion_end_byte,
                    i.expansion_start_line, i.definition_file, i.definition_start_byte,
                    i.definition_end_byte, i.definition_start_line
             FROM compiler_instantiation i
             JOIN compiler_unit u ON u.id = i.compiler_unit_id
             WHERE i.instantiation_key = ?1 AND u.scan_run_id = ?2
             ORDER BY i.id",
        )?;
        let rows = statement
            .query_map(params![key, run_id], |row| {
                Ok(StoredExpansion {
                    unit: UnitRef {
                        unit: row.get(0)?,
                        file: row.get(1)?,
                        variant: row.get(2)?,
                    },
                    definition: row.get(3)?,
                    anchor: anchor_at(row, 4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Everything hanging off one analysed unit.
    fn payload(
        conn: &Connection,
        id: i64,
        unit: UnitRef,
        schema_version: String,
        flags: (bool, bool, bool),
    ) -> Result<CompilerIr, StoreError> {
        let (has_cfg, effects_computed, data_flow_computed) = flags;
        Ok(CompilerIr {
            schema_version,
            unit,
            symbols: symbols(conn, id)?,
            types: types(conn, id)?,
            calls: calls(conn, id)?,
            cfg: if has_cfg { Some(cfg(conn, id)?) } else { None },
            instantiations: instantiations(conn, id)?,
            effects: effects(conn, id, effects_computed)?,
            data_flow: data_flow(conn, id, data_flow_computed)?,
        })
    }

    fn types(conn: &Connection, id: i64) -> Result<Vec<ResolvedType>, StoreError> {
        let mut arguments: BTreeMap<i64, Vec<u32>> = BTreeMap::new();
        let mut statement = conn.prepare(
            "SELECT type_index, argument_index FROM compiler_type_argument
             WHERE compiler_unit_id = ?1 ORDER BY type_index, position",
        )?;
        for row in statement.query_map([id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (index, argument) = row?;
            arguments.entry(index).or_default().push(slot(argument));
        }
        let mut statement = conn.prepare(
            "SELECT type_index, display, category, definition FROM compiler_type
             WHERE compiler_unit_id = ?1 ORDER BY type_index",
        )?;
        let rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(index, display, name, definition)| {
                Ok(ResolvedType {
                    display,
                    category: category(&name)?,
                    arguments: arguments.remove(&index).unwrap_or_default(),
                    definition,
                })
            })
            .collect()
    }

    fn symbols(conn: &Connection, id: i64) -> Result<Vec<ResolvedSymbol>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT symbol_id, name, symbol_kind, type_index, external,
                    expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_symbol WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    anchor_at(row, 5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(symbol_id, name, kind, type_index, external, anchor)| {
                Ok(ResolvedSymbol {
                    id: symbol_id,
                    name,
                    kind: symbol_kind(&kind)?,
                    anchor,
                    type_index: type_index.map(slot),
                    external,
                })
            })
            .collect()
    }

    fn calls(conn: &Connection, id: i64) -> Result<Vec<CallSite>, StoreError> {
        let mut candidates: BTreeMap<i64, Vec<String>> = BTreeMap::new();
        let mut statement = conn.prepare(
            "SELECT c.compiler_call_id, c.symbol FROM compiler_call_candidate c
             JOIN compiler_call k ON k.id = c.compiler_call_id
             WHERE k.compiler_unit_id = ?1 ORDER BY c.compiler_call_id, c.position",
        )?;
        for row in statement.query_map([id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })? {
            let (call_id, symbol) = row?;
            candidates.entry(call_id).or_default().push(symbol);
        }
        let mut statement = conn.prepare(
            "SELECT id, resolution, target_symbol,
                    expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_call WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    anchor_at(row, 3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(call_id, resolution, target, anchor)| {
                let target = match (resolution.as_str(), target) {
                    ("static", Some(symbol)) => CallTarget::Static { symbol },
                    ("dynamic", _) => CallTarget::Dynamic {
                        candidates: candidates.remove(&call_id).unwrap_or_default(),
                    },
                    ("unresolved", _) => CallTarget::Unresolved,
                    _ => {
                        return Err(StoreError::UnknownVocabulary {
                            field: "resolution",
                            value: resolution,
                        });
                    }
                };
                Ok(CallSite { anchor, target })
            })
            .collect()
    }

    fn cfg(conn: &Connection, id: i64) -> Result<ControlFlowGraph, StoreError> {
        let mut statement = conn.prepare(
            "SELECT length, expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_block WHERE compiler_unit_id = ?1 ORDER BY block_index",
        )?;
        let blocks = statement
            .query_map([id], |row| {
                Ok(BasicBlock {
                    length: slot(row.get::<_, i64>(0)?),
                    anchor: anchor_at(row, 1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut statement = conn.prepare(
            "SELECT from_block, to_block, edge_kind FROM compiler_edge
             WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let edges = rows
            .into_iter()
            .map(|(from, to, kind)| {
                Ok(Edge {
                    from: slot(from),
                    to: slot(to),
                    kind: edge_kind(&kind)?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(ControlFlowGraph { blocks, edges })
    }

    fn instantiations(conn: &Connection, id: i64) -> Result<Vec<Instantiation>, StoreError> {
        let mut arguments: BTreeMap<i64, Vec<u32>> = BTreeMap::new();
        let mut statement = conn.prepare(
            "SELECT a.compiler_instantiation_id, a.type_index
             FROM compiler_instantiation_argument a
             JOIN compiler_instantiation i ON i.id = a.compiler_instantiation_id
             WHERE i.compiler_unit_id = ?1
             ORDER BY a.compiler_instantiation_id, a.position",
        )?;
        for row in statement.query_map([id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (row_id, argument) = row?;
            arguments.entry(row_id).or_default().push(slot(argument));
        }
        let mut statement = conn.prepare(
            "SELECT id, definition, instantiation_key,
                    expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_instantiation WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([id], |row| {
                let row_id: i64 = row.get(0)?;
                Ok(Instantiation {
                    definition: row.get(1)?,
                    instantiation_key: row.get(2)?,
                    anchor: anchor_at(row, 3)?,
                    arguments: arguments.remove(&row_id).unwrap_or_default(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn effects(conn: &Connection, id: i64, computed: bool) -> Result<EffectSummary, StoreError> {
        let mut summary = EffectSummary {
            computed,
            ..EffectSummary::default()
        };
        let mut statement = conn.prepare(
            "SELECT effect_kind, subject FROM compiler_effect
             WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (kind, subject) in rows {
            match kind.as_str() {
                "write" => summary.writes.push(subject),
                "interaction" => summary.interactions.push(subject),
                _ => {
                    return Err(StoreError::UnknownVocabulary {
                        field: "effect_kind",
                        value: kind,
                    });
                }
            }
        }
        Ok(summary)
    }

    fn data_flow(
        conn: &Connection,
        id: i64,
        computed: bool,
    ) -> Result<DataFlowSummary, StoreError> {
        let mut statement = conn.prepare(
            "SELECT source_symbol, sink_symbol FROM compiler_data_flow
             WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
        let flows = statement
            .query_map([id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DataFlowSummary { computed, flows })
    }

    fn capabilities(conn: &Connection, id: i64) -> Result<Vec<Capability>, StoreError> {
        let names = strings(
            conn,
            "SELECT capability FROM compiler_helper_capability
             WHERE compiler_helper_id = ?1 ORDER BY capability",
            id,
        )?;
        Ok(names.iter().map(|name| capability(name)).collect())
    }

    fn strings(conn: &Connection, sql: &str, id: i64) -> Result<Vec<String>, StoreError> {
        let mut statement = conn.prepare(sql)?;
        let rows = statement
            .query_map([id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn helper_ref(row: &Row<'_>) -> rusqlite::Result<Option<StoredHelperRef>> {
        let name: Option<String> = row.get(9)?;
        let version: Option<String> = row.get(10)?;
        Ok(name
            .zip(version)
            .map(|(name, version)| StoredHelperRef { name, version }))
    }

    /// A capability name as this build reads it. An unrecognised one folds
    /// into `Unknown` rather than failing, the same way the handshake does:
    /// a newer helper may offer more than this build knows to ask for, and a
    /// stored run of it must still be readable.
    fn capability(name: &str) -> Capability {
        match name {
            "types" => Capability::Types,
            "call_targets" => Capability::CallTargets,
            "mir_cfg" => Capability::MirCfg,
            "macro_expansion" => Capability::MacroExpansion,
            "template_instantiation" => Capability::TemplateInstantiation,
            "overload_resolution" => Capability::OverloadResolution,
            _ => Capability::Unknown,
        }
    }

    fn unavailability(name: &str) -> Result<Unavailability, StoreError> {
        match name {
            "requires_execution" => Ok(Unavailability::RequiresExecution),
            "no_build_information" => Ok(Unavailability::NoBuildInformation),
            "toolchain_mismatch" => Ok(Unavailability::ToolchainMismatch),
            "helper_timed_out" => Ok(Unavailability::HelperTimedOut),
            "helper_died" => Ok(Unavailability::HelperDied),
            "unreadable_schema" => Ok(Unavailability::UnreadableSchema),
            "not_supported" => Ok(Unavailability::NotSupported),
            _ => Err(StoreError::UnknownVocabulary {
                field: "unavailable_reason",
                value: name.to_owned(),
            }),
        }
    }

    fn category(name: &str) -> Result<TypeCategory, StoreError> {
        match name {
            "integer" => Ok(TypeCategory::Integer),
            "float" => Ok(TypeCategory::Float),
            "boolean" => Ok(TypeCategory::Boolean),
            "character" => Ok(TypeCategory::Character),
            "text" => Ok(TypeCategory::Text),
            "handle" => Ok(TypeCategory::Handle),
            "sequence" => Ok(TypeCategory::Sequence),
            "mapping" => Ok(TypeCategory::Mapping),
            "tuple" => Ok(TypeCategory::Tuple),
            "record" => Ok(TypeCategory::Record),
            "enumeration" => Ok(TypeCategory::Enumeration),
            "interface" => Ok(TypeCategory::Interface),
            "callable" => Ok(TypeCategory::Callable),
            "parameter" => Ok(TypeCategory::Parameter),
            "unresolved" => Ok(TypeCategory::Unresolved),
            "nothing" => Ok(TypeCategory::Nothing),
            _ => Err(StoreError::UnknownVocabulary {
                field: "category",
                value: name.to_owned(),
            }),
        }
    }

    /// A symbol kind as this build reads it. `other` is a real value the write
    /// path produces, and an unrecognised one is not folded into it: `other`
    /// means the helper had no name for the thing, while an unknown name means
    /// a newer build did.
    fn symbol_kind(name: &str) -> Result<SymbolKind, StoreError> {
        match name {
            "function" => Ok(SymbolKind::Function),
            "type" => Ok(SymbolKind::Type),
            "field" => Ok(SymbolKind::Field),
            "variant" => Ok(SymbolKind::Variant),
            "binding" => Ok(SymbolKind::Binding),
            "constant" => Ok(SymbolKind::Constant),
            "namespace" => Ok(SymbolKind::Namespace),
            "other" => Ok(SymbolKind::Other),
            _ => Err(StoreError::UnknownVocabulary {
                field: "symbol_kind",
                value: name.to_owned(),
            }),
        }
    }

    fn edge_kind(name: &str) -> Result<EdgeKind, StoreError> {
        match name {
            "flow" => Ok(EdgeKind::Flow),
            "taken" => Ok(EdgeKind::Taken),
            "not_taken" => Ok(EdgeKind::NotTaken),
            "unwind" => Ok(EdgeKind::Unwind),
            "return" => Ok(EdgeKind::Return),
            _ => Err(StoreError::UnknownVocabulary {
                field: "edge_kind",
                value: name.to_owned(),
            }),
        }
    }

    /// A stored index or count back in its own width.
    fn slot(value: i64) -> u32 {
        u32::try_from(value).unwrap_or(u32::MAX)
    }

    /// A stored protocol revision back in its own width.
    fn revision(value: i64) -> u32 {
        u32::try_from(value).unwrap_or(u32::MAX)
    }

    /// A stored byte offset back in its own width.
    pub(super) fn extent(value: i64) -> u64 {
        u64::try_from(value).unwrap_or(0)
    }
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
