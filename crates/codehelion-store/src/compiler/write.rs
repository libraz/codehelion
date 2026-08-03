use super::{
    Anchor, BTreeSet, CallSite, CallTarget, CompilerHelperRow, CompilerIr, CompilerOutcome,
    ControlFlowGraph, DataFlowSummary, DirectPropagation, EffectSummary, FallibleKind,
    Instantiation, ResolvedExpression, ResolvedSymbol, ResolvedType, SemanticConstruct, Snapshot,
    StoreError, Transaction, UnexpandedMacro, params,
};

/// Write a run's compiler results, returning the distinct IR schema versions
/// they were written against.
///
/// The versions come back rather than being recorded here so the caller can
/// declare them as detector versions of the run: a run holding IR from a
/// schema this build no longer reads has to be recognisable as such, and the
/// stored rows say which schema each unit used but nothing at run level does.
pub(super) fn write(
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
                 (scan_run_id, name, version, protocol_version, restarts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                run_id,
                helper.identity.name,
                helper.identity.version,
                i64::from(helper.identity.protocol),
                helper.restarts.map(i64::from),
            ],
        )?;
        let id = tx.last_insert_rowid();
        for capability in &helper.identity.capabilities {
            tx.execute(
                "INSERT OR IGNORE INTO compiler_helper_capability
                     (compiler_helper_id, capability) VALUES (?1, ?2)",
                params![id, capability.name()],
            )?;
        }
        for toolchain in &helper.identity.toolchains {
            tx.execute(
                "INSERT OR IGNORE INTO compiler_helper_toolchain
                     (compiler_helper_id, toolchain) VALUES (?1, ?2)",
                params![id, toolchain],
            )?;
        }
        for execution in &helper.identity.executes {
            tx.execute(
                "INSERT OR IGNORE INTO compiler_helper_execution
                     (compiler_helper_id, execution) VALUES (?1, ?2)",
                params![id, execution.name()],
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
    let (schema, anchored_at, reason, diagnostic, cfg, effects, flows) = match outcome {
        CompilerOutcome::Analyzed(ir) => (
            Some(ir.schema_version.as_str()),
            ir.anchored_at.as_deref(),
            None,
            None,
            ir.cfg.is_some(),
            ir.effects.computed,
            ir.data_flow.computed,
        ),
        CompilerOutcome::Unavailable {
            reason, diagnostic, ..
        } => (
            None,
            None,
            Some(reason.name()),
            diagnostic.as_deref(),
            false,
            false,
            false,
        ),
    };
    tx.execute(
        "INSERT INTO compiler_unit
             (scan_run_id, build_variant_id, compiler_helper_id, unit_name, file_path,
              variant_key, schema_version, anchored_at, unavailable_reason, unavailable_diagnostic,
              has_cfg, effects_computed, data_flow_computed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            run_id,
            variant_id,
            helper_id,
            unit.unit,
            unit.file,
            unit.variant,
            schema,
            anchored_at,
            reason,
            diagnostic,
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
    write_semantic_constructs(tx, &ir.semantic_constructs, unit_id)?;
    write_expressions(tx, &ir.expressions, unit_id)?;
    write_unexpanded_macros(tx, &ir.unexpanded_macros, unit_id)?;
    if let Some(cfg) = &ir.cfg {
        write_cfg(tx, cfg, unit_id)?;
    }
    write_instantiations(tx, &ir.instantiations, unit_id)?;
    write_effects(tx, &ir.effects, unit_id)?;
    write_data_flow(tx, &ir.data_flow, unit_id)?;
    Ok(())
}

fn write_semantic_constructs(
    tx: &Transaction<'_>,
    constructs: &[SemanticConstruct],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, construct) in constructs.iter().enumerate() {
        let cells = AnchorCells::of(&construct.anchor);
        tx.execute(
            "INSERT INTO compiler_semantic_construct
             (compiler_unit_id, ordinal, kind, fallible_kind, direct_propagation, resource_kind, expansion_file, expansion_start_byte,
              expansion_end_byte, expansion_start_line, definition_file,
              definition_start_byte, definition_end_byte, definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                unit_id,
                index_of(ordinal),
                construct.kind.name(),
                construct.fallible_kind.map(FallibleKind::name),
                construct.direct_propagation.map(DirectPropagation::name),
                construct.resource_kind,
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line
            ],
        )?;
    }
    Ok(())
}

fn write_expressions(
    tx: &Transaction<'_>,
    expressions: &[ResolvedExpression],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, expression) in expressions.iter().enumerate() {
        let cells = AnchorCells::of(&expression.anchor);
        tx.execute(
            "INSERT INTO compiler_expression
                 (compiler_unit_id, ordinal, type_index, expansion_file,
                  expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                unit_id,
                index_of(ordinal),
                i64::from(expression.type_index),
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

fn write_unexpanded_macros(
    tx: &Transaction<'_>,
    macros: &[UnexpandedMacro],
    unit_id: i64,
) -> Result<(), StoreError> {
    for (ordinal, macro_) in macros.iter().enumerate() {
        tx.execute(
            "INSERT INTO compiler_unexpanded_macro
                 (compiler_unit_id, ordinal, reason, invocation_file,
                  invocation_start_byte, invocation_end_byte, invocation_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                unit_id,
                index_of(ordinal),
                macro_.reason.name(),
                macro_.invocation.file,
                offset(macro_.invocation.start_byte),
                offset(macro_.invocation.end_byte),
                macro_.invocation.start_line,
            ],
        )?;
    }
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
                resolved.category.name(),
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
                symbol.kind.name(),
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
                 (compiler_unit_id, ordinal, resolution, target_symbol, api_name,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                unit_id,
                index_of(ordinal),
                resolution,
                target,
                call.api_name,
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
                edge.kind.name(),
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
                 (compiler_unit_id, ordinal, definition, artifact_match_key, instantiation_key,
                  expansion_file, expansion_start_byte, expansion_end_byte, expansion_start_line,
                  definition_file, definition_start_byte, definition_end_byte,
                  definition_start_line, definition_end_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                unit_id,
                index_of(ordinal),
                instantiation.definition,
                instantiation.artifact_match_key,
                instantiation.instantiation_key,
                cells.file,
                cells.start_byte,
                cells.end_byte,
                cells.start_line,
                cells.definition_file,
                cells.definition_start_byte,
                cells.definition_end_byte,
                cells.definition_start_line,
                instantiation.definition_end_line.map(i64::from),
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
