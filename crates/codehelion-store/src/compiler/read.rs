use std::collections::BTreeMap;

use rusqlite::Connection;

use super::{
    CompilerCoverage, CompilerHelperRow, CompilerOutcome, StoredCompilerUnit, StoredExpansion,
    StoredHelperRef, anchor_at,
};
use crate::StoreError;
use codehelion_helper_protocol::ir::{
    BasicBlock, CallSite, CallTarget, CompilerIr, ControlFlowGraph, DataFlowSummary,
    DirectPropagation, Edge, EdgeKind, EffectSummary, FallibleKind, Instantiation,
    ResolvedExpression, ResolvedSymbol, ResolvedType, SemanticConstruct, SemanticConstructKind,
    SourceRange, SymbolKind, TypeCategory, Unavailability, UnexpandedMacro, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper_protocol::protocol::{Capability, Execution, HelperIdentity};
use rusqlite::{Row, params};
pub(super) fn helpers(
    conn: &Connection,
    run_id: i64,
) -> Result<Vec<CompilerHelperRow>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT id, name, version, protocol_version, restarts
             FROM compiler_helper WHERE scan_run_id = ?1 ORDER BY name, version",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut helpers = Vec::with_capacity(rows.len());
    for (id, name, version, protocol, restarts) in rows {
        helpers.push(CompilerHelperRow {
            identity: HelperIdentity {
                name,
                version,
                protocol: revision(protocol),
                toolchains: strings(
                    conn,
                    "SELECT toolchain FROM compiler_helper_toolchain
                         WHERE compiler_helper_id = ?1 ORDER BY toolchain",
                    id,
                )?,
                capabilities: capabilities(conn, id)?,
                executes: executions(conn, id)?,
            },
            restarts: restarts.map(revision),
        });
    }
    Ok(helpers)
}

pub(super) fn units(conn: &Connection, run_id: i64) -> Result<Vec<StoredCompilerUnit>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT u.id, u.unit_name, u.file_path, u.variant_key, u.schema_version,
                    u.unavailable_reason, u.unavailable_diagnostic, u.has_cfg, u.effects_computed, u.data_flow_computed,
                    h.name, h.version, u.anchored_at
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
                row.get::<_, Option<String>>(6)?,
                (
                    row.get::<_, i64>(7)? != 0,
                    row.get::<_, i64>(8)? != 0,
                    row.get::<_, i64>(9)? != 0,
                ),
                helper_ref(row)?,
                row.get::<_, Option<String>>(12)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut units = Vec::with_capacity(rows.len());
    for (id, unit, schema, reason, diagnostic, flags, helper, anchored_at) in rows {
        let outcome = match (schema, reason) {
            (Some(schema), _) => CompilerOutcome::Analyzed(Box::new(payload(
                conn,
                id,
                unit,
                Written {
                    schema_version: schema,
                    anchored_at,
                },
                flags,
            )?)),
            (None, Some(reason)) => CompilerOutcome::Unavailable {
                unit,
                reason: unavailability(&reason)?,
                diagnostic,
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

/// The counts, straight out of one grouped query.
///
/// A run that put nothing to a compiler has no rows and answers `None`,
/// which is the claim that no compiler was asked — not that one was asked
/// and said nothing.
///
/// The two gaps are told apart by the reason alone, the same way the run
/// itself told them apart while it was scanning. Reading them off the helper
/// column instead would work only while a failing helper still managed to
/// name itself: a process that died before its handshake stores its reason
/// beside no helper at all, and counting that as a file nobody was asked
/// about would replace the diagnosis with its opposite.
pub(super) fn coverage(
    conn: &Connection,
    run_id: i64,
) -> Result<Option<CompilerCoverage>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT unavailable_reason, unavailable_diagnostic, count(*)
             FROM compiler_unit WHERE scan_run_id = ?1
             GROUP BY unavailable_reason, unavailable_diagnostic",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut coverage = CompilerCoverage {
        restarts: restarts(conn, run_id)?,
        ..CompilerCoverage::default()
    };
    for (reason, diagnostic, count) in rows {
        let count = u64::try_from(count).unwrap_or(0);
        match reason {
            None => coverage.answered += count,
            Some(reason) => {
                if unavailability(&reason)?.is_helper_failure() {
                    *coverage.unavailable.entry(reason).or_default() += count;
                } else {
                    coverage.not_asked += count;
                    *coverage.not_asked_reasons.entry(reason).or_default() += count;
                }
            }
        }
        if let Some(diagnostic) = diagnostic {
            *coverage.diagnostics.entry(diagnostic).or_default() += count;
        }
    }
    Ok(Some(coverage))
}

/// How often the run's helpers were restarted, summed because each counts
/// its own.
///
/// A run with no helper row restarted nothing, which is zero rather than
/// unknown: it put files to nobody. One helper row that did not count is
/// what makes the total unknown, and it makes the whole total unknown
/// rather than a sum of the rest that reads like the answer.
fn restarts(conn: &Connection, run_id: i64) -> Result<Option<u32>, StoreError> {
    let mut statement =
        conn.prepare("SELECT restarts FROM compiler_helper WHERE scan_run_id = ?1")?;
    let rows = statement
        .query_map([run_id], |row| row.get::<_, Option<i64>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut total: u32 = 0;
    for row in rows {
        let Some(count) = row else {
            return Ok(None);
        };
        total = total.saturating_add(revision(count));
    }
    Ok(Some(total))
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

/// What an analysis says about itself rather than about the code.
struct Written {
    schema_version: String,
    anchored_at: Option<String>,
}

/// Everything hanging off one analysed unit.
fn payload(
    conn: &Connection,
    id: i64,
    unit: UnitRef,
    written: Written,
    flags: (bool, bool, bool),
) -> Result<CompilerIr, StoreError> {
    let (has_cfg, effects_computed, data_flow_computed) = flags;
    Ok(CompilerIr {
        schema_version: written.schema_version,
        anchored_at: written.anchored_at,
        unit,
        symbols: symbols(conn, id)?,
        types: types(conn, id)?,
        calls: calls(conn, id)?,
        semantic_constructs: semantic_constructs(conn, id)?,
        expressions: expressions(conn, id)?,
        unexpanded_macros: unexpanded_macros(conn, id)?,
        cfg: if has_cfg { Some(cfg(conn, id)?) } else { None },
        instantiations: instantiations(conn, id)?,
        effects: effects(conn, id, effects_computed)?,
        data_flow: data_flow(conn, id, data_flow_computed)?,
    })
}

fn semantic_constructs(conn: &Connection, id: i64) -> Result<Vec<SemanticConstruct>, StoreError> {
    let mut statement = conn.prepare(
            "SELECT kind, fallible_kind, direct_propagation, resource_kind, expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_semantic_construct WHERE compiler_unit_id = ?1 ORDER BY ordinal",
        )?;
    statement
        .query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                anchor_at(row, 4)?,
            ))
        })?
        .map(|row| {
            let (kind, fallible_kind, direct_propagation, resource_kind, anchor) = row?;
            let kind = SemanticConstructKind::parse(&kind).ok_or({
                StoreError::UnknownVocabulary {
                    field: "semantic construct kind",
                    value: kind,
                }
            })?;
            let fallible_kind = fallible_kind
                .map(|kind| {
                    FallibleKind::parse(&kind).ok_or(StoreError::UnknownVocabulary {
                        field: "semantic construct fallible kind",
                        value: kind,
                    })
                })
                .transpose()?;
            let direct_propagation = direct_propagation
                .map(|form| {
                    DirectPropagation::parse(&form).ok_or(StoreError::UnknownVocabulary {
                        field: "semantic construct direct propagation",
                        value: form,
                    })
                })
                .transpose()?;
            Ok(SemanticConstruct {
                anchor,
                kind,
                fallible_kind,
                direct_propagation,
                resource_kind,
            })
        })
        .collect()
}

fn expressions(conn: &Connection, id: i64) -> Result<Vec<ResolvedExpression>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT type_index, expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line
             FROM compiler_expression WHERE compiler_unit_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([id], |row| {
            Ok(ResolvedExpression {
                type_index: slot(row.get::<_, i64>(0)?),
                anchor: anchor_at(row, 1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn unexpanded_macros(conn: &Connection, id: i64) -> Result<Vec<UnexpandedMacro>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT reason, invocation_file, invocation_start_byte, invocation_end_byte,
                    invocation_start_line
             FROM compiler_unexpanded_macro WHERE compiler_unit_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                SourceRange {
                    file: row.get(1)?,
                    start_byte: extent(row.get(2)?),
                    end_byte: extent(row.get(3)?),
                    start_line: row.get(4)?,
                },
            ))
        })?
        .map(|row| {
            let (reason, invocation) = row?;
            let reason = UnexpandedMacroReason::parse(&reason).ok_or({
                StoreError::UnknownVocabulary {
                    field: "unexpanded macro reason",
                    value: reason,
                }
            })?;
            Ok(UnexpandedMacro { invocation, reason })
        })
        .collect()
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
        "SELECT id, resolution, target_symbol, api_name,
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
                row.get::<_, Option<String>>(3)?,
                anchor_at(row, 4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(call_id, resolution, target, api_name, anchor)| {
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
            Ok(CallSite {
                anchor,
                target,
                api_name,
            })
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
        "SELECT id, definition, artifact_match_key, instantiation_key,
                    expansion_file, expansion_start_byte, expansion_end_byte,
                    expansion_start_line, definition_file, definition_start_byte,
                    definition_end_byte, definition_start_line, definition_end_line
             FROM compiler_instantiation WHERE compiler_unit_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([id], |row| {
            let row_id: i64 = row.get(0)?;
            Ok(Instantiation {
                definition: row.get(1)?,
                artifact_match_key: row.get(2)?,
                instantiation_key: row.get(3)?,
                anchor: anchor_at(row, 4)?,
                definition_end_line: row.get(12)?,
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

fn data_flow(conn: &Connection, id: i64, computed: bool) -> Result<DataFlowSummary, StoreError> {
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
    names.iter().map(|name| capability(name)).collect()
}

fn executions(conn: &Connection, id: i64) -> Result<Vec<Execution>, StoreError> {
    let names = strings(
        conn,
        "SELECT execution FROM compiler_helper_execution
             WHERE compiler_helper_id = ?1 ORDER BY execution",
        id,
    )?;
    names
        .iter()
        .map(|name| {
            Execution::from_name(name).ok_or_else(|| StoreError::UnknownVocabulary {
                field: "compiler_helper_execution",
                value: name.clone(),
            })
        })
        .collect()
}

fn strings(conn: &Connection, sql: &str, id: i64) -> Result<Vec<String>, StoreError> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement
        .query_map([id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn helper_ref(row: &Row<'_>) -> rusqlite::Result<Option<StoredHelperRef>> {
    let name: Option<String> = row.get(10)?;
    let version: Option<String> = row.get(11)?;
    Ok(name
        .zip(version)
        .map(|(name, version)| StoredHelperRef { name, version }))
}

/// A capability name as this v2 build reads it.
fn capability(name: &str) -> Result<Capability, StoreError> {
    match name {
        "types" => Ok(Capability::Types),
        "name_resolution" => Ok(Capability::NameResolution),
        "call_targets" => Ok(Capability::CallTargets),
        "mir_cfg" => Ok(Capability::MirCfg),
        "macro_expansion" => Ok(Capability::MacroExpansion),
        "template_instantiation" => Ok(Capability::TemplateInstantiation),
        _ => Err(StoreError::UnknownVocabulary {
            field: "compiler_helper_capability",
            value: name.to_owned(),
        }),
    }
}

/// A stored reason back as the reason a helper reported.
///
/// Resolved through the protocol's own list of reasons, which is what the
/// column's vocabulary is built from: reading and writing therefore accept the
/// same set, and a reason cannot become storable but unreadable.
fn unavailability(name: &str) -> Result<Unavailability, StoreError> {
    Unavailability::from_name(name).ok_or_else(|| StoreError::UnknownVocabulary {
        field: "unavailable_reason",
        value: name.to_owned(),
    })
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
